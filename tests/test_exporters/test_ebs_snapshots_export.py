#!/usr/bin/env python3
"""
Moto-based tests for ebs_snapshots_export.py.

Covers:
- get_snapshots()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ebs_snapshots_export  # noqa: E402
from ebs_snapshots_export import get_snapshots  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_snapshot(ec2):
    volume = ec2.create_volume(Size=8, AvailabilityZone=f"{REGION}a")
    snapshot = ec2.create_snapshot(VolumeId=volume["VolumeId"])
    return snapshot["SnapshotId"]


class TestGetSnapshots:
    """Tests for get_snapshots()."""

    @mock_aws
    def test_created_snapshot_appears_in_results(self):
        """A newly created EBS snapshot is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        snapshot_id = _create_snapshot(ec2)

        result = get_snapshots(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["Snapshot ID"] == snapshot_id for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        _create_snapshot(ec2)

        result = get_snapshots(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Name", "Snapshot ID", "Volume ID", "Region", "Encryption"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_empty_region_returns_list_without_created_snapshot(self):
        """
        Region with no volume-backed snapshots created by the test does not
        contain a snapshot this test never made. (moto seeds baseline
        AMI-owned snapshots for 'self' in a fresh account, so this asserts
        non-presence rather than strict emptiness.)
        """
        result = get_snapshots(REGION)
        assert isinstance(result, list)
        assert not any(row["Description"] == "unique-marker-not-created" for row in result)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 audit / 07.16.2026 blast-radius sweep:
    exporters silently lost data because a collection error was swallowed to
    an empty list, indistinguishable from a genuinely empty region. See
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One snapshot that fails to process must not discard the whole
        region's results — the healthy snapshot is still collected.
        """
        ec2 = boto3.client("ec2", region_name=REGION)
        good_id = _create_snapshot(ec2)
        bad_id = _create_snapshot(ec2)

        original = ebs_snapshots_export._build_snapshot_row

        def raise_for_bad(snapshot, region):
            if snapshot.get("SnapshotId") == bad_id:
                raise KeyError("SomeUnexpectedField")
            return original(snapshot, region)

        monkeypatch.setattr(ebs_snapshots_export, "_build_snapshot_row", raise_for_bad)

        result = get_snapshots(REGION)

        ids = {row["Snapshot ID"] for row in result}
        assert good_id in ids, "healthy snapshot was lost when a sibling failed"
        assert bad_id not in ids, "malformed snapshot should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeSnapshots",
            )

        monkeypatch.setattr(ebs_snapshots_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_snapshots(REGION)
