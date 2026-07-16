#!/usr/bin/env python3
"""
Moto-based tests for ebs_volumes_export.py.

Covers:
- get_ebs_volumes()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ebs_volumes_export  # noqa: E402
from ebs_volumes_export import get_ebs_volumes  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestGetEbsVolumes:
    """Tests for get_ebs_volumes()."""

    @mock_aws
    def test_created_volume_appears_in_results(self):
        """A newly created EBS volume is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        volume = ec2.create_volume(Size=8, AvailabilityZone=f"{REGION}a", VolumeType="gp3")

        result = get_ebs_volumes(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["Volume ID"] == volume["VolumeId"] for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.create_volume(Size=8, AvailabilityZone=f"{REGION}a", VolumeType="gp3")

        result = get_ebs_volumes(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Volume ID", "Size (GB)", "State", "Region"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no EBS volumes returns an empty list."""
        result = get_ebs_volumes(REGION)
        assert result == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the silent-collection-failure sweep: EBS volume data
    silently lost because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region. See
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One volume that fails to process must not discard the whole region's
        results — the healthy volume is still collected.
        """
        ec2 = boto3.client("ec2", region_name=REGION)
        good_volume = ec2.create_volume(Size=8, AvailabilityZone=f"{REGION}a", VolumeType="gp3")
        bad_volume = ec2.create_volume(Size=8, AvailabilityZone=f"{REGION}a", VolumeType="gp3")

        original = ebs_volumes_export._build_volume_data

        def raise_for_bad(volume, *args, **kwargs):
            if volume.get("VolumeId") == bad_volume["VolumeId"]:
                raise KeyError("SomeUnexpectedField")
            return original(volume, *args, **kwargs)

        monkeypatch.setattr(ebs_volumes_export, "_build_volume_data", raise_for_bad)

        result = get_ebs_volumes(REGION)

        ids = {row["Volume ID"] for row in result}
        assert good_volume["VolumeId"] in ids, "healthy volume was lost when a sibling failed"
        assert bad_volume["VolumeId"] not in ids, "malformed volume should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeVolumes",
            )

        monkeypatch.setattr(ebs_volumes_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_ebs_volumes(REGION)
