#!/usr/bin/env python3
"""
Moto-based tests for efs_export.py.

Focus: the silent-collection-failure contract (Tier-2b). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import efs_export  # noqa: E402
from efs_export import _scan_efs_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_file_system(client, creation_token):
    """Create an EFS file system with the given creation token."""
    return client.create_file_system(CreationToken=creation_token)


class TestScanEfsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_file_systems(self):
        client = boto3.client("efs", region_name=REGION)
        _create_file_system(client, "web-fs")

        rows = _scan_efs_region(REGION)

        tokens = {row["Creation Token"] for row in rows}
        assert "web-fs" in tokens

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("efs", region_name=REGION)  # region exists, no file systems

        rows = _scan_efs_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One file system that fails to process must not discard the whole region."""
        client = boto3.client("efs", region_name=REGION)
        _create_file_system(client, "good-fs")
        _create_file_system(client, "bad-fs")

        original = efs_export._build_filesystem_row

        def raise_for_bad(fs, region, pricing):
            if fs.get("CreationToken") == "bad-fs":
                raise KeyError("SomeUnexpectedField")
            return original(fs, region, pricing)

        monkeypatch.setattr(efs_export, "_build_filesystem_row", raise_for_bad)

        rows = _scan_efs_region(REGION)

        tokens = {row["Creation Token"] for row in rows}
        assert "good-fs" in tokens, "healthy file system was lost when a sibling failed"
        assert "bad-fs" not in tokens, "malformed file system should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeFileSystems",
            )

        monkeypatch.setattr(efs_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_efs_region(REGION)

    @mock_aws
    def test_collect_efs_file_systems_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeFileSystems",
            )

        monkeypatch.setattr(efs_export, "_scan_efs_region", boom)

        file_systems, failed_regions = efs_export.collect_efs_file_systems([REGION])

        assert file_systems == []
        assert [r for r, _ in failed_regions] == [REGION]
