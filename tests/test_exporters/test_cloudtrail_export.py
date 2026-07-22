#!/usr/bin/env python3
"""
Moto-based tests for cloudtrail_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cloudtrail_export  # noqa: E402
from cloudtrail_export import collect_trails_from_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_trail(ct_client, s3_client, name):
    """Create an S3 bucket + CloudTrail trail named ``name``."""
    bucket_name = f"{name}-bucket-12345"
    s3_client.create_bucket(Bucket=bucket_name)
    ct_client.create_trail(Name=name, S3BucketName=bucket_name)


class TestCollectTrailsFromRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_trails(self):
        ct_client = boto3.client("cloudtrail", region_name=REGION)
        s3_client = boto3.client("s3", region_name=REGION)
        _create_trail(ct_client, s3_client, "web-trail")

        rows = collect_trails_from_region(REGION)

        names = {row["Trail Name"] for row in rows}
        assert "web-trail" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("cloudtrail", region_name=REGION)  # region exists, no trails

        rows = collect_trails_from_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One trail that fails to process must not discard the whole region."""
        ct_client = boto3.client("cloudtrail", region_name=REGION)
        s3_client = boto3.client("s3", region_name=REGION)
        _create_trail(ct_client, s3_client, "good-trail")
        _create_trail(ct_client, s3_client, "bad-trail")

        original = cloudtrail_export._build_trail_row

        def raise_for_bad(ct_client, trail_summary, region):
            if trail_summary.get("Name") == "bad-trail":
                raise KeyError("SomeUnexpectedField")
            return original(ct_client, trail_summary, region)

        monkeypatch.setattr(cloudtrail_export, "_build_trail_row", raise_for_bad)

        rows = collect_trails_from_region(REGION)

        names = {row["Trail Name"] for row in rows}
        assert "good-trail" in names, "healthy trail was lost when a sibling failed"
        assert "bad-trail" not in names, "malformed trail should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListTrails",
            )

        monkeypatch.setattr(cloudtrail_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_trails_from_region(REGION)

    @mock_aws
    def test_collect_trails_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListTrails",
            )

        monkeypatch.setattr(cloudtrail_export, "collect_trails_from_region", boom)

        trails, failed_regions = cloudtrail_export.collect_trails([REGION])

        assert trails == []
        assert [r for r, _ in failed_regions] == [REGION]
