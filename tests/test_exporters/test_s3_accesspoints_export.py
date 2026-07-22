#!/usr/bin/env python3
"""
Moto-based tests for s3_accesspoints_export.py.

Focus: the silent-collection-failure contract (Tier-2b) for the primary
regional scope, collect_standard_access_points()/
_scan_standard_access_points_region(). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

moto's S3 Control (Access Points) support covers create/list/get for a
single happy-path access point, but not the full surface (pagination
tokens, GetPublicAccessBlock/GetAccessPointPolicyStatus edge cases, error
injection). The regression tests below therefore monkeypatch the s3control
client directly rather than relying on moto for the error-path and
malformed-item cases; only the happy-path class exercises real moto calls.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import s3_accesspoints_export  # noqa: E402
from s3_accesspoints_export import _scan_standard_access_points_region  # noqa: E402

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakeS3Control:
    """
    Minimal stand-in for an s3control client used by the regression tests
    below, since moto's Access Points support does not cover pagination
    tokens or error injection. ``list_access_points`` returns the fixed
    ``access_points`` list; the detail calls return the same "nothing
    configured" responses AWS returns for a fresh access point (verified
    against moto's real GetPublicAccessBlock/GetAccessPointPolicyStatus
    behavior).
    """

    def __init__(self, access_points):
        self._access_points = access_points

    def list_access_points(self, **kwargs):
        return {"AccessPointList": self._access_points}

    def get_access_point(self, **kwargs):
        return {"CreationDate": "N/A"}

    def get_public_access_block(self, **kwargs):
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "NoSuchPublicAccessBlockConfiguration",
                    "Message": "The public access block configuration was not found",
                }
            },
            "GetPublicAccessBlock",
        )

    def get_access_point_policy_status(self, **kwargs):
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "NoSuchAccessPointPolicy",
                    "Message": "The specified accesspoint policy does not exist",
                }
            },
            "GetAccessPointPolicyStatus",
        )


class TestScanStandardAccessPointsRegion:
    """Happy-path collection (real moto S3 Control calls)."""

    @mock_aws
    def test_collects_access_points(self):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="test-bucket-ap")
        s3control = boto3.client("s3control", region_name=REGION)
        s3control.create_access_point(AccountId=ACCOUNT_ID, Name="test-ap", Bucket="test-bucket-ap")

        rows = _scan_standard_access_points_region(REGION, ACCOUNT_ID)

        names = {row["AccessPointName"] for row in rows}
        assert "test-ap" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("s3control", region_name=REGION)  # region exists, no access points

        rows = _scan_standard_access_points_region(REGION, ACCOUNT_ID)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One access point that fails to process must not discard the whole region."""
        fake_client = _FakeS3Control(
            [
                {
                    "Name": "good-ap",
                    "AccessPointArn": f"arn:aws:s3:{REGION}:{ACCOUNT_ID}:accesspoint/good-ap",
                    "Bucket": "good-bucket",
                    "NetworkOrigin": "Internet",
                },
                {
                    "Name": "bad-ap",
                    "AccessPointArn": f"arn:aws:s3:{REGION}:{ACCOUNT_ID}:accesspoint/bad-ap",
                    "Bucket": "bad-bucket",
                    "NetworkOrigin": "Internet",
                },
            ]
        )
        monkeypatch.setattr(
            s3_accesspoints_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        original = s3_accesspoints_export._build_access_point_row

        def raise_for_bad(ap, region, account_id, s3control):
            if ap.get("Name") == "bad-ap":
                raise KeyError("SomeUnexpectedField")
            return original(ap, region, account_id, s3control)

        monkeypatch.setattr(s3_accesspoints_export, "_build_access_point_row", raise_for_bad)

        rows = _scan_standard_access_points_region(REGION, ACCOUNT_ID)

        names = {row["AccessPointName"] for row in rows}
        assert "good-ap" in names, "healthy access point was lost when a sibling failed"
        assert "bad-ap" not in names, "malformed access point should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListAccessPoints",
            )

        monkeypatch.setattr(s3_accesspoints_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_standard_access_points_region(REGION, ACCOUNT_ID)

    def test_collect_standard_access_points_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region, account_id):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListAccessPoints",
            )

        monkeypatch.setattr(s3_accesspoints_export, "_scan_standard_access_points_region", boom)

        access_points, failed_regions = s3_accesspoints_export.collect_standard_access_points(
            [REGION], ACCOUNT_ID
        )

        assert access_points == []
        assert [r for r, _ in failed_regions] == [REGION]
