#!/usr/bin/env python3
"""
Moto-based tests for s3_export.py.

Covers:
- get_s3_buckets_info()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import s3_export  # noqa: E402
from s3_export import get_s3_buckets_info  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestGetS3BucketsInfo:
    """Tests for get_s3_buckets_info()."""

    @mock_aws
    def test_created_bucket_appears_in_results(self):
        """A newly created S3 bucket is returned by the collector."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="my-test-bucket-abc123")

        result, failed = get_s3_buckets_info()

        assert isinstance(result, list)
        assert failed == []
        assert len(result) >= 1
        assert any(row["Bucket Name"] == "my-test-bucket-abc123" for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="col-check-bucket-xyz")

        result, failed = get_s3_buckets_info()

        assert failed == []
        assert len(result) >= 1
        row = result[0]
        for col in ("Bucket Name", "Region", "Creation Date"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_bucket_with_objects_is_returned(self):
        """A bucket containing objects still appears in results."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="objects-bucket-test1")
        s3.put_object(Bucket="objects-bucket-test1", Key="file.txt", Body=b"hello")

        result, failed = get_s3_buckets_info()

        assert failed == []
        assert any(row["Bucket Name"] == "objects-bucket-test1" for row in result)

    @mock_aws
    def test_empty_account_returns_empty_list(self):
        """Account with no S3 buckets returns an empty list and no failures."""
        result, failed = get_s3_buckets_info()
        assert result == []
        assert failed == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 audit: exporters could silently lose
    data because a collection error was swallowed into an empty result,
    indistinguishable from a genuinely empty account. See
    .collab/audit/07.15.2026-rds-silent-collection-failure.md and the
    07.16.2026 blast-radius sweep.

    S3 is structured differently from the region-scanned exporters: buckets
    (not regions) are the unit of collection, and get_s3_buckets_info() runs
    its own internal per-bucket loop. So failures are tracked per-bucket and
    returned as (buckets_info, failed_buckets) instead of via
    scan_regions_concurrent(collect_failures=True).
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One bucket that fails to process must not discard the other buckets'
        results — the healthy bucket is still collected, and the bad one is
        reported back via failed_buckets instead of raising.
        """
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="good-bucket")
        s3.create_bucket(Bucket="bad-bucket")

        original = s3_export._build_bucket_row

        def raise_for_bad(bucket, *args, **kwargs):
            if bucket.get("Name") == "bad-bucket":
                raise KeyError("SomeUnexpectedField")
            return original(bucket, *args, **kwargs)

        monkeypatch.setattr(s3_export, "_build_bucket_row", raise_for_bad)

        result, failed = get_s3_buckets_info()

        names = {row["Bucket Name"] for row in result}
        assert "good-bucket" in names, "healthy bucket was lost when a sibling failed"
        assert "bad-bucket" not in names, "malformed bucket should have been skipped"

        failed_names = {name for name, _ in failed}
        assert "bad-bucket" in failed_names, "bad bucket should be reported in failed_buckets"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A top-level API failure (e.g. list_buckets throttling, or client
        creation) must propagate (so the caller can distinguish a failed
        collection from an empty account) rather than being swallowed into an
        empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListBuckets",
            )

        monkeypatch.setattr(s3_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_s3_buckets_info()
