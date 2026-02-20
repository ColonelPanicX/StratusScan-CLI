#!/usr/bin/env python3
"""
Moto-based tests for s3_export.py.

Covers:
- get_s3_buckets_info()
"""

import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
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

        result = get_s3_buckets_info()

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["Bucket Name"] == "my-test-bucket-abc123" for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="col-check-bucket-xyz")

        result = get_s3_buckets_info()

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

        result = get_s3_buckets_info()

        assert any(row["Bucket Name"] == "objects-bucket-test1" for row in result)

    @mock_aws
    def test_empty_account_returns_empty_list(self):
        """Account with no S3 buckets returns an empty list."""
        result = get_s3_buckets_info()
        assert result == []
