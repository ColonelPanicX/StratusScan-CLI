#!/usr/bin/env python3
"""
Moto-based tests for s3-export.py.

Covers:
- get_s3_buckets_info()
"""

import importlib.util
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

# ---------------------------------------------------------------------------
# Load exporter module
# ---------------------------------------------------------------------------

_scripts_dir = Path(__file__).parent.parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location(
    "s3_export", _scripts_dir / "s3-export.py"
)
_s3_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_s3_export)

get_s3_buckets_info = _s3_export.get_s3_buckets_info


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetS3BucketsInfo:
    """Tests for get_s3_buckets_info()."""

    @mock_aws
    def test_created_bucket_appears_in_results(self):
        """A newly created S3 bucket is returned by the collector."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="my-test-bucket-abc123")

        result = get_s3_buckets_info()

        assert isinstance(result, list)
        assert len(result) >= 1
        bucket_names = [row["Bucket Name"] for row in result]
        assert "my-test-bucket-abc123" in bucket_names

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="col-check-bucket-xyz")

        result = get_s3_buckets_info()

        assert len(result) >= 1
        row = result[0]
        for col in ("Bucket Name", "Region", "Creation Date"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_bucket_with_objects_counted(self):
        """A bucket with objects has a non-zero object count."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="objects-bucket-test1")
        s3.put_object(Bucket="objects-bucket-test1", Key="file.txt", Body=b"hello")

        result = get_s3_buckets_info()

        bucket_row = next(
            (r for r in result if r["Bucket Name"] == "objects-bucket-test1"), None
        )
        assert bucket_row is not None

    @mock_aws
    def test_empty_account_returns_empty_list(self):
        """Account with no S3 buckets returns an empty list."""
        result = get_s3_buckets_info()
        assert result == []
