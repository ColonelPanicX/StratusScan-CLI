#!/usr/bin/env python3
"""
Moto-based tests for the S3 output-delivery feature (Issue #175) in utils.py.

Covers:
- upload_to_s3()            — success deletes local + returns s3 uri; failure retains local
- deliver_output()          — routes to S3 when enabled, passthrough when local
- resolve_s3_destination()  — config vs STRATUSSCAN_S3_BUCKET env override
- test_s3_connectivity()    — HeadBucket -> PutObject -> DeleteObject step reporting
- _build_s3_key()           — prefix/basename joining
"""

import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

try:
    import utils
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import utils

REGION = "us-east-1"
BUCKET = "stratusscan-test-bucket"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    # Ensure no stray env override leaks between tests.
    monkeypatch.delenv("STRATUSSCAN_S3_BUCKET", raising=False)
    monkeypatch.delenv("STRATUSSCAN_S3_PREFIX", raising=False)
    monkeypatch.delenv("STRATUSSCAN_REGIONS", raising=False)


def _make_bucket():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET)
    return s3


def _local_file(tmp_path, name="acct-ec2-export-01.01.2026.xlsx", body=b"data"):
    p = tmp_path / name
    p.write_bytes(body)
    return str(p)


class TestBuildS3Key:
    def test_prefix_and_basename_joined(self):
        assert utils._build_s3_key("stratusscan/", "/out/acct-ec2.xlsx") == "stratusscan/acct-ec2.xlsx"

    def test_prefix_without_trailing_slash_gets_one(self):
        assert utils._build_s3_key("evidence", "/out/x.csv") == "evidence/x.csv"

    def test_empty_prefix_is_bare_key(self):
        assert utils._build_s3_key("", "/out/x.csv") == "x.csv"

    def test_leading_slash_stripped(self):
        assert utils._build_s3_key("/stratusscan/", "/out/x.csv") == "stratusscan/x.csv"


class TestUploadToS3:
    @mock_aws
    def test_success_uploads_and_deletes_local(self, tmp_path):
        s3 = _make_bucket()
        local = _local_file(tmp_path)

        uri = utils.upload_to_s3(local, BUCKET, "stratusscan/")

        assert uri == f"s3://{BUCKET}/stratusscan/acct-ec2-export-01.01.2026.xlsx"
        # Object landed in S3
        obj = s3.get_object(Bucket=BUCKET, Key="stratusscan/acct-ec2-export-01.01.2026.xlsx")
        assert obj["Body"].read() == b"data"
        # Local copy deleted on success
        assert not Path(local).exists()

    @mock_aws
    def test_failure_retains_local_and_returns_none(self, tmp_path):
        _make_bucket()
        local = _local_file(tmp_path)

        # Upload to a bucket that does not exist -> failure
        uri = utils.upload_to_s3(local, "no-such-bucket-xyz", "stratusscan/")

        assert uri is None
        assert Path(local).exists()  # retained as fallback

    @mock_aws
    def test_missing_local_file_returns_none(self):
        _make_bucket()
        assert utils.upload_to_s3("/does/not/exist.xlsx", BUCKET) is None

    def test_empty_bucket_returns_none(self, tmp_path):
        local = _local_file(tmp_path)
        assert utils.upload_to_s3(local, "") is None
        assert Path(local).exists()


class TestResolveS3Destination:
    def test_env_var_forces_s3(self, monkeypatch):
        monkeypatch.setenv("STRATUSSCAN_S3_BUCKET", "env-bucket")
        monkeypatch.setenv("STRATUSSCAN_S3_PREFIX", "ci/")
        dest = utils.resolve_s3_destination()
        assert dest == {"enabled": True, "bucket": "env-bucket", "prefix": "ci/"}

    def test_config_s3_destination(self, monkeypatch):
        def fake_config_value(key, default=None, section=None):
            values = {
                ("destination", "output_settings"): "s3",
                ("s3", "output_settings"): {"bucket": "cfg-bucket", "prefix": "stratusscan/"},
            }
            return values.get((key, section), default)

        monkeypatch.setattr(utils, "config_value", fake_config_value)
        dest = utils.resolve_s3_destination()
        assert dest["enabled"] is True
        assert dest["bucket"] == "cfg-bucket"
        assert dest["prefix"] == "stratusscan/"

    def test_local_destination_not_enabled(self, monkeypatch):
        def fake_config_value(key, default=None, section=None):
            values = {
                ("destination", "output_settings"): "local",
                ("s3", "output_settings"): {"bucket": "", "prefix": "stratusscan/"},
            }
            return values.get((key, section), default)

        monkeypatch.setattr(utils, "config_value", fake_config_value)
        assert utils.resolve_s3_destination()["enabled"] is False

    def test_s3_selected_but_no_bucket_not_enabled(self, monkeypatch):
        def fake_config_value(key, default=None, section=None):
            values = {
                ("destination", "output_settings"): "s3",
                ("s3", "output_settings"): {"bucket": "", "prefix": "stratusscan/"},
            }
            return values.get((key, section), default)

        monkeypatch.setattr(utils, "config_value", fake_config_value)
        assert utils.resolve_s3_destination()["enabled"] is False


class TestDeliverOutput:
    def test_local_destination_passthrough(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            utils, "resolve_s3_destination",
            lambda: {"enabled": False, "bucket": "", "prefix": ""},
        )
        local = _local_file(tmp_path)
        assert utils.deliver_output(local) == local
        assert Path(local).exists()

    @mock_aws
    def test_s3_destination_uploads(self, monkeypatch, tmp_path):
        _make_bucket()
        monkeypatch.setattr(
            utils, "resolve_s3_destination",
            lambda: {"enabled": True, "bucket": BUCKET, "prefix": "stratusscan/"},
        )
        local = _local_file(tmp_path)
        result = utils.deliver_output(local)
        assert result.startswith(f"s3://{BUCKET}/stratusscan/")
        assert not Path(local).exists()

    @mock_aws
    def test_failed_upload_falls_back_to_local(self, monkeypatch, tmp_path):
        # bucket not created -> upload fails -> deliver returns local path
        monkeypatch.setattr(
            utils, "resolve_s3_destination",
            lambda: {"enabled": True, "bucket": "missing-bucket", "prefix": "stratusscan/"},
        )
        local = _local_file(tmp_path)
        assert utils.deliver_output(local) == local
        assert Path(local).exists()


class TestS3Connectivity:
    @mock_aws
    def test_full_roundtrip_ok(self):
        _make_bucket()
        result = utils.test_s3_connectivity(BUCKET, "stratusscan/")
        assert result["ok"] is True
        assert result["failed_step"] is None
        assert [s["step"] for s in result["steps"]] == ["HeadBucket", "PutObject", "DeleteObject"]
        assert all(s["ok"] for s in result["steps"])
        # Probe object cleaned up
        s3 = boto3.client("s3", region_name=REGION)
        assert "Contents" not in s3.list_objects_v2(Bucket=BUCKET)

    @mock_aws
    def test_missing_bucket_fails_at_headbucket(self):
        result = utils.test_s3_connectivity("no-such-bucket-zzz", "stratusscan/")
        assert result["ok"] is False
        assert result["failed_step"] == "HeadBucket"

    def test_no_bucket_fails_at_config(self):
        result = utils.test_s3_connectivity("", "stratusscan/")
        assert result["ok"] is False
        assert result["failed_step"] == "config"
