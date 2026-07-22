#!/usr/bin/env python3
"""
Moto-based tests for config_export.py.

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
import config_export  # noqa: E402
from config_export import _scan_recorders_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_recorder(client, name):
    """Create a Config configuration recorder named ``name``."""
    client.put_configuration_recorder(
        ConfigurationRecorder={
            "name": name,
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {
                "allSupported": True,
                "includeGlobalResourceTypes": True,
            },
        }
    )


class TestScanRecordersRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_recorders(self):
        client = boto3.client("config", region_name=REGION)
        _create_recorder(client, "default")

        rows = _scan_recorders_region(REGION)

        names = {row["Recorder Name"] for row in rows}
        assert "default" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("config", region_name=REGION)  # region exists, no recorders

        rows = _scan_recorders_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One recorder that fails to process must not discard the whole region."""
        # AWS Config only allows a single configuration recorder per region,
        # so a second "bad" recorder is injected via a wrapped
        # describe_configuration_recorders response rather than a real
        # put_configuration_recorder call.
        client = boto3.client("config", region_name=REGION)
        _create_recorder(client, "good-recorder")

        real_describe = client.describe_configuration_recorders

        def fake_describe(*args, **kwargs):
            resp = dict(real_describe(*args, **kwargs))
            resp["ConfigurationRecorders"] = list(resp["ConfigurationRecorders"]) + [
                {
                    "name": "bad-recorder",
                    "roleARN": "arn:aws:iam::123456789012:role/config-role",
                    "recordingGroup": {"allSupported": True},
                }
            ]
            return resp

        monkeypatch.setattr(client, "describe_configuration_recorders", fake_describe)
        monkeypatch.setattr(
            config_export.utils, "get_boto3_client", lambda service, region_name=None: client
        )

        original = config_export._build_recorder_row

        def raise_for_bad(recorder, region, config_client):
            if recorder.get("name") == "bad-recorder":
                raise KeyError("SomeUnexpectedField")
            return original(recorder, region, config_client)

        monkeypatch.setattr(config_export, "_build_recorder_row", raise_for_bad)

        rows = _scan_recorders_region(REGION)

        names = {row["Recorder Name"] for row in rows}
        assert "good-recorder" in names, "healthy recorder was lost when a sibling failed"
        assert "bad-recorder" not in names, "malformed recorder should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeConfigurationRecorders",
            )

        monkeypatch.setattr(config_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_recorders_region(REGION)

    @mock_aws
    def test_collect_configuration_recorders_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeConfigurationRecorders",
            )

        monkeypatch.setattr(config_export, "_scan_recorders_region", boom)

        recorders, failed_regions = config_export.collect_configuration_recorders([REGION])

        assert recorders == []
        assert [r for r, _ in failed_regions] == [REGION]
