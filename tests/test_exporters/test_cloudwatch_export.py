#!/usr/bin/env python3
"""
Moto-based tests for cloudwatch_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cloudwatch_export  # noqa: E402
from cloudwatch_export import _scan_cloudwatch_alarms_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_alarm(client, name, dimensions=None):
    """Create a CloudWatch metric alarm named ``name``."""
    client.put_metric_alarm(
        AlarmName=name,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        Dimensions=dimensions if dimensions is not None else [
            {"Name": "InstanceId", "Value": "i-1234567890abcdef0"}
        ],
    )


class TestScanCloudwatchAlarmsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_alarms(self):
        client = boto3.client("cloudwatch", region_name=REGION)
        _create_alarm(client, "cpu-high-alarm")

        rows = _scan_cloudwatch_alarms_region(REGION)

        names = {row["Alarm Name"] for row in rows}
        assert "cpu-high-alarm" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("cloudwatch", region_name=REGION)  # region exists, no alarms

        rows = _scan_cloudwatch_alarms_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One alarm that fails to process must not discard the whole region."""
        client = boto3.client("cloudwatch", region_name=REGION)
        _create_alarm(client, "good-alarm")
        _create_alarm(client, "bad-alarm")

        original = cloudwatch_export._build_alarm_row

        def raise_for_bad(alarm, region):
            if alarm.get("AlarmName") == "bad-alarm":
                raise KeyError("SomeUnexpectedField")
            return original(alarm, region)

        monkeypatch.setattr(cloudwatch_export, "_build_alarm_row", raise_for_bad)

        rows = _scan_cloudwatch_alarms_region(REGION)

        names = {row["Alarm Name"] for row in rows}
        assert "good-alarm" in names, "healthy alarm was lost when a sibling failed"
        assert "bad-alarm" not in names, "malformed alarm should have been skipped"

    def test_dimensions_missing_name_key_is_skipped_not_fatal(self):
        """
        Known KeyError trigger from the audit: a dimension entry missing the
        'Name' key used to raise via a hard subscript (d['Name']) at the old
        line ~84. moto's put_metric_alarm validates dimension shape, so this
        malformed shape cannot be produced through the API — it is exercised
        directly against ``_build_alarm_row`` to prove the ``.get()``
        conversion holds and no KeyError is raised.
        """
        malformed_alarm = {
            "AlarmName": "weird-dims-alarm",
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Dimensions": [{"Value": "i-missing-name-key"}],
        }
        row = cloudwatch_export._build_alarm_row(malformed_alarm, REGION)
        assert row["Dimensions"] == "N/A=i-missing-name-key"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeAlarms",
            )

        monkeypatch.setattr(cloudwatch_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_cloudwatch_alarms_region(REGION)

    @mock_aws
    def test_collect_cloudwatch_alarms_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeAlarms",
            )

        monkeypatch.setattr(cloudwatch_export, "_scan_cloudwatch_alarms_region", boom)

        alarms, failed_regions = cloudwatch_export.collect_cloudwatch_alarms([REGION])

        assert alarms == []
        assert [r for r, _ in failed_regions] == [REGION]
