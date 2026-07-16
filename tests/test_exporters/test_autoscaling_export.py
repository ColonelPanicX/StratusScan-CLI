#!/usr/bin/env python3
"""
Moto-based tests for autoscaling_export.py.

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
import autoscaling_export  # noqa: E402
from autoscaling_export import _scan_asgs_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_asg(client, name):
    """Create a launch configuration + Auto Scaling Group named ``name``."""
    client.create_launch_configuration(
        LaunchConfigurationName=f"{name}-lc",
        ImageId="ami-12345678",
        InstanceType="t3.micro",
    )
    client.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchConfigurationName=f"{name}-lc",
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[f"{REGION}a"],
    )


class TestScanAsgsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_asgs(self):
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")

        rows = _scan_asgs_region(REGION)

        names = {row["ASG Name"] for row in rows}
        assert "web-asg" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("autoscaling", region_name=REGION)  # region exists, no ASGs

        rows = _scan_asgs_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One ASG that fails to process must not discard the whole region."""
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "good-asg")
        _create_asg(client, "bad-asg")

        original = autoscaling_export._build_asg_row

        def raise_for_bad(asg, region):
            if asg.get("AutoScalingGroupName") == "bad-asg":
                raise KeyError("SomeUnexpectedField")
            return original(asg, region)

        monkeypatch.setattr(autoscaling_export, "_build_asg_row", raise_for_bad)

        rows = _scan_asgs_region(REGION)

        names = {row["ASG Name"] for row in rows}
        assert "good-asg" in names, "healthy ASG was lost when a sibling failed"
        assert "bad-asg" not in names, "malformed ASG should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeAutoScalingGroups",
            )

        monkeypatch.setattr(autoscaling_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_asgs_region(REGION)

    @mock_aws
    def test_collect_autoscaling_groups_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeAutoScalingGroups",
            )

        monkeypatch.setattr(autoscaling_export, "_scan_asgs_region", boom)

        asgs, failed_regions = autoscaling_export.collect_autoscaling_groups([REGION])

        assert asgs == []
        assert [r for r, _ in failed_regions] == [REGION]
