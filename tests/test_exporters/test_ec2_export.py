#!/usr/bin/env python3
"""
Moto-based tests for ec2_export.py.

Covers:
- get_instance_data()
"""

import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
from ec2_export import get_instance_data  # noqa: E402

REGION = "us-east-1"
AMI_ID = "ami-12345678"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestGetInstanceData:
    """Tests for get_instance_data()."""

    @mock_aws
    def test_launched_instance_appears_in_results(self):
        """A running EC2 instance is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        response = ec2.run_instances(
            ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )
        instance_id = response["Instances"][0]["InstanceId"]

        result = get_instance_data(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["Instance ID"] == instance_id for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the core expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.run_instances(ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.micro")

        result = get_instance_data(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Instance ID", "State", "Instance Type", "Region", "Private IPv4"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_instance_type_is_preserved(self):
        """The instance type from launch is reflected in the results."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.run_instances(ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.small")

        result = get_instance_data(REGION)

        assert len(result) >= 1
        assert result[0]["Instance Type"] == "t3.small"

    @mock_aws
    def test_region_field_matches_requested_region(self):
        """The Region field on every returned row matches the requested region."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.run_instances(ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.micro")

        result = get_instance_data(REGION)

        assert all(row["Region"] == REGION for row in result)

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no EC2 instances returns an empty list."""
        result = get_instance_data(REGION)
        assert result == []
