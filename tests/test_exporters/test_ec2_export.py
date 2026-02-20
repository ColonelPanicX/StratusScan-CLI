#!/usr/bin/env python3
"""
Moto-based tests for ec2-export.py.

Covers:
- get_instance_data()
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
    "ec2_export", _scripts_dir / "ec2-export.py"
)
_ec2_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ec2_export)

get_instance_data = _ec2_export.get_instance_data

REGION = "us-east-1"
AMI_ID = "ami-12345678"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetInstanceData:
    """Tests for get_instance_data()."""

    @mock_aws
    def test_launched_instance_appears_in_results(self):
        """A running EC2 instance is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        response = ec2.run_instances(
            ImageId=AMI_ID,
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.micro",
        )
        instance_id = response["Instances"][0]["InstanceId"]

        result = get_instance_data(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        instance_ids = [row["Instance ID"] for row in result]
        assert instance_id in instance_ids

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the core expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.run_instances(
            ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )

        result = get_instance_data(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Instance ID", "State", "Instance Type", "Region", "Private IPv4"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_instance_type_is_preserved(self):
        """The instance type from launch is reflected in the results."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.run_instances(
            ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.small"
        )

        result = get_instance_data(REGION)

        assert len(result) >= 1
        assert result[0]["Instance Type"] == "t3.small"

    @mock_aws
    def test_region_field_matches_requested_region(self):
        """The Region field on every returned row matches the requested region."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.run_instances(
            ImageId=AMI_ID, MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )

        result = get_instance_data(REGION)

        assert all(row["Region"] == REGION for row in result)

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no EC2 instances returns an empty list."""
        result = get_instance_data(REGION)
        assert result == []
