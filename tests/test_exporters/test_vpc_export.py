#!/usr/bin/env python3
"""
Moto-based tests for vpc_data_export.py.

Covers:
- collect_vpc_subnet_data_for_region()
"""

import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
from vpc_data_export import collect_vpc_subnet_data_for_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestCollectVpcSubnetDataForRegion:
    """Tests for collect_vpc_subnet_data_for_region()."""

    @mock_aws
    def test_created_subnet_appears_in_results(self):
        """A subnet inside a custom VPC is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{REGION}a"
        )["Subnet"]["SubnetId"]

        result = collect_vpc_subnet_data_for_region(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["Subnet ID"] == subnet_id for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.1.1.0/24")

        result = collect_vpc_subnet_data_for_region(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Region", "VPC ID", "Subnet ID", "IPv4 CIDR Block", "Availability Zone"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_subnet_cidr_matches_created_subnet(self):
        """The CIDR block of the created subnet is preserved in results."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.2.1.0/24")

        result = collect_vpc_subnet_data_for_region(REGION)

        assert "10.2.1.0/24" in [row["IPv4 CIDR Block"] for row in result]

    @mock_aws
    def test_region_field_is_set(self):
        """Every returned row has the correct Region value."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.3.0.0/16")["Vpc"]["VpcId"]
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.3.1.0/24")

        result = collect_vpc_subnet_data_for_region(REGION)

        assert all(row["Region"] == REGION for row in result)
