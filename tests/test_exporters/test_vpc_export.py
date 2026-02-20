#!/usr/bin/env python3
"""
Moto-based tests for vpc-data-export.py.

Covers:
- collect_vpc_subnet_data_for_region()  (uses describe_vpcs + describe_subnets +
  describe_route_tables — all well-supported by moto)
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
    "vpc_data_export", _scripts_dir / "vpc-data-export.py"
)
_vpc_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vpc_export)

collect_vpc_subnet_data_for_region = _vpc_export.collect_vpc_subnet_data_for_region

REGION = "us-east-1"


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

class TestCollectVpcSubnetDataForRegion:
    """Tests for collect_vpc_subnet_data_for_region()."""

    @mock_aws
    def test_created_subnet_appears_in_results(self):
        """A subnet created inside a custom VPC is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_resp = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_resp["Vpc"]["VpcId"]
        subnet_resp = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{REGION}a"
        )
        subnet_id = subnet_resp["Subnet"]["SubnetId"]

        result = collect_vpc_subnet_data_for_region(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        subnet_ids = [row["Subnet ID"] for row in result]
        assert subnet_id in subnet_ids

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_resp = ec2.create_vpc(CidrBlock="10.1.0.0/16")
        vpc_id = vpc_resp["Vpc"]["VpcId"]
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
        vpc_resp = ec2.create_vpc(CidrBlock="10.2.0.0/16")
        vpc_id = vpc_resp["Vpc"]["VpcId"]
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.2.1.0/24")

        result = collect_vpc_subnet_data_for_region(REGION)

        cidrs = [row["IPv4 CIDR Block"] for row in result]
        assert "10.2.1.0/24" in cidrs

    @mock_aws
    def test_region_field_is_set(self):
        """The Region field on every returned row matches the requested region."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_resp = ec2.create_vpc(CidrBlock="10.3.0.0/16")
        vpc_id = vpc_resp["Vpc"]["VpcId"]
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.3.1.0/24")

        result = collect_vpc_subnet_data_for_region(REGION)

        assert all(row["Region"] == REGION for row in result)
