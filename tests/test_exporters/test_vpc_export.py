#!/usr/bin/env python3
"""
Moto-based tests for vpc_data_export.py.

Covers:
- collect_vpc_subnet_data_for_region()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import vpc_data_export  # noqa: E402
from vpc_data_export import (  # noqa: E402
    collect_vpc_data_for_region,
    collect_vpc_subnet_data_for_region,
)

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


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 blast-radius audit: VPC collectors
    swallowed region-level errors into an empty list, indistinguishable from
    a genuinely empty region. See
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One VPC that fails to process must not discard the whole region's
        results — the healthy VPC is still collected.
        """
        ec2 = boto3.client("ec2", region_name=REGION)
        good_vpc_id = ec2.create_vpc(CidrBlock="10.10.0.0/16")["Vpc"]["VpcId"]
        bad_vpc_id = ec2.create_vpc(CidrBlock="10.11.0.0/16")["Vpc"]["VpcId"]

        original = vpc_data_export._build_vpc_row

        def raise_for_bad(vpc, *args, **kwargs):
            if vpc.get("VpcId") == bad_vpc_id:
                raise KeyError("SomeUnexpectedField")
            return original(vpc, *args, **kwargs)

        monkeypatch.setattr(vpc_data_export, "_build_vpc_row", raise_for_bad)

        result = collect_vpc_data_for_region(REGION)

        ids = {row["VPC ID"] for row in result}
        assert good_vpc_id in ids, "healthy VPC was lost when a sibling failed"
        assert bad_vpc_id not in ids, "malformed VPC should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeVpcs",
            )

        monkeypatch.setattr(vpc_data_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_vpc_data_for_region(REGION)
