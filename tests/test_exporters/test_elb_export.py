#!/usr/bin/env python3
"""
Moto-based tests for elb_export.py.

Covers:
- get_classic_load_balancers()
- get_application_network_load_balancers()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import elb_export  # noqa: E402
from elb_export import (  # noqa: E402
    get_application_network_load_balancers,
    get_classic_load_balancers,
)

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_vpc_and_subnets():
    """Create a VPC with two subnets across AZs, required for ALB/NLB creation."""
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet_a = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24", AvailabilityZone=f"{REGION}a"
    )["Subnet"]
    subnet_b = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.2.0/24", AvailabilityZone=f"{REGION}b"
    )["Subnet"]
    return vpc, [subnet_a["SubnetId"], subnet_b["SubnetId"]]


class TestGetClassicLoadBalancers:
    """Tests for get_classic_load_balancers()."""

    @mock_aws
    def test_created_lb_appears_in_results(self):
        """A newly created Classic LB is returned by the collector."""
        elb = boto3.client("elb", region_name=REGION)
        elb.create_load_balancer(
            LoadBalancerName="test-classic-lb",
            Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 80}],
            AvailabilityZones=[f"{REGION}a"],
        )

        result = get_classic_load_balancers(REGION)

        assert isinstance(result, list)
        assert any(row["Name"] == "test-classic-lb" for row in result)

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no Classic LBs returns an empty list."""
        result = get_classic_load_balancers(REGION)
        assert result == []


class TestGetApplicationNetworkLoadBalancers:
    """Tests for get_application_network_load_balancers()."""

    @mock_aws
    def test_created_alb_appears_in_results(self):
        """A newly created ALB is returned by the collector."""
        _, subnet_ids = _create_vpc_and_subnets()
        elbv2 = boto3.client("elbv2", region_name=REGION)
        elbv2.create_load_balancer(
            Name="test-alb",
            Subnets=subnet_ids,
            Type="application",
        )

        result = get_application_network_load_balancers(REGION)

        assert isinstance(result, list)
        assert any(row["Name"] == "test-alb" for row in result)

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no ALB/NLBs returns an empty list."""
        result = get_application_network_load_balancers(REGION)
        assert result == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 audit / 07.16.2026 blast-radius sweep:
    ELB data silently lost because a collection error was swallowed to an
    empty list, indistinguishable from a genuinely empty region.
    See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_classic_lb_is_skipped_not_fatal(self, monkeypatch):
        """
        One Classic LB that fails to process must not discard the whole
        region's results — the healthy LB is still collected.
        """
        elb = boto3.client("elb", region_name=REGION)
        for name in ("good-classic-lb", "bad-classic-lb"):
            elb.create_load_balancer(
                LoadBalancerName=name,
                Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 80}],
                AvailabilityZones=[f"{REGION}a"],
            )

        original = elb_export._build_classic_lb_row

        def raise_for_bad(lb, *args, **kwargs):
            if lb.get("LoadBalancerName") == "bad-classic-lb":
                raise KeyError("SomeField")
            return original(lb, *args, **kwargs)

        monkeypatch.setattr(elb_export, "_build_classic_lb_row", raise_for_bad)

        result = get_classic_load_balancers(REGION)

        names = {row["Name"] for row in result}
        assert "good-classic-lb" in names, "healthy LB was lost when a sibling failed"
        assert "bad-classic-lb" not in names, "malformed LB should have been skipped"

    @mock_aws
    def test_classic_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeLoadBalancers",
            )

        monkeypatch.setattr(elb_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_classic_load_balancers(REGION)

    @mock_aws
    def test_malformed_albnlb_is_skipped_not_fatal(self, monkeypatch):
        """
        One ALB/NLB that fails to process must not discard the whole
        region's results — the healthy LB is still collected.
        """
        _, subnet_ids = _create_vpc_and_subnets()
        elbv2 = boto3.client("elbv2", region_name=REGION)
        for name in ("good-alb", "bad-alb"):
            elbv2.create_load_balancer(
                Name=name,
                Subnets=subnet_ids,
                Type="application",
            )

        original = elb_export._build_albnlb_row

        def raise_for_bad(lb, *args, **kwargs):
            if lb.get("LoadBalancerName") == "bad-alb":
                raise KeyError("SomeField")
            return original(lb, *args, **kwargs)

        monkeypatch.setattr(elb_export, "_build_albnlb_row", raise_for_bad)

        result = get_application_network_load_balancers(REGION)

        names = {row["Name"] for row in result}
        assert "good-alb" in names, "healthy LB was lost when a sibling failed"
        assert "bad-alb" not in names, "malformed LB should have been skipped"

    @mock_aws
    def test_albnlb_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeLoadBalancers",
            )

        monkeypatch.setattr(elb_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_application_network_load_balancers(REGION)
