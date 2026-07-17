#!/usr/bin/env python3
"""
Moto-based tests for transit_gateway_export.py.

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
import transit_gateway_export  # noqa: E402
from transit_gateway_export import scan_transit_gateways_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_tgw(client, name):
    """Create a Transit Gateway tagged with ``Name=name``."""
    response = client.create_transit_gateway(
        Description=f"{name}-tgw",
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
    )
    return response["TransitGateway"]["TransitGatewayId"]


class TestScanTransitGatewaysRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_transit_gateways(self):
        client = boto3.client("ec2", region_name=REGION)
        _create_tgw(client, "web-tgw")

        rows = scan_transit_gateways_in_region(REGION)

        names = {row["Name"] for row in rows}
        assert "web-tgw" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ec2", region_name=REGION)  # region exists, no TGWs

        rows = scan_transit_gateways_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One Transit Gateway that fails to process must not discard the whole region."""
        client = boto3.client("ec2", region_name=REGION)
        _create_tgw(client, "good-tgw")
        _create_tgw(client, "bad-tgw")

        original = transit_gateway_export._build_tgw_row

        def raise_for_bad(tgw, region):
            if tgw.get("TransitGatewayId") and any(
                tag.get("Key") == "Name" and tag.get("Value") == "bad-tgw"
                for tag in tgw.get("Tags", [])
            ):
                raise KeyError("SomeUnexpectedField")
            return original(tgw, region)

        monkeypatch.setattr(transit_gateway_export, "_build_tgw_row", raise_for_bad)

        rows = scan_transit_gateways_in_region(REGION)

        names = {row["Name"] for row in rows}
        assert "good-tgw" in names, "healthy Transit Gateway was lost when a sibling failed"
        assert "bad-tgw" not in names, "malformed Transit Gateway should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeTransitGateways",
            )

        monkeypatch.setattr(transit_gateway_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_transit_gateways_in_region(REGION)

    @mock_aws
    def test_collect_transit_gateways_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeTransitGateways",
            )

        monkeypatch.setattr(transit_gateway_export, "scan_transit_gateways_in_region", boom)

        tgws, failed_regions = transit_gateway_export.collect_transit_gateways([REGION])

        assert tgws == []
        assert [r for r, _ in failed_regions] == [REGION]
