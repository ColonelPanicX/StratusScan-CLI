#!/usr/bin/env python3
"""
Moto-based tests for vpn_export.py.

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
import vpn_export  # noqa: E402
from vpn_export import scan_vpn_connections_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_vpn_connection(client, bgp_asn=65000, public_ip="203.0.113.1"):
    """Create a customer gateway + VPN gateway + Site-to-Site VPN connection."""
    cgw_id = client.create_customer_gateway(
        BgpAsn=bgp_asn,
        PublicIp=public_ip,
        Type="ipsec.1",
    )["CustomerGateway"]["CustomerGatewayId"]

    vgw_id = client.create_vpn_gateway(Type="ipsec.1")["VpnGateway"]["VpnGatewayId"]

    conn = client.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Type="ipsec.1",
    )["VpnConnection"]

    return conn["VpnConnectionId"]


class TestScanVpnConnectionsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_vpn_connections(self):
        client = boto3.client("ec2", region_name=REGION)
        vpn_id = _create_vpn_connection(client)

        rows = scan_vpn_connections_in_region(REGION)

        ids = {row["VPN Connection ID"] for row in rows}
        assert vpn_id in ids

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ec2", region_name=REGION)  # region exists, no VPN connections

        rows = scan_vpn_connections_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list, indistinguishable
    from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One VPN connection that fails to process must not discard the whole region."""
        client = boto3.client("ec2", region_name=REGION)
        good_id = _create_vpn_connection(client, bgp_asn=65000, public_ip="203.0.113.1")
        bad_id = _create_vpn_connection(client, bgp_asn=65001, public_ip="203.0.113.2")

        original = vpn_export._build_vpn_row

        def raise_for_bad(vpn, region):
            if vpn.get("VpnConnectionId") == bad_id:
                raise KeyError("SomeUnexpectedField")
            return original(vpn, region)

        monkeypatch.setattr(vpn_export, "_build_vpn_row", raise_for_bad)

        rows = scan_vpn_connections_in_region(REGION)

        ids = {row["VPN Connection ID"] for row in rows}
        assert good_id in ids, "healthy VPN connection was lost when a sibling failed"
        assert bad_id not in ids, "malformed VPN connection should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeVpnConnections",
            )

        monkeypatch.setattr(vpn_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_vpn_connections_in_region(REGION)

    @mock_aws
    def test_collect_vpn_connections_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeVpnConnections",
            )

        monkeypatch.setattr(vpn_export, "scan_vpn_connections_in_region", boom)

        vpns, failed_regions = vpn_export.collect_vpn_connections([REGION])

        assert vpns == []
        assert [r for r, _ in failed_regions] == [REGION]
