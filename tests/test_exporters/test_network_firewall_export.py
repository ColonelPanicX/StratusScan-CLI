#!/usr/bin/env python3
"""
Tests for network_firewall_export.py.

Focus: the silent-collection-failure contract (Tier-2D / network exporters).
See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on moto coverage: moto's network-firewall backend supports
create_firewall / list_firewalls / describe_firewall, but not
list_firewall_policies / describe_firewall_policy / list_rule_groups /
describe_rule_group, and its describe_firewall response shape does not
reliably round-trip tags. The regression tests below drive
collect_network_firewalls_from_region through a small monkeypatched fake
network-firewall client instead of moto so behavior is deterministic and
independent of moto's partial NFW coverage.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import network_firewall_export  # noqa: E402
from network_firewall_export import collect_network_firewalls_from_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Minimal paginator stand-in yielding a single page."""

    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        yield self._page


class _FakeNfwClient:
    """Minimal fake network-firewall client driving two fake firewalls."""

    def __init__(self, firewalls_metadata, describe_map, describe_error_for=None):
        self._firewalls_metadata = firewalls_metadata
        self._describe_map = describe_map
        self._describe_error_for = describe_error_for or set()

    def get_paginator(self, operation_name):
        if operation_name == "list_firewalls":
            return _FakePaginator({"Firewalls": self._firewalls_metadata})
        raise NotImplementedError(operation_name)

    def describe_firewall(self, **kwargs):
        firewall_arn = kwargs["FirewallArn"]
        if firewall_arn in self._describe_error_for:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalError", "Message": "boom"}},
                "DescribeFirewall",
            )
        return self._describe_map[firewall_arn]


def _fw_response(name, arn, vpc_id="vpc-123"):
    return {
        "Firewall": {
            "FirewallName": name,
            "FirewallArn": arn,
            "FirewallId": f"{name}-id",
            "VpcId": vpc_id,
            "SubnetMappings": [],
            "Tags": [{"Key": "Env", "Value": "test"}],
        },
        "FirewallStatus": {
            "Status": "READY",
            "SyncStates": {},
        },
    }


class TestCollectNetworkFirewallsFromRegion:
    """Happy-path collection."""

    def test_collects_firewalls(self, monkeypatch):
        arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall/web-fw"
        fake_client = _FakeNfwClient(
            firewalls_metadata=[{"FirewallArn": arn, "FirewallName": "web-fw"}],
            describe_map={arn: _fw_response("web-fw", arn)},
        )
        monkeypatch.setattr(
            network_firewall_export.utils, "get_boto3_client", lambda service, region_name: fake_client
        )

        rows = collect_network_firewalls_from_region(REGION)

        names = {row["Firewall Name"] for row in rows}
        assert "web-fw" in names

    def test_empty_region_returns_empty_list(self, monkeypatch):
        fake_client = _FakeNfwClient(firewalls_metadata=[], describe_map={})
        monkeypatch.setattr(
            network_firewall_export.utils, "get_boto3_client", lambda service, region_name: fake_client
        )

        rows = collect_network_firewalls_from_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One firewall that fails to process must not discard the whole region."""
        good_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall/good-fw"
        bad_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall/bad-fw"

        fake_client = _FakeNfwClient(
            firewalls_metadata=[
                {"FirewallArn": good_arn, "FirewallName": "good-fw"},
                {"FirewallArn": bad_arn, "FirewallName": "bad-fw"},
            ],
            describe_map={
                good_arn: _fw_response("good-fw", good_arn),
                bad_arn: _fw_response("bad-fw", bad_arn),
            },
            describe_error_for={bad_arn},
        )
        monkeypatch.setattr(
            network_firewall_export.utils, "get_boto3_client", lambda service, region_name: fake_client
        )

        rows = collect_network_firewalls_from_region(REGION)

        names = {row["Firewall Name"] for row in rows}
        assert "good-fw" in names, "healthy firewall was lost when a sibling failed"
        assert "bad-fw" not in names, "malformed firewall should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListFirewalls",
            )

        monkeypatch.setattr(network_firewall_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_network_firewalls_from_region(REGION)

    def test_collect_network_firewalls_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListFirewalls",
            )

        monkeypatch.setattr(network_firewall_export, "collect_network_firewalls_from_region", boom)

        firewalls, failed_regions = network_firewall_export.collect_network_firewalls([REGION])

        assert firewalls == []
        assert [r for r, _ in failed_regions] == [REGION]
