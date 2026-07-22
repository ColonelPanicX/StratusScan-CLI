#!/usr/bin/env python3
"""
Moto-based tests for ec2_dedicated_hosts_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

ec2_dedicated_hosts_export.py already writes a forced ``Summary`` sheet, so a
workbook always lands even on total failure. What was missing — and what
these tests guard — is failed-scope tracking: on ANY scope failure the
exporter must ALSO write the ``*-FAILED-*.txt`` marker and exit non-zero, so
a failed collection is never indistinguishable from a genuinely empty
account.

Note: moto (5.1.21) implements ``ec2:AllocateHosts`` / ``ec2:DescribeHosts``
but NOT ``ec2:DescribeHostReservations`` (raises ``NotImplementedError``), so
the host-reservations scope is exercised via monkeypatch rather than a live
mocked API call.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ec2_dedicated_hosts_export  # noqa: E402
from ec2_dedicated_hosts_export import (  # noqa: E402
    _scan_dedicated_hosts_region,
    _scan_host_reservations_region,
)

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _allocate_host(client):
    """Allocate a single dedicated host and return its HostId."""
    resp = client.allocate_hosts(
        AvailabilityZone=f"{REGION}a",
        InstanceType="m5.large",
        Quantity=1,
        AutoPlacement="on",
    )
    return resp["HostIds"][0]


class TestScanDedicatedHostsRegion:
    """Happy-path collection for the primary (dedicated hosts) scope."""

    @mock_aws
    def test_collects_hosts(self):
        client = boto3.client("ec2", region_name=REGION)
        host_id = _allocate_host(client)

        rows = _scan_dedicated_hosts_region(REGION)

        host_ids = {row["HostId"] for row in rows}
        assert host_id in host_ids

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ec2", region_name=REGION)  # region exists, no hosts

        rows = _scan_dedicated_hosts_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One dedicated host that fails to process must not discard the whole region."""
        client = boto3.client("ec2", region_name=REGION)
        good_host_id = _allocate_host(client)
        bad_host_id = _allocate_host(client)

        original = ec2_dedicated_hosts_export._build_host_row

        def raise_for_bad(host, region, host_pricing, is_govcloud):
            if host.get("HostId") == bad_host_id:
                raise KeyError("SomeUnexpectedField")
            return original(host, region, host_pricing, is_govcloud)

        monkeypatch.setattr(ec2_dedicated_hosts_export, "_build_host_row", raise_for_bad)

        rows = _scan_dedicated_hosts_region(REGION)

        host_ids = {row["HostId"] for row in rows}
        assert good_host_id in host_ids, "healthy host was lost when a sibling failed"
        assert bad_host_id not in host_ids, "malformed host should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeHosts",
            )

        monkeypatch.setattr(ec2_dedicated_hosts_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_dedicated_hosts_region(REGION)

    @mock_aws
    def test_collect_dedicated_hosts_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeHosts",
            )

        monkeypatch.setattr(ec2_dedicated_hosts_export, "_scan_dedicated_hosts_region", boom)

        hosts, failed_regions = ec2_dedicated_hosts_export.collect_dedicated_hosts([REGION])

        assert hosts == []
        assert [r for r, _ in failed_regions] == [REGION]

    def test_host_reservations_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        Host Reservations is a second, independent top-level inventory scope
        (own worksheet, not derived from the hosts data) — it must follow the
        same not-swallowed contract as the primary dedicated-hosts scope.

        moto does not implement ec2:DescribeHostReservations, so the
        underlying client call is monkeypatched directly rather than mocked
        with @mock_aws.
        """

        class _BoomPaginator:
            def paginate(self, **kwargs):
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                    "DescribeHostReservations",
                )

        class _BoomClient:
            def get_paginator(self, name):
                return _BoomPaginator()

        monkeypatch.setattr(
            ec2_dedicated_hosts_export.utils,
            "get_boto3_client",
            lambda *a, **kw: _BoomClient(),
        )

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_host_reservations_region(REGION)

    def test_collect_host_reservations_surfaces_failed_regions(self, monkeypatch):
        """The reservations scope wrapper must surface failed regions too."""

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeHostReservations",
            )

        monkeypatch.setattr(ec2_dedicated_hosts_export, "_scan_host_reservations_region", boom)

        reservations, failed_regions = ec2_dedicated_hosts_export.collect_host_reservations([REGION])

        assert reservations == []
        assert [r for r, _ in failed_regions] == [REGION]
