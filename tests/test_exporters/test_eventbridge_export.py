#!/usr/bin/env python3
"""
Moto-based tests for eventbridge_export.py.

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
import eventbridge_export  # noqa: E402
from eventbridge_export import _scan_event_buses_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_event_bus(client, name):
    """Create a custom event bus named ``name``."""
    client.create_event_bus(Name=name)


class TestScanEventBusesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_event_buses(self):
        client = boto3.client("events", region_name=REGION)
        _create_event_bus(client, "my-bus")

        rows = _scan_event_buses_region(REGION)

        names = {row["Event Bus Name"] for row in rows}
        assert "my-bus" in names

    @mock_aws
    def test_default_bus_only_still_returns_rows(self):
        boto3.client("events", region_name=REGION)  # region exists, no custom buses

        rows = _scan_event_buses_region(REGION)

        # moto always seeds the "default" event bus.
        names = {row["Event Bus Name"] for row in rows}
        assert "default" in names


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One event bus that fails to process must not discard the whole region."""
        client = boto3.client("events", region_name=REGION)
        _create_event_bus(client, "good-bus")
        _create_event_bus(client, "bad-bus")

        original = eventbridge_export._build_event_bus_row

        def raise_for_bad(item, region):
            if item.get("Name") == "bad-bus":
                raise KeyError("SomeUnexpectedField")
            return original(item, region)

        monkeypatch.setattr(eventbridge_export, "_build_event_bus_row", raise_for_bad)

        rows = _scan_event_buses_region(REGION)

        names = {row["Event Bus Name"] for row in rows}
        assert "good-bus" in names, "healthy event bus was lost when a sibling failed"
        assert "bad-bus" not in names, "malformed event bus should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListEventBuses",
            )

        monkeypatch.setattr(eventbridge_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_event_buses_region(REGION)

    @mock_aws
    def test_collect_event_buses_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListEventBuses",
            )

        monkeypatch.setattr(eventbridge_export, "_scan_event_buses_region", boom)

        buses, failed_regions = eventbridge_export.collect_event_buses([REGION])

        assert buses == []
        assert [r for r, _ in failed_regions] == [REGION]
