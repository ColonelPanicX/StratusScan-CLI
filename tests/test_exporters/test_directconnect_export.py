#!/usr/bin/env python3
"""
Moto-based tests for directconnect_export.py.

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
import directconnect_export  # noqa: E402
from directconnect_export import _scan_connections_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class FakeDirectConnectClient:
    """
    Minimal stand-in for a boto3 Direct Connect client.

    moto's Direct Connect coverage does not let ``describe_connections`` be
    shaped precisely enough to drive the malformed-item path (connections
    created via moto always come back with every field populated), so this
    test double is used instead of a real moto-backed client for that case.
    """

    def __init__(self, connections):
        self._connections = connections

    def describe_connections(self):
        return {'connections': self._connections}


class TestScanConnectionsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("directconnect", region_name=REGION)  # region exists, no connections

        rows = _scan_connections_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.

    Note: moto's Direct Connect support does not model connection resources
    richly enough to reliably produce a malformed row or a raw API failure,
    so these tests monkeypatch ``utils.get_boto3_client`` / module internals
    directly rather than relying on moto-created resources.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One connection that fails to process must not discard the whole region."""
        good_conn = {
            'connectionId': 'dxcon-good',
            'connectionName': 'good-conn',
            'connectionState': 'available',
        }
        bad_conn = {
            'connectionId': 'dxcon-bad',
            'connectionName': 'bad-conn',
            'connectionState': 'available',
        }

        monkeypatch.setattr(
            directconnect_export.utils,
            "get_boto3_client",
            lambda *args, **kwargs: FakeDirectConnectClient([good_conn, bad_conn]),
        )

        original = directconnect_export._build_connection_row

        def raise_for_bad(conn, region):
            if conn.get("connectionId") == "dxcon-bad":
                raise KeyError("SomeUnexpectedField")
            return original(conn, region)

        monkeypatch.setattr(directconnect_export, "_build_connection_row", raise_for_bad)

        rows = _scan_connections_region(REGION)

        ids = {row["Connection ID"] for row in rows}
        assert "dxcon-good" in ids, "healthy connection was lost when a sibling failed"
        assert "dxcon-bad" not in ids, "malformed connection should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeConnections",
            )

        monkeypatch.setattr(directconnect_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_connections_region(REGION)

    @mock_aws
    def test_collect_connections_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeConnections",
            )

        monkeypatch.setattr(directconnect_export, "_scan_connections_region", boom)

        connections, failed_regions = directconnect_export.collect_connections([REGION])

        assert connections == []
        assert [r for r, _ in failed_regions] == [REGION]
