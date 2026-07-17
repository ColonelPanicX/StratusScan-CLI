#!/usr/bin/env python3
"""
Tests for transfer_family_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's Transfer Family support implements ``create_server`` /
``describe_server`` but not ``list_servers`` (raises
``NotImplementedError`` as of moto 5.1.21), so region scanning is
exercised against a small fake Transfer client (monkeypatched in place of
``utils.get_boto3_client``) rather than ``@mock_aws`` end-to-end.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import transfer_family_export  # noqa: E402
from transfer_family_export import _build_server_row, _scan_transfer_servers_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Minimal paginator stand-in: ``paginate(**kwargs)`` returns an iterable of pages."""

    def __init__(self, pages_fn):
        self._pages_fn = pages_fn

    def paginate(self, **kwargs):
        return self._pages_fn(**kwargs)


class _FakeTransferClient:
    """
    Fake Transfer Family client covering just the calls
    ``_scan_transfer_servers_region`` makes: ``list_servers``,
    ``describe_server``, and ``list_users``.
    """

    def __init__(self, server_ids, describe_overrides=None, users_by_server=None, list_servers_error=None):
        self._server_ids = server_ids
        self._describe_overrides = describe_overrides or {}
        self._users_by_server = users_by_server or {}
        self._list_servers_error = list_servers_error

    def get_paginator(self, operation_name):
        if operation_name == "list_servers":
            def _pages(**kwargs):
                if self._list_servers_error:
                    raise self._list_servers_error
                yield {"Servers": [{"ServerId": sid} for sid in self._server_ids]}

            return _FakePaginator(_pages)

        if operation_name == "list_users":
            def _pages(**kwargs):
                server_id = kwargs.get("ServerId")
                usernames = self._users_by_server.get(server_id, [])
                yield {"Users": [{"UserName": u} for u in usernames]}

            return _FakePaginator(_pages)

        raise NotImplementedError(f"get_paginator({operation_name!r}) not stubbed")

    def describe_server(self, **kwargs):
        server_id = kwargs["ServerId"]
        override = self._describe_overrides.get(server_id)
        if isinstance(override, Exception):
            raise override
        if override is not None:
            return {"Server": override}
        return {
            "Server": {
                "ServerId": server_id,
                "Arn": f"arn:aws:transfer:{REGION}:123456789012:server/{server_id}",
                "State": "ONLINE",
                "Protocols": ["SFTP"],
                "EndpointType": "PUBLIC",
                "IdentityProviderType": "SERVICE_MANAGED",
                "Domain": "S3",
                "Tags": [{"Key": "Name", "Value": server_id}],
            }
        }


def _install_fake_client(monkeypatch, client):
    monkeypatch.setattr(
        transfer_family_export.utils,
        "get_boto3_client",
        lambda service, region_name=None: client,
    )


class TestBuildServerRow:
    """Pure row-building tests — no AWS calls."""

    def test_builds_row_from_minimal_item(self):
        item = {"ServerId": "s-123", "State": "ONLINE", "UserCount": 2}

        row = _build_server_row(item, REGION)

        assert row["Server ID"] == "s-123"
        assert row["Region"] == REGION
        assert row["State"] == "ONLINE"
        assert row["User Count"] == 2

    def test_missing_fields_default_gracefully(self):
        """A divergent server variant missing optional fields must not raise."""
        row = _build_server_row({"ServerId": "s-456"}, REGION)

        assert row["Server ID"] == "s-456"
        assert row["ARN"] == "N/A"
        assert row["Tags"] == "None"

    def test_malformed_tags_do_not_raise(self):
        """Tags missing Key/Value must not raise a KeyError (the RDS pattern)."""
        item = {"ServerId": "s-789", "Tags": [{"Key": "onlykey"}, {"Value": "onlyvalue"}]}

        row = _build_server_row(item, REGION)

        assert "onlykey=" in row["Tags"]
        assert "=onlyvalue" in row["Tags"]


class TestScanTransferServersRegion:
    """Happy-path collection against the fake Transfer client."""

    def test_collects_servers(self, monkeypatch):
        client = _FakeTransferClient(server_ids=["s-1", "s-2"])
        _install_fake_client(monkeypatch, client)

        rows = _scan_transfer_servers_region(REGION)

        server_ids = {row["Server ID"] for row in rows}
        assert server_ids == {"s-1", "s-2"}

    def test_empty_region_returns_empty_list(self, monkeypatch):
        client = _FakeTransferClient(server_ids=[])
        _install_fake_client(monkeypatch, client)

        rows = _scan_transfer_servers_region(REGION)

        assert rows == []

    def test_invalid_region_is_skipped(self):
        rows = _scan_transfer_servers_region("not-a-region")

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed into an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One server whose describe_server fails must not discard the whole region."""
        client = _FakeTransferClient(
            server_ids=["good-server", "bad-server"],
            describe_overrides={"bad-server": KeyError("SomeUnexpectedField")},
        )
        _install_fake_client(monkeypatch, client)

        rows = _scan_transfer_servers_region(REGION)

        server_ids = {row["Server ID"] for row in rows}
        assert "good-server" in server_ids, "healthy server was lost when a sibling failed"
        assert "bad-server" not in server_ids, "malformed server should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure (e.g. list_servers throttled) must
        propagate so the caller can record a FAILED region, rather than
        being swallowed into an empty list.
        """
        client = _FakeTransferClient(
            server_ids=[],
            list_servers_error=botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListServers",
            ),
        )
        _install_fake_client(monkeypatch, client)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_transfer_servers_region(REGION)

    def test_collect_transfer_servers_all_regions_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker and
        exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListServers",
            )

        monkeypatch.setattr(transfer_family_export, "_scan_transfer_servers_region", boom)

        servers, failed_regions = transfer_family_export.collect_transfer_servers_all_regions([REGION])

        assert servers == []
        assert [r for r, _ in failed_regions] == [REGION]
