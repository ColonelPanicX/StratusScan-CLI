#!/usr/bin/env python3
"""
Tests for verifiedpermissions_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on moto coverage: as of moto 5.1.21 there is no AWS Verified Permissions
backend implemented — even ``list_policy_stores`` under ``@mock_aws`` raises a
botocore ClientError with message "Not yet implemented". These tests therefore
monkeypatch ``utils.get_boto3_client`` with a small fake client instead of
using moto to back the API calls (see ``_FakeVPClient`` below).
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import verifiedpermissions_export  # noqa: E402
from verifiedpermissions_export import _scan_policy_stores_region  # noqa: E402

REGION = "us-east-1"


class _FakePaginator:
    """Minimal paginator stand-in that yields exactly one page."""

    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        return iter([self._page])


class _FakeVPClient:
    """Minimal Verified Permissions client stand-in (moto has no backend)."""

    def __init__(self, stores):
        self._stores = stores

    def get_paginator(self, operation_name):
        assert operation_name == "list_policy_stores"
        return _FakePaginator({"policyStores": self._stores})

    def get_policy_store(self, **kwargs):
        return {"validationSettings": {"mode": "OFF"}}


def _store(policy_store_id):
    return {
        "policyStoreId": policy_store_id,
        "arn": f"arn:aws:verifiedpermissions::123456789012:policy-store/{policy_store_id}",
        "description": "N/A",
        "createdDate": None,
        "lastUpdatedDate": None,
    }


class TestScanPolicyStoresRegion:
    """Happy-path collection."""

    def test_collects_policy_stores(self, monkeypatch):
        client = _FakeVPClient([_store("PS-good")])
        monkeypatch.setattr(verifiedpermissions_export.utils, "get_boto3_client", lambda *a, **k: client)

        rows = _scan_policy_stores_region(REGION)

        ids = {row["PolicyStoreId"] for row in rows}
        assert "PS-good" in ids

    def test_empty_region_returns_empty_list(self, monkeypatch):
        client = _FakeVPClient([])
        monkeypatch.setattr(verifiedpermissions_export.utils, "get_boto3_client", lambda *a, **k: client)

        rows = _scan_policy_stores_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit. This exporter already writes a
    forced Summary sheet on every run (a workbook always lands — Tier-3
    PARTIAL) but previously could not distinguish a genuinely-empty account
    from a failed collection scope. These tests lock in the fix: a real
    collection failure must propagate/surface, never collapse into "empty".
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One policy store that fails to process must not discard the whole region."""
        client = _FakeVPClient([_store("good-store"), _store("bad-store")])
        monkeypatch.setattr(verifiedpermissions_export.utils, "get_boto3_client", lambda *a, **k: client)

        original = verifiedpermissions_export._build_policy_store_row

        def raise_for_bad(store, region, vp):
            if store.get("policyStoreId") == "bad-store":
                raise KeyError("PolicyStoreId")
            return original(store, region, vp)

        monkeypatch.setattr(verifiedpermissions_export, "_build_policy_store_row", raise_for_bad)

        rows = _scan_policy_stores_region(REGION)

        ids = {row["PolicyStoreId"] for row in rows}
        assert "good-store" in ids, "healthy policy store was lost when a sibling failed"
        assert "bad-store" not in ids, "malformed policy store should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
                "ListPolicyStores",
            )

        monkeypatch.setattr(verifiedpermissions_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_policy_stores_region(REGION)

    def test_collect_policy_stores_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets ``_run_export`` write a FAILED marker
        and exit non-zero.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListPolicyStores",
            )

        monkeypatch.setattr(verifiedpermissions_export, "_scan_policy_stores_region", boom)

        stores, failed_regions = verifiedpermissions_export.collect_policy_stores([REGION])

        assert stores == []
        assert [r for r, _ in failed_regions] == [REGION]
