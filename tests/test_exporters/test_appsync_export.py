#!/usr/bin/env python3
"""
Tests for appsync_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's AppSync support does not implement failure injection (its
list_graphql_apis always succeeds against an empty/mocked account), so the
region-failure cases here monkeypatch the boto3 client / scan function
directly instead of relying on moto to raise.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import appsync_export  # noqa: E402
from appsync_export import _scan_graphql_apis_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Minimal stand-in for a boto3 paginator over a fixed set of pages."""

    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeAppSyncClient:
    """Minimal stand-in for the AppSync boto3 client's list_graphql_apis paginator."""

    def __init__(self, apis):
        self._apis = apis

    def get_paginator(self, name):
        assert name == "list_graphql_apis"
        return _FakePaginator([{"graphqlApis": self._apis}])


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One GraphQL API that fails to process must not discard the whole region."""
        fake_apis = [
            {"apiId": "good-id", "name": "good-api", "authenticationType": "API_KEY"},
            {"apiId": "bad-id", "name": "bad-api", "authenticationType": "API_KEY"},
        ]
        monkeypatch.setattr(
            appsync_export.utils,
            "get_boto3_client",
            lambda *args, **kwargs: _FakeAppSyncClient(fake_apis),
        )

        original = appsync_export._build_graphql_api_row

        def raise_for_bad(api, region):
            if api.get("apiId") == "bad-id":
                raise KeyError("SomeUnexpectedField")
            return original(api, region)

        monkeypatch.setattr(appsync_export, "_build_graphql_api_row", raise_for_bad)

        rows = _scan_graphql_apis_region(REGION)

        names = {row["API Name"] for row in rows}
        assert "good-api" in names, "healthy API was lost when a sibling failed"
        assert "bad-api" not in names, "malformed API should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListGraphqlApis",
            )

        monkeypatch.setattr(appsync_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_graphql_apis_region(REGION)

    def test_collect_graphql_apis_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListGraphqlApis",
            )

        monkeypatch.setattr(appsync_export, "_scan_graphql_apis_region", boom)

        apis, failed_regions = appsync_export.collect_graphql_apis([REGION])

        assert apis == []
        assert [r for r, _ in failed_regions] == [REGION]
