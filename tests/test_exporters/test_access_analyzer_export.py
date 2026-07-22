#!/usr/bin/env python3
"""
Tests for access_analyzer_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

NOTE: moto (5.1.21) does not implement an ``accessanalyzer`` backend
(``create_analyzer`` returns a 404 "Not yet implemented" from moto itself,
and the service has no entry in ``moto.backends.list_of_moto_modules()``).
These tests therefore monkeypatch ``utils.get_boto3_client`` to return a
fake client with a fake paginator rather than using ``@mock_aws`` against a
real accessanalyzer backend.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import access_analyzer_export  # noqa: E402
from access_analyzer_export import collect_analyzers_from_region  # noqa: E402

REGION = "us-east-1"


class _FakePaginator:
    """Minimal stand-in for a boto3 paginator yielding fixed pages."""

    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeAccessAnalyzerClient:
    """Minimal stand-in for the accessanalyzer boto3 client."""

    def __init__(self, analyzers):
        self._analyzers = analyzers

    def get_paginator(self, operation_name):
        if operation_name == "list_analyzers":
            return _FakePaginator([{"analyzers": self._analyzers}])
        raise ValueError(f"Unexpected paginator requested: {operation_name}")


def _make_analyzer(name, analyzer_type="ACCOUNT", status="ACTIVE"):
    return {
        "arn": f"arn:aws:access-analyzer:{REGION}:123456789012:analyzer/{name}",
        "name": name,
        "type": analyzer_type,
        "status": status,
        "createdAt": "2026-01-01T00:00:00Z",
        "tags": {},
    }


class TestCollectAnalyzersFromRegion:
    """Happy-path collection."""

    def test_collects_analyzers(self, monkeypatch):
        client = _FakeAccessAnalyzerClient([_make_analyzer("web-analyzer")])
        monkeypatch.setattr(
            access_analyzer_export.utils, "get_boto3_client", lambda *a, **k: client
        )

        rows = collect_analyzers_from_region(REGION)

        names = {row["Analyzer Name"] for row in rows}
        assert "web-analyzer" in names

    def test_empty_region_returns_empty_list(self, monkeypatch):
        client = _FakeAccessAnalyzerClient([])
        monkeypatch.setattr(
            access_analyzer_export.utils, "get_boto3_client", lambda *a, **k: client
        )

        rows = collect_analyzers_from_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One analyzer that fails to process must not discard the whole region."""
        client = _FakeAccessAnalyzerClient(
            [_make_analyzer("good-analyzer"), _make_analyzer("bad-analyzer")]
        )
        monkeypatch.setattr(
            access_analyzer_export.utils, "get_boto3_client", lambda *a, **k: client
        )

        original = access_analyzer_export._build_analyzer_row

        def raise_for_bad(analyzer, region):
            if analyzer.get("name") == "bad-analyzer":
                raise KeyError("SomeUnexpectedField")
            return original(analyzer, region)

        monkeypatch.setattr(access_analyzer_export, "_build_analyzer_row", raise_for_bad)

        rows = collect_analyzers_from_region(REGION)

        names = {row["Analyzer Name"] for row in rows}
        assert "good-analyzer" in names, "healthy analyzer was lost when a sibling failed"
        assert "bad-analyzer" not in names, "malformed analyzer should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListAnalyzers",
            )

        monkeypatch.setattr(access_analyzer_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_analyzers_from_region(REGION)

    def test_collect_analyzers_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListAnalyzers",
            )

        monkeypatch.setattr(access_analyzer_export, "collect_analyzers_from_region", boom)

        analyzers, failed_regions = access_analyzer_export.collect_analyzers([REGION])

        assert analyzers == []
        assert [r for r, _ in failed_regions] == [REGION]
