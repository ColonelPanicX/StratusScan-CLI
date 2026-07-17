#!/usr/bin/env python3
"""
Moto-based tests for cloudmap_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's servicediscovery support does not model API-level failures
(e.g. a namespace whose ``get_namespace`` call raises, or a region-level
paginator failure), so the regression cases below use monkeypatched fake
clients/functions instead of real moto failures. The happy-path class uses
real moto since ``create_http_namespace`` / ``list_namespaces`` /
``get_namespace`` are supported there.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cloudmap_export  # noqa: E402
from cloudmap_export import _scan_namespaces_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Minimal paginator stand-in returning pre-built pages."""

    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeServiceDiscoveryClient:
    """
    Fake ``servicediscovery`` client used where moto cannot simulate the
    failure being tested (a namespace whose detail lookup raises).
    """

    def __init__(self, namespace_summaries, raise_for_ids=None):
        self._namespace_summaries = namespace_summaries
        self._raise_for_ids = raise_for_ids or set()

    def get_paginator(self, operation_name):
        if operation_name == "list_namespaces":
            return _FakePaginator([{"Namespaces": self._namespace_summaries}])
        raise NotImplementedError(operation_name)

    def get_namespace(self, Id):  # noqa: N803 - mirrors the boto3 servicediscovery API
        if Id in self._raise_for_ids:
            raise KeyError("SomeUnexpectedField")
        return {
            "Namespace": {
                "Id": Id,
                "Name": f"name-{Id}",
                "Type": "HTTP",
                "Arn": f"arn:aws:servicediscovery:{REGION}:123456789012:namespace/{Id}",
                "CreateDate": "N/A",
                "Properties": {},
            }
        }


class TestScanNamespacesRegion:
    """Happy-path collection (real moto)."""

    @mock_aws
    def test_collects_namespaces(self):
        client = boto3.client("servicediscovery", region_name=REGION)
        client.create_http_namespace(Name="web-namespace")

        rows = _scan_namespaces_region(REGION)

        names = {row["Namespace Name"] for row in rows}
        assert "web-namespace" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("servicediscovery", region_name=REGION)  # region exists, no namespaces

        rows = _scan_namespaces_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One namespace that fails to process must not discard the whole region."""
        fake_client = _FakeServiceDiscoveryClient(
            namespace_summaries=[
                {"Id": "good-ns", "Name": "good", "Type": "HTTP"},
                {"Id": "bad-ns", "Name": "bad", "Type": "HTTP"},
            ],
            raise_for_ids={"bad-ns"},
        )
        monkeypatch.setattr(
            cloudmap_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_namespaces_region(REGION)

        ids = {row["Namespace ID"] for row in rows}
        assert "good-ns" in ids, "healthy namespace was lost when a sibling failed"
        assert "bad-ns" not in ids, "malformed namespace should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListNamespaces",
            )

        monkeypatch.setattr(cloudmap_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_namespaces_region(REGION)

    def test_collect_namespaces_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListNamespaces",
            )

        monkeypatch.setattr(cloudmap_export, "_scan_namespaces_region", boom)

        namespaces, failed_regions = cloudmap_export.collect_namespaces([REGION])

        assert namespaces == []
        assert [r for r, _ in failed_regions] == [REGION]
