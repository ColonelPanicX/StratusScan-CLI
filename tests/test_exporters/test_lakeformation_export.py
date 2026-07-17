#!/usr/bin/env python3
"""
Tests for lakeformation_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on mocking strategy: moto's Lake Formation support is limited (no
``list_resources``/``list_permissions`` backend as of the moto version
pinned in this project), so these tests do not use ``@mock_aws``. Instead
they monkeypatch ``utils.get_boto3_client`` with a small fake client object
that mimics the subset of the boto3 Lake Formation API surface
``_scan_lakeformation_resources_region`` calls (``list_resources``). This
keeps the tests focused on the collection-failure contract (raise vs.
skip-and-continue vs. surfaced failed_regions) rather than on AWS API
fidelity.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import lakeformation_export  # noqa: E402
from lakeformation_export import _scan_lakeformation_resources_region  # noqa: E402

REGION = "us-east-1"


class _FakeLakeFormationClient:
    """Minimal fake Lake Formation client for ``list_resources`` paging."""

    def __init__(self, resource_pages):
        self._pages = list(resource_pages)

    def list_resources(self, **kwargs):
        if not self._pages:
            return {"ResourceInfoList": []}
        return self._pages.pop(0)


def _resource(arn="arn:aws:s3:::my-bucket/prefix", role_arn="arn:aws:iam::123456789012:role/LFRole"):
    return {
        "ResourceArn": arn,
        "RoleArn": role_arn,
        "LastModified": None,
    }


class TestScanLakeformationResourcesRegion:
    """Happy-path collection."""

    def test_collects_resources(self, monkeypatch):
        fake_client = _FakeLakeFormationClient(
            [{"ResourceInfoList": [_resource()], "NextToken": None}]
        )
        monkeypatch.setattr(
            lakeformation_export.utils, "get_boto3_client", lambda *a, **k: fake_client
        )

        rows = _scan_lakeformation_resources_region(REGION)

        arns = {row["Resource ARN"] for row in rows}
        assert "arn:aws:s3:::my-bucket/prefix" in arns

    def test_empty_region_returns_empty_list(self, monkeypatch):
        fake_client = _FakeLakeFormationClient([{"ResourceInfoList": [], "NextToken": None}])
        monkeypatch.setattr(
            lakeformation_export.utils, "get_boto3_client", lambda *a, **k: fake_client
        )

        rows = _scan_lakeformation_resources_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One resource that fails to process must not discard the whole region."""
        fake_client = _FakeLakeFormationClient(
            [
                {
                    "ResourceInfoList": [
                        _resource(arn="arn:aws:s3:::good-bucket"),
                        _resource(arn="arn:aws:s3:::bad-bucket"),
                    ],
                    "NextToken": None,
                }
            ]
        )
        monkeypatch.setattr(
            lakeformation_export.utils, "get_boto3_client", lambda *a, **k: fake_client
        )

        original = lakeformation_export._build_resource_row

        def raise_for_bad(resource, region):
            if resource.get("ResourceArn") == "arn:aws:s3:::bad-bucket":
                raise KeyError("SomeUnexpectedField")
            return original(resource, region)

        monkeypatch.setattr(lakeformation_export, "_build_resource_row", raise_for_bad)

        rows = _scan_lakeformation_resources_region(REGION)

        arns = {row["Resource ARN"] for row in rows}
        assert "arn:aws:s3:::good-bucket" in arns, "healthy resource was lost when a sibling failed"
        assert "arn:aws:s3:::bad-bucket" not in arns, "malformed resource should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise RuntimeError("Rate exceeded")

        monkeypatch.setattr(lakeformation_export.utils, "get_boto3_client", boom)

        with pytest.raises(RuntimeError):
            _scan_lakeformation_resources_region(REGION)

    def test_collect_resources_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise RuntimeError("AccessDenied: nope")

        monkeypatch.setattr(lakeformation_export, "_scan_lakeformation_resources_region", boom)

        resources, failed_regions = lakeformation_export.collect_lakeformation_resources([REGION])

        assert resources == []
        assert [r for r, _ in failed_regions] == [REGION]
