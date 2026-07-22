#!/usr/bin/env python3
"""
Moto-based tests for service_catalog_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's Service Catalog support covers create_portfolio/list_portfolios
well, but search_products_as_admin and scan_provisioned_products are not
meaningfully implemented (they return empty results regardless of state), so
the regression tests below target the portfolios scope directly (which is
fully supported) and monkeypatch the scan function where moto coverage would
otherwise mask the behavior under test.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import service_catalog_export  # noqa: E402
from service_catalog_export import _scan_portfolios_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_portfolio(client, name):
    """Create a Service Catalog portfolio named ``name``."""
    return client.create_portfolio(DisplayName=name, ProviderName="test-provider")


class TestScanPortfoliosRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_portfolios(self):
        client = boto3.client("servicecatalog", region_name=REGION)
        _create_portfolio(client, "web-portfolio")

        rows = _scan_portfolios_region(REGION)

        names = {row["DisplayName"] for row in rows}
        assert "web-portfolio" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("servicecatalog", region_name=REGION)  # region exists, no portfolios

        rows = _scan_portfolios_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One portfolio that fails to process must not discard the whole region."""
        client = boto3.client("servicecatalog", region_name=REGION)
        _create_portfolio(client, "good-portfolio")
        _create_portfolio(client, "bad-portfolio")

        original = service_catalog_export._build_portfolio_row

        def raise_for_bad(portfolio, region):
            if portfolio.get("DisplayName") == "bad-portfolio":
                raise KeyError("SomeUnexpectedField")
            return original(portfolio, region)

        monkeypatch.setattr(service_catalog_export, "_build_portfolio_row", raise_for_bad)

        rows = _scan_portfolios_region(REGION)

        names = {row["DisplayName"] for row in rows}
        assert "good-portfolio" in names, "healthy portfolio was lost when a sibling failed"
        assert "bad-portfolio" not in names, "malformed portfolio should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListPortfolios",
            )

        monkeypatch.setattr(service_catalog_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_portfolios_region(REGION)

    @mock_aws
    def test_collect_portfolios_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        even though the Tier-3 Summary sheet is always written.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListPortfolios",
            )

        monkeypatch.setattr(service_catalog_export, "_scan_portfolios_region", boom)

        portfolios, failed_regions = service_catalog_export.collect_portfolios([REGION])

        assert portfolios == []
        assert [r for r, _ in failed_regions] == [REGION]
