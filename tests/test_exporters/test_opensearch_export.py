#!/usr/bin/env python3
"""
Moto-based tests for opensearch_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's OpenSearch support is limited (no simulated API throttling /
access-denied errors, and DescribeDomain returns a fixed shape), so the
failure-path tests below monkeypatch the relevant call/function directly
instead of trying to coax moto into raising.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import opensearch_export  # noqa: E402
from opensearch_export import scan_opensearch_domains_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_domain(client, name):
    """Create an OpenSearch domain named ``name``."""
    client.create_domain(DomainName=name)


class TestScanOpensearchDomainsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_domains(self):
        client = boto3.client("opensearch", region_name=REGION)
        _create_domain(client, "search-domain")

        rows = scan_opensearch_domains_in_region(REGION)

        names = {row["Domain Name"] for row in rows}
        assert "search-domain" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("opensearch", region_name=REGION)  # region exists, no domains

        rows = scan_opensearch_domains_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One domain that fails to describe/build must not discard the whole region."""
        client = boto3.client("opensearch", region_name=REGION)
        _create_domain(client, "good-domain")
        _create_domain(client, "bad-domain")

        original = opensearch_export._build_domain_row

        def raise_for_bad(domain, region, pricing_data, cost_note):
            if domain.get("DomainName") == "bad-domain":
                raise KeyError("SomeUnexpectedField")
            return original(domain, region, pricing_data, cost_note)

        monkeypatch.setattr(opensearch_export, "_build_domain_row", raise_for_bad)

        rows = scan_opensearch_domains_in_region(REGION)

        names = {row["Domain Name"] for row in rows}
        assert "good-domain" in names, "healthy domain was lost when a sibling failed"
        assert "bad-domain" not in names, "malformed domain should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure (e.g. list_domain_names) must propagate (so
        the caller can record a FAILED region) rather than being swallowed
        into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListDomainNames",
            )

        monkeypatch.setattr(opensearch_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_opensearch_domains_in_region(REGION)

    @mock_aws
    def test_collect_opensearch_domains_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListDomainNames",
            )

        monkeypatch.setattr(opensearch_export, "scan_opensearch_domains_in_region", boom)

        domains, failed_regions = opensearch_export.collect_opensearch_domains([REGION])

        assert domains == []
        assert [r for r, _ in failed_regions] == [REGION]
