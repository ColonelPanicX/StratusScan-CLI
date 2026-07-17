#!/usr/bin/env python3
"""
Moto-based tests for acm_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import acm_export  # noqa: E402
from acm_export import scan_acm_certificates_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_certificate(client, domain_name):
    """Request a certificate for ``domain_name`` and return its ARN."""
    response = client.request_certificate(
        DomainName=domain_name,
        ValidationMethod="DNS",
    )
    return response["CertificateArn"]


class TestScanAcmCertificatesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_certificates(self):
        client = boto3.client("acm", region_name=REGION)
        _create_certificate(client, "web.example.com")

        rows = scan_acm_certificates_in_region(REGION)

        domains = {row["Domain Name"] for row in rows}
        assert "web.example.com" in domains

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("acm", region_name=REGION)  # region exists, no certificates

        rows = scan_acm_certificates_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One certificate that fails to process must not discard the whole region."""
        client = boto3.client("acm", region_name=REGION)
        good_arn = _create_certificate(client, "good.example.com")
        bad_arn = _create_certificate(client, "bad.example.com")

        original = acm_export._build_certificate_row

        def raise_for_bad(cert_summary, region, acm_client):
            if cert_summary.get("CertificateArn") == bad_arn:
                raise KeyError("SomeUnexpectedField")
            return original(cert_summary, region, acm_client)

        monkeypatch.setattr(acm_export, "_build_certificate_row", raise_for_bad)

        rows = scan_acm_certificates_in_region(REGION)

        arns = {row["Certificate ARN"] for row in rows}
        assert good_arn in arns, "healthy certificate was lost when a sibling failed"
        assert bad_arn not in arns, "malformed certificate should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListCertificates",
            )

        monkeypatch.setattr(acm_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_acm_certificates_in_region(REGION)

    @mock_aws
    def test_collect_acm_certificates_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListCertificates",
            )

        monkeypatch.setattr(acm_export, "scan_acm_certificates_in_region", boom)

        certificates, failed_regions = acm_export.collect_acm_certificates([REGION])

        assert certificates == []
        assert [r for r, _ in failed_regions] == [REGION]
