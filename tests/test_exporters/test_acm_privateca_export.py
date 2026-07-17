#!/usr/bin/env python3
"""
Moto-based tests for acm_privateca_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on moto coverage: moto's ``acm-pca`` backend supports
``create_certificate_authority``, ``list_certificate_authorities``,
``describe_certificate_authority``, and ``list_tags``, which is enough to
exercise the primary CA-listing scope directly. It does not model the
region-level ``Throttling``/``AccessDenied`` failures we need to test, so
those cases monkeypatch ``utils.get_boto3_client`` (region-failure tests) or
the module's ``_scan_private_cas_region``/``collect_private_cas`` functions
(scope-wrapper tests) to raise instead of hitting a real botocore call.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import acm_privateca_export  # noqa: E402
from acm_privateca_export import _build_ca_row, _scan_private_cas_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_ca(client, common_name="example.com"):
    """Create a root Private CA and return its ARN."""
    resp = client.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
    )
    return resp["CertificateAuthorityArn"]


class TestScanPrivateCasRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_cas(self):
        client = boto3.client("acm-pca", region_name=REGION)
        _create_ca(client, "web.example.com")

        rows = _scan_private_cas_region(REGION)

        common_names = {row["Common Name"] for row in rows}
        assert "web.example.com" in common_names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("acm-pca", region_name=REGION)  # region exists, no CAs

        rows = _scan_private_cas_region(REGION)

        assert rows == []

    def test_build_ca_row_from_list_response_shape(self):
        """
        ListCertificateAuthorities already returns the full CertificateAuthority
        shape (same fields as DescribeCertificateAuthority) — _build_ca_row must
        work directly off that item with no secondary API call.
        """
        item = {
            "Arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/abc",
            "OwnerAccount": "123456789012",
            "Type": "ROOT",
            "Status": "ACTIVE",
            "CertificateAuthorityConfiguration": {
                "KeyAlgorithm": "RSA_2048",
                "SigningAlgorithm": "SHA256WITHRSA",
                "Subject": {"CommonName": "example.com"},
            },
            "RevocationConfiguration": {"CrlConfiguration": {"Enabled": False}},
            "KeyStorageSecurityStandard": "FIPS_140_2_LEVEL_3_OR_HIGHER",
            "UsageMode": "SHORT_LIVED_CERTIFICATE",
        }

        row = _build_ca_row(item, REGION)

        assert row["CA ARN"] == item["Arn"]
        assert row["Common Name"] == "example.com"
        assert row["Status"] == "ACTIVE"
        assert row["Tags"] == "N/A"


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed into an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One CA that fails to process must not discard the whole region."""
        client = boto3.client("acm-pca", region_name=REGION)
        _create_ca(client, "good-ca.example.com")
        _create_ca(client, "bad-ca.example.com")

        original = acm_privateca_export._build_ca_row

        def raise_for_bad(item, region):
            config = item.get("CertificateAuthorityConfiguration", {}) or {}
            subject = config.get("Subject", {}) or {}
            if subject.get("CommonName") == "bad-ca.example.com":
                raise KeyError("SomeUnexpectedField")
            return original(item, region)

        monkeypatch.setattr(acm_privateca_export, "_build_ca_row", raise_for_bad)

        rows = _scan_private_cas_region(REGION)

        common_names = {row["Common Name"] for row in rows}
        assert "good-ca.example.com" in common_names, "healthy CA was lost when a sibling failed"
        assert "bad-ca.example.com" not in common_names, "malformed CA should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.

        moto does not simulate Throttling/AccessDenied for acm-pca, so the
        boto3 client factory itself is monkeypatched to raise — this still
        exercises the real code path in _scan_private_cas_region, which no
        longer wraps the listing call in a broad try/except.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListCertificateAuthorities",
            )

        monkeypatch.setattr(acm_privateca_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_private_cas_region(REGION)

    def test_collect_private_cas_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets main() write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListCertificateAuthorities",
            )

        monkeypatch.setattr(acm_privateca_export, "_scan_private_cas_region", boom)

        cas, failed_regions = acm_privateca_export.collect_private_cas([REGION])

        assert cas == []
        assert [r for r, _ in failed_regions] == [REGION]
