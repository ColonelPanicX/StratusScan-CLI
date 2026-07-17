#!/usr/bin/env python3
"""
Moto-based tests for ses_export.py.

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
import ses_export  # noqa: E402
from ses_export import _scan_email_identities_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_identity(client, domain):
    """Create a verified SES domain identity named ``domain``.

    Domain identities are used (rather than email-address identities)
    because moto's sesv2 ``get_email_identity`` mock has a lookup bug for
    email-address identity names containing ``@``.
    """
    client.create_email_identity(EmailIdentity=domain)


class TestScanEmailIdentitiesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_identities(self):
        client = boto3.client("sesv2", region_name=REGION)
        _create_identity(client, "web.example.com")

        rows = _scan_email_identities_region(REGION)

        names = {row["Identity Name"] for row in rows}
        assert "web.example.com" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("sesv2", region_name=REGION)  # region exists, no identities

        rows = _scan_email_identities_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One identity that fails to process must not discard the whole region."""
        client = boto3.client("sesv2", region_name=REGION)
        _create_identity(client, "good.example.com")
        _create_identity(client, "bad.example.com")

        original = ses_export._build_identity_row

        def raise_for_bad(identity_summary, region, ses_client):
            if identity_summary.get("IdentityName") == "bad.example.com":
                raise KeyError("SomeUnexpectedField")
            return original(identity_summary, region, ses_client)

        monkeypatch.setattr(ses_export, "_build_identity_row", raise_for_bad)

        rows = _scan_email_identities_region(REGION)

        names = {row["Identity Name"] for row in rows}
        assert "good.example.com" in names, "healthy identity was lost when a sibling failed"
        assert "bad.example.com" not in names, "malformed identity should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListEmailIdentities",
            )

        monkeypatch.setattr(ses_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_email_identities_region(REGION)

    @mock_aws
    def test_collect_email_identities_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListEmailIdentities",
            )

        monkeypatch.setattr(ses_export, "_scan_email_identities_region", boom)

        identities, failed_regions = ses_export.collect_email_identities([REGION])

        assert identities == []
        assert [r for r, _ in failed_regions] == [REGION]
