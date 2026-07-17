#!/usr/bin/env python3
"""
Moto-based tests for macie_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's ``macie2`` mock has limited fidelity — ``get_macie_session``
always succeeds as if Macie is already enabled and does not model the
account-not-enabled ``ResourceNotFoundException`` or throttling/access-denied
errors. Those behaviors are exercised here via monkeypatching the boto3
client (or ``utils.get_boto3_client``) rather than via moto's own state.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import macie_export  # noqa: E402
from macie_export import collect_macie_status_from_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _resource_not_found_error(op_name="GetMacieSession"):
    return botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "The request failed because the specified account isn't associated with Amazon Macie.",
            }
        },
        op_name,
    )


class TestCollectMacieStatusFromRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_status(self):
        rows = collect_macie_status_from_region(REGION)

        assert len(rows) == 1
        assert rows[0]["Region"] == REGION
        assert rows[0]["Status"] == "ENABLED"

    def test_invalid_region_returns_empty(self):
        rows = collect_macie_status_from_region("not-a-real-region")

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty/default
    result, indistinguishable from a genuinely empty or disabled region.
    """

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A real region-level API failure (e.g. throttling) must propagate (so
        the caller can record a FAILED region) rather than being swallowed
        into an empty/"Not Enabled" result.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
                "GetMacieSession",
            )

        monkeypatch.setattr(macie_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_macie_status_from_region(REGION)

    @mock_aws
    def test_access_denied_raises_not_empty(self, monkeypatch):
        """An AccessDenied error must also propagate as a real failure."""
        client = boto3.client("macie2", region_name=REGION)

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                "GetMacieSession",
            )

        monkeypatch.setattr(client, "get_macie_session", boom)
        monkeypatch.setattr(macie_export.utils, "get_boto3_client", lambda *a, **k: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_macie_status_from_region(REGION)

    @mock_aws
    def test_collect_macie_status_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker +
        exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                "GetMacieSession",
            )

        monkeypatch.setattr(macie_export, "collect_macie_status_from_region", boom)

        status, failed_regions = macie_export.collect_macie_status([REGION])

        assert status == []
        assert [r for r, _ in failed_regions] == [REGION]

    def test_macie_not_enabled_is_not_a_failed_region(self, monkeypatch):
        """
        A region where Macie is simply not enabled (ResourceNotFoundException
        from GetMacieSession) is a legitimate, non-failure, disabled state.
        It must come back as a normal 'Not Enabled' row and must NOT be
        counted as a failed region.
        """
        client = boto3.client("macie2", region_name=REGION)
        monkeypatch.setattr(
            client, "get_macie_session", lambda: (_ for _ in ()).throw(_resource_not_found_error())
        )
        monkeypatch.setattr(macie_export.utils, "get_boto3_client", lambda *a, **k: client)

        rows = collect_macie_status_from_region(REGION)

        assert len(rows) == 1
        assert rows[0]["Region"] == REGION
        assert rows[0]["Status"] == "Not Enabled"

        # And at the collect_macie_status() wrapper level, this must not be
        # reported as a failed region.
        monkeypatch.setattr(
            macie_export, "collect_macie_status_from_region", lambda region: rows
        )
        status, failed_regions = macie_export.collect_macie_status([REGION])

        assert status == rows
        assert failed_regions == []
