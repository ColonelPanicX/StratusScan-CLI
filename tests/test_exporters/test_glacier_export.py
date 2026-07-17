#!/usr/bin/env python3
"""
Moto-based tests for glacier_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

glacier_export.py already writes a forced Summary sheet, so a workbook
always lands. The contract this fix adds is failed-scope tracking: any
region-level scope failure must ALSO write the FAILED marker and exit
non-zero, while a genuinely-empty account (every region succeeds, zero
vaults) stays exit 0 with no marker.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import glacier_export  # noqa: E402
from glacier_export import _scan_vaults_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_vault(client, name):
    """Create a Glacier vault named ``name``."""
    client.create_vault(vaultName=name)


class TestScanVaultsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_vaults(self):
        client = boto3.client("glacier", region_name=REGION)
        _create_vault(client, "cold-vault")

        rows = _scan_vaults_region(REGION)

        names = {row["Vault Name"] for row in rows}
        assert "cold-vault" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("glacier", region_name=REGION)  # region exists, no vaults

        rows = _scan_vaults_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list
    (or, for PARTIAL exporters like this one, an always-written Summary
    sheet with silently zero rows), indistinguishable from a genuinely
    empty account.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One vault that fails to process must not discard the whole region."""
        client = boto3.client("glacier", region_name=REGION)
        _create_vault(client, "good-vault")
        _create_vault(client, "bad-vault")

        original = glacier_export._build_vault_row

        def raise_for_bad(vault, region, glacier_client):
            if vault.get("VaultName") == "bad-vault":
                raise KeyError("SomeUnexpectedField")
            return original(vault, region, glacier_client)

        monkeypatch.setattr(glacier_export, "_build_vault_row", raise_for_bad)

        rows = _scan_vaults_region(REGION)

        names = {row["Vault Name"] for row in rows}
        assert "good-vault" in names, "healthy vault was lost when a sibling failed"
        assert "bad-vault" not in names, "malformed vault should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListVaults",
            )

        monkeypatch.setattr(glacier_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_vaults_region(REGION)

    @mock_aws
    def test_collect_vaults_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        even though the Summary sheet always lands.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListVaults",
            )

        monkeypatch.setattr(glacier_export, "_scan_vaults_region", boom)

        vaults, failed_regions = glacier_export.collect_vaults([REGION])

        assert vaults == []
        assert [r for r, _ in failed_regions] == [REGION]
