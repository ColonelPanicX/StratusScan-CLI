#!/usr/bin/env python3
"""
Moto-based tests for backup_export.py.

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
import backup_export  # noqa: E402
from backup_export import _scan_backup_vaults_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_vault(client, name):
    """Create a backup vault named ``name``."""
    client.create_backup_vault(BackupVaultName=name)


class TestScanBackupVaultsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_vaults(self):
        client = boto3.client("backup", region_name=REGION)
        _create_vault(client, "prod-vault")

        rows = _scan_backup_vaults_region(REGION)

        names = {row["Vault Name"] for row in rows}
        assert "prod-vault" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("backup", region_name=REGION)  # region exists, no vaults

        rows = _scan_backup_vaults_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One vault that fails to process must not discard the whole region."""
        client = boto3.client("backup", region_name=REGION)
        _create_vault(client, "good-vault")
        _create_vault(client, "bad-vault")

        original = backup_export._build_vault_row

        def raise_for_bad(vault, region):
            if vault.get("BackupVaultName") == "bad-vault":
                raise KeyError("SomeUnexpectedField")
            return original(vault, region)

        monkeypatch.setattr(backup_export, "_build_vault_row", raise_for_bad)

        rows = _scan_backup_vaults_region(REGION)

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
                "ListBackupVaults",
            )

        monkeypatch.setattr(backup_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_backup_vaults_region(REGION)

    @mock_aws
    def test_collect_backup_vaults_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListBackupVaults",
            )

        monkeypatch.setattr(backup_export, "_scan_backup_vaults_region", boom)

        vaults, failed_regions = backup_export.collect_backup_vaults([REGION])

        assert vaults == []
        assert [r for r, _ in failed_regions] == [REGION]
