#!/usr/bin/env python3
"""
Moto-based tests for secrets_manager_export.py.

Focus: the silent-collection-failure contract (Tier-2c). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import secrets_manager_export  # noqa: E402
from secrets_manager_export import scan_secrets_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_secret(client, name):
    """Create a Secrets Manager secret named ``name``."""
    client.create_secret(Name=name, SecretString="super-secret-value")


class TestScanSecretsInRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_secrets(self):
        client = boto3.client("secretsmanager", region_name=REGION)
        _create_secret(client, "app/db-password")

        rows = scan_secrets_in_region(REGION)

        names = {row["Secret Name"] for row in rows}
        assert "app/db-password" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("secretsmanager", region_name=REGION)  # region exists, no secrets

        rows = scan_secrets_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One secret that fails to process must not discard the whole region."""
        client = boto3.client("secretsmanager", region_name=REGION)
        _create_secret(client, "good-secret")
        _create_secret(client, "bad-secret")

        original = secrets_manager_export._build_secret_row

        def raise_for_bad(item, region):
            if item.get("Name") == "bad-secret":
                raise KeyError("SomeUnexpectedField")
            return original(item, region)

        monkeypatch.setattr(secrets_manager_export, "_build_secret_row", raise_for_bad)

        rows = scan_secrets_in_region(REGION)

        names = {row["Secret Name"] for row in rows}
        assert "good-secret" in names, "healthy secret was lost when a sibling failed"
        assert "bad-secret" not in names, "malformed secret should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListSecrets",
            )

        monkeypatch.setattr(secrets_manager_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_secrets_in_region(REGION)

    @mock_aws
    def test_collect_secrets_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListSecrets",
            )

        monkeypatch.setattr(secrets_manager_export, "scan_secrets_in_region", boom)

        secrets, failed_regions = secrets_manager_export.collect_secrets([REGION])

        assert secrets == []
        assert [r for r, _ in failed_regions] == [REGION]
