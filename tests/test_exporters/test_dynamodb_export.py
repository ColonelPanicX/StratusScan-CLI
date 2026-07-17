#!/usr/bin/env python3
"""
Moto-based tests for dynamodb_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import dynamodb_export  # noqa: E402
from dynamodb_export import _scan_dynamodb_tables_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_table(client, name):
    """Create a simple pay-per-request DynamoDB table named ``name``."""
    client.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


class TestScanDynamodbTablesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_tables(self):
        client = boto3.client("dynamodb", region_name=REGION)
        _create_table(client, "orders-table")

        rows = _scan_dynamodb_tables_region(REGION)

        names = {row["Table Name"] for row in rows}
        assert "orders-table" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("dynamodb", region_name=REGION)  # region exists, no tables

        rows = _scan_dynamodb_tables_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One table that fails to process must not discard the whole region."""
        client = boto3.client("dynamodb", region_name=REGION)
        _create_table(client, "good-table")
        _create_table(client, "bad-table")

        original = dynamodb_export._build_table_row

        def raise_for_bad(client_arg, table, region):
            if table.get("TableName") == "bad-table":
                raise KeyError("SomeUnexpectedField")
            return original(client_arg, table, region)

        monkeypatch.setattr(dynamodb_export, "_build_table_row", raise_for_bad)

        rows = _scan_dynamodb_tables_region(REGION)

        names = {row["Table Name"] for row in rows}
        assert "good-table" in names, "healthy table was lost when a sibling failed"
        assert "bad-table" not in names, "malformed table should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListTables",
            )

        monkeypatch.setattr(dynamodb_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_dynamodb_tables_region(REGION)

    @mock_aws
    def test_collect_dynamodb_tables_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListTables",
            )

        monkeypatch.setattr(dynamodb_export, "_scan_dynamodb_tables_region", boom)

        tables, failed_regions = dynamodb_export.collect_dynamodb_tables([REGION])

        assert tables == []
        assert [r for r, _ in failed_regions] == [REGION]
