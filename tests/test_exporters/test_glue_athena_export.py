#!/usr/bin/env python3
"""
Moto-based tests for glue_athena_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Unlike the Tier-2 VULNERABLE exporters (e.g. autoscaling_export.py), this
script already writes a forced Summary sheet, so a workbook always lands even
when a scope fails. That must not mask the failure: on any scope failure the
export must ALSO write the ``*-glue-athena-FAILED-*.txt`` marker and exit
non-zero. A genuinely empty account (every scope succeeded, nothing found)
must stay exit 0 with no marker.

These tests target the Glue databases scope (``_scan_glue_databases_region`` /
``collect_glue_databases``), the primary scope per the audit.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import glue_athena_export  # noqa: E402
from glue_athena_export import _scan_glue_databases_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestScanGlueDatabasesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_databases(self):
        client = boto3.client("glue", region_name=REGION)
        client.create_database(DatabaseInput={"Name": "analytics-db"})

        rows = _scan_glue_databases_region(REGION)

        names = {row["Database Name"] for row in rows}
        assert "analytics-db" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("glue", region_name=REGION)  # region exists, no databases

        rows = _scan_glue_databases_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.

    glue_athena_export.py is a Tier-3 PARTIAL exporter: it already forces a
    Summary sheet so a workbook is always written. The fix here adds
    failed-scope tracking on top of that so a scope failure is also
    surfaced via the FAILED marker + non-zero exit, instead of hiding
    inside a complete-looking zero-row workbook.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One database that fails to process must not discard the whole region."""
        client = boto3.client("glue", region_name=REGION)
        client.create_database(DatabaseInput={"Name": "good-db"})
        client.create_database(DatabaseInput={"Name": "bad-db"})

        original = glue_athena_export._build_database_row

        def raise_for_bad(db, region):
            if db.get("Name") == "bad-db":
                raise KeyError("SomeUnexpectedField")
            return original(db, region)

        monkeypatch.setattr(glue_athena_export, "_build_database_row", raise_for_bad)

        rows = _scan_glue_databases_region(REGION)

        names = {row["Database Name"] for row in rows}
        assert "good-db" in names, "healthy database was lost when a sibling failed"
        assert "bad-db" not in names, "malformed database should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "GetDatabases",
            )

        monkeypatch.setattr(glue_athena_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_glue_databases_region(REGION)

    @mock_aws
    def test_collect_glue_databases_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets the export write a FAILED marker +
        exit 1 even though the forced Summary sheet still lands a workbook.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "GetDatabases",
            )

        monkeypatch.setattr(glue_athena_export, "_scan_glue_databases_region", boom)

        databases, failed_regions = glue_athena_export.collect_glue_databases([REGION])

        assert databases == []
        assert [r for r, _ in failed_regions] == [REGION]
