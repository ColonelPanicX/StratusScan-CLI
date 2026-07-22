#!/usr/bin/env python3
"""
Tests for budgets_export.py.

Covers:
- collect_budgets() per-item guarding and account-scope failure propagation
- export_budgets_data()'s failed-scope tracking, finalize, and exit-code behavior

Budgets is a global/account-scope service (not multi-region), so
collect_budgets() is the account-scope PRIMARY collector -- mirrors the
scripts/shield_export.py account-scope pattern (see scripts/lambda_export.py
for the finalize shape). moto has reasonable AWS Budgets support (create/
describe budgets), which is used for the per-item guard test; the API-error
and main()-level tests drive the module through monkeypatched boto3 clients /
module functions instead, since moto has no way to inject a mid-pagination
failure.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import budgets_export  # noqa: E402
from budgets_export import collect_budgets  # noqa: E402

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture(autouse=True)
def patch_output_dir(tmp_path, monkeypatch):
    """Redirect get_output_dir() to a temp directory for every test."""
    monkeypatch.setattr(budgets_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _create_budget(client, name, amount="100"):
    client.create_budget(
        AccountId=ACCOUNT_ID,
        Budget={
            "BudgetName": name,
            "BudgetType": "COST",
            "TimeUnit": "MONTHLY",
            "BudgetLimit": {"Amount": amount, "Unit": "USD"},
        },
    )


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to AWS Budgets: collect_budgets() -- the PRIMARY,
    global/account-scope collector -- used to swallow a real API error into
    an empty list, indistinguishable from an account with no budgets
    configured. export_budgets_data() also used to have no way to signal
    that failure downstream. These tests cover: (a) a malformed budget is
    skipped, not fatal; (b) collect_budgets() raises rather than swallowing
    a real API error; (c) that failure surfaces through export_budgets_data()
    as a non-zero exit plus a utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard ------------------------------------------------

    @mock_aws
    def test_malformed_budget_is_skipped_not_fatal(self, monkeypatch):
        """One budget that fails to process must not discard the others."""
        client = boto3.client("budgets", region_name=REGION)
        _create_budget(client, "good-budget")
        _create_budget(client, "bad-budget")

        original = budgets_export._build_budget_row

        def raise_for_bad(budget):
            if budget.get("BudgetName") == "bad-budget":
                raise KeyError("SomeUnexpectedField")
            return original(budget)

        monkeypatch.setattr(budgets_export, "_build_budget_row", raise_for_bad)

        result = collect_budgets(ACCOUNT_ID)

        names = {row["Budget Name"] for row in result}
        assert "good-budget" in names, "healthy budget was lost when a sibling failed"
        assert "bad-budget" not in names, "malformed budget should have been skipped"

    # -- (b) Account-scope failure propagation ------------------------------

    def test_collect_budgets_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Budgets API error during collection must propagate, not
        collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "DescribeBudgets",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(budgets_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_budgets(ACCOUNT_ID)

    # -- (c) export_budgets_data(): failure surfaced, non-zero exit ---------

    def test_export_budgets_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A budgets API failure in export_budgets_data() must exit non-zero
        and call utils.report_collection_failures -- never silently collapse
        into an empty export."""

        def boom(account_id):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "DescribeBudgets",
            )

        monkeypatch.setattr(budgets_export, "collect_budgets", boom)
        monkeypatch.setattr(budgets_export, "collect_budget_notifications", lambda *a, **kw: [])

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(budgets_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            budgets_export.export_budgets_data(ACCOUNT_ID, "test-account")

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "budgets"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "budgets"

    def test_export_budgets_success_does_not_exit_or_report(self, monkeypatch):
        """A successful (even genuinely empty) collection must not exit
        non-zero or write a failure marker."""
        monkeypatch.setattr(budgets_export, "collect_budgets", lambda account_id: [])
        monkeypatch.setattr(budgets_export, "collect_budget_notifications", lambda *a, **kw: [])

        report_called = []
        monkeypatch.setattr(
            budgets_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        # Should return normally (no SystemExit) for a genuinely empty account.
        budgets_export.export_budgets_data(ACCOUNT_ID, "test-account")

        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
