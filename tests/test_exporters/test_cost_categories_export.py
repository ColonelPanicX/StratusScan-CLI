#!/usr/bin/env python3
"""
Tests for cost_categories_export.py.

Covers:
- list_cost_category_definitions() per-item guarding and account-scope
  failure propagation
- main()'s failed-scope tracking, always-written Summary sheet, and
  exit-code behavior

Cost Categories (Cost Explorer) is a global, account-scope service (not
multi-region), so list_cost_category_definitions() is the account-scope
PRIMARY collector -- mirrors the scripts/shield_export.py account-scope
pattern (see scripts/lambda_export.py for the finalize shape). This script
is a Tier-3 PARTIAL case: it already builds an always-written Summary
sheet, so the fix adds failed-scope tracking + a *-FAILED-*.txt marker +
non-zero exit on top of that, without breaking the "a workbook always
lands" guarantee.

moto has NO support at all for Cost Explorer's Cost Categories APIs
(list_cost_category_definitions / describe_cost_category_definition both
raise NotImplementedError under @mock_aws as of the moto version pinned in
this repo). These tests therefore drive the module entirely through
monkeypatched boto3 clients / module functions rather than real
moto-backed Cost Explorer state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cost_categories_export  # noqa: E402
from cost_categories_export import list_cost_category_definitions  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _fake_ce_client(cost_category_refs=None):
    """Build a MagicMock standing in for a boto3 Cost Explorer (ce) client."""
    client = MagicMock()
    client.list_cost_category_definitions.return_value = {
        "CostCategoryReferences": cost_category_refs or [],
    }
    return client


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 silent-collection-failure audit,
    applied to Cost Categories: list_cost_category_definitions() -- the
    PRIMARY, global/account-scope collector -- used to swallow a real API
    error into an empty list, indistinguishable from an account with no
    Cost Categories configured. main() also had no way to signal that
    failure downstream despite always writing a Summary sheet. These tests
    cover: (a) a malformed Cost Category reference is skipped, not fatal;
    (b) list_cost_category_definitions() raises rather than swallowing a
    real API error; (c) that failure surfaces through main() as a non-zero
    exit plus a utils.report_collection_failures() call; (d) a genuinely
    empty account (primary scope succeeds, nothing configured) completes
    with no marker.
    """

    # -- (a) Per-item guard --------------------------------------------

    def test_malformed_reference_is_skipped_not_fatal(self, monkeypatch):
        """One Cost Category reference that fails to process must not
        discard the others."""
        good_ref = {
            "Name": "good-category",
            "CostCategoryArn": "arn:aws:ce::123456789012:costcategory/good",
            "NumberOfRules": 1,
        }
        bad_ref = {
            "Name": "bad-category",
            "CostCategoryArn": "arn:aws:ce::123456789012:costcategory/bad",
            "NumberOfRules": 1,
        }

        client = _fake_ce_client(cost_category_refs=[good_ref, bad_ref])
        monkeypatch.setattr(cost_categories_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = cost_categories_export._build_cost_category_row

        def raise_for_bad(cc_ref):
            if cc_ref.get("Name") == "bad-category":
                raise KeyError("SomeUnexpectedField")
            return original(cc_ref)

        monkeypatch.setattr(cost_categories_export, "_build_cost_category_row", raise_for_bad)

        result = list_cost_category_definitions()

        names = {row["Name"] for row in result}
        assert "good-category" in names, "healthy Cost Category was lost when a sibling failed"
        assert "bad-category" not in names, "malformed Cost Category should have been skipped"

    # -- (b) Account-scope failure propagation ------------------------------

    def test_list_cost_category_definitions_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Cost Explorer API error during collection must propagate,
        not collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListCostCategoryDefinitions",
            )

        client = MagicMock()
        client.list_cost_category_definitions.side_effect = boom
        monkeypatch.setattr(cost_categories_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            list_cost_category_definitions()

    # -- (c) main(): failure surfaced, non-zero exit, marker written --------

    def test_main_primary_scope_failure_exits_nonzero_and_reports(self, monkeypatch, tmp_path):
        """
        A cost_categories-scope failure must exit non-zero and call
        utils.report_collection_failures -- even though this script always
        builds a Summary sheet and would otherwise write a complete-looking
        workbook (the Tier-3 PARTIAL failure mode).
        """
        monkeypatch.setattr(cost_categories_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(
            cost_categories_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(cost_categories_export.utils, "mask_account_id", lambda *a, **kw: "1234****9012")
        monkeypatch.setattr(cost_categories_export.utils, "detect_partition", lambda *a, **kw: "aws")
        monkeypatch.setattr(
            cost_categories_export.utils, "is_service_available_in_partition", lambda *a, **kw: True
        )
        monkeypatch.setattr(cost_categories_export.utils, "prompt_confirmation", lambda *a, **kw: "confirm")

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListCostCategoryDefinitions",
            )

        monkeypatch.setattr(cost_categories_export, "list_cost_category_definitions", boom)

        monkeypatch.setattr(cost_categories_export.utils, "create_export_filename", lambda *a, **kw: "fake.xlsx")
        monkeypatch.setattr(
            cost_categories_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda *a, **kw: str(tmp_path / "fake.xlsx"),
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(cost_categories_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            cost_categories_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "cost-categories"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "cost_categories"

    # -- (d) Genuinely empty: graceful, no marker ----------------------------

    def test_main_genuinely_empty_completes_no_marker(self, monkeypatch, tmp_path):
        """
        An account with zero Cost Categories (primary scope succeeds, just
        returns nothing) must complete without raising and never call
        utils.report_collection_failures -- a real Summary-only workbook is
        not a failure. main() has no explicit ``sys.exit(0)`` on the
        success path (unlike the failure path), so success here means
        "returns normally," not "raises SystemExit(0)".
        """
        monkeypatch.setattr(cost_categories_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(
            cost_categories_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(cost_categories_export.utils, "mask_account_id", lambda *a, **kw: "1234****9012")
        monkeypatch.setattr(cost_categories_export.utils, "detect_partition", lambda *a, **kw: "aws")
        monkeypatch.setattr(
            cost_categories_export.utils, "is_service_available_in_partition", lambda *a, **kw: True
        )
        monkeypatch.setattr(cost_categories_export.utils, "prompt_confirmation", lambda *a, **kw: "confirm")

        monkeypatch.setattr(cost_categories_export, "list_cost_category_definitions", lambda: [])

        monkeypatch.setattr(cost_categories_export.utils, "create_export_filename", lambda *a, **kw: "fake.xlsx")
        monkeypatch.setattr(
            cost_categories_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda *a, **kw: str(tmp_path / "fake.xlsx"),
        )

        report_called = []
        monkeypatch.setattr(
            cost_categories_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        cost_categories_export.main()

        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
