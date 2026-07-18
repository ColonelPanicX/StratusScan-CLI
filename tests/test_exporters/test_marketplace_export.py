#!/usr/bin/env python3
"""
Tests for marketplace_export.py.

Covers:
- _build_agreement_row() per-item field extraction
- collect_agreements() per-item guarding and account-scope failure propagation
- main()'s failed-scope tracking, always-written Summary sheet, and exit-code
  behavior

AWS Marketplace is a global/account-scope service (not multi-region), so
collect_agreements() is the account-scope PRIMARY collector -- mirrors the
scripts/shield_export.py sibling global/account-scope PARTIAL-tier fix (see
scripts/lambda_export.py for the finalize shape). moto's Marketplace Agreement
support is limited (no search_agreements / describe_agreement /
get_agreement_terms state to seed), so these tests drive the module through
monkeypatched boto3 clients / module functions rather than real moto-backed
Marketplace state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import marketplace_export  # noqa: E402
from marketplace_export import _build_agreement_row, collect_agreements  # noqa: E402

REGION = "us-east-1"


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
    monkeypatch.setattr(marketplace_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_agreement_summary(agreement_id: str) -> dict:
    return {"agreementId": agreement_id}


def _fake_agreement_details(agreement_id: str, status: str = "ACTIVE") -> dict:
    return {
        "proposer": {"accountId": "111111111111"},
        "acceptor": {"accountId": "222222222222"},
        "agreementType": "PurchaseAgreement",
        "status": status,
        "acceptanceTime": "N/A",
        "startTime": "N/A",
        "endTime": "N/A",
        "estimatedCharges": {"agreementValue": "100.00", "currencyCode": "USD"},
    }


class TestBuildAgreementRow:
    """_build_agreement_row() extracts a single agreement's fields with safe defaults."""

    def test_builds_row_from_agreement_details(self):
        client = MagicMock()
        client.describe_agreement.return_value = _fake_agreement_details("agr-good")

        row = _build_agreement_row(client, _fake_agreement_summary("agr-good"))

        assert row["Agreement ID"] == "agr-good"
        assert row["Status"] == "ACTIVE"
        assert row["Proposer Account ID"] == "111111111111"
        assert row["Acceptor Account ID"] == "222222222222"
        assert row["Agreement Amount"] == "100.00"
        assert row["Currency"] == "USD"

    def test_missing_agreement_id_defaults_to_na(self):
        client = MagicMock()
        client.describe_agreement.return_value = {}

        row = _build_agreement_row(client, {})

        assert row["Agreement ID"] == "N/A"


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to AWS Marketplace: collect_agreements() -- the PRIMARY,
    global/account-scope collector -- used to swallow a real API error (via
    @utils.aws_error_handler(default_return=[]) plus a broad manual
    try/except around search_agreements) into an empty list,
    indistinguishable from an account with no Marketplace agreements. main()
    also used to have no way to signal that failure downstream -- it always
    wrote a non-empty Summary sheet regardless. These tests cover: (a) a
    malformed/inaccessible agreement is skipped, not fatal; (b)
    collect_agreements() raises rather than swallowing a real API error; (c)
    that failure surfaces through main() as a non-zero exit plus a
    utils.report_collection_failures() call, even though the Summary sheet
    is still written and a workbook still lands.
    """

    # -- (a) Per-item guard ------------------------------------------------

    def test_malformed_agreement_is_skipped_not_fatal(self, monkeypatch):
        """One agreement that fails to enrich must not discard the others."""
        good_summary = _fake_agreement_summary("agr-good")
        bad_summary = _fake_agreement_summary("agr-bad")

        client = MagicMock()
        client.search_agreements.return_value = {
            "agreementViewSummaries": [good_summary, bad_summary],
            "nextToken": None,
        }

        def describe_agreement(**kwargs):
            agreement_id = kwargs.get("agreementId")
            if agreement_id == "agr-bad":
                raise KeyError("SomeUnexpectedField")
            return _fake_agreement_details(agreement_id)

        client.describe_agreement.side_effect = describe_agreement
        monkeypatch.setattr(
            marketplace_export.utils, "get_boto3_client", lambda *a, **kw: client
        )

        result = collect_agreements()

        ids = {row["Agreement ID"] for row in result}
        assert "agr-good" in ids, "healthy agreement was lost when a sibling failed"
        assert "agr-bad" not in ids, "malformed agreement should have been skipped"

    # -- (b) Account-scope failure propagation ------------------------------

    def test_collect_agreements_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Marketplace API error during collection must propagate,
        not collapse to an empty list."""

        def boom(**kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "SearchAgreements",
            )

        client = MagicMock()
        client.search_agreements.side_effect = boom
        monkeypatch.setattr(
            marketplace_export.utils, "get_boto3_client", lambda *a, **kw: client
        )

        with pytest.raises(botocore.exceptions.ClientError):
            collect_agreements()

    # -- (c) main(): failure surfaced, non-zero exit ------------------------

    def test_main_agreements_failure_exits_nonzero_and_reports(self, monkeypatch):
        """An agreements API failure in main() must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty (but still Summary-populated) export."""
        monkeypatch.setattr(marketplace_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(marketplace_export.utils, "setup_logging", lambda *a, **kw: None)
        monkeypatch.setattr(marketplace_export.utils, "log_script_start", lambda *a, **kw: None)
        monkeypatch.setattr(marketplace_export.utils, "detect_partition", lambda *a, **kw: "aws")
        monkeypatch.setattr(
            marketplace_export.utils, "is_service_available_in_partition", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            marketplace_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(
            marketplace_export.utils,
            "create_export_filename",
            lambda *a, **kw: "test-account-marketplace-global-export.xlsx",
        )
        monkeypatch.setattr(
            marketplace_export.utils, "save_multiple_dataframes_to_excel", lambda *a, **kw: "fake-path.xlsx"
        )

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "SearchAgreements",
            )

        monkeypatch.setattr(marketplace_export, "collect_agreements", boom)
        monkeypatch.setattr(marketplace_export, "collect_agreement_terms", lambda agreements: [])

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(marketplace_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            marketplace_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "marketplace"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "agreements"
