#!/usr/bin/env python3
"""
Tests for trusted_advisor_cost_optimization_export.py.

Covers:
- get_trusted_advisor_checks() / get_check_result() distinguishing a
  graceful "not subscribed" state from a real API error
- _build_check_row() per-item guarding (malformed check entries)
- get_all_check_results()'s failed-check tracking and account-scope
  failure propagation
- main()'s failed-scope tracking, finalize, and exit-code behavior

Trusted Advisor is a global/account-scope service (not multi-region), so
get_all_check_results() is the account-scope PRIMARY collector -- mirrors
the scripts/shield_export.py account-scope pattern (see
scripts/lambda_export.py for the finalize shape). moto's support/Trusted
Advisor coverage is limited (no describe_trusted_advisor_checks /
describe_trusted_advisor_check_result mocking, no configurable
subscription state), so these tests drive the module through monkeypatched
boto3 clients / module functions rather than real moto-backed Support
state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import trusted_advisor_cost_optimization_export as ta_export  # noqa: E402
from trusted_advisor_cost_optimization_export import (  # noqa: E402
    TrustedAdvisorNotSubscribedError,
    _build_check_row,
    get_all_check_results,
    get_check_result,
    get_trusted_advisor_checks,
)

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
    monkeypatch.setattr(ta_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _subscription_required_error(op_name):
    return botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "SubscriptionRequiredException",
                "Message": "AWS Premium Support Subscription is required to use this service.",
            }
        },
        op_name,
    )


def _real_client_error(op_name, code="ThrottlingException"):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "Something broke"}},
        op_name,
    )


class TestGetTrustedAdvisorChecks:
    """
    get_trusted_advisor_checks() is the top-level listing call: a
    SubscriptionRequiredException is a legitimate, expected "not available"
    state (raises TrustedAdvisorNotSubscribedError) while any other error
    must raise through unmodified -- never swallowed to an empty list.
    """

    def test_subscription_required_raises_not_subscribed(self, monkeypatch):
        client = MagicMock()
        client.describe_trusted_advisor_checks.side_effect = _subscription_required_error(
            "DescribeTrustedAdvisorChecks"
        )
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(TrustedAdvisorNotSubscribedError):
            get_trusted_advisor_checks()

    def test_real_error_is_not_swallowed(self, monkeypatch):
        client = MagicMock()
        client.describe_trusted_advisor_checks.side_effect = _real_client_error(
            "DescribeTrustedAdvisorChecks", code="AccessDeniedException"
        )
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            get_trusted_advisor_checks()

    def test_filters_to_cost_optimizing_checks(self, monkeypatch):
        client = MagicMock()
        client.describe_trusted_advisor_checks.return_value = {
            "checks": [
                {"id": "cost-1", "name": "Cost Check", "description": "d", "category": "cost_optimizing"},
                {"id": "sec-1", "name": "Security Check", "description": "d", "category": "security"},
            ]
        }
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        checks = get_trusted_advisor_checks()

        assert [c["id"] for c in checks] == ["cost-1"]


class TestGetCheckResult:
    """
    get_check_result() -- formerly @aws_error_handler(default_return=None),
    which swallowed every error into None. Now raises real errors and only
    treats SubscriptionRequiredException as graceful.
    """

    def test_subscription_required_raises_not_subscribed(self, monkeypatch):
        client = MagicMock()
        client.describe_trusted_advisor_check_result.side_effect = _subscription_required_error(
            "DescribeTrustedAdvisorCheckResult"
        )
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(TrustedAdvisorNotSubscribedError):
            get_check_result("check-1")

    def test_real_api_error_is_not_swallowed(self, monkeypatch):
        """A real error must raise, not collapse to None (the old bug)."""
        client = MagicMock()
        client.describe_trusted_advisor_check_result.side_effect = _real_client_error(
            "DescribeTrustedAdvisorCheckResult"
        )
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            get_check_result("check-1")

    def test_successful_result_returned(self, monkeypatch):
        client = MagicMock()
        client.describe_trusted_advisor_check_result.return_value = {
            "result": {"status": "ok", "flaggedResources": []}
        }
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        assert get_check_result("check-1") == {"status": "ok", "flaggedResources": []}


class TestBuildCheckRow:
    """(a) Per-item guard: a malformed check entry must not raise KeyError."""

    def test_missing_id_raises_value_error_not_key_error(self, monkeypatch):
        malformed_check = {"name": "No ID Check", "description": "d"}

        with pytest.raises(ValueError):
            _build_check_row(malformed_check)

    def test_well_formed_check_builds_entry(self, monkeypatch):
        monkeypatch.setattr(
            ta_export, "get_check_result", lambda check_id: {"status": "ok", "flaggedResources": []}
        )
        check = {"id": "check-1", "name": "My Check", "description": "d"}

        check_id, entry = _build_check_row(check)

        assert check_id == "check-1"
        assert entry == {"name": "My Check", "description": "d", "result": {"status": "ok", "flaggedResources": []}}

    def test_no_result_returns_none_entry(self, monkeypatch):
        monkeypatch.setattr(ta_export, "get_check_result", lambda check_id: None)
        check = {"id": "check-1", "name": "My Check", "description": "d"}

        check_id, entry = _build_check_row(check)

        assert check_id == "check-1"
        assert entry is None


class TestGetAllCheckResults:
    """
    (a) A malformed check is skipped, not fatal.
    (b) A real per-check API error is tracked in failed_checks, not
        swallowed into an empty/success result.
    Not-subscribed at the top-level listing call propagates immediately.
    """

    def test_malformed_check_is_skipped_not_fatal(self, monkeypatch):
        good_check = {"id": "good-id", "name": "Good Check", "description": "d"}
        malformed_check = {"name": "No ID Check", "description": "d"}  # missing 'id'

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", lambda: [good_check, malformed_check])
        monkeypatch.setattr(
            ta_export, "get_check_result", lambda check_id: {"status": "ok", "flaggedResources": []}
        )

        results, failed_checks = get_all_check_results()

        assert "good-id" in results
        assert len(failed_checks) == 1
        assert failed_checks[0][0] == "Unknown"

    def test_real_api_error_on_one_check_is_tracked_not_swallowed(self, monkeypatch):
        good_check = {"id": "good-id", "name": "Good Check", "description": "d"}
        bad_check = {"id": "bad-id", "name": "Bad Check", "description": "d"}

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", lambda: [good_check, bad_check])

        def fake_get_check_result(check_id):
            if check_id == "bad-id":
                raise _real_client_error("DescribeTrustedAdvisorCheckResult")
            return {"status": "ok", "flaggedResources": []}

        monkeypatch.setattr(ta_export, "get_check_result", fake_get_check_result)

        results, failed_checks = get_all_check_results()

        assert "good-id" in results
        assert "bad-id" not in results
        assert len(failed_checks) == 1
        assert failed_checks[0][0] == "bad-id"

    def test_not_subscribed_propagates_from_listing(self, monkeypatch):
        def raise_not_subscribed():
            raise TrustedAdvisorNotSubscribedError("no support plan")

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", raise_not_subscribed)

        with pytest.raises(TrustedAdvisorNotSubscribedError):
            get_all_check_results()


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to Trusted Advisor cost optimization: get_check_result()
    -- the PRIMARY collector -- used to swallow every real API error into
    None via @aws_error_handler(default_return=None), indistinguishable
    from a check with no result. main() also had no way to signal that
    failure downstream (it just logged "No cost optimization opportunities
    found" and exited 0). These tests cover: (a) a malformed check is
    skipped, not fatal; (b) a real API error surfaces as a failed scope
    rather than an empty result; (c) that failure surfaces through main()
    as a non-zero exit plus a utils.report_collection_failures() call; (d)
    a genuine "not subscribed" state is a graceful exit 0 with no failure
    marker.
    """

    # -- (a) Per-item guard --------------------------------------------

    def test_malformed_check_is_skipped_not_fatal(self, monkeypatch):
        """One malformed check entry must not discard the others."""
        good_check = {"id": "good-id", "name": "Good Check", "description": "d"}
        bad_check = {"name": "Bad Check (no id)", "description": "d"}

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", lambda: [good_check, bad_check])
        monkeypatch.setattr(
            ta_export, "get_check_result", lambda check_id: {"status": "ok", "flaggedResources": []}
        )

        results, failed_checks = get_all_check_results()

        assert "good-id" in results, "healthy check was lost when a sibling was malformed"
        assert len(failed_checks) == 1

    # -- (b) Real error surfaces, not swallowed -------------------------

    def test_get_check_result_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Trusted Advisor API error must propagate, not collapse to
        None (the old @aws_error_handler(default_return=None) behavior)."""
        client = MagicMock()
        client.describe_trusted_advisor_check_result.side_effect = _real_client_error(
            "DescribeTrustedAdvisorCheckResult", code="InternalServerError"
        )
        monkeypatch.setattr(ta_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            get_check_result("check-1")

    # -- (c) main()/_run_export(): failure surfaced, non-zero exit ------

    def test_run_export_check_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A real per-check API failure must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into
        'No cost optimization opportunities found.'"""
        monkeypatch.setattr(ta_export.utils, "ensure_dependencies", lambda *a, **kw: True)

        good_check = {"id": "good-id", "name": "Good Check", "description": "d"}
        bad_check = {"id": "bad-id", "name": "Bad Check", "description": "d"}
        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", lambda: [good_check, bad_check])

        def fake_get_check_result(check_id):
            if check_id == "bad-id":
                raise _real_client_error("DescribeTrustedAdvisorCheckResult")
            # "good-id" has no flagged resources -- legitimately empty, but
            # the run must still be flagged as failed because of bad-id.
            return {"status": "ok", "flaggedResources": []}

        monkeypatch.setattr(ta_export, "get_check_result", fake_get_check_result)

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(ta_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            ta_export._run_export("123456789012", "test-account")

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "trusted-advisor-cost-optimization"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "cost_checks"

    def test_run_export_listing_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A real error on the top-level checks listing call must also
        surface as a failed 'cost_checks' scope, not an empty export."""
        monkeypatch.setattr(ta_export.utils, "ensure_dependencies", lambda *a, **kw: True)

        def raise_real_error():
            raise _real_client_error("DescribeTrustedAdvisorChecks", code="AccessDeniedException")

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", raise_real_error)

        calls = {}
        monkeypatch.setattr(
            ta_export.utils,
            "report_collection_failures",
            lambda account_name, resource_type, failed_scopes: calls.update(
                account_name=account_name, resource_type=resource_type, failed_scopes=failed_scopes
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            ta_export._run_export("123456789012", "test-account")

        assert exc_info.value.code == 1
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "cost_checks"

    # -- (d) Not subscribed: graceful skip, no marker --------------------

    def test_not_subscribed_exits_zero_no_marker(self, monkeypatch):
        """Trusted Advisor requiring Business/Enterprise Support is a
        legitimate, expected state -- exit 0, and
        utils.report_collection_failures is never called (no
        *-FAILED-*.txt marker is written)."""
        monkeypatch.setattr(ta_export.utils, "ensure_dependencies", lambda *a, **kw: True)

        def raise_not_subscribed():
            raise TrustedAdvisorNotSubscribedError("no support plan")

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", raise_not_subscribed)

        report_called = []
        monkeypatch.setattr(
            ta_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        with pytest.raises(SystemExit) as exc_info:
            ta_export._run_export("123456789012", "test-account")

        assert exc_info.value.code == 0
        assert report_called == []

    def test_genuinely_empty_exits_zero_no_marker(self, monkeypatch):
        """No cost-optimizing checks exist for this account (subscription
        active, listing call succeeded) -- genuinely nothing to optimize --
        must exit 0 with no failure marker."""
        monkeypatch.setattr(ta_export.utils, "ensure_dependencies", lambda *a, **kw: True)

        monkeypatch.setattr(ta_export, "get_trusted_advisor_checks", lambda: [])

        report_called = []
        monkeypatch.setattr(
            ta_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        with pytest.raises(SystemExit) as exc_info:
            ta_export._run_export("123456789012", "test-account")

        assert exc_info.value.code == 0
        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
