#!/usr/bin/env python3
"""
Tests for cost_anomaly_detection_export.py.

Covers:
- get_anomaly_monitors() / get_anomaly_subscriptions() per-item guarding and
  account-scope failure propagation (the PRIMARY scopes)
- _run_export()'s failed-scope tracking, always-written Summary sheet, and
  exit-code behavior

Cost Anomaly Detection is a global/account-scope service (Cost Explorer,
accessed via the partition-aware home region), not multi-region -- mirrors
the scripts/iam_export.py account-scope pattern (see scripts/shield_export.py
and scripts/lambda_export.py for the closest existing examples). moto's
Cost Explorer / Cost Anomaly Detection support is limited (no
get_anomaly_monitors/get_anomaly_subscriptions mocking), so these tests drive
the module through monkeypatched boto3 clients / module functions rather than
real moto-backed Cost Explorer state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cost_anomaly_detection_export  # noqa: E402
from cost_anomaly_detection_export import (  # noqa: E402
    get_anomaly_monitors,
    get_anomaly_subscriptions,
)

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
    monkeypatch.setattr(cost_anomaly_detection_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_ce_client(monitors=None, subscriptions=None):
    """Build a MagicMock standing in for a boto3 Cost Explorer client."""
    client = MagicMock()
    client.get_anomaly_monitors.return_value = {"AnomalyMonitors": monitors or []}
    client.get_anomaly_subscriptions.return_value = {"AnomalySubscriptions": subscriptions or []}
    client.get_anomalies.return_value = {"Anomalies": []}
    return client


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to Cost Anomaly Detection: get_anomaly_monitors() and
    get_anomaly_subscriptions() -- the PRIMARY, global/account-scope
    collectors -- used to swallow a real API error into an empty list via
    ``@utils.aws_error_handler(default_return=[])``, indistinguishable from an
    account with nothing configured. ``_run_export()`` also had no way to
    signal that failure downstream (it always wrote a "successful" Summary
    sheet). These tests cover: (a) a malformed monitor/subscription item is
    skipped, not fatal; (b) both PRIMARY collectors raise rather than
    swallowing a real API error; (c) that failure surfaces through
    ``_run_export()`` as a non-zero exit plus a
    ``utils.report_collection_failures()`` call, while the workbook is still
    written.
    """

    # -- (a) Per-item guard --------------------------------------------------

    def test_malformed_monitor_is_skipped_not_fatal(self, monkeypatch):
        """One monitor that fails to process must not discard the others."""
        good = {
            "MonitorArn": "arn:aws:ce::123456789012:anomalymonitor/good",
            "MonitorName": "good-monitor",
        }
        bad = {
            "MonitorArn": "arn:aws:ce::123456789012:anomalymonitor/bad",
            "MonitorName": "bad-monitor",
        }

        client = _fake_ce_client(monitors=[good, bad])
        monkeypatch.setattr(cost_anomaly_detection_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = cost_anomaly_detection_export._build_monitor_row

        def raise_for_bad(monitor):
            if monitor.get("MonitorName") == "bad-monitor":
                raise KeyError("SomeUnexpectedField")
            return original(monitor)

        monkeypatch.setattr(cost_anomaly_detection_export, "_build_monitor_row", raise_for_bad)

        result = get_anomaly_monitors()

        names = {row["MonitorName"] for row in result}
        assert "good-monitor" in names, "healthy monitor was lost when a sibling failed"
        assert "bad-monitor" not in names, "malformed monitor should have been skipped"

    def test_malformed_subscription_is_skipped_not_fatal(self, monkeypatch):
        """One subscription that fails to process must not discard the others."""
        good = {
            "SubscriptionArn": "arn:aws:ce::123456789012:anomalysubscription/good",
            "SubscriptionName": "good-subscription",
        }
        bad = {
            "SubscriptionArn": "arn:aws:ce::123456789012:anomalysubscription/bad",
            "SubscriptionName": "bad-subscription",
        }

        client = _fake_ce_client(subscriptions=[good, bad])
        monkeypatch.setattr(cost_anomaly_detection_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = cost_anomaly_detection_export._build_subscription_row

        def raise_for_bad(subscription, account_id):
            if subscription.get("SubscriptionName") == "bad-subscription":
                raise KeyError("SomeUnexpectedField")
            return original(subscription, account_id)

        monkeypatch.setattr(cost_anomaly_detection_export, "_build_subscription_row", raise_for_bad)

        result = get_anomaly_subscriptions(ACCOUNT_ID)

        names = {row["SubscriptionName"] for row in result}
        assert "good-subscription" in names, "healthy subscription was lost when a sibling failed"
        assert "bad-subscription" not in names, "malformed subscription should have been skipped"

    # -- (b) Account-scope failure propagation -------------------------------

    def test_get_anomaly_monitors_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Cost Explorer API error during monitor collection must
        propagate, not collapse to an empty list."""

        def boom(**kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "GetAnomalyMonitors",
            )

        client = MagicMock()
        client.get_anomaly_monitors.side_effect = boom
        monkeypatch.setattr(cost_anomaly_detection_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            get_anomaly_monitors()

    def test_get_anomaly_subscriptions_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Cost Explorer API error during subscription collection must
        propagate, not collapse to an empty list."""

        def boom(**kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "GetAnomalySubscriptions",
            )

        client = MagicMock()
        client.get_anomaly_subscriptions.side_effect = boom
        monkeypatch.setattr(cost_anomaly_detection_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            get_anomaly_subscriptions(ACCOUNT_ID)

    # -- (c) _run_export(): failure surfaced, non-zero exit ------------------

    def test_run_export_monitors_failure_exits_nonzero_and_reports(self, monkeypatch):
        """An anomaly_monitors API failure in _run_export() must exit
        non-zero and call utils.report_collection_failures -- never silently
        collapse into an empty (but "successful") export."""
        monkeypatch.setattr(cost_anomaly_detection_export, "pd", __import__("pandas"), raising=False)

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "GetAnomalyMonitors",
            )

        monkeypatch.setattr(cost_anomaly_detection_export, "get_anomaly_monitors", boom)
        monkeypatch.setattr(cost_anomaly_detection_export, "get_anomaly_subscriptions", lambda account_id: [])
        monkeypatch.setattr(
            cost_anomaly_detection_export, "get_anomalies", lambda start_date, end_date, monitor_arn=None: []
        )

        save_calls = []
        monkeypatch.setattr(
            cost_anomaly_detection_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda sheets, filename: save_calls.append((sheets, filename)) or "fake-path.xlsx",
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(cost_anomaly_detection_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            cost_anomaly_detection_export._run_export(ACCOUNT_ID, "test-account")

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "cost-anomaly-detection"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "anomaly_monitors"

        # The workbook (Summary sheet included) is still written despite the
        # scope failure -- a partial export must never be lost, only unmarked.
        assert save_calls, "Excel export was not written even though it must always land"
        sheets = save_calls[0][0]
        assert "Summary" in sheets

    def test_run_export_subscriptions_failure_exits_nonzero_and_reports(self, monkeypatch):
        """An anomaly_subscriptions API failure in _run_export() must exit
        non-zero and call utils.report_collection_failures."""
        monkeypatch.setattr(cost_anomaly_detection_export, "pd", __import__("pandas"), raising=False)

        monkeypatch.setattr(cost_anomaly_detection_export, "get_anomaly_monitors", lambda: [])

        def boom(account_id):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "GetAnomalySubscriptions",
            )

        monkeypatch.setattr(cost_anomaly_detection_export, "get_anomaly_subscriptions", boom)
        monkeypatch.setattr(
            cost_anomaly_detection_export, "get_anomalies", lambda start_date, end_date, monitor_arn=None: []
        )
        monkeypatch.setattr(
            cost_anomaly_detection_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda sheets, filename: "fake-path.xlsx",
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(cost_anomaly_detection_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            cost_anomaly_detection_export._run_export(ACCOUNT_ID, "test-account")

        assert exc_info.value.code == 1
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "anomaly_subscriptions"

    # -- (d) Genuine empty: both primary scopes succeed with nothing --------

    def test_run_export_genuinely_empty_exits_zero_no_marker(self, monkeypatch):
        """Both PRIMARY scopes succeeding with nothing configured is a
        legitimate, expected state -- no exception, no
        utils.report_collection_failures call (no *-FAILED-*.txt marker)."""
        monkeypatch.setattr(cost_anomaly_detection_export, "pd", __import__("pandas"), raising=False)

        monkeypatch.setattr(cost_anomaly_detection_export, "get_anomaly_monitors", lambda: [])
        monkeypatch.setattr(cost_anomaly_detection_export, "get_anomaly_subscriptions", lambda account_id: [])
        monkeypatch.setattr(
            cost_anomaly_detection_export, "get_anomalies", lambda start_date, end_date, monitor_arn=None: []
        )
        monkeypatch.setattr(
            cost_anomaly_detection_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda sheets, filename: "fake-path.xlsx",
        )

        report_called = []
        monkeypatch.setattr(
            cost_anomaly_detection_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        # No SystemExit should be raised -- _run_export() returns normally.
        cost_anomaly_detection_export._run_export(ACCOUNT_ID, "test-account")

        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
