#!/usr/bin/env python3
"""
Tests for shield_export.py.

Covers:
- check_subscription() as a graceful availability probe
- collect_protections() per-item guarding and account-scope failure propagation
- main()'s failed-scope tracking, finalize, and exit-code behavior

Shield Advanced is a global/account-scope service (not multi-region), so
collect_protections() is the account-scope PRIMARY collector -- mirrors the
scripts/iam_export.py account-scope pattern (see scripts/lambda_export.py
for the finalize shape). moto's Shield support is limited (no
protection-mutation APIs and no configurable subscription state), so these
tests drive the module through monkeypatched boto3 clients / module
functions rather than real moto-backed Shield state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import shield_export  # noqa: E402
from shield_export import check_subscription, collect_protections  # noqa: E402

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
    monkeypatch.setattr(shield_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_shield_client(protections=None):
    """Build a MagicMock standing in for a boto3 Shield client."""
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Protections": protections or []}]
    client.get_paginator.return_value = paginator
    client.describe_protection.return_value = {"Protection": {}}
    return client


class TestCheckSubscription:
    """
    check_subscription() is a graceful availability probe: Shield Advanced
    not being subscribed (ResourceNotFoundException) is a legitimate,
    expected state and returns None rather than raising.
    """

    def test_resource_not_found_returns_none(self, monkeypatch):
        client = MagicMock()
        client.describe_subscription.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "not subscribed"}},
            "DescribeSubscription",
        )
        monkeypatch.setattr(shield_export.utils, "get_boto3_client", lambda *a, **kw: client)

        assert check_subscription() is None

    def test_active_subscription_returns_dict(self, monkeypatch):
        client = MagicMock()
        client.describe_subscription.return_value = {
            "Subscription": {"SubscriptionArn": "arn:aws:shield::123456789012:subscription/x"}
        }
        monkeypatch.setattr(shield_export.utils, "get_boto3_client", lambda *a, **kw: client)

        result = check_subscription()

        assert result == {"SubscriptionArn": "arn:aws:shield::123456789012:subscription/x"}


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to Shield Advanced: collect_protections() -- the PRIMARY,
    global/account-scope collector -- used to swallow a real API error into
    an empty list, indistinguishable from an account with no protections
    configured. main() also used to have no way to signal that failure
    downstream. These tests cover: (a) a malformed protection is skipped, not
    fatal; (b) collect_protections() raises rather than swallowing a real API
    error; (c) that failure surfaces through main() as a non-zero exit plus a
    utils.report_collection_failures() call; (d) a genuine "not subscribed"
    state is a graceful exit 0 with no failure marker.
    """

    # -- (a) Per-item guard ------------------------------------------------

    def test_malformed_protection_is_skipped_not_fatal(self, monkeypatch):
        """One protection that fails to process must not discard the others."""
        good = {
            "Id": "good-id",
            "Name": "good-protection",
            "ResourceArn": "arn:aws:ec2:us-east-1:123456789012:eip-allocation/eipalloc-good",
        }
        bad = {
            "Id": "bad-id",
            "Name": "bad-protection",
            "ResourceArn": "arn:aws:ec2:us-east-1:123456789012:eip-allocation/eipalloc-bad",
        }

        client = _fake_shield_client(protections=[good, bad])
        monkeypatch.setattr(shield_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = shield_export._build_protection_row

        def raise_for_bad(client_arg, protection, processed, total):
            if protection.get("Id") == "bad-id":
                raise KeyError("SomeUnexpectedField")
            return original(client_arg, protection, processed, total)

        monkeypatch.setattr(shield_export, "_build_protection_row", raise_for_bad)

        result = collect_protections()

        ids = {row["Protection ID"] for row in result}
        assert "good-id" in ids, "healthy protection was lost when a sibling failed"
        assert "bad-id" not in ids, "malformed protection should have been skipped"

    # -- (b) Account-scope failure propagation ------------------------------

    def test_collect_protections_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Shield API error during collection must propagate, not
        collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListProtections",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(shield_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_protections()

    # -- (c) main(): failure surfaced, non-zero exit ------------------------

    def test_main_protections_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A protections API failure in main() must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty export."""
        monkeypatch.setattr(shield_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(shield_export.utils, "setup_logging", lambda *a, **kw: None)
        monkeypatch.setattr(
            shield_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        monkeypatch.setattr(
            shield_export.utils, "get_boto3_client", lambda service, *a, **kw: sts_client
        )

        monkeypatch.setattr(
            shield_export,
            "check_subscription",
            lambda: {"SubscriptionArn": "arn:aws:shield::123456789012:subscription/x"},
        )

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListProtections",
            )

        monkeypatch.setattr(shield_export, "collect_protections", boom)
        monkeypatch.setattr(shield_export, "collect_attacks", lambda: [])
        monkeypatch.setattr(shield_export, "collect_emergency_contacts", lambda: [])
        monkeypatch.setattr(shield_export, "collect_protection_groups", lambda: [])
        monkeypatch.setattr(shield_export, "collect_drt_access", lambda: {})

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(shield_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            shield_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "shield-advanced"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "protections"

    # -- (d) Subscription not active: graceful skip, no marker --------------

    def test_subscription_not_active_exits_zero_no_marker(self, monkeypatch):
        """Shield Advanced not being subscribed is a legitimate, expected
        state -- exit 0, and utils.report_collection_failures is never
        called (no *-FAILED-*.txt marker is written)."""
        monkeypatch.setattr(shield_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(shield_export.utils, "setup_logging", lambda *a, **kw: None)
        monkeypatch.setattr(
            shield_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        monkeypatch.setattr(
            shield_export.utils, "get_boto3_client", lambda service, *a, **kw: sts_client
        )

        monkeypatch.setattr(shield_export, "check_subscription", lambda: None)

        report_called = []
        monkeypatch.setattr(
            shield_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        with pytest.raises(SystemExit) as exc_info:
            shield_export.main()

        assert exc_info.value.code == 0
        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
