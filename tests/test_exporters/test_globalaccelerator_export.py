#!/usr/bin/env python3
"""
Tests for globalaccelerator_export.py.

Covers:
- collect_accelerators() per-item guarding and account-scope failure propagation
- export_globalaccelerator_data()'s failed-scope tracking, finalize, and
  exit-code behavior

Global Accelerator is a global/account-scope service (control plane in
us-west-2, not multi-region), so collect_accelerators() is the account-scope
PRIMARY collector -- mirrors the scripts/shield_export.py account-scope
pattern (see scripts/lambda_export.py for the finalize shape). moto's
Global Accelerator support is limited (no configurable accelerator/listener
mutation state usable for failure-injection scenarios), so these tests drive
the module through monkeypatched boto3 clients / module functions rather
than real moto-backed Global Accelerator state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import globalaccelerator_export  # noqa: E402
from globalaccelerator_export import collect_accelerators  # noqa: E402

REGION = "us-west-2"


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
    monkeypatch.setattr(globalaccelerator_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_globalaccelerator_client(accelerators=None):
    """Build a MagicMock standing in for a boto3 Global Accelerator client."""
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Accelerators": accelerators or []}]
    client.get_paginator.return_value = paginator
    return client


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to Global Accelerator: collect_accelerators() -- the
    PRIMARY, global/account-scope collector -- used to be wrapped in
    ``utils.aws_error_handler(default_return=[])`` and additionally swallowed
    real API errors internally, returning an empty list indistinguishable
    from an account with no accelerators configured.
    export_globalaccelerator_data() also had no way to signal that failure
    downstream. These tests cover: (a) a malformed accelerator is skipped,
    not fatal; (b) collect_accelerators() raises rather than swallowing a
    real API error; (c) that failure surfaces through
    export_globalaccelerator_data() as a non-zero exit plus a
    utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard ------------------------------------------------

    def test_malformed_accelerator_is_skipped_not_fatal(self, monkeypatch):
        """One accelerator that fails to process must not discard the others."""
        good = {
            "AcceleratorArn": "arn:aws:globalaccelerator::123456789012:accelerator/good-id",
            "Name": "good-accelerator",
            "Enabled": True,
            "Status": "DEPLOYED",
        }
        bad = {
            "AcceleratorArn": "arn:aws:globalaccelerator::123456789012:accelerator/bad-id",
            "Name": "bad-accelerator",
            "Enabled": True,
            "Status": "DEPLOYED",
        }

        client = _fake_globalaccelerator_client(accelerators=[good, bad])
        monkeypatch.setattr(globalaccelerator_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = globalaccelerator_export._build_accelerator_row

        def raise_for_bad(acc):
            if acc.get("Name") == "bad-accelerator":
                raise KeyError("SomeUnexpectedField")
            return original(acc)

        monkeypatch.setattr(globalaccelerator_export, "_build_accelerator_row", raise_for_bad)

        result = collect_accelerators()

        arns = {row["Accelerator ARN"] for row in result}
        assert "arn:aws:globalaccelerator::123456789012:accelerator/good-id" in arns, (
            "healthy accelerator was lost when a sibling failed"
        )
        assert "arn:aws:globalaccelerator::123456789012:accelerator/bad-id" not in arns, (
            "malformed accelerator should have been skipped"
        )

    # -- (b) Account-scope failure propagation ------------------------------

    def test_collect_accelerators_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Global Accelerator API error during collection must
        propagate, not collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServiceErrorException", "Message": "Something broke"}},
                "ListAccelerators",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(globalaccelerator_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_accelerators()

    # -- (c) export function: failure surfaced, non-zero exit ---------------

    def test_export_accelerators_failure_exits_nonzero_and_reports(self, monkeypatch):
        """An accelerators API failure must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty export."""
        monkeypatch.setattr(globalaccelerator_export.utils, "prompt_for_confirmation", lambda *a, **kw: True)

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServiceErrorException", "Message": "Something broke"}},
                "ListAccelerators",
            )

        monkeypatch.setattr(globalaccelerator_export, "collect_accelerators", boom)
        monkeypatch.setattr(globalaccelerator_export, "collect_custom_routing_accelerators", lambda: [])

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(globalaccelerator_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            globalaccelerator_export.export_globalaccelerator_data("123456789012", "test-account")

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "globalaccelerator"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "accelerators"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
