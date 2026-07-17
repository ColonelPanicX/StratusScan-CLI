#!/usr/bin/env python3
"""
Tests for network_manager_export.py.

Covers:
- collect_global_networks() per-item guarding and account-scope failure
  propagation
- main()'s failed-scope tracking, always-written Summary sheet, and
  exit-code behavior

Network Manager is a global, account-scope service (not multi-region), so
collect_global_networks() is the account-scope PRIMARY collector -- mirrors
the scripts/shield_export.py account-scope pattern (see
scripts/lambda_export.py for the finalize shape). This script is a Tier-3
PARTIAL case: it already builds an always-written Summary sheet, so the fix
adds failed-scope tracking + a *-FAILED-*.txt marker + non-zero exit on top
of that, without breaking the "a workbook always lands" guarantee.

moto's ``networkmanager`` backend supports ``create_global_network`` /
``describe_global_networks`` (including the paginator), which is enough to
exercise the PRIMARY scope realistically. Per-global-network enrichment
(get_sites / get_links / get_devices / get_connections /
get_transit_gateway_registrations / get_customer_gateway_associations) is
NOT exercised against moto here -- moto's support for those calls is thin
and the enrichment collectors are unaffected by this fix (they keep their
own ``aws_error_handler`` decorators and degrade gracefully). The (c) main()
failure test never reaches enrichment because the PRIMARY scope raises
before any global network exists.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import network_manager_export  # noqa: E402
from network_manager_export import collect_global_networks  # noqa: E402

REGION = "us-west-2"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture(autouse=True)
def fixed_home_region(monkeypatch):
    """collect_global_networks() reads the module-level home_region."""
    monkeypatch.setattr(network_manager_export, "home_region", REGION)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 silent-collection-failure audit,
    applied to Network Manager: collect_global_networks() -- the PRIMARY,
    global/account-scope collector -- used to swallow a real API error into
    an empty list (and separately had a hard ``network['GlobalNetworkId']``
    subscript in the per-global-network enrichment loop), indistinguishable
    from an account with no global networks configured. main() also had no
    way to signal that failure downstream despite always writing a Summary
    sheet. These tests cover: (a) a malformed global network is skipped, not
    fatal; (b) collect_global_networks() raises rather than swallowing a
    real API error; (c) that failure surfaces through main() as a non-zero
    exit plus a utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard --------------------------------------------

    @mock_aws
    def test_malformed_global_network_is_skipped_not_fatal(self, monkeypatch):
        """One global network that fails to process must not discard the others."""
        client = boto3.client("networkmanager", region_name=REGION)
        good_id = client.create_global_network(Description="good-network")[
            "GlobalNetwork"
        ]["GlobalNetworkId"]
        bad_id = client.create_global_network(Description="bad-network")[
            "GlobalNetwork"
        ]["GlobalNetworkId"]

        original = network_manager_export._build_global_network_row

        def raise_for_bad(network):
            if network.get("GlobalNetworkId") == bad_id:
                raise KeyError("SomeUnexpectedField")
            return original(network)

        monkeypatch.setattr(network_manager_export, "_build_global_network_row", raise_for_bad)

        rows = collect_global_networks()

        ids = {row["GlobalNetworkId"] for row in rows}
        assert good_id in ids, "healthy global network was lost when a sibling failed"
        assert bad_id not in ids, "malformed global network should have been skipped"

    # -- (b) Account-scope failure propagation --------------------------

    def test_collect_global_networks_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Network Manager API error during collection must propagate,
        not collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Something broke"}},
                "DescribeGlobalNetworks",
            )

        monkeypatch.setattr(network_manager_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_global_networks()

    # -- (c) main(): failure surfaced, non-zero exit, marker written ----

    def test_main_failure_exits_nonzero_and_reports_despite_summary_sheet(self, monkeypatch, tmp_path):
        """
        A global_networks-scope failure must exit non-zero and call
        utils.report_collection_failures -- even though this script always
        builds a non-empty Summary sheet and would otherwise write a
        complete-looking workbook (the Tier-3 PARTIAL failure mode).
        """
        monkeypatch.setattr(network_manager_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(
            network_manager_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(network_manager_export.utils, "mask_account_id", lambda *a, **kw: "1234****9012")
        monkeypatch.setattr(network_manager_export.utils, "prompt_region_selection", lambda *a, **kw: [REGION])
        monkeypatch.setattr(network_manager_export.utils, "prompt_confirmation", lambda *a, **kw: "confirm")

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Something broke"}},
                "DescribeGlobalNetworks",
            )

        monkeypatch.setattr(network_manager_export, "collect_global_networks", boom)

        monkeypatch.setattr(network_manager_export.utils, "create_export_filename", lambda *a, **kw: "fake.xlsx")
        monkeypatch.setattr(
            network_manager_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda *a, **kw: str(tmp_path / "fake.xlsx"),
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(network_manager_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            network_manager_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "network-manager"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "global_networks"

    # -- (d) Genuinely empty: graceful, no marker ------------------------

    @mock_aws
    def test_main_genuinely_empty_completes_no_marker(self, monkeypatch, tmp_path):
        """
        An account with zero global networks (primary scope succeeds, just
        returns nothing) must complete without raising and never call
        utils.report_collection_failures -- a real Summary-only workbook is
        not a failure. main() has no explicit ``sys.exit(0)`` on the success
        path (unlike the failure path), so success here means "returns
        normally," not "raises SystemExit(0)".
        """
        monkeypatch.setattr(network_manager_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(
            network_manager_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(network_manager_export.utils, "mask_account_id", lambda *a, **kw: "1234****9012")
        monkeypatch.setattr(network_manager_export.utils, "prompt_region_selection", lambda *a, **kw: [REGION])
        monkeypatch.setattr(network_manager_export.utils, "prompt_confirmation", lambda *a, **kw: "confirm")

        monkeypatch.setattr(network_manager_export.utils, "create_export_filename", lambda *a, **kw: "fake.xlsx")
        monkeypatch.setattr(
            network_manager_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda *a, **kw: str(tmp_path / "fake.xlsx"),
        )

        report_called = []
        monkeypatch.setattr(
            network_manager_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        # No sys.exit(0) on the success path -- main() should simply return.
        network_manager_export.main()

        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
