#!/usr/bin/env python3
"""
Tests for route53_export.py.

Covers:
- _build_hosted_zone_row() per-item guarding
- collect_hosted_zones() -- the PRIMARY, global/account-scope collector --
  account-scope failure propagation
- export_route53_data()'s failed-scope tracking, finalize, and exit-code
  behavior

Route 53 hosted zones are a global/account-scope resource (not multi-region
-- see scripts/shield_export.py for the account-scope reference pattern;
scripts/lambda_export.py for the finalize shape). This mirrors
tests/test_exporters/test_shield_export.py.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import route53_export  # noqa: E402
from route53_export import collect_hosted_zones  # noqa: E402

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
    monkeypatch.setattr(route53_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to Route 53: collect_hosted_zones() -- the PRIMARY,
    global/account-scope collector -- used to swallow a real API error into
    an empty list (via ``@utils.aws_error_handler(default_return=[])``),
    indistinguishable from an account with no hosted zones. Route 53 is a
    Tier-3 PARTIAL case: a forced Summary sheet always lands a workbook, so
    the fix is failed-scope tracking + marker + non-zero exit layered on top
    of the existing always-written export. These tests cover: (a) a
    malformed hosted zone is skipped, not fatal; (b) collect_hosted_zones()
    raises rather than swallowing a real API error; (c) that failure
    surfaces through export_route53_data() as a non-zero exit plus a
    utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard --------------------------------------------

    @mock_aws
    def test_malformed_hosted_zone_is_skipped_not_fatal(self, monkeypatch):
        """One hosted zone whose detail lookup fails must not discard the
        others."""
        client = route53_export.utils.get_boto3_client("route53", region_name=REGION)
        good = client.create_hosted_zone(
            Name="good.example.com.",
            CallerReference="good-ref",
        )["HostedZone"]
        bad = client.create_hosted_zone(
            Name="bad.example.com.",
            CallerReference="bad-ref",
        )["HostedZone"]

        good_id = good["Id"].split("/")[-1]
        bad_id = bad["Id"].split("/")[-1]

        original = route53_export._build_hosted_zone_row

        def raise_for_bad(route53_client, zone):
            zone_id = zone.get("Id", "").split("/")[-1]
            if zone_id == bad_id:
                raise KeyError("SomeUnexpectedField")
            return original(route53_client, zone)

        monkeypatch.setattr(route53_export, "_build_hosted_zone_row", raise_for_bad)

        result = collect_hosted_zones()

        ids = {row["Zone ID"] for row in result}
        assert good_id in ids, "healthy hosted zone was lost when a sibling failed"
        assert bad_id not in ids, "malformed hosted zone should have been skipped"

    # -- (b) Account-scope failure propagation --------------------------

    def test_collect_hosted_zones_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Route 53 API error during collection must propagate, not
        collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalError", "Message": "Something broke"}},
                "ListHostedZones",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(route53_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_hosted_zones()

    # -- (c) export_route53_data(): failure surfaced, non-zero exit -----

    def test_export_hosted_zones_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A hosted-zones API failure must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty/summary-only export that looks complete."""

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalError", "Message": "Something broke"}},
                "ListHostedZones",
            )

        monkeypatch.setattr(route53_export, "collect_hosted_zones", boom)
        monkeypatch.setattr(route53_export, "collect_dns_records", lambda: [])
        monkeypatch.setattr(route53_export, "collect_health_checks", lambda: [])
        monkeypatch.setattr(route53_export, "collect_resolver_endpoints", lambda regions: [])
        monkeypatch.setattr(route53_export, "collect_resolver_rules", lambda regions: [])
        monkeypatch.setattr(route53_export, "collect_query_logging_configs", lambda: [])

        # Let the (forced) Summary sheet still get "written" without
        # touching real Excel I/O.
        monkeypatch.setattr(
            route53_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda data_frames, filename, **kw: str(Path("fake") / filename),
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(route53_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            route53_export.export_route53_data("123456789012", "test-account", [REGION])

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "route53"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "hosted_zones"

    # -- (d) Genuinely empty: no failure marker, exit path not taken ----

    def test_genuinely_empty_account_reports_no_failure(self, monkeypatch):
        """Every scope succeeding with zero resources is NOT a failure --
        utils.report_collection_failures must never be called and no
        SystemExit(1) should be raised."""
        monkeypatch.setattr(route53_export, "collect_hosted_zones", lambda: [])
        monkeypatch.setattr(route53_export, "collect_dns_records", lambda: [])
        monkeypatch.setattr(route53_export, "collect_health_checks", lambda: [])
        monkeypatch.setattr(route53_export, "collect_resolver_endpoints", lambda regions: [])
        monkeypatch.setattr(route53_export, "collect_resolver_rules", lambda regions: [])
        monkeypatch.setattr(route53_export, "collect_query_logging_configs", lambda: [])

        monkeypatch.setattr(
            route53_export.utils,
            "save_multiple_dataframes_to_excel",
            lambda data_frames, filename, **kw: str(Path("fake") / filename),
        )

        report_called = []
        monkeypatch.setattr(
            route53_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        # Should return normally -- no SystemExit.
        route53_export.export_route53_data("123456789012", "test-account", [REGION])

        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
