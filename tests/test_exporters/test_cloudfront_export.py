#!/usr/bin/env python3
"""
Tests for cloudfront_export.py.

Covers:
- collect_cloudfront_distributions() per-item guarding and account-scope
  failure propagation
- export_cloudfront_data()'s failed-scope tracking and exit-code behavior

CloudFront is a global/account-scope service (not multi-region), so
collect_cloudfront_distributions() is the account-scope PRIMARY collector --
mirrors the scripts/shield_export.py account-scope pattern (see
scripts/lambda_export.py for the finalize shape). moto supports
cloudfront:create_distribution / list_distributions / get_distribution, so
these tests are moto-backed where possible.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cloudfront_export  # noqa: E402
from cloudfront_export import collect_cloudfront_distributions  # noqa: E402

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
    monkeypatch.setattr(cloudfront_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _distribution_config(caller_reference: str, comment: str = "test dist") -> dict:
    """Minimal DistributionConfig accepted by moto's create_distribution."""
    return {
        "CallerReference": caller_reference,
        "Comment": comment,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "example-bucket.s3.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {
                "QueryString": False,
                "Cookies": {"Forward": "none"},
            },
            "MinTTL": 0,
        },
    }


def _create_distribution(client, caller_reference: str, comment: str = "test dist") -> str:
    """Create a CloudFront distribution via moto and return its Id."""
    response = client.create_distribution(
        DistributionConfig=_distribution_config(caller_reference, comment)
    )
    return response["Distribution"]["Id"]


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to CloudFront: collect_cloudfront_distributions() -- the
    PRIMARY, global/account-scope collector -- used to be wrapped in
    ``@utils.aws_error_handler(default_return=[])``, swallowing a real API
    error into an empty list indistinguishable from an account with no
    distributions configured. export_cloudfront_data() also had no way to
    signal that failure downstream. These tests cover: (a) a malformed
    distribution is skipped, not fatal; (b)
    collect_cloudfront_distributions() raises rather than swallowing a real
    API error; (c) that failure surfaces through export_cloudfront_data() as
    a non-zero exit plus a utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard ------------------------------------------------

    @mock_aws
    def test_malformed_distribution_is_skipped_not_fatal(self, monkeypatch):
        """One distribution that fails to process must not discard the others."""
        client = boto3.client("cloudfront", region_name=REGION)
        good_id = _create_distribution(client, "good-ref", comment="good-distribution")
        bad_id = _create_distribution(client, "bad-ref", comment="bad-distribution")

        original = cloudfront_export._build_distribution_row

        def raise_for_bad(cf_client, dist_summary):
            if dist_summary.get("Id") == bad_id:
                raise KeyError("SomeUnexpectedField")
            return original(cf_client, dist_summary)

        monkeypatch.setattr(cloudfront_export, "_build_distribution_row", raise_for_bad)

        result = collect_cloudfront_distributions()

        ids = {row["Distribution ID"] for row in result}
        assert good_id in ids, "healthy distribution was lost when a sibling failed"
        assert bad_id not in ids, "malformed distribution should have been skipped"

    # -- (b) Account-scope failure propagation ------------------------------

    def test_collect_cloudfront_distributions_raises_on_api_error_not_swallowed(
        self, monkeypatch
    ):
        """A real CloudFront API error during collection must propagate, not
        collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalError", "Message": "Something broke"}},
                "ListDistributions",
            )

        client = type("FakeClient", (), {})()
        client.get_paginator = boom
        monkeypatch.setattr(cloudfront_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_cloudfront_distributions()

    # -- (c) export_cloudfront_data(): failure surfaced, non-zero exit ------

    def test_export_distributions_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A distributions API failure must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty export."""

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalError", "Message": "Something broke"}},
                "ListDistributions",
            )

        monkeypatch.setattr(cloudfront_export, "collect_cloudfront_distributions", boom)
        monkeypatch.setattr(cloudfront_export, "collect_origin_details", lambda: [])
        monkeypatch.setattr(cloudfront_export, "collect_cache_behaviors", lambda: [])

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(cloudfront_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            cloudfront_export.export_cloudfront_data("123456789012", "test-account")

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "cloudfront"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "distributions"

    # -- (d) Genuinely empty account: no failure marker ----------------------

    @mock_aws
    def test_genuinely_empty_account_no_failure_marker(self, monkeypatch):
        """An account with zero distributions (and a successful collection
        scope) must not be reported as a failure."""
        report_called = []
        monkeypatch.setattr(
            cloudfront_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        # export_cloudfront_data() only calls sys.exit() on failure; a clean
        # empty run returns normally.
        cloudfront_export.export_cloudfront_data("123456789012", "test-account")

        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
