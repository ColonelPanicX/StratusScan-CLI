#!/usr/bin/env python3
"""
Tests for iam_identity_providers_export.py.

Covers:
- collect_saml_providers() / collect_oidc_providers() per-item guarding and
  account-scope failure propagation
- main()'s failed-scope tracking, finalize, and exit-code behavior

IAM identity providers are a global/account-scope resource (not
multi-region), so both collect_saml_providers() and collect_oidc_providers()
are PRIMARY account-scope collectors -- mirrors the scripts/shield_export.py
account-scope pattern (see scripts/lambda_export.py for the finalize shape).
moto supports create_saml_provider/list_saml_providers and
create_open_id_connect_provider/list_open_id_connect_providers, so the
per-item ("malformed provider") tests build real providers via @mock_aws and
monkeypatch the extracted _build_*_row() helper to simulate the one bad item
(moto cannot itself produce a malformed API response). The API-error tests
monkeypatch the boto3 client directly, since moto has no way to force a
ListSAMLProviders/ListOpenIDConnectProviders failure.

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
import iam_identity_providers_export  # noqa: E402
from iam_identity_providers_export import (  # noqa: E402
    collect_oidc_providers,
    collect_saml_providers,
)

REGION = "us-east-1"
SAML_METADATA = '<xml>entityID="https://example.com/saml"</xml>' + ("x" * 1000)


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
    monkeypatch.setattr(iam_identity_providers_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to IAM identity providers: collect_saml_providers() and
    collect_oidc_providers() -- the two PRIMARY, global/account-scope
    collectors -- used to swallow a real API error into an empty list,
    indistinguishable from an account with no providers configured. main()
    also used to have no way to signal that failure downstream. These tests
    cover: (a) a malformed provider is skipped, not fatal, for both scopes;
    (b) both collectors raise rather than swallowing a real API error; (c) a
    primary-scope failure surfaces through main() as a non-zero exit plus a
    utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard --------------------------------------------------

    @mock_aws
    def test_malformed_saml_provider_is_skipped_not_fatal(self, monkeypatch):
        """One SAML provider that fails to process must not discard the others."""
        iam = boto3.client("iam", region_name=REGION)
        good = iam.create_saml_provider(Name="good-saml", SAMLMetadataDocument=SAML_METADATA)
        bad = iam.create_saml_provider(Name="bad-saml", SAMLMetadataDocument=SAML_METADATA)

        original = iam_identity_providers_export._build_saml_row

        def raise_for_bad(client_arg, provider):
            if provider.get("Arn") == bad["SAMLProviderArn"]:
                raise KeyError("SomeUnexpectedField")
            return original(client_arg, provider)

        monkeypatch.setattr(iam_identity_providers_export, "_build_saml_row", raise_for_bad)

        result = collect_saml_providers()

        arns = {row["ARN"] for row in result}
        assert good["SAMLProviderArn"] in arns, "healthy SAML provider was lost when a sibling failed"
        assert bad["SAMLProviderArn"] not in arns, "malformed SAML provider should have been skipped"

    @mock_aws
    def test_malformed_oidc_provider_is_skipped_not_fatal(self, monkeypatch):
        """One OIDC provider that fails to process must not discard the others."""
        iam = boto3.client("iam", region_name=REGION)
        good = iam.create_open_id_connect_provider(
            Url="https://good.example.com/oidc",
            ClientIDList=["sts.amazonaws.com"],
            ThumbprintList=["a" * 40],
        )
        bad = iam.create_open_id_connect_provider(
            Url="https://bad.example.com/oidc",
            ClientIDList=["sts.amazonaws.com"],
            ThumbprintList=["b" * 40],
        )

        original = iam_identity_providers_export._build_oidc_row

        def raise_for_bad(client_arg, provider):
            if provider.get("Arn") == bad["OpenIDConnectProviderArn"]:
                raise KeyError("SomeUnexpectedField")
            return original(client_arg, provider)

        monkeypatch.setattr(iam_identity_providers_export, "_build_oidc_row", raise_for_bad)

        result = collect_oidc_providers()

        arns = {row["ARN"] for row in result}
        assert good["OpenIDConnectProviderArn"] in arns, "healthy OIDC provider was lost when a sibling failed"
        assert bad["OpenIDConnectProviderArn"] not in arns, "malformed OIDC provider should have been skipped"

    # -- (b) Account-scope failure propagation -------------------------------

    def test_collect_saml_providers_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real ListSAMLProviders error must propagate, not collapse to an
        empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ServiceFailureException", "Message": "Something broke"}},
                "ListSAMLProviders",
            )

        client = MagicMock()
        client.list_saml_providers.side_effect = boom
        monkeypatch.setattr(
            iam_identity_providers_export.utils, "get_boto3_client", lambda *a, **kw: client
        )

        with pytest.raises(botocore.exceptions.ClientError):
            collect_saml_providers()

    def test_collect_oidc_providers_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real ListOpenIDConnectProviders error must propagate, not
        collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ServiceFailureException", "Message": "Something broke"}},
                "ListOpenIDConnectProviders",
            )

        client = MagicMock()
        client.list_open_id_connect_providers.side_effect = boom
        monkeypatch.setattr(
            iam_identity_providers_export.utils, "get_boto3_client", lambda *a, **kw: client
        )

        with pytest.raises(botocore.exceptions.ClientError):
            collect_oidc_providers()

    # -- (c) main(): failure surfaced, non-zero exit -------------------------

    def test_main_saml_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A SAML providers API failure in main() must exit non-zero and
        call utils.report_collection_failures -- never silently collapse
        into an empty export."""
        monkeypatch.setattr(
            iam_identity_providers_export.utils, "ensure_dependencies", lambda *a, **kw: True
        )
        # setup_logging()/log_script_start() are left un-patched (run for
        # real, writing to the redirected tmp_path output dir) because
        # utils.save_multiple_dataframes_to_excel() logs via the raw module
        # -level ``logger`` global, not get_logger() -- a no-op'd
        # setup_logging() leaves that global None and crashes the export.
        monkeypatch.setattr(
            iam_identity_providers_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ServiceFailureException", "Message": "Something broke"}},
                "ListSAMLProviders",
            )

        monkeypatch.setattr(iam_identity_providers_export, "collect_saml_providers", boom)
        monkeypatch.setattr(iam_identity_providers_export, "collect_oidc_providers", lambda: [])
        monkeypatch.setattr(
            iam_identity_providers_export, "collect_roles_using_providers", lambda *a, **kw: []
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(
            iam_identity_providers_export.utils, "report_collection_failures", fake_report
        )

        with pytest.raises(SystemExit) as exc_info:
            iam_identity_providers_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "iam-identity-providers"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "saml_providers"

    def test_main_oidc_failure_exits_nonzero_and_reports(self, monkeypatch):
        """An OIDC providers API failure in main() must exit non-zero and
        call utils.report_collection_failures -- never silently collapse
        into an empty export."""
        monkeypatch.setattr(
            iam_identity_providers_export.utils, "ensure_dependencies", lambda *a, **kw: True
        )
        # setup_logging()/log_script_start() are left un-patched (run for
        # real, writing to the redirected tmp_path output dir) because
        # utils.save_multiple_dataframes_to_excel() logs via the raw module
        # -level ``logger`` global, not get_logger() -- a no-op'd
        # setup_logging() leaves that global None and crashes the export.
        monkeypatch.setattr(
            iam_identity_providers_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )

        monkeypatch.setattr(iam_identity_providers_export, "collect_saml_providers", lambda: [])

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ServiceFailureException", "Message": "Something broke"}},
                "ListOpenIDConnectProviders",
            )

        monkeypatch.setattr(iam_identity_providers_export, "collect_oidc_providers", boom)
        monkeypatch.setattr(
            iam_identity_providers_export, "collect_roles_using_providers", lambda *a, **kw: []
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(
            iam_identity_providers_export.utils, "report_collection_failures", fake_report
        )

        with pytest.raises(SystemExit) as exc_info:
            iam_identity_providers_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "iam-identity-providers"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "oidc_providers"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
