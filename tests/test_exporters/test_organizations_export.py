#!/usr/bin/env python3
"""
Tests for organizations_export.py.

Covers:
- get_organization_info() as a graceful availability probe
- collect_organizational_units() / collect_accounts() / collect_policies()
  per-item guarding and account-scope failure propagation
- main()'s failed-scope tracking, finalize, and exit-code behavior

AWS Organizations is a global, account-scope service run from the
management account (no region scan) -- collect_organizational_units(),
collect_accounts(), and collect_policies() are the PRIMARY account-scope
collectors -- mirrors the scripts/shield_export.py account-scope pattern
(see scripts/lambda_export.py for the finalize shape). moto's Organizations
support is partial (create_organization exists but does not model
policies/targets/tags realistically for this script's flows), so these
tests drive the module through monkeypatched boto3 clients / module
functions rather than real moto-backed Organizations state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import organizations_export  # noqa: E402
from organizations_export import (  # noqa: E402
    collect_accounts,
    collect_organizational_units,
    collect_policies,
    get_organization_info,
)

REGION = "us-east-1"

POLICY_TYPES = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
    "AISERVICES_OPT_OUT_POLICY",
]


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
    monkeypatch.setattr(organizations_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_org_client(roots=None, ou_pages=None, account_pages=None, policy_pages_by_type=None):
    """Build a MagicMock standing in for a boto3 Organizations client."""
    client = MagicMock()

    root_entries = (
        roots
        if roots is not None
        else [
            {
                "Id": "r-root",
                "Name": "Root",
                "Arn": "arn:aws:organizations::123456789012:root/o-abc/r-root",
                "PolicyTypes": [],
            }
        ]
    )
    client.list_roots.return_value = {"Roots": root_entries}
    root_id = root_entries[0]["Id"] if root_entries else None

    # Only the top-level (root) call returns the configured OU page(s) --
    # every recursive call for a child OU's own children returns empty, so
    # a fixture OU never appears as a child of itself (infinite recursion).
    ou_paginator = MagicMock()

    def paginate_ous(ParentId=None, **kwargs):  # noqa: N803
        if ou_pages is not None and ParentId == root_id:
            return ou_pages
        return [{"OrganizationalUnits": []}]

    ou_paginator.paginate.side_effect = paginate_ous

    accounts_paginator = MagicMock()
    accounts_paginator.paginate.return_value = (
        account_pages if account_pages is not None else [{"Accounts": []}]
    )

    pages_by_type = policy_pages_by_type or {}

    policies_paginator = MagicMock()

    def paginate_policies(Filter=None, **kwargs):  # noqa: N803
        return pages_by_type.get(Filter, [{"Policies": []}])

    policies_paginator.paginate.side_effect = paginate_policies

    targets_paginator = MagicMock()
    targets_paginator.paginate.return_value = [{"Targets": []}]

    paginators = {
        "list_organizational_units_for_parent": ou_paginator,
        "list_accounts": accounts_paginator,
        "list_policies": policies_paginator,
        "list_targets_for_policy": targets_paginator,
    }

    client.get_paginator.side_effect = lambda op_name: paginators.get(op_name, MagicMock())

    # Sensible defaults for per-field enrichment helpers (get_account_parent,
    # get_account_tags, _build_ou_row's parent-name lookup, _build_policy_row).
    client.list_parents.return_value = {"Parents": []}
    client.list_tags_for_resource.return_value = {"Tags": []}
    client.describe_organizational_unit.return_value = {"OrganizationalUnit": {"Name": "Unknown"}}
    client.describe_policy.return_value = {
        "Policy": {
            "PolicySummary": {"Description": "N/A", "AwsManaged": False, "Arn": "arn:policy"},
            "Content": "{}",
        }
    }

    return client


class TestGetOrganizationInfo:
    """
    get_organization_info() is a graceful availability probe:
    AWSOrganizationsNotInUseException / AccessDeniedException are
    legitimate, expected states and return None rather than raising.
    """

    def test_org_not_in_use_returns_none(self, monkeypatch):
        client = MagicMock()
        client.describe_organization.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "not in use"}},
            "DescribeOrganization",
        )
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        assert get_organization_info() is None

    def test_active_organization_returns_dict(self, monkeypatch):
        client = MagicMock()
        client.describe_organization.return_value = {
            "Organization": {"Id": "o-abc123", "MasterAccountId": "123456789012"}
        }
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        result = get_organization_info()

        assert result == {"Id": "o-abc123", "MasterAccountId": "123456789012"}


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to Organizations: collect_organizational_units(),
    collect_accounts(), and collect_policies() -- the PRIMARY, global/
    account-scope collectors -- used to swallow real API errors into empty
    lists, indistinguishable from an organization with no OUs/accounts/
    policies. main() also used to have no way to signal that failure
    downstream. These tests cover: (a) a malformed account/OU is skipped,
    not fatal; (b) a primary collector raises rather than swallowing a real
    API error; (c) that failure surfaces through main() as a non-zero exit
    plus a utils.report_collection_failures() call; (d) a genuine
    "Organizations not in use" state is a graceful exit 0 with no failure
    marker.
    """

    # -- (a) Per-item guards -------------------------------------------------

    def test_malformed_account_is_skipped_not_fatal(self, monkeypatch):
        """One account that fails to process must not discard the others."""
        good = {
            "Id": "111111111111",
            "Name": "good-account",
            "Email": "good@example.com",
            "Status": "ACTIVE",
        }
        bad = {
            "Id": "222222222222",
            "Name": "bad-account",
            "Email": "bad@example.com",
            "Status": "ACTIVE",
        }

        client = _fake_org_client(account_pages=[{"Accounts": [good, bad]}])
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = organizations_export._build_account_row

        def raise_for_bad(org_client, account, processed, total):
            if account.get("Id") == "222222222222":
                raise KeyError("SomeUnexpectedField")
            return original(org_client, account, processed, total)

        monkeypatch.setattr(organizations_export, "_build_account_row", raise_for_bad)

        result = collect_accounts()

        ids = {row["Account ID"] for row in result}
        assert "111111111111" in ids, "healthy account was lost when a sibling failed"
        assert "222222222222" not in ids, "malformed account should have been skipped"

    def test_malformed_ou_is_skipped_not_fatal(self, monkeypatch):
        """One OU that fails to process must not discard its siblings."""
        good_ou = {
            "Id": "ou-good",
            "Name": "good-ou",
            "Arn": "arn:aws:organizations::123456789012:ou/o-abc/ou-good",
        }
        bad_ou = {
            "Id": "ou-bad",
            "Name": "bad-ou",
            "Arn": "arn:aws:organizations::123456789012:ou/o-abc/ou-bad",
        }

        client = _fake_org_client(ou_pages=[{"OrganizationalUnits": [good_ou, bad_ou]}])
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = organizations_export._build_ou_row

        def raise_for_bad(org_client, ou, parent_id, parent_path, level):
            if ou.get("Id") == "ou-bad":
                raise KeyError("SomeUnexpectedField")
            return original(org_client, ou, parent_id, parent_path, level)

        monkeypatch.setattr(organizations_export, "_build_ou_row", raise_for_bad)

        result = collect_organizational_units()

        ids = {row["OU ID"] for row in result}
        assert "ou-good" in ids, "healthy OU was lost when a sibling failed"
        assert "ou-bad" not in ids, "malformed OU should have been skipped"

    # -- (b) Account-scope failure propagation --------------------------------

    def test_collect_organizational_units_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Organizations API error while listing the root must
        propagate, not collapse to an empty list."""
        client = MagicMock()
        client.list_roots.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
            "ListRoots",
        )
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_organizational_units()

    def test_collect_accounts_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Organizations API error during list_accounts must
        propagate, not collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListAccounts",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_accounts()

    def test_collect_policies_raises_on_generic_api_error_not_swallowed(self, monkeypatch):
        """A real (non-PolicyTypeNotEnabledException) Organizations API
        error during list_policies must propagate, not collapse to an
        empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListPolicies",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_policies()

    def test_collect_policies_skips_not_enabled_policy_type_gracefully(self, monkeypatch):
        """PolicyTypeNotEnabledException for a single policy type is a
        legitimate, expected condition and must not abort collection of the
        remaining policy types."""
        scp_policy = {"Id": "p-scp1", "Name": "scp-1"}

        def paginate_policies(Filter=None, **kwargs):  # noqa: N803
            if Filter == "TAG_POLICY":
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "PolicyTypeNotEnabledException", "Message": "not enabled"}},
                    "ListPolicies",
                )
            if Filter == "SERVICE_CONTROL_POLICY":
                return [{"Policies": [scp_policy]}]
            return [{"Policies": []}]

        client = _fake_org_client()
        # Override the default dispatcher's policies paginator with one that
        # also raises for TAG_POLICY.
        policies_paginator = MagicMock()
        policies_paginator.paginate.side_effect = paginate_policies
        original_get_paginator = client.get_paginator.side_effect

        def get_paginator(op_name):
            if op_name == "list_policies":
                return policies_paginator
            return original_get_paginator(op_name)

        client.get_paginator.side_effect = get_paginator
        monkeypatch.setattr(organizations_export.utils, "get_boto3_client", lambda *a, **kw: client)

        result = collect_policies()

        ids = {row["Policy ID"] for row in result}
        assert "p-scp1" in ids, "SCP collection should still succeed despite TAG_POLICY being disabled"

    # -- (c) main(): failure surfaced, non-zero exit ---------------------------

    def test_main_ou_collection_failure_exits_nonzero_and_reports(self, monkeypatch):
        """An organizational-units API failure in main() must exit non-zero
        and call utils.report_collection_failures -- never silently
        collapse into an empty export."""
        monkeypatch.setattr(organizations_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(organizations_export.utils, "setup_logging", lambda *a, **kw: None)
        monkeypatch.setattr(
            organizations_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        monkeypatch.setattr(
            organizations_export.utils, "get_boto3_client", lambda service, *a, **kw: sts_client
        )

        monkeypatch.setattr(
            organizations_export,
            "get_organization_info",
            lambda: {"Id": "o-abc123", "MasterAccountId": "123456789012"},
        )

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalErrorException", "Message": "Something broke"}},
                "ListOrganizationalUnitsForParent",
            )

        monkeypatch.setattr(organizations_export, "collect_organizational_units", boom)
        monkeypatch.setattr(organizations_export, "collect_accounts", lambda: [])
        monkeypatch.setattr(organizations_export, "collect_policies", lambda: [])

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(organizations_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            organizations_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "organizations"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "organizational_units"

    # -- (d) Organizations not in use: graceful skip, no marker ---------------

    def test_org_not_in_use_returns_gracefully_no_marker(self, monkeypatch):
        """AWS Organizations not being in use (or this account not being
        the management account) is a legitimate, expected state -- exit 0,
        and utils.report_collection_failures is never called (no
        *-FAILED-*.txt marker is written)."""
        monkeypatch.setattr(organizations_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(organizations_export.utils, "setup_logging", lambda *a, **kw: None)
        monkeypatch.setattr(
            organizations_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        monkeypatch.setattr(
            organizations_export.utils, "get_boto3_client", lambda service, *a, **kw: sts_client
        )

        monkeypatch.setattr(organizations_export, "get_organization_info", lambda: None)

        report_called = []
        monkeypatch.setattr(
            organizations_export.utils,
            "report_collection_failures",
            lambda *a, **kw: report_called.append((a, kw)),
        )

        result = organizations_export.main()

        assert result is None
        assert report_called == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
