#!/usr/bin/env python3
"""
Moto-based tests for iam_export.py.

Covers:
- collect_iam_user_information()
"""

import sys
from pathlib import Path

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import iam_export  # noqa: E402
from iam_export import (  # noqa: E402
    collect_iam_role_information,
    collect_iam_user_information,
    collect_inline_policies,
    collect_managed_policies,
)

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestCollectIamUserInformation:
    """Tests for collect_iam_user_information()."""

    @mock_aws
    def test_created_user_appears_in_results(self):
        """A newly created IAM user is returned by the collector."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="test-user")

        result = collect_iam_user_information()

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["User Name"] == "test-user" for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="col-check-user")

        result = collect_iam_user_information()

        assert len(result) >= 1
        row = result[0]
        for col in ("User Name", "MFA", "Console Access", "Creation Date"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_user_with_access_key_reflects_key_data(self):
        """Access key metadata is captured for users that have keys."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="key-user")
        iam.create_access_key(UserName="key-user")

        result = collect_iam_user_information()

        assert any(row["User Name"] == "key-user" for row in result)

    @mock_aws
    def test_empty_account_returns_empty_list(self):
        """Account with no IAM users returns an empty list."""
        result = collect_iam_user_information()
        assert result == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits: IAM's account-scope collectors used to swallow a collection error
    into an empty list, indistinguishable from a genuinely empty account. IAM
    is global/account-scope (not multi-region), so each top-level collector
    (users, roles, managed policies, inline policies) is verified separately:
    a malformed item must be skipped without sinking the whole collection,
    and an account-scope API failure must raise rather than return [].
    See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    # -- Users ---------------------------------------------------------

    @mock_aws
    def test_malformed_user_is_skipped_not_fatal(self, monkeypatch):
        """One user that fails to process must not discard the others."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="good-user")
        iam.create_user(UserName="bad-user")

        original = iam_export._build_user_row

        def raise_for_bad(iam_client, user):
            if user.get("UserName") == "bad-user":
                raise KeyError("SomeUnexpectedField")
            return original(iam_client, user)

        monkeypatch.setattr(iam_export, "_build_user_row", raise_for_bad)

        result = collect_iam_user_information()

        names = {row["User Name"] for row in result}
        assert "good-user" in names, "healthy user was lost when a sibling failed"
        assert "bad-user" not in names, "malformed user should have been skipped"

    @mock_aws
    def test_users_account_scope_failure_raises_not_empty(self, monkeypatch):
        """An account-scope API failure must propagate, not collapse to []."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListUsers",
            )

        monkeypatch.setattr(iam_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_iam_user_information()

    # -- Roles -----------------------------------------------------------

    @mock_aws
    def test_malformed_role_is_skipped_not_fatal(self, monkeypatch):
        """One role that fails to process must not discard the others."""
        iam = boto3.client("iam", region_name=REGION)
        trust_policy = (
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
            '"Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
        )
        iam.create_role(RoleName="good-role", AssumeRolePolicyDocument=trust_policy)
        iam.create_role(RoleName="bad-role", AssumeRolePolicyDocument=trust_policy)

        original = iam_export._build_role_row

        def raise_for_bad(iam_client, role):
            if role.get("RoleName") == "bad-role":
                raise KeyError("SomeUnexpectedField")
            return original(iam_client, role)

        monkeypatch.setattr(iam_export, "_build_role_row", raise_for_bad)

        result = collect_iam_role_information()

        names = {row["Role Name"] for row in result}
        assert "good-role" in names, "healthy role was lost when a sibling failed"
        assert "bad-role" not in names, "malformed role should have been skipped"

    @mock_aws
    def test_roles_account_scope_failure_raises_not_empty(self, monkeypatch):
        """An account-scope API failure must propagate, not collapse to []."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListRoles",
            )

        monkeypatch.setattr(iam_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_iam_role_information()

    # -- Managed policies --------------------------------------------------

    @mock_aws
    def test_malformed_managed_policy_is_skipped_not_fatal(self, monkeypatch):
        """One policy that fails to process must not discard the others."""
        iam = boto3.client("iam", region_name=REGION)
        policy_doc = (
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
            '"Action": "s3:GetObject", "Resource": "*"}]}'
        )
        iam.create_policy(PolicyName="good-policy", PolicyDocument=policy_doc)
        iam.create_policy(PolicyName="bad-policy", PolicyDocument=policy_doc)

        original = iam_export.process_managed_policy

        def raise_for_bad(iam_client, policy, policy_type):
            if policy.get("PolicyName") == "bad-policy":
                raise KeyError("SomeUnexpectedField")
            return original(iam_client, policy, policy_type)

        monkeypatch.setattr(iam_export, "process_managed_policy", raise_for_bad)

        iam_client = boto3.client("iam", region_name=REGION)
        result = collect_managed_policies(iam_client)

        names = {row["Policy Name"] for row in result}
        assert "good-policy" in names, "healthy policy was lost when a sibling failed"
        assert "bad-policy" not in names, "malformed policy should have been skipped"

    @mock_aws
    def test_managed_policies_account_scope_failure_raises_not_empty(self, monkeypatch):
        """An account-scope API failure must propagate, not collapse to []."""
        iam_client = boto3.client("iam", region_name=REGION)

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListPolicies",
            )

        monkeypatch.setattr(iam_client, "get_paginator", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_managed_policies(iam_client)

    # -- Inline policies -----------------------------------------------------

    @mock_aws
    def test_inline_policies_account_scope_failure_raises_not_empty(self, monkeypatch):
        """An account-scope API failure must propagate, not collapse to []."""
        iam_client = boto3.client("iam", region_name=REGION)

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListUsers",
            )

        monkeypatch.setattr(iam_client, "get_paginator", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_inline_policies(iam_client)
