#!/usr/bin/env python3
"""
Moto-based tests for iam_identity_center_export.py.

Covers:
- get_identity_center_instance() — "not enabled" vs "API failure" distinction
- collect_identity_center_users() — account-scope collection
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import iam_identity_center_export  # noqa: E402
from iam_identity_center_export import (  # noqa: E402
    collect_identity_center_users,
    get_identity_center_instance,
)

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestGetIdentityCenterInstance:
    """Tests for get_identity_center_instance()."""

    @mock_aws
    def test_instance_is_discovered(self):
        """The moto-provisioned default Identity Center instance is returned."""
        instance_arn, identity_store_id = get_identity_center_instance()
        assert instance_arn is not None
        assert identity_store_id is not None
        assert instance_arn.startswith("arn:")


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the account-scope silent-collection-failure fix
    (07.15.2026 audit / 07.16.2026 blast-radius sweep). IAM Identity Center is
    account-scope (not multi-region): a collection error must raise so the
    caller can record a FAILED scope, and IAM Identity Center being genuinely
    "not enabled" in an account must never be conflated with an API failure.
    See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_user_is_skipped_not_fatal(self, monkeypatch):
        """
        One user record that fails to process must not discard the whole
        account's results — the healthy user is still collected.
        """
        instance_arn, identity_store_id = get_identity_center_instance()

        identitystore = boto3.client("identitystore", region_name=REGION)
        identitystore.create_user(
            IdentityStoreId=identity_store_id,
            UserName="good-user",
            DisplayName="Good User",
            Name={"GivenName": "Good", "FamilyName": "User"},
            Emails=[{"Value": "good-user@example.com", "Primary": True}],
        )
        identitystore.create_user(
            IdentityStoreId=identity_store_id,
            UserName="bad-user",
            DisplayName="Bad User",
            Name={"GivenName": "Bad", "FamilyName": "User"},
            Emails=[{"Value": "bad-user@example.com", "Primary": True}],
        )

        original = iam_identity_center_export._build_identity_center_user_row

        def raise_for_bad(identitystore_client, sso_admin_client, identity_store_id, instance_arn, user):
            if user.get("UserName") == "bad-user":
                raise KeyError("SomeMalformedField")
            return original(identitystore_client, sso_admin_client, identity_store_id, instance_arn, user)

        monkeypatch.setattr(
            iam_identity_center_export, "_build_identity_center_user_row", raise_for_bad
        )

        result = collect_identity_center_users(identity_store_id, instance_arn)

        names = {row["User Name"] for row in result}
        assert "good-user" in names, "healthy user was lost when a sibling failed"
        assert "bad-user" not in names, "malformed user should have been skipped"

    @mock_aws
    def test_collector_api_failure_raises_not_empty(self, monkeypatch):
        """
        An account-scope API failure must propagate (so the caller can record
        a FAILED scope) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListUsers",
            )

        monkeypatch.setattr(iam_identity_center_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_identity_center_users("d-fakestoreid", "arn:aws:sso:::instance/ssoins-fake")

    @mock_aws
    def test_no_instances_is_not_enabled_not_a_failure(self, monkeypatch):
        """
        A clean, valid API response with zero IAM Identity Center instances is
        a legitimate account state ("not enabled") and must return (None,
        None) WITHOUT raising — it must never be reported as a failed scope.
        """

        class _EmptyInstancesClient:
            def list_instances(self):
                return {"Instances": []}

        monkeypatch.setattr(
            iam_identity_center_export.utils,
            "get_boto3_client",
            lambda *args, **kwargs: _EmptyInstancesClient(),
        )

        instance_arn, identity_store_id = get_identity_center_instance()

        assert instance_arn is None
        assert identity_store_id is None

    @mock_aws
    def test_instance_discovery_api_failure_raises(self, monkeypatch):
        """
        An API failure during instance discovery (throttling, access denied,
        etc.) must propagate rather than being conflated with "not enabled".
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListInstances",
            )

        monkeypatch.setattr(iam_identity_center_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_identity_center_instance()
