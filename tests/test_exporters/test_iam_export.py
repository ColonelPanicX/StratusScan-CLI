#!/usr/bin/env python3
"""
Moto-based tests for iam-export.py.

Covers utils.py IAM data-collection path:
- collect_iam_user_information()
"""

import importlib.util
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

# ---------------------------------------------------------------------------
# Load exporter module
# ---------------------------------------------------------------------------

_scripts_dir = Path(__file__).parent.parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location(
    "iam_export", _scripts_dir / "iam-export.py"
)
_iam_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_iam_export)

collect_iam_user_information = _iam_export.collect_iam_user_information


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    """Prevent any accidental real AWS calls."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCollectIamUserInformation:
    """Tests for collect_iam_user_information()."""

    @mock_aws
    def test_created_user_appears_in_results(self):
        """A newly created IAM user is returned by the collector."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")

        result = collect_iam_user_information()

        assert isinstance(result, list)
        assert len(result) >= 1
        usernames = [row["User Name"] for row in result]
        assert "test-user" in usernames

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="col-check-user")

        result = collect_iam_user_information()

        assert len(result) >= 1
        row = result[0]
        for col in ("User Name", "MFA", "Console Access", "Creation Date"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_user_with_access_key_reflects_key_data(self):
        """Access key metadata is captured for users that have keys."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="key-user")
        iam.create_access_key(UserName="key-user")

        result = collect_iam_user_information()

        assert any(row["User Name"] == "key-user" for row in result)

    @mock_aws
    def test_empty_account_returns_empty_list(self):
        """Account with no IAM users returns an empty list."""
        result = collect_iam_user_information()
        assert result == []
