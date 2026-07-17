#!/usr/bin/env python3
"""
Moto-based tests for codedeploy_export.py.

Focus: the silent-collection-failure contract (Tier-2e). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import codedeploy_export  # noqa: E402
from codedeploy_export import _scan_applications_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_application(client, name):
    """Create a CodeDeploy application named ``name``."""
    client.create_application(applicationName=name, computePlatform="Server")


class TestScanApplicationsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_applications(self):
        client = boto3.client("codedeploy", region_name=REGION)
        _create_application(client, "web-app")

        rows = _scan_applications_region(REGION)

        names = {row["Application Name"] for row in rows}
        assert "web-app" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("codedeploy", region_name=REGION)  # region exists, no apps

        rows = _scan_applications_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One application that fails to process must not discard the whole region."""
        client = boto3.client("codedeploy", region_name=REGION)
        _create_application(client, "good-app")
        _create_application(client, "bad-app")

        original = codedeploy_export._build_application_row

        def raise_for_bad(app, region):
            if app.get("applicationName") == "bad-app":
                raise KeyError("SomeUnexpectedField")
            return original(app, region)

        monkeypatch.setattr(codedeploy_export, "_build_application_row", raise_for_bad)

        rows = _scan_applications_region(REGION)

        names = {row["Application Name"] for row in rows}
        assert "good-app" in names, "healthy application was lost when a sibling failed"
        assert "bad-app" not in names, "malformed application should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListApplications",
            )

        monkeypatch.setattr(codedeploy_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_applications_region(REGION)

    @mock_aws
    def test_collect_applications_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListApplications",
            )

        monkeypatch.setattr(codedeploy_export, "_scan_applications_region", boom)

        applications, failed_regions = codedeploy_export.collect_applications([REGION])

        assert applications == []
        assert [r for r, _ in failed_regions] == [REGION]
