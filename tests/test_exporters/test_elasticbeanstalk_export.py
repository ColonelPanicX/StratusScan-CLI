#!/usr/bin/env python3
"""
Moto-based tests for elasticbeanstalk_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import elasticbeanstalk_export  # noqa: E402
from elasticbeanstalk_export import collect_applications_from_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_application(client, name):
    """Create an Elastic Beanstalk application named ``name``."""
    client.create_application(ApplicationName=name, Description=f"{name} description")


class TestCollectApplicationsFromRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_applications(self):
        client = boto3.client("elasticbeanstalk", region_name=REGION)
        _create_application(client, "web-app")

        rows = collect_applications_from_region(REGION)

        names = {row["Application Name"] for row in rows}
        assert "web-app" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("elasticbeanstalk", region_name=REGION)  # region exists, no apps

        rows = collect_applications_from_region(REGION)

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
        client = boto3.client("elasticbeanstalk", region_name=REGION)
        _create_application(client, "good-app")
        _create_application(client, "bad-app")

        original = elasticbeanstalk_export._build_application_row

        def raise_for_bad(app, region):
            if app.get("ApplicationName") == "bad-app":
                raise KeyError("SomeUnexpectedField")
            return original(app, region)

        monkeypatch.setattr(elasticbeanstalk_export, "_build_application_row", raise_for_bad)

        rows = collect_applications_from_region(REGION)

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
                "DescribeApplications",
            )

        monkeypatch.setattr(elasticbeanstalk_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_applications_from_region(REGION)

    @mock_aws
    def test_collect_applications_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        while still writing the always-on Summary sheet workbook.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeApplications",
            )

        monkeypatch.setattr(elasticbeanstalk_export, "collect_applications_from_region", boom)

        applications, failed_regions = elasticbeanstalk_export.collect_applications([REGION])

        assert applications == []
        assert [r for r, _ in failed_regions] == [REGION]
