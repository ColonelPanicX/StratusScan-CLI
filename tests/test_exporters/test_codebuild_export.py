#!/usr/bin/env python3
"""
Moto-based tests for codebuild_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's codebuild backend implements create_project / list_projects /
batch_get_projects, so the primary scope (_scan_projects_region /
collect_projects) is exercised with @mock_aws directly. It does not
implement list_report_groups (raises NotImplementedError) or
batch_get_builds, but those are enrichment scopes outside this file's
assigned surface (_scan_projects_region / collect_projects) and are not
touched by this fix.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import codebuild_export  # noqa: E402
from codebuild_export import _scan_projects_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_project(client, name):
    """Create a minimal CodeBuild project named ``name``."""
    client.create_project(
        name=name,
        source={"type": "GITHUB", "location": "https://github.com/example/repo.git"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole="arn:aws:iam::123456789012:role/service-role/codebuild-role",
    )


class TestScanProjectsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_projects(self):
        client = boto3.client("codebuild", region_name=REGION)
        _create_project(client, "web-project")

        rows = _scan_projects_region(REGION)

        names = {row["Project Name"] for row in rows}
        assert "web-project" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("codebuild", region_name=REGION)  # region exists, no projects

        rows = _scan_projects_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One CodeBuild project that fails to process must not discard the whole region."""
        client = boto3.client("codebuild", region_name=REGION)
        _create_project(client, "good-project")
        _create_project(client, "bad-project")

        original = codebuild_export._build_project_row

        def raise_for_bad(project, region):
            if project.get("name") == "bad-project":
                raise KeyError("SomeUnexpectedField")
            return original(project, region)

        monkeypatch.setattr(codebuild_export, "_build_project_row", raise_for_bad)

        rows = _scan_projects_region(REGION)

        names = {row["Project Name"] for row in rows}
        assert "good-project" in names, "healthy project was lost when a sibling failed"
        assert "bad-project" not in names, "malformed project should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListProjects",
            )

        monkeypatch.setattr(codebuild_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_projects_region(REGION)

    @mock_aws
    def test_collect_projects_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListProjects",
            )

        monkeypatch.setattr(codebuild_export, "_scan_projects_region", boom)

        projects, failed_regions = codebuild_export.collect_projects([REGION])

        assert projects == []
        assert [r for r, _ in failed_regions] == [REGION]
