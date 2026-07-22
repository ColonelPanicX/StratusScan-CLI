#!/usr/bin/env python3
"""
Moto-based tests for ecr_export.py.

Focus: the silent-collection-failure contract (Tier-2a). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ecr_export  # noqa: E402
from ecr_export import scan_ecr_repositories_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_repo(client, name):
    """Create an ECR repository named ``name``."""
    client.create_repository(repositoryName=name)


class TestScanEcrRepositoriesInRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_repositories(self):
        client = boto3.client("ecr", region_name=REGION)
        _create_repo(client, "web-repo")

        rows = scan_ecr_repositories_in_region(REGION)

        names = {row["Repository Name"] for row in rows}
        assert "web-repo" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ecr", region_name=REGION)  # region exists, no repos

        rows = scan_ecr_repositories_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One repository that fails to process must not discard the whole region."""
        client = boto3.client("ecr", region_name=REGION)
        _create_repo(client, "good-repo")
        _create_repo(client, "bad-repo")

        original = ecr_export._build_repo_row

        def raise_for_bad(repo, region, ecr_client=None):
            if repo.get("repositoryName") == "bad-repo":
                raise KeyError("SomeUnexpectedField")
            return original(repo, region, ecr_client)

        monkeypatch.setattr(ecr_export, "_build_repo_row", raise_for_bad)

        rows = scan_ecr_repositories_in_region(REGION)

        names = {row["Repository Name"] for row in rows}
        assert "good-repo" in names, "healthy repository was lost when a sibling failed"
        assert "bad-repo" not in names, "malformed repository should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeRepositories",
            )

        monkeypatch.setattr(ecr_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_ecr_repositories_in_region(REGION)

    @mock_aws
    def test_collect_ecr_repositories_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeRepositories",
            )

        monkeypatch.setattr(ecr_export, "scan_ecr_repositories_in_region", boom)

        repos, failed_regions = ecr_export.collect_ecr_repositories([REGION])

        assert repos == []
        assert [r for r, _ in failed_regions] == [REGION]
