#!/usr/bin/env python3
"""
Tests for codecommit_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's CodeCommit support implements create_repository/get_repository
but not list_repositories (``NotImplementedError`` at call time as of
moto 5.1). Since the primary scope collector (``_scan_repositories_region``)
fans out via ``list_repositories``, these tests monkeypatch
``utils.get_boto3_client`` to return a hand-rolled fake CodeCommit client
instead of relying on ``@mock_aws`` end-to-end.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import codecommit_export  # noqa: E402
from codecommit_export import _scan_repositories_region  # noqa: E402

REGION = "us-east-1"


class _FakePaginator:
    """Minimal paginator stub that yields a single page."""

    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        yield self._page


class _FakeCodeCommitClient:
    """
    Minimal CodeCommit client stub standing in for moto's missing
    ``list_repositories`` support.
    """

    def __init__(self, repo_names, get_repository_errors=None):
        self._repo_names = repo_names
        self._get_repository_errors = get_repository_errors or {}

    def get_paginator(self, operation_name):
        if operation_name == "list_repositories":
            return _FakePaginator(
                {"repositories": [{"repositoryName": name} for name in self._repo_names]}
            )
        raise NotImplementedError(operation_name)

    def get_repository(self, **kwargs):
        repo_name = kwargs["repositoryName"]
        if repo_name in self._get_repository_errors:
            raise self._get_repository_errors[repo_name]
        return {
            "repositoryMetadata": {
                "repositoryName": repo_name,
                "repositoryId": f"{repo_name}-id",
            }
        }


class TestScanRepositoriesRegion:
    """Happy-path collection."""

    def test_collects_repositories(self, monkeypatch):
        fake_client = _FakeCodeCommitClient(["web-repo"])
        monkeypatch.setattr(
            codecommit_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_repositories_region(REGION)

        names = {row["Repository Name"] for row in rows}
        assert "web-repo" in names

    def test_empty_region_returns_empty_list(self, monkeypatch):
        fake_client = _FakeCodeCommitClient([])
        monkeypatch.setattr(
            codecommit_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_repositories_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One repository that fails to process must not discard the whole region."""
        fake_client = _FakeCodeCommitClient(
            ["good-repo", "bad-repo"],
            get_repository_errors={
                "bad-repo": botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": "RepositoryDoesNotExistException",
                            "Message": "gone",
                        }
                    },
                    "GetRepository",
                )
            },
        )
        monkeypatch.setattr(
            codecommit_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_repositories_region(REGION)

        names = {row["Repository Name"] for row in rows}
        assert "good-repo" in names, "healthy repository was lost when a sibling failed"
        assert "bad-repo" not in names, "malformed repository should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListRepositories",
            )

        monkeypatch.setattr(codecommit_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_repositories_region(REGION)

    def test_collect_repositories_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListRepositories",
            )

        monkeypatch.setattr(codecommit_export, "_scan_repositories_region", boom)

        repositories, failed_regions = codecommit_export.collect_repositories([REGION])

        assert repositories == []
        assert [r for r, _ in failed_regions] == [REGION]
