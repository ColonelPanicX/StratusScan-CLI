#!/usr/bin/env python3
"""
Tests for datasync_export.py.

Focus: the silent-collection-failure contract (Tier-2), scoped to the
primary DataSync Tasks collector. See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's DataSync support does not cover the full ``describe_task``
field set this exporter reads (Tags, Schedule, Options, ...), so these tests
build a fake boto3 client via monkeypatch rather than ``@mock_aws``.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import datasync_export  # noqa: E402
from datasync_export import collect_datasync_tasks  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _make_fake_client(tasks, describe_map):
    """
    Build a fake DataSync client whose ``list_tasks`` paginator yields
    ``tasks`` (a list of ``{'TaskArn': ...}`` dicts) and whose
    ``describe_task`` returns ``describe_map[task_arn]``.
    """
    client = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [{'Tasks': tasks}]
    client.get_paginator.return_value = paginator

    def describe_task(**kwargs):
        return describe_map[kwargs["TaskArn"]]

    client.describe_task.side_effect = describe_task
    return client


class TestCollectDatasyncTasks:
    """Happy-path collection."""

    def test_collects_tasks(self, monkeypatch):
        task_arn = "arn:aws:datasync:us-east-1:111222333444:task/task-1"
        fake_client = _make_fake_client(
            tasks=[{'TaskArn': task_arn}],
            describe_map={
                task_arn: {
                    'TaskArn': task_arn,
                    'Status': 'AVAILABLE',
                    'SourceLocationArn': 'arn:aws:datasync:us-east-1:111222333444:location/loc-1',
                    'DestinationLocationArn': 'arn:aws:datasync:us-east-1:111222333444:location/loc-2',
                }
            },
        )
        monkeypatch.setattr(datasync_export.utils, "get_boto3_client", lambda *a, **k: fake_client)

        result = collect_datasync_tasks(REGION)

        assert len(result) == 1
        assert result[0]["Task ARN"] == task_arn
        assert result[0]["Status"] == "AVAILABLE"

    def test_empty_region_returns_empty_list(self, monkeypatch):
        fake_client = _make_fake_client(tasks=[], describe_map={})
        monkeypatch.setattr(datasync_export.utils, "get_boto3_client", lambda *a, **k: fake_client)

        result = collect_datasync_tasks(REGION)

        assert result == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One task that fails to process must not discard the whole region."""
        good_arn = "arn:aws:datasync:us-east-1:111222333444:task/good"
        bad_arn = "arn:aws:datasync:us-east-1:111222333444:task/bad"

        fake_client = _make_fake_client(
            tasks=[{'TaskArn': good_arn}, {'TaskArn': bad_arn}],
            describe_map={
                good_arn: {'TaskArn': good_arn, 'Status': 'AVAILABLE'},
                bad_arn: {'TaskArn': bad_arn, 'Status': 'AVAILABLE'},
            },
        )
        monkeypatch.setattr(datasync_export.utils, "get_boto3_client", lambda *a, **k: fake_client)

        original = datasync_export._build_task_row

        def raise_for_bad(item, region):
            if item == bad_arn:
                raise KeyError("SomeUnexpectedField")
            return original(item, region)

        monkeypatch.setattr(datasync_export, "_build_task_row", raise_for_bad)

        result = collect_datasync_tasks(REGION)

        arns = {row["Task ARN"] for row in result}
        assert good_arn in arns, "healthy task was lost when a sibling failed"
        assert bad_arn not in arns, "malformed task should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListTasks",
            )

        monkeypatch.setattr(datasync_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_datasync_tasks(REGION)

    def test_collect_datasync_tasks_all_regions_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker and
        exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListTasks",
            )

        monkeypatch.setattr(datasync_export, "collect_datasync_tasks", boom)

        tasks, failed_regions = datasync_export.collect_datasync_tasks_all_regions([REGION])

        assert tasks == []
        assert [r for r, _ in failed_regions] == [REGION]
