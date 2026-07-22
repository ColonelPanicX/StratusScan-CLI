#!/usr/bin/env python3
"""
Moto-based tests for sqs_sns_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import sqs_sns_export  # noqa: E402
from sqs_sns_export import _scan_sqs_queues_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_queue(client, name):
    """Create a standard SQS queue named ``name``."""
    client.create_queue(QueueName=name)


class TestScanSqsQueuesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_queues(self):
        client = boto3.client("sqs", region_name=REGION)
        _create_queue(client, "orders-queue")

        rows = _scan_sqs_queues_region(REGION)

        names = {row["Queue Name"] for row in rows}
        assert "orders-queue" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("sqs", region_name=REGION)  # region exists, no queues

        rows = _scan_sqs_queues_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One queue that fails to process must not discard the whole region."""
        client = boto3.client("sqs", region_name=REGION)
        _create_queue(client, "good-queue")
        _create_queue(client, "bad-queue")

        original = sqs_sns_export._build_queue_row

        def raise_for_bad(queue_url, attributes, region):
            if queue_url.endswith("bad-queue"):
                raise KeyError("SomeUnexpectedField")
            return original(queue_url, attributes, region)

        monkeypatch.setattr(sqs_sns_export, "_build_queue_row", raise_for_bad)

        rows = _scan_sqs_queues_region(REGION)

        names = {row["Queue Name"] for row in rows}
        assert "good-queue" in names, "healthy queue was lost when a sibling failed"
        assert "bad-queue" not in names, "malformed queue should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListQueues",
            )

        monkeypatch.setattr(sqs_sns_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_sqs_queues_region(REGION)

    @mock_aws
    def test_collect_sqs_queues_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListQueues",
            )

        monkeypatch.setattr(sqs_sns_export, "_scan_sqs_queues_region", boom)

        queues, failed_regions = sqs_sns_export.collect_sqs_queues([REGION])

        assert queues == []
        assert [r for r, _ in failed_regions] == [REGION]
