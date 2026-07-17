#!/usr/bin/env python3
"""
Moto-based tests for cloudformation_export.py.

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
import cloudformation_export  # noqa: E402
from cloudformation_export import _scan_stacks_region  # noqa: E402

REGION = "us-east-1"

MINIMAL_TEMPLATE = """{
  "Resources": {
    "MyBucket": {"Type": "AWS::S3::Bucket"}
  }
}"""


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_stack(client, name):
    """Create a CloudFormation stack named ``name``."""
    client.create_stack(StackName=name, TemplateBody=MINIMAL_TEMPLATE)


class TestScanStacksRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_stacks(self):
        client = boto3.client("cloudformation", region_name=REGION)
        _create_stack(client, "web-stack")

        rows = _scan_stacks_region(REGION)

        names = {row["StackName"] for row in rows}
        assert "web-stack" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("cloudformation", region_name=REGION)  # region exists, no stacks

        rows = _scan_stacks_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One stack that fails to process must not discard the whole region."""
        client = boto3.client("cloudformation", region_name=REGION)
        _create_stack(client, "good-stack")
        _create_stack(client, "bad-stack")

        original = cloudformation_export._build_stack_row

        def raise_for_bad(stack, region):
            if stack.get("StackName") == "bad-stack":
                raise KeyError("SomeUnexpectedField")
            return original(stack, region)

        monkeypatch.setattr(cloudformation_export, "_build_stack_row", raise_for_bad)

        rows = _scan_stacks_region(REGION)

        names = {row["StackName"] for row in rows}
        assert "good-stack" in names, "healthy stack was lost when a sibling failed"
        assert "bad-stack" not in names, "malformed stack should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeStacks",
            )

        monkeypatch.setattr(cloudformation_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_stacks_region(REGION)

    @mock_aws
    def test_collect_stacks_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeStacks",
            )

        monkeypatch.setattr(cloudformation_export, "_scan_stacks_region", boom)

        stacks, failed_regions = cloudformation_export.collect_stacks([REGION])

        assert stacks == []
        assert [r for r, _ in failed_regions] == [REGION]
