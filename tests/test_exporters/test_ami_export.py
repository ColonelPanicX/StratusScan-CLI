#!/usr/bin/env python3
"""
Moto-based tests for ami_export.py.

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
import ami_export  # noqa: E402
from ami_export import collect_amis_in_region  # noqa: E402

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_ami(ec2_client, name):
    """Launch a minimal instance and register/create an AMI named ``name``."""
    reservation = ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    response = ec2_client.create_image(
        InstanceId=instance_id,
        Name=name,
        Description="test AMI",
    )
    return response["ImageId"]


class TestCollectAmisInRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_amis(self):
        client = boto3.client("ec2", region_name=REGION)
        _create_ami(client, "web-ami")

        rows = collect_amis_in_region(REGION, ACCOUNT_ID)

        names = {row["AMI Name"] for row in rows}
        assert "web-ami" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ec2", region_name=REGION)  # region exists, no AMIs

        rows = collect_amis_in_region(REGION, ACCOUNT_ID)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One AMI that fails to process must not discard the whole region."""
        client = boto3.client("ec2", region_name=REGION)
        _create_ami(client, "good-ami")
        _create_ami(client, "bad-ami")

        original = ami_export._build_ami_row

        def raise_for_bad(ami, region):
            if ami.get("Name") == "bad-ami":
                raise KeyError("SomeUnexpectedField")
            return original(ami, region)

        monkeypatch.setattr(ami_export, "_build_ami_row", raise_for_bad)

        rows = collect_amis_in_region(REGION, ACCOUNT_ID)

        names = {row["AMI Name"] for row in rows}
        assert "good-ami" in names, "healthy AMI was lost when a sibling failed"
        assert "bad-ami" not in names, "malformed AMI should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeImages",
            )

        monkeypatch.setattr(ami_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_amis_in_region(REGION, ACCOUNT_ID)

    @mock_aws
    def test_collect_amis_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region, account_id):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeImages",
            )

        monkeypatch.setattr(ami_export, "collect_amis_in_region", boom)

        amis, failed_regions = ami_export.collect_amis([REGION], ACCOUNT_ID)

        assert amis == []
        assert [r for r, _ in failed_regions] == [REGION]
