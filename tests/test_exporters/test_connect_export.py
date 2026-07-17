#!/usr/bin/env python3
"""
Moto-based tests for connect_export.py.

Focus: the silent-collection-failure contract (Tier-2a). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

moto's Amazon Connect support covers create_instance/list_instances, so the
malformed-item and happy-path cases exercise real moto resources. moto does
not implement list_queues/list_phone_numbers_v2 in a way that's practical to
seed with real data for this regression suite, so the queues/phone-number
raise-and-surface cases (b)/(c) are exercised purely via monkeypatch, with no
real AWS/moto resources involved.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import connect_export  # noqa: E402
from connect_export import _scan_instances_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_instance(client, alias):
    """Create a Connect instance named ``alias``."""
    return client.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )


class TestScanInstancesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_instances(self):
        client = boto3.client("connect", region_name=REGION)
        _create_instance(client, "web-instance")

        rows = _scan_instances_region(REGION)

        aliases = {row["Instance Alias"] for row in rows}
        assert "web-instance" in aliases

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("connect", region_name=REGION)  # region exists, no instances

        rows = _scan_instances_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One instance that fails to process must not discard the whole region."""
        client = boto3.client("connect", region_name=REGION)
        _create_instance(client, "good-instance")
        _create_instance(client, "bad-instance")

        original = connect_export._build_instance_row

        def raise_for_bad(instance_summary, region):
            if instance_summary.get("InstanceAlias") == "bad-instance":
                raise KeyError("SomeUnexpectedField")
            return original(instance_summary, region)

        monkeypatch.setattr(connect_export, "_build_instance_row", raise_for_bad)

        rows = _scan_instances_region(REGION)

        aliases = {row["Instance Alias"] for row in rows}
        assert "good-instance" in aliases, "healthy instance was lost when a sibling failed"
        assert "bad-instance" not in aliases, "malformed instance should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListInstances",
            )

        monkeypatch.setattr(connect_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_instances_region(REGION)

    @mock_aws
    def test_collect_instances_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListInstances",
            )

        monkeypatch.setattr(connect_export, "_scan_instances_region", boom)

        instances, failed_regions = connect_export.collect_instances([REGION])

        assert instances == []
        assert [r for r, _ in failed_regions] == [REGION]

    def test_scan_queues_region_raises_not_empty(self, monkeypatch):
        """
        The queues scope collector (blast-radius "+2" sibling of the primary
        scope) must also propagate region-level API failures rather than
        swallowing them into an empty list. Exercised purely via monkeypatch —
        no real moto/AWS resources involved.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListQueues",
            )

        monkeypatch.setattr(connect_export.utils, "get_boto3_client", boom)

        instances = [{"Region": REGION, "Instance ID": "fake-instance-id", "ARN": "fake-arn"}]

        with pytest.raises(botocore.exceptions.ClientError):
            connect_export._scan_queues_region(REGION, instances)

    def test_collect_queues_surfaces_failed_regions(self, monkeypatch):
        """
        collect_queues must surface failed regions via collect_failures rather
        than dropping them. Exercised purely via monkeypatch — no real
        moto/AWS resources involved.
        """

        def boom(region, instances):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListQueues",
            )

        monkeypatch.setattr(connect_export, "_scan_queues_region", boom)

        queues, failed_regions = connect_export.collect_queues([], [REGION])

        assert queues == []
        assert [r for r, _ in failed_regions] == [REGION]

    def test_scan_phone_numbers_region_raises_not_empty(self, monkeypatch):
        """
        The phone-numbers scope collector (blast-radius "+2" sibling of the
        primary scope) must also propagate region-level API failures rather
        than swallowing them into an empty list. Exercised purely via
        monkeypatch — no real moto/AWS resources involved.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListPhoneNumbersV2",
            )

        monkeypatch.setattr(connect_export.utils, "get_boto3_client", boom)

        instances = [{"Region": REGION, "Instance ID": "fake-instance-id", "ARN": "fake-arn"}]

        with pytest.raises(botocore.exceptions.ClientError):
            connect_export._scan_phone_numbers_region(REGION, instances)

    def test_collect_phone_numbers_surfaces_failed_regions(self, monkeypatch):
        """
        collect_phone_numbers must surface failed regions via
        collect_failures rather than dropping them. Exercised purely via
        monkeypatch — no real moto/AWS resources involved.
        """

        def boom(region, instances):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListPhoneNumbersV2",
            )

        monkeypatch.setattr(connect_export, "_scan_phone_numbers_region", boom)

        numbers, failed_regions = connect_export.collect_phone_numbers([], [REGION])

        assert numbers == []
        assert [r for r, _ in failed_regions] == [REGION]
