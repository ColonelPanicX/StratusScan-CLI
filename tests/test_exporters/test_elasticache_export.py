#!/usr/bin/env python3
"""
Moto-based tests for elasticache_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's ElastiCache support does not implement create_cache_cluster's
error paths the way we need for the region-API-failure regression test, so
that case (and the malformed-item case) monkeypatch the boto3 client factory
/ row builder directly rather than relying on moto to produce the failure.
create_replication_group itself is fully supported by moto and used for the
happy-path and scope-aggregation tests.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import elasticache_export  # noqa: E402
from elasticache_export import _scan_replication_groups_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_replication_group(client, rg_id):
    """Create a minimal ElastiCache (Redis) replication group named ``rg_id``."""
    client.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription=f"test group {rg_id}",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
    )


class TestScanReplicationGroupsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_replication_groups(self):
        client = boto3.client("elasticache", region_name=REGION)
        _create_replication_group(client, "web-cache")

        rows = _scan_replication_groups_region(REGION)

        ids = {row["Replication Group ID"] for row in rows}
        assert "web-cache" in ids

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("elasticache", region_name=REGION)  # region exists, no groups

        rows = _scan_replication_groups_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One replication group that fails to process must not discard the whole region."""
        client = boto3.client("elasticache", region_name=REGION)
        _create_replication_group(client, "good-cache")
        _create_replication_group(client, "bad-cache")

        original = elasticache_export._build_replication_group_row

        def raise_for_bad(rg, region, pricing_data, cost_note):
            if rg.get("ReplicationGroupId") == "bad-cache":
                raise KeyError("SomeUnexpectedField")
            return original(rg, region, pricing_data, cost_note)

        monkeypatch.setattr(elasticache_export, "_build_replication_group_row", raise_for_bad)

        rows = _scan_replication_groups_region(REGION)

        ids = {row["Replication Group ID"] for row in rows}
        assert "good-cache" in ids, "healthy replication group was lost when a sibling failed"
        assert "bad-cache" not in ids, "malformed replication group should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeReplicationGroups",
            )

        monkeypatch.setattr(elasticache_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_replication_groups_region(REGION)

    @mock_aws
    def test_collect_replication_groups_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeReplicationGroups",
            )

        monkeypatch.setattr(elasticache_export, "_scan_replication_groups_region", boom)

        replication_groups, failed_regions = elasticache_export.collect_replication_groups([REGION])

        assert replication_groups == []
        assert [r for r, _ in failed_regions] == [REGION]
