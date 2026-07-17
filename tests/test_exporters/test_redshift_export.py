#!/usr/bin/env python3
"""
Moto-based tests for redshift_export.py.

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
import redshift_export  # noqa: E402
from redshift_export import scan_redshift_clusters_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_cluster(client, name):
    """Create a Redshift cluster named ``name``."""
    client.create_cluster(
        ClusterIdentifier=name,
        NodeType="dc2.large",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        DBName="mydb",
        ClusterType="single-node",
    )


class TestScanRedshiftClustersInRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_clusters(self):
        client = boto3.client("redshift", region_name=REGION)
        _create_cluster(client, "web-cluster")

        rows = scan_redshift_clusters_in_region(REGION)

        ids = {row["Cluster ID"] for row in rows}
        assert "web-cluster" in ids

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("redshift", region_name=REGION)  # region exists, no clusters

        rows = scan_redshift_clusters_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list (or, for
    Tier-3 PARTIAL scripts, into a zero-row sheet buried inside an
    always-written Summary workbook), indistinguishable from a genuinely
    empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One cluster that fails to process must not discard the whole region."""
        client = boto3.client("redshift", region_name=REGION)
        _create_cluster(client, "good-cluster")
        _create_cluster(client, "bad-cluster")

        original = redshift_export._build_cluster_row

        def raise_for_bad(cluster, region, pricing_data, cost_note):
            if cluster.get("ClusterIdentifier") == "bad-cluster":
                raise KeyError("SomeUnexpectedField")
            return original(cluster, region, pricing_data, cost_note)

        monkeypatch.setattr(redshift_export, "_build_cluster_row", raise_for_bad)

        rows = scan_redshift_clusters_in_region(REGION)

        ids = {row["Cluster ID"] for row in rows}
        assert "good-cluster" in ids, "healthy cluster was lost when a sibling failed"
        assert "bad-cluster" not in ids, "malformed cluster should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeClusters",
            )

        monkeypatch.setattr(redshift_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_redshift_clusters_in_region(REGION)

    @mock_aws
    def test_collect_redshift_clusters_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        even though the always-written Summary sheet means a workbook still
        lands (Tier-3 PARTIAL nuance).
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeClusters",
            )

        monkeypatch.setattr(redshift_export, "scan_redshift_clusters_in_region", boom)

        clusters, failed_regions = redshift_export.collect_redshift_clusters([REGION])

        assert clusters == []
        assert [r for r, _ in failed_regions] == [REGION]
