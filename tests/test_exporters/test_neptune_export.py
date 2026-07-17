#!/usr/bin/env python3
"""
Moto-based tests for neptune_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's Neptune support rides on the RDS backend (``describe_db_clusters``
etc. are served by the same moto RDS backend Neptune's API shape reuses), so
``@mock_aws`` covers ``create_db_cluster`` / ``describe_db_clusters`` against
the ``neptune`` boto3 client directly — no monkeypatch workaround needed.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import neptune_export  # noqa: E402
from neptune_export import _scan_neptune_clusters_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_cluster(client, name):
    """Create a Neptune DB cluster named ``name``."""
    client.create_db_cluster(
        DBClusterIdentifier=name,
        Engine="neptune",
        MasterUsername="admin",
        MasterUserPassword="password123",
    )


class TestScanNeptuneClustersRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_clusters(self):
        client = boto3.client("neptune", region_name=REGION)
        _create_cluster(client, "graph-cluster")

        rows = _scan_neptune_clusters_region(REGION)

        names = {row["Cluster ID"] for row in rows}
        assert "graph-cluster" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("neptune", region_name=REGION)  # region exists, no clusters

        rows = _scan_neptune_clusters_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region. Neptune previously wrote
    a forced Summary sheet on every run (so the workbook always landed), but
    could not tell a failed region apart from a genuinely empty one — this
    suite locks in the failed-scope tracking added on top of that.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One cluster that fails to process must not discard the whole region."""
        client = boto3.client("neptune", region_name=REGION)
        _create_cluster(client, "good-cluster")
        _create_cluster(client, "bad-cluster")

        original = neptune_export._build_cluster_row

        def raise_for_bad(cluster, region):
            if cluster.get("DBClusterIdentifier") == "bad-cluster":
                raise KeyError("SomeUnexpectedField")
            return original(cluster, region)

        monkeypatch.setattr(neptune_export, "_build_cluster_row", raise_for_bad)

        rows = _scan_neptune_clusters_region(REGION)

        names = {row["Cluster ID"] for row in rows}
        assert "good-cluster" in names, "healthy cluster was lost when a sibling failed"
        assert "bad-cluster" not in names, "malformed cluster should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeDBClusters",
            )

        monkeypatch.setattr(neptune_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_neptune_clusters_region(REGION)

    @mock_aws
    def test_collect_neptune_clusters_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets the export write a FAILED marker + exit 1
        even though the always-written Summary sheet still lands.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeDBClusters",
            )

        monkeypatch.setattr(neptune_export, "_scan_neptune_clusters_region", boom)

        clusters, failed_regions = neptune_export.collect_neptune_clusters([REGION])

        assert clusters == []
        assert [r for r, _ in failed_regions] == [REGION]
