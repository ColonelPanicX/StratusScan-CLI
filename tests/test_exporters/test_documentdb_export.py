#!/usr/bin/env python3
"""
Tests for documentdb_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on moto: moto's ``docdb`` client backend rejects
``Engine='docdb'`` on ``create_db_cluster`` (it only accepts the RDS/Neptune
engine set), so a real DocumentDB cluster cannot be created through moto.
``describe_db_clusters`` itself works fine (returns an empty list), so the
empty-region path is exercised against moto directly; everything that needs
an actual cluster in the response is exercised via a small fake docdb client
substituted for ``utils.get_boto3_client``.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import documentdb_export  # noqa: E402
from documentdb_export import _scan_documentdb_clusters_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _cluster(cluster_id, **overrides):
    """Build a minimal describe_db_clusters-shaped cluster dict."""
    cluster = {
        "DBClusterIdentifier": cluster_id,
        "Engine": "docdb",
        "EngineVersion": "5.0.0",
        "Status": "available",
        "Endpoint": f"{cluster_id}.cluster.docdb.amazonaws.com",
        "ReaderEndpoint": f"{cluster_id}.cluster-ro.docdb.amazonaws.com",
        "Port": 27017,
        "DBClusterMembers": [],
        "MultiAZ": False,
        "AvailabilityZones": [f"{REGION}a"],
        "BackupRetentionPeriod": 1,
        "PreferredBackupWindow": "07:00-08:00",
        "PreferredMaintenanceWindow": "sun:05:00-sun:06:00",
        "StorageEncrypted": False,
        "KmsKeyId": "N/A",
        "DeletionProtection": False,
        "ClusterCreateTime": None,
        "VpcSecurityGroups": [],
        "DBSubnetGroup": "default",
        "DBClusterParameterGroup": "default.docdb5.0",
        "EnabledCloudwatchLogsExports": [],
    }
    cluster.update(overrides)
    return cluster


class _FakePaginator:
    """Minimal paginator stand-in returning a single canned page."""

    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        return iter([self._page])


class _FakeDocDBClient:
    """Minimal docdb client stand-in — moto cannot create DocumentDB clusters."""

    def __init__(self, clusters):
        self._clusters = clusters

    def get_paginator(self, operation_name):
        assert operation_name == "describe_db_clusters"
        return _FakePaginator({"DBClusters": self._clusters})


class TestScanDocumentdbClustersRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_clusters(self, monkeypatch):
        fake_client = _FakeDocDBClient([_cluster("docdb-cluster")])
        monkeypatch.setattr(
            documentdb_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_documentdb_clusters_region(REGION)

        names = {row["Cluster ID"] for row in rows}
        assert "docdb-cluster" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("docdb", region_name=REGION)  # region exists, no clusters

        rows = _scan_documentdb_clusters_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region. documentdb_export.py is
    a Tier-3 PARTIAL exporter: it always writes a forced Summary sheet (a
    workbook always lands), so the fix must ADD failed-scope tracking on top
    of that — a scope failure must ALSO write the FAILED marker and exit
    non-zero, while a genuinely empty account still exits 0 with no marker.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One cluster that fails to process must not discard the whole region."""
        fake_client = _FakeDocDBClient(
            [_cluster("good-cluster"), _cluster("bad-cluster")]
        )
        monkeypatch.setattr(
            documentdb_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        original = documentdb_export._build_cluster_row

        def raise_for_bad(cluster, region):
            if cluster.get("DBClusterIdentifier") == "bad-cluster":
                raise KeyError("SomeUnexpectedField")
            return original(cluster, region)

        monkeypatch.setattr(documentdb_export, "_build_cluster_row", raise_for_bad)

        rows = _scan_documentdb_clusters_region(REGION)

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

        monkeypatch.setattr(documentdb_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_documentdb_clusters_region(REGION)

    @mock_aws
    def test_collect_documentdb_clusters_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        even though the Summary sheet always makes a workbook land.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeDBClusters",
            )

        monkeypatch.setattr(documentdb_export, "_scan_documentdb_clusters_region", boom)

        clusters, failed_regions = documentdb_export.collect_documentdb_clusters([REGION])

        assert clusters == []
        assert [r for r, _ in failed_regions] == [REGION]
