#!/usr/bin/env python3
"""
Moto-based tests for eks_export.py.

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
import eks_export  # noqa: E402
from eks_export import _scan_eks_clusters_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_cluster(client, name):
    """Create an EKS cluster named ``name``."""
    client.create_cluster(
        name=name,
        roleArn="arn:aws:iam::123456789012:role/eks-role",
        resourcesVpcConfig={"subnetIds": ["subnet-12345678"]},
    )


class TestScanEksClustersRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_clusters(self):
        client = boto3.client("eks", region_name=REGION)
        _create_cluster(client, "web-cluster")

        rows = _scan_eks_clusters_region(REGION)

        names = {row["Cluster Name"] for row in rows}
        assert "web-cluster" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("eks", region_name=REGION)  # region exists, no clusters

        rows = _scan_eks_clusters_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One cluster that fails to process must not discard the whole region."""
        client = boto3.client("eks", region_name=REGION)
        _create_cluster(client, "good-cluster")
        _create_cluster(client, "bad-cluster")

        original = eks_export._build_cluster_row

        def raise_for_bad(client, cluster_name, region):
            if cluster_name == "bad-cluster":
                raise KeyError("SomeUnexpectedField")
            return original(client, cluster_name, region)

        monkeypatch.setattr(eks_export, "_build_cluster_row", raise_for_bad)

        rows = _scan_eks_clusters_region(REGION)

        names = {row["Cluster Name"] for row in rows}
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
                "ListClusters",
            )

        monkeypatch.setattr(eks_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_eks_clusters_region(REGION)

    @mock_aws
    def test_collect_eks_clusters_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListClusters",
            )

        monkeypatch.setattr(eks_export, "_scan_eks_clusters_region", boom)

        clusters, failed_regions = eks_export.collect_eks_clusters([REGION])

        assert clusters == []
        assert [r for r, _ in failed_regions] == [REGION]
