#!/usr/bin/env python3
"""
Moto-based tests for ecs_export.py.

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
import ecs_export  # noqa: E402
from ecs_export import _scan_ecs_region  # noqa: E402

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_cluster_with_service(client, cluster_name, service_name):
    """Create an ECS cluster + task definition + service named as given."""
    client.create_cluster(clusterName=cluster_name)
    client.register_task_definition(
        family=f"{service_name}-family",
        containerDefinitions=[{"name": "web", "image": "nginx", "memory": 128}],
    )
    client.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=f"{service_name}-family",
        desiredCount=1,
    )


class TestScanEcsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_ecs_services(self):
        client = boto3.client("ecs", region_name=REGION)
        _create_cluster_with_service(client, "web-cluster", "web-service")

        rows = _scan_ecs_region(REGION)

        names = {row["Service Name"] for row in rows}
        assert "web-service" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ecs", region_name=REGION)  # region exists, no clusters

        rows = _scan_ecs_region(REGION)

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
        client = boto3.client("ecs", region_name=REGION)
        _create_cluster_with_service(client, "good-cluster", "good-service")
        _create_cluster_with_service(client, "bad-cluster", "bad-service")

        original = ecs_export._build_cluster_rows

        def raise_for_bad(ecs_client, elbv2_client, cluster_arn, region):
            if "bad-cluster" in cluster_arn:
                raise KeyError("SomeUnexpectedField")
            return original(ecs_client, elbv2_client, cluster_arn, region)

        monkeypatch.setattr(ecs_export, "_build_cluster_rows", raise_for_bad)

        rows = _scan_ecs_region(REGION)

        names = {row["Service Name"] for row in rows}
        assert "good-service" in names, "healthy cluster was lost when a sibling failed"
        assert "bad-service" not in names, "malformed cluster should have been skipped"

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

        monkeypatch.setattr(ecs_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_ecs_region(REGION)

    @mock_aws
    def test_get_ecs_resources_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListClusters",
            )

        monkeypatch.setattr(ecs_export, "_scan_ecs_region", boom)

        resources, failed_regions = ecs_export.get_ecs_resources([REGION])

        assert resources == []
        assert [r for r, _ in failed_regions] == [REGION]
