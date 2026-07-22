#!/usr/bin/env python3
"""
Moto-based tests for sagemaker_export.py.

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
import sagemaker_export  # noqa: E402
from sagemaker_export import _scan_notebook_instances_region  # noqa: E402

REGION = "us-east-1"
ROLE_ARN = "arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_notebook(client, name):
    """Create a SageMaker notebook instance named ``name``."""
    client.create_notebook_instance(
        NotebookInstanceName=name,
        InstanceType="ml.t2.medium",
        RoleArn=ROLE_ARN,
    )


class TestScanNotebookInstancesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_notebook_instances(self):
        client = boto3.client("sagemaker", region_name=REGION)
        _create_notebook(client, "dev-notebook")

        rows = _scan_notebook_instances_region(REGION)

        names = {row["Notebook Name"] for row in rows}
        assert "dev-notebook" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("sagemaker", region_name=REGION)  # region exists, no notebooks

        rows = _scan_notebook_instances_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One notebook that fails to process must not discard the whole region."""
        client = boto3.client("sagemaker", region_name=REGION)
        _create_notebook(client, "good-notebook")
        _create_notebook(client, "bad-notebook")

        original = sagemaker_export._build_notebook_row

        def raise_for_bad(notebook, region, sagemaker_client, sm_pricing_data):
            if notebook.get("NotebookInstanceName") == "bad-notebook":
                raise KeyError("SomeUnexpectedField")
            return original(notebook, region, sagemaker_client, sm_pricing_data)

        monkeypatch.setattr(sagemaker_export, "_build_notebook_row", raise_for_bad)

        rows = _scan_notebook_instances_region(REGION)

        names = {row["Notebook Name"] for row in rows}
        assert "good-notebook" in names, "healthy notebook was lost when a sibling failed"
        assert "bad-notebook" not in names, "malformed notebook should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListNotebookInstances",
            )

        monkeypatch.setattr(sagemaker_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_notebook_instances_region(REGION)

    @mock_aws
    def test_collect_notebook_instances_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListNotebookInstances",
            )

        monkeypatch.setattr(sagemaker_export, "_scan_notebook_instances_region", boom)

        notebooks, failed_regions = sagemaker_export.collect_notebook_instances([REGION])

        assert notebooks == []
        assert [r for r, _ in failed_regions] == [REGION]
