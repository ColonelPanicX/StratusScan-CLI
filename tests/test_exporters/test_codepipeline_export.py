#!/usr/bin/env python3
"""
Moto-based tests for codepipeline_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's codepipeline backend implements create_pipeline / list_pipelines
/ get_pipeline, but raises NotImplementedError for get_pipeline_state. That
call is an enrichment lookup in codepipeline_export._build_pipeline_row and
is already wrapped in its own try/except (degrades to 'Unknown'), so it does
not block these tests — it just means "Latest Status" is always 'Unknown'
under moto.
"""

import json
import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import codepipeline_export  # noqa: E402
from codepipeline_export import _scan_pipelines_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_role(region=REGION):
    """Create a minimal IAM role CodePipeline can assume, return its ARN."""
    iam = boto3.client("iam", region_name=region)
    role = iam.create_role(
        RoleName="codepipeline-role",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codepipeline.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    return role["Role"]["Arn"]


def _create_pipeline(client, name, role_arn):
    """Create a minimal two-stage CodePipeline pipeline named ``name``."""
    client.create_pipeline(
        pipeline={
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": "test-bucket"},
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "SourceAction",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "outputArtifacts": [{"name": "SourceOutput"}],
                            "configuration": {
                                "S3Bucket": "test-bucket",
                                "S3ObjectKey": "source.zip",
                            },
                        }
                    ],
                },
                {
                    "name": "Deploy",
                    "actions": [
                        {
                            "name": "DeployAction",
                            "actionTypeId": {
                                "category": "Deploy",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "inputArtifacts": [{"name": "SourceOutput"}],
                            "configuration": {
                                "BucketName": "test-bucket",
                                "Extract": "true",
                            },
                        }
                    ],
                },
            ],
        }
    )


class TestScanPipelinesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_pipelines(self):
        role_arn = _create_role()
        client = boto3.client("codepipeline", region_name=REGION)
        _create_pipeline(client, "web-pipeline", role_arn)

        rows = _scan_pipelines_region(REGION)

        names = {row["Pipeline Name"] for row in rows}
        assert "web-pipeline" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("codepipeline", region_name=REGION)  # region exists, no pipelines

        rows = _scan_pipelines_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list, indistinguishable
    from a genuinely empty region. codepipeline_export.py is Tier-3 PARTIAL: a
    forced Summary sheet already means a workbook always lands, but the export
    must still ADD failed-scope tracking so a failure is never indistinguishable
    from a genuinely empty account.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One pipeline that fails to process must not discard the whole region."""
        role_arn = _create_role()
        client = boto3.client("codepipeline", region_name=REGION)
        _create_pipeline(client, "good-pipeline", role_arn)
        _create_pipeline(client, "bad-pipeline", role_arn)

        original = codepipeline_export._build_pipeline_row

        def raise_for_bad(client, pipeline_summary, region):
            if pipeline_summary.get("name") == "bad-pipeline":
                raise KeyError("SomeUnexpectedField")
            return original(client, pipeline_summary, region)

        monkeypatch.setattr(codepipeline_export, "_build_pipeline_row", raise_for_bad)

        rows = _scan_pipelines_region(REGION)

        names = {row["Pipeline Name"] for row in rows}
        assert "good-pipeline" in names, "healthy pipeline was lost when a sibling failed"
        assert "bad-pipeline" not in names, "malformed pipeline should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListPipelines",
            )

        monkeypatch.setattr(codepipeline_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_pipelines_region(REGION)

    @mock_aws
    def test_collect_pipelines_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        even though the forced Summary sheet means a workbook still lands.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListPipelines",
            )

        monkeypatch.setattr(codepipeline_export, "_scan_pipelines_region", boom)

        pipelines, failed_regions = codepipeline_export.collect_pipelines([REGION])

        assert pipelines == []
        assert [r for r, _ in failed_regions] == [REGION]
