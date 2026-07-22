#!/usr/bin/env python3
"""
Tests for image_builder_export.py.

Focus: the silent-collection-failure contract (Tier-2a) applied to the
PIPELINES scope. See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

NOTE: moto (5.1.21, at the time this test was written) does not implement an
EC2 Image Builder backend, so this file cannot use ``@mock_aws`` against a
simulated ``imagebuilder`` service the way the RDS/Lambda/Auto Scaling
regression suites do. Instead, ``utils.get_boto3_client`` is monkeypatched to
return either a raising stub (region-level failure case) or a minimal fake
client object exposing just the ``list_image_pipelines`` /
``get_image_pipeline`` surface the collector calls (malformed-item case).
This still exercises the real control flow in
``_scan_pipelines_region`` / ``_build_pipeline_row`` / ``collect_image_pipelines``
without touching real AWS or requiring a moto backend.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import image_builder_export  # noqa: E402
from image_builder_export import _scan_pipelines_region  # noqa: E402

REGION = "us-east-1"
GOOD_ARN = f"arn:aws:imagebuilder:{REGION}:123456789012:image-pipeline/good-pipeline"
BAD_ARN = f"arn:aws:imagebuilder:{REGION}:123456789012:image-pipeline/bad-pipeline"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakeImageBuilderClient:
    """
    Minimal stand-in for the boto3 ``imagebuilder`` client, exposing only the
    two calls ``_scan_pipelines_region`` / ``_build_pipeline_row`` use:
    ``list_image_pipelines`` and ``get_image_pipeline``. One pipeline
    (``BAD_ARN``) raises when its details are fetched, to exercise the
    per-item skip-not-fatal path.
    """

    def list_image_pipelines(self, **kwargs):
        return {
            "imagePipelineList": [
                {"arn": GOOD_ARN},
                {"arn": BAD_ARN},
            ]
        }

    def get_image_pipeline(self, **kwargs):
        pipeline_arn = kwargs.get("imagePipelineArn")
        if pipeline_arn == BAD_ARN:
            raise KeyError("SomeUnexpectedField")
        return {
            "imagePipeline": {
                "name": "good-pipeline",
                "status": "ENABLED",
                "imageRecipeArn": f"arn:aws:imagebuilder:{REGION}:123456789012:image-recipe/good-recipe/1.0.0",
                "infrastructureConfigurationArn": "N/A",
                "distributionConfigurationArn": "N/A",
                "schedule": {},
                "enhancedImageMetadataEnabled": True,
                "imageTestsConfiguration": {},
                "dateCreated": "2026-01-01T00:00:00.000Z",
                "description": "test pipeline",
                "tags": {},
            }
        }


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit applied to the Image Builder
    pipelines scope: a collection error must never be swallowed into an
    empty result indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One pipeline that fails to fetch details must not discard the whole region."""
        monkeypatch.setattr(
            image_builder_export.utils,
            "get_boto3_client",
            lambda service, region_name=None: _FakeImageBuilderClient(),
        )

        rows = _scan_pipelines_region(REGION)

        names = {row["Pipeline Name"] for row in rows}
        assert "good-pipeline" in names, "healthy pipeline was lost when a sibling failed"
        assert len(rows) == 1, "malformed pipeline should have been skipped, not included"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListImagePipelines",
            )

        monkeypatch.setattr(image_builder_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_pipelines_region(REGION)

    def test_collect_image_pipelines_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListImagePipelines",
            )

        monkeypatch.setattr(image_builder_export, "_scan_pipelines_region", boom)

        pipelines, failed_regions = image_builder_export.collect_image_pipelines([REGION])

        assert pipelines == []
        assert [r for r, _ in failed_regions] == [REGION]

    def test_invalid_region_is_skipped_not_scanned(self):
        """An invalid region string is skipped locally, not sent to AWS."""
        rows = _scan_pipelines_region("not-a-region")
        assert rows == []
