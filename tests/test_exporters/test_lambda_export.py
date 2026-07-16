#!/usr/bin/env python3
"""
Moto-based tests for lambda_export.py.

Covers:
- collect_lambda_functions_for_region()
"""

import io
import json
import sys
import zipfile
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import lambda_export  # noqa: E402
from lambda_export import collect_lambda_functions_for_region  # noqa: E402

REGION = "us-east-1"
ROLE_NAME = "test-lambda-role"

_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _lambda_role_arn():
    """Create (or reuse) an IAM role Lambda can assume, and return its ARN."""
    iam = boto3.client("iam", region_name=REGION)
    try:
        response = iam.get_role(RoleName=ROLE_NAME)
    except botocore.exceptions.ClientError:
        response = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        )
    return response["Role"]["Arn"]


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _zip_bytes():
    """Build a minimal in-memory Lambda deployment package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return event\n")
    buf.seek(0)
    return buf.read()


def _create_function(client, name):
    client.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=_lambda_role_arn(),
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_bytes()},
        Description="test function",
        Timeout=30,
        MemorySize=128,
        Publish=True,
    )


class TestCollectLambdaFunctionsForRegion:
    """Tests for collect_lambda_functions_for_region()."""

    @mock_aws
    def test_created_function_appears_in_results(self):
        """A newly created Lambda function is returned by the collector."""
        client = boto3.client("lambda", region_name=REGION)
        _create_function(client, "test-function")

        result = collect_lambda_functions_for_region(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["Function Name"] == "test-function" for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        client = boto3.client("lambda", region_name=REGION)
        _create_function(client, "col-check-fn")

        result = collect_lambda_functions_for_region(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Function Name", "Runtime", "Region", "Handler"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_runtime_is_preserved(self):
        """The runtime from the created function appears in results."""
        client = boto3.client("lambda", region_name=REGION)
        _create_function(client, "runtime-check-fn")

        result = collect_lambda_functions_for_region(REGION)

        row = next(r for r in result if r["Function Name"] == "runtime-check-fn")
        assert "python3.12" in row["Runtime"]

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no Lambda functions returns an empty list."""
        result = collect_lambda_functions_for_region(REGION)
        assert result == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 audits: exporters
    silently lost data because a collection error was swallowed to an empty
    list, indistinguishable from a genuinely empty region. See
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One function that fails to process must not discard the whole
        region's results — the healthy function is still collected.
        """
        client = boto3.client("lambda", region_name=REGION)
        _create_function(client, "good-fn")
        _create_function(client, "bad-fn")

        original = lambda_export._build_function_row

        def raise_for_bad(func, region):
            if func.get("FunctionName") == "bad-fn":
                raise KeyError("SomeUnexpectedField")
            return original(func, region)

        monkeypatch.setattr(lambda_export, "_build_function_row", raise_for_bad)

        result = collect_lambda_functions_for_region(REGION)

        names = {row["Function Name"] for row in result}
        assert "good-fn" in names, "healthy function was lost when a sibling failed"
        assert "bad-fn" not in names, "malformed function should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListFunctions",
            )

        monkeypatch.setattr(lambda_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_lambda_functions_for_region(REGION)
