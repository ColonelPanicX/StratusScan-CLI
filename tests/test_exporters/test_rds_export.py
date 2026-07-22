#!/usr/bin/env python3
"""
Moto-based tests for rds_export.py.

Covers:
- get_rds_instances()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import rds_export  # noqa: E402
from rds_export import get_rds_instances  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestGetRdsInstances:
    """Tests for get_rds_instances()."""

    @mock_aws
    def test_created_instance_appears_in_results(self):
        """A newly created RDS instance is returned by the collector."""
        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="test-db-instance",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )

        result = get_rds_instances(REGION)

        assert isinstance(result, list)
        assert len(result) >= 1
        assert any(row["DB Identifier"] == "test-db-instance" for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="col-check-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )

        result = get_rds_instances(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("DB Identifier", "Engine", "Region", "Size"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_engine_is_preserved(self):
        """The engine name from the created instance appears in results."""
        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="engine-check-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )

        result = get_rds_instances(REGION)

        row = next(r for r in result if r["DB Identifier"] == "engine-check-db")
        assert "postgres" in row["Engine"].lower()

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no RDS instances returns an empty list."""
        result = get_rds_instances(REGION)
        assert result == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 audit: RDS data silently lost because a
    collection error was swallowed to an empty list, indistinguishable from a
    genuinely empty region. See .collab/audit/07.15.2026-rds-silent-collection-failure.md
    """

    @mock_aws
    def test_malformed_instance_is_skipped_not_fatal(self, monkeypatch):
        """
        One instance that fails to process must not discard the whole region's
        results — the healthy instances are still collected.
        """
        rds = boto3.client("rds", region_name=REGION)
        for name in ("good-db", "bad-db"):
            rds.create_db_instance(
                DBInstanceIdentifier=name,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="admin",
                MasterUserPassword="password123",
                AllocatedStorage=20,
            )

        original = rds_export._build_instance_data

        def raise_for_bad(instance, *args, **kwargs):
            if instance.get("DBInstanceIdentifier") == "bad-db":
                raise KeyError("SomeEngineSpecificField")
            return original(instance, *args, **kwargs)

        monkeypatch.setattr(rds_export, "_build_instance_data", raise_for_bad)

        result = get_rds_instances(REGION)

        ids = {row["DB Identifier"] for row in result}
        assert "good-db" in ids, "healthy instance was lost when a sibling failed"
        assert "bad-db" not in ids, "malformed instance should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeDBInstances",
            )

        monkeypatch.setattr(rds_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_rds_instances(REGION)
