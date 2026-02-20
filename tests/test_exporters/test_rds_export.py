#!/usr/bin/env python3
"""
Moto-based tests for rds-export.py.

Covers:
- get_rds_instances()
"""

import importlib.util
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

# ---------------------------------------------------------------------------
# Load exporter module
# ---------------------------------------------------------------------------

_scripts_dir = Path(__file__).parent.parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location(
    "rds_export", _scripts_dir / "rds-export.py"
)
_rds_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rds_export)

get_rds_instances = _rds_export.get_rds_instances

REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

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
        db_ids = [row["DB Identifier"] for row in result]
        assert "test-db-instance" in db_ids

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
