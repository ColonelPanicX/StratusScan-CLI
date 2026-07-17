#!/usr/bin/env python3
"""
Moto-based tests for fsx_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's FSx support does not implement create_file_system /
describe_file_systems in a way this suite can rely on for happy-path
fixture creation, so the malformed-item and region-failure regression
cases below are driven via monkeypatch instead of real moto-created
file systems.
"""

import sys
from pathlib import Path

import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import fsx_export  # noqa: E402
from fsx_export import _scan_fsx_file_systems_region  # noqa: E402

REGION = "us-east-1"

_FAKE_FS_GOOD = {
    "FileSystemId": "fs-good",
    "FileSystemType": "WINDOWS",
    "Lifecycle": "AVAILABLE",
    "StorageCapacity": 300,
    "StorageType": "SSD",
    "VpcId": "vpc-12345",
}

_FAKE_FS_BAD = {
    "FileSystemId": "fs-bad",
    "FileSystemType": "WINDOWS",
    "Lifecycle": "AVAILABLE",
    "StorageCapacity": 300,
    "StorageType": "SSD",
    "VpcId": "vpc-12345",
}


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Yields a single page containing the given file systems."""

    def __init__(self, file_systems):
        self._file_systems = file_systems

    def paginate(self, **kwargs):
        yield {"FileSystems": self._file_systems}


class _FakeFsxClient:
    def __init__(self, file_systems):
        self._file_systems = file_systems

    def get_paginator(self, name):
        assert name == "describe_file_systems"
        return _FakePaginator(self._file_systems)


class TestScanFsxFileSystemsRegion:
    """Happy-path collection, driven via monkeypatch since moto FSx support
    is limited."""

    def test_collects_file_systems(self, monkeypatch):
        monkeypatch.setattr(
            fsx_export.utils,
            "get_boto3_client",
            lambda service, region_name=None: _FakeFsxClient([_FAKE_FS_GOOD]),
        )

        rows = _scan_fsx_file_systems_region(REGION)

        ids = {row["File System ID"] for row in rows}
        assert "fs-good" in ids

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        # moto does support the fsx client existing even without real FSx
        # CRUD support, so this exercises the "no file systems" path via a
        # real (empty) paginator.
        rows = _scan_fsx_file_systems_region(REGION)
        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One file system that fails to process must not discard the whole
        region."""
        monkeypatch.setattr(
            fsx_export.utils,
            "get_boto3_client",
            lambda service, region_name=None: _FakeFsxClient([_FAKE_FS_GOOD, _FAKE_FS_BAD]),
        )

        original = fsx_export._build_filesystem_row

        def raise_for_bad(fs, region, pricing):
            if fs.get("FileSystemId") == "fs-bad":
                raise KeyError("SomeUnexpectedField")
            return original(fs, region, pricing)

        monkeypatch.setattr(fsx_export, "_build_filesystem_row", raise_for_bad)

        rows = _scan_fsx_file_systems_region(REGION)

        ids = {row["File System ID"] for row in rows}
        assert "fs-good" in ids, "healthy file system was lost when a sibling failed"
        assert "fs-bad" not in ids, "malformed file system should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeFileSystems",
            )

        monkeypatch.setattr(fsx_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_fsx_file_systems_region(REGION)

    def test_collect_fsx_file_systems_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeFileSystems",
            )

        monkeypatch.setattr(fsx_export, "_scan_fsx_file_systems_region", boom)

        file_systems, failed_regions = fsx_export.collect_fsx_file_systems([REGION])

        assert file_systems == []
        assert [r for r, _ in failed_regions] == [REGION]
