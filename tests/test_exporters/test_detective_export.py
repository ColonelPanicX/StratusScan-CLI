#!/usr/bin/env python3
"""
Moto-based tests for detective_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's AWS Detective support is limited (no ``create_graph``/member
management surface as of this writing), so cases (b) and (c) below exercise
the contract via monkeypatch rather than a real moto-backed Detective graph.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import detective_export  # noqa: E402
from detective_export import _scan_graphs_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakeGraphsClient:
    """Fake Detective client returning two graphs, one of which is malformed."""

    def list_graphs(self):
        return {
            "GraphList": [
                {"Arn": "arn:aws:detective:us-east-1:111122223333:graph:good-graph"},
                {"Arn": "arn:aws:detective:us-east-1:111122223333:graph:bad-graph"},
            ]
        }

    def list_members(self, **kwargs):
        return {"MemberDetails": []}

    def list_tags_for_resource(self, **kwargs):
        return {"Tags": {}}


class _FakeEmptyGraphsClient:
    """Fake Detective client with no graphs (Detective not enabled)."""

    def list_graphs(self):
        return {"GraphList": []}


class TestScanGraphsRegion:
    """Happy-path collection.

    moto has no working AWS Detective backend (``ListGraphs`` responds "Not
    yet implemented"), so these exercise the contract via a fake client
    rather than @mock_aws.
    """

    def test_empty_region_returns_empty_list(self, monkeypatch):
        # No graphs — Detective is not enabled in this region.
        monkeypatch.setattr(
            detective_export.utils,
            "get_boto3_client",
            lambda *a, **k: _FakeEmptyGraphsClient(),
        )

        rows = _scan_graphs_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One graph that fails to process must not discard the whole region."""
        fake_client = _FakeGraphsClient()
        monkeypatch.setattr(
            detective_export.utils, "get_boto3_client", lambda *a, **k: fake_client
        )

        original = detective_export._build_graph_row

        def raise_for_bad(graph, region, client):
            if graph.get("Arn", "").endswith("bad-graph"):
                raise KeyError("SomeUnexpectedField")
            return original(graph, region, client)

        monkeypatch.setattr(detective_export, "_build_graph_row", raise_for_bad)

        rows = _scan_graphs_region(REGION)

        arns = {row["Graph ARN"] for row in rows}
        assert any(a.endswith("good-graph") for a in arns), (
            "healthy graph was lost when a sibling failed"
        )
        assert not any(a.endswith("bad-graph") for a in arns), (
            "malformed graph should have been skipped"
        )

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListGraphs",
            )

        monkeypatch.setattr(detective_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_graphs_region(REGION)

    def test_collect_graphs_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListGraphs",
            )

        monkeypatch.setattr(detective_export, "_scan_graphs_region", boom)

        graphs, failed_regions = detective_export.collect_graphs([REGION])

        assert graphs == []
        assert [r for r, _ in failed_regions] == [REGION]
