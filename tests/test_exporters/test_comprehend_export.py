#!/usr/bin/env python3
"""
Tests for comprehend_export.py.

Focus: the silent-collection-failure contract (Tier-2A) against the ENTITY
RECOGNIZERS scope. See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's Comprehend support does not cover list_entity_recognizers /
create_entity_recognizer, so all three regression cases here use monkeypatch
to fake the boto3 client/paginator rather than moto's @mock_aws — no real
AWS resources are created or contacted.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import comprehend_export  # noqa: E402
from comprehend_export import _scan_recognizers_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Fake paginator that yields a single page with the given recognizers."""

    def __init__(self, recognizers):
        self._recognizers = recognizers

    def paginate(self, **kwargs):
        yield {"EntityRecognizerPropertiesList": self._recognizers}


class _FakeComprehendClient:
    """Fake Comprehend client exposing only what list_entity_recognizers needs."""

    def __init__(self, recognizers):
        self._recognizers = recognizers

    def get_paginator(self, operation_name):
        assert operation_name == "list_entity_recognizers"
        return _FakePaginator(self._recognizers)


def _fake_recognizer(name, language_code="en"):
    """Build a minimal fake EntityRecognizerPropertiesList entry."""
    return {
        "EntityRecognizerArn": f"arn:aws:comprehend:{REGION}:123456789012:entity-recognizer/{name}",
        "LanguageCode": language_code,
        "Status": "TRAINED",
    }


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One recognizer that fails to process must not discard the whole region."""
        good = _fake_recognizer("good-recognizer")
        bad = _fake_recognizer("bad-recognizer")

        fake_client = _FakeComprehendClient([good, bad])
        monkeypatch.setattr(
            comprehend_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        original = comprehend_export._build_recognizer_row

        def raise_for_bad(recognizer, region):
            if recognizer.get("EntityRecognizerArn", "").endswith("bad-recognizer"):
                raise KeyError("SomeUnexpectedField")
            return original(recognizer, region)

        monkeypatch.setattr(comprehend_export, "_build_recognizer_row", raise_for_bad)

        rows = _scan_recognizers_region(REGION)

        names = {row["Recognizer Name"] for row in rows}
        assert "good-recognizer" in names, "healthy recognizer was lost when a sibling failed"
        assert "bad-recognizer" not in names, "malformed recognizer should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListEntityRecognizers",
            )

        monkeypatch.setattr(comprehend_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_recognizers_region(REGION)

    def test_collect_entity_recognizers_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListEntityRecognizers",
            )

        monkeypatch.setattr(comprehend_export, "_scan_recognizers_region", boom)

        recognizers, failed_regions = comprehend_export.collect_entity_recognizers([REGION])

        assert recognizers == []
        assert [r for r, _ in failed_regions] == [REGION]
