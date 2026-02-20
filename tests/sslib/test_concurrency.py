"""
Unit tests for sslib.concurrency — concurrent region scanning and pagination.
"""

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sslib.concurrency import (
    ConcurrentScanningError,
    _scan_regions_sequential,
    build_dataframe_in_batches,
    paginate_with_progress,
    scan_regions_concurrent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _noop_config():
    return ({}, {})


# ---------------------------------------------------------------------------
# ConcurrentScanningError
# ---------------------------------------------------------------------------


class TestConcurrentScanningError:
    def test_is_exception_subclass(self):
        assert issubclass(ConcurrentScanningError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(ConcurrentScanningError):
            raise ConcurrentScanningError("too many errors")


# ---------------------------------------------------------------------------
# _scan_regions_sequential
# ---------------------------------------------------------------------------


class TestScanRegionsSequential:
    def test_calls_function_for_each_region(self):
        called_regions = []

        def scan(region):
            called_regions.append(region)
            return f"result-{region}"

        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        results = _scan_regions_sequential(regions, scan, show_progress=False)

        assert called_regions == regions
        assert results == ["result-us-east-1", "result-us-west-2", "result-eu-west-1"]

    def test_continues_on_error(self):
        def scan(region):
            if region == "us-west-2":
                raise RuntimeError("API error")
            return f"ok-{region}"

        results = _scan_regions_sequential(["us-east-1", "us-west-2", "eu-west-1"], scan, False)
        # Error region is skipped; others succeed
        assert len(results) == 2
        assert "ok-us-east-1" in results

    def test_empty_regions_list(self):
        results = _scan_regions_sequential([], lambda r: r, False)
        assert results == []


# ---------------------------------------------------------------------------
# scan_regions_concurrent
# ---------------------------------------------------------------------------


class TestScanRegionsConcurrent:
    def test_returns_results_for_all_regions(self):
        with patch("sslib.concurrency.get_config", return_value=_noop_config()):
            results = scan_regions_concurrent(
                ["us-east-1", "us-west-2"],
                lambda r: f"data-{r}",
                max_workers=2,
                show_progress=False,
                fallback_on_error=False,
            )
        assert len(results) == 2

    def test_disabled_config_falls_back_to_sequential(self):
        config_with_disabled = {"advanced_settings": {"concurrent_scanning": {"enabled": False}}}
        called = []

        with patch("sslib.concurrency.get_config", return_value=({}, config_with_disabled)):
            with patch("sslib.concurrency._scan_regions_sequential", side_effect=lambda r, f, p: []) as mock_seq:
                scan_regions_concurrent(
                    ["us-east-1"],
                    lambda r: r,
                    show_progress=False,
                )
                mock_seq.assert_called_once()

    def test_fallback_on_all_errors(self):
        """If every worker fails, fallback_on_error triggers sequential."""
        def always_fail(region):
            raise RuntimeError("boom")

        with patch("sslib.concurrency.get_config", return_value=_noop_config()):
            # With fallback enabled, no exception is raised
            results = scan_regions_concurrent(
                ["r1", "r2", "r3", "r4"],
                always_fail,
                max_workers=4,
                show_progress=False,
                fallback_on_error=True,
            )
        # Sequential also fails silently per _scan_regions_sequential behaviour
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# paginate_with_progress
# ---------------------------------------------------------------------------


class TestPaginateWithProgress:
    def test_yields_all_pages(self):
        page1 = {"Items": [1, 2]}
        page2 = {"Items": [3, 4]}

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = iter([page1, page2])

        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator

        with patch("sslib.concurrency.get_config", return_value=_noop_config()):
            pages = list(paginate_with_progress(mock_client, "list_items", "items"))

        assert pages == [page1, page2]

    def test_passes_kwargs_to_paginator(self):
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = iter([{}])
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator

        with patch("sslib.concurrency.get_config", return_value=_noop_config()):
            list(paginate_with_progress(mock_client, "list_items", "items", Bucket="my-bucket"))

        mock_paginator.paginate.assert_called_once_with(Bucket="my-bucket")


# ---------------------------------------------------------------------------
# build_dataframe_in_batches
# ---------------------------------------------------------------------------


class TestBuildDataframeInBatches:
    def test_small_dataset_no_batching(self):
        data = [{"a": i} for i in range(10)]
        df = build_dataframe_in_batches(data, batch_size=100)
        assert len(df) == 10
        assert list(df.columns) == ["a"]

    def test_large_dataset_batched(self):
        data = [{"val": i} for i in range(2500)]
        df = build_dataframe_in_batches(data, batch_size=1000)
        assert len(df) == 2500
        assert df["val"].tolist() == list(range(2500))

    def test_empty_data(self):
        df = build_dataframe_in_batches([], batch_size=100)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0

    def test_exact_batch_boundary(self):
        data = [{"x": i} for i in range(1000)]
        df = build_dataframe_in_batches(data, batch_size=1000)
        assert len(df) == 1000
