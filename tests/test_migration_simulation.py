#!/usr/bin/env python3
"""
Tests for core utils DataFrame and error-handling functions.

Covers functions that have no other test coverage:
- utils.prepare_dataframe_for_export()
- utils.sanitize_for_export()
- utils.aws_error_handler()
"""

import pytest
from pathlib import Path
import sys

# Add parent directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent.parent))
import utils

pd = pytest.importorskip("pandas")


class TestPrepareDataframeForExport:
    """Test utils.prepare_dataframe_for_export()."""

    def test_nan_replaced_with_na_string(self):
        """None values are replaced with 'N/A' by default."""
        df = pd.DataFrame([{"A": "value", "B": None}])
        result = utils.prepare_dataframe_for_export(df)
        assert result["B"].iloc[0] == "N/A"

    def test_valid_values_preserved(self):
        """Non-null values are not modified."""
        df = pd.DataFrame([{"A": "hello", "B": "world"}])
        result = utils.prepare_dataframe_for_export(df)
        assert result["A"].iloc[0] == "hello"
        assert result["B"].iloc[0] == "world"

    def test_timezone_stripped_from_datetime_column(self):
        """Timezone-aware datetimes are converted to naive datetimes."""
        df = pd.DataFrame([{
            "ts": pd.Timestamp("2025-01-01 10:00:00", tz="UTC"),
        }])
        result = utils.prepare_dataframe_for_export(df)
        # After stripping, dtype should be timezone-naive
        assert result["ts"].dt.tz is None

    def test_empty_dataframe_returned_unchanged(self):
        """Empty DataFrames are returned without error."""
        df = pd.DataFrame()
        result = utils.prepare_dataframe_for_export(df)
        assert result.empty

    def test_original_dataframe_not_mutated(self):
        """Input DataFrame is not modified in-place."""
        df = pd.DataFrame([{"A": None, "B": "x"}])
        original_val = df["A"].iloc[0]
        utils.prepare_dataframe_for_export(df)
        assert pd.isna(df["A"].iloc[0]) == pd.isna(original_val)

    def test_multiple_rows(self):
        """All rows are processed, not just the first."""
        df = pd.DataFrame([
            {"A": None},
            {"A": None},
            {"A": "present"},
        ])
        result = utils.prepare_dataframe_for_export(df)
        assert result["A"].iloc[0] == "N/A"
        assert result["A"].iloc[1] == "N/A"
        assert result["A"].iloc[2] == "present"


class TestSanitizeForExport:
    """Test utils.sanitize_for_export()."""

    def test_password_pattern_masked(self):
        """Values matching password: pattern are redacted."""
        df = pd.DataFrame([{
            "Tags": "Environment:Production, password:SuperSecret123, Owner:TeamA"
        }])
        result = utils.sanitize_for_export(df)
        assert "SuperSecret123" not in result["Tags"].iloc[0]

    def test_api_key_pattern_masked(self):
        """Values matching api_key= pattern are redacted."""
        df = pd.DataFrame([{
            "Config": "host=localhost, api_key=sk-1234567890abcdef, port=5432"
        }])
        result = utils.sanitize_for_export(df)
        assert "sk-1234567890abcdef" not in result["Config"].iloc[0]

    def test_access_key_pattern_masked(self):
        """Values matching AccessKey: pattern are redacted."""
        df = pd.DataFrame([{
            "Tags": "Environment:Development, AccessKey:AKIAIOSFODNN7EXAMPLE"
        }])
        result = utils.sanitize_for_export(df)
        assert "AKIAIOSFODNN7EXAMPLE" not in result["Tags"].iloc[0]

    def test_safe_field_unchanged(self):
        """Values with no sensitive patterns are not modified."""
        df = pd.DataFrame([{"SafeField": "This is safe data"}])
        result = utils.sanitize_for_export(df)
        assert result["SafeField"].iloc[0] == "This is safe data"

    def test_original_dataframe_not_mutated(self):
        """Input DataFrame is not modified in-place."""
        original_tags = "password:secret123"
        df = pd.DataFrame([{"Tags": original_tags}])
        utils.sanitize_for_export(df)
        assert df["Tags"].iloc[0] == original_tags

    def test_empty_dataframe_returned_unchanged(self):
        """Empty DataFrames are returned without error."""
        df = pd.DataFrame()
        result = utils.sanitize_for_export(df)
        assert result.empty


class TestAwsErrorHandler:
    """Test utils.aws_error_handler() decorator."""

    def test_exception_returns_default_list(self):
        """Exception in decorated function returns the default_return value."""
        @utils.aws_error_handler("Test operation", default_return=[])
        def failing():
            raise ValueError("Simulated AWS error")

        result = failing()
        assert result == []

    def test_success_returns_actual_value(self):
        """Decorated function that succeeds returns its actual return value."""
        @utils.aws_error_handler("Successful operation", default_return=[])
        def succeeding():
            return [{"id": 1, "name": "test"}]

        result = succeeding()
        assert result == [{"id": 1, "name": "test"}]

    def test_default_return_dict(self):
        """Default return value of {} is used on exception."""
        @utils.aws_error_handler("Dict operation", default_return={})
        def failing():
            raise RuntimeError("error")

        result = failing()
        assert result == {}

    def test_default_return_none(self):
        """Default return value of None is used on exception."""
        @utils.aws_error_handler("None operation", default_return=None)
        def failing():
            raise RuntimeError("error")

        result = failing()
        assert result is None

    def test_decorated_function_remains_callable(self):
        """Decorated function is still a callable."""
        @utils.aws_error_handler("Test", default_return=[])
        def my_func():
            return []

        assert callable(my_func)
