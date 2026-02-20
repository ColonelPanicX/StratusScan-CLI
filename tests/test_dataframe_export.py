#!/usr/bin/env python3
"""
Comprehensive test suite for DataFrame preparation and export utilities.

This test module validates the prepare_dataframe_for_export() and sanitize_for_export()
functions added to utils.py as part of Improvement #6.
"""

import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Import utils
try:
    import utils
except ImportError:
    sys.path.append(str(Path(__file__).parent.absolute()))
    import utils

# Import required libraries (will be checked at runtime)
try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


class TestPrepareDataFrameForExport(unittest.TestCase):
    """Test cases for prepare_dataframe_for_export() function."""

    def setUp(self):
        """Set up test fixtures before each test."""
        if not PANDAS_AVAILABLE:
            self.skipTest("pandas not available")

    def test_timezone_removal_from_datetime_column(self):
        """Test that timezone information is removed from datetime columns."""
        # Create DataFrame with timezone-aware datetime
        df = pd.DataFrame({
            'timestamp': [
                datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
            ],
            'value': [100, 200]
        })

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df)

        # Verify timezone was removed
        self.assertIsInstance(result['timestamp'].iloc[0], (datetime, pd.Timestamp))
        # Check that tzinfo is None
        if hasattr(result['timestamp'].iloc[0], 'tzinfo'):
            self.assertIsNone(result['timestamp'].iloc[0].tzinfo)

    def test_nan_value_filling(self):
        """Test that NaN values are filled with the specified string."""
        # Create DataFrame with NaN values
        df = pd.DataFrame({
            'col1': [1, np.nan, 3],
            'col2': ['a', None, 'c']
        })

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df, fill_na='N/A')

        # Verify NaN values were filled
        self.assertEqual(result['col1'].iloc[1], 'N/A')
        self.assertEqual(result['col2'].iloc[1], 'N/A')

    def test_string_truncation(self):
        """Test that long strings are truncated to the specified length."""
        # Create DataFrame with long strings
        long_string = 'a' * 1500  # 1500 characters
        df = pd.DataFrame({
            'short': ['short text'],
            'long': [long_string]
        })

        # Prepare for export with truncation at 1000 chars
        result = utils.prepare_dataframe_for_export(df, truncate_strings=1000)

        # Verify long string was truncated
        self.assertEqual(len(result['short'].iloc[0]), 10)  # Unchanged
        self.assertTrue(len(result['long'].iloc[0]) <= 1003)  # 1000 + '...'
        self.assertTrue(result['long'].iloc[0].endswith('...'))

    def test_string_truncation_disabled(self):
        """Test that string truncation can be disabled."""
        # Create DataFrame with long string
        long_string = 'a' * 1500
        df = pd.DataFrame({
            'long': [long_string]
        })

        # Prepare for export with truncation disabled
        result = utils.prepare_dataframe_for_export(df, truncate_strings=None)

        # Verify string was not truncated
        self.assertEqual(len(result['long'].iloc[0]), 1500)

    def test_empty_dataframe_handling(self):
        """Test that empty DataFrames are handled gracefully."""
        # Create empty DataFrame
        df = pd.DataFrame()

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df)

        # Verify empty DataFrame is returned
        self.assertTrue(result.empty)

    def test_dataframe_with_no_datetime_columns(self):
        """Test that DataFrames without datetime columns are processed correctly."""
        # Create DataFrame with no datetime columns
        df = pd.DataFrame({
            'col1': [1, 2, 3],
            'col2': ['a', 'b', 'c']
        })

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df)

        # Verify DataFrame is unchanged (except NaN filling)
        self.assertEqual(len(result), 3)
        self.assertEqual(list(result.columns), ['col1', 'col2'])

    def test_dataframe_with_no_nan_values(self):
        """Test that DataFrames without NaN values are processed correctly."""
        # Create DataFrame with no NaN values
        df = pd.DataFrame({
            'col1': [1, 2, 3],
            'col2': ['a', 'b', 'c']
        })

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df)

        # Verify DataFrame values are unchanged
        pd.testing.assert_frame_equal(result, df.fillna('N/A'))

    def test_mixed_data_types(self):
        """Test DataFrame with mixed data types."""
        # Create DataFrame with mixed types
        df = pd.DataFrame({
            'int_col': [1, 2, np.nan],
            'str_col': ['a', 'b', None],
            'float_col': [1.1, 2.2, 3.3],
            'bool_col': [True, False, True]
        })

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df)

        # Verify all columns are present and NaN values filled
        self.assertEqual(len(result.columns), 4)
        self.assertEqual(result['int_col'].iloc[2], 'N/A')
        self.assertEqual(result['str_col'].iloc[2], 'N/A')

    def test_original_dataframe_not_modified(self):
        """Test that the original DataFrame is not modified."""
        # Create DataFrame
        df = pd.DataFrame({
            'col1': [1, np.nan, 3]
        })
        df_copy = df.copy()

        # Prepare for export
        result = utils.prepare_dataframe_for_export(df)

        # Verify original DataFrame is unchanged
        pd.testing.assert_frame_equal(df, df_copy)

    def test_custom_fill_na_value(self):
        """Test that custom NaN fill value works correctly."""
        # Create DataFrame with NaN
        df = pd.DataFrame({
            'col1': [1, np.nan, 3]
        })

        # Prepare with custom fill value
        result = utils.prepare_dataframe_for_export(df, fill_na='MISSING')

        # Verify custom value is used
        self.assertEqual(result['col1'].iloc[1], 'MISSING')


class TestSanitizeForExport(unittest.TestCase):
    """Test cases for sanitize_for_export() function."""

    def setUp(self):
        """Set up test fixtures before each test."""
        if not PANDAS_AVAILABLE:
            self.skipTest("pandas not available")

    def test_password_pattern_masking(self):
        """Test that password patterns are masked."""
        # Create DataFrame with password in tags
        df = pd.DataFrame({
            'Tags': [
                'env=prod,password=secret123',
                'env=dev,pwd=mypassword'
            ]
        })

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify passwords are masked
        self.assertIn('password***REDACTED***', result['Tags'].iloc[0])
        self.assertIn('pwd***REDACTED***', result['Tags'].iloc[1])
        self.assertNotIn('secret123', result['Tags'].iloc[0])
        self.assertNotIn('mypassword', result['Tags'].iloc[1])

    def test_api_key_pattern_masking(self):
        """Test that API key patterns are masked."""
        # Create DataFrame with API keys
        df = pd.DataFrame({
            'Config': [
                'api_key=AKIAIOSFODNN7EXAMPLE',
                'apikey: sk-proj-abc123xyz'
            ]
        })

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify API keys are masked
        self.assertIn('***REDACTED***', result['Config'].iloc[0])
        self.assertIn('***REDACTED***', result['Config'].iloc[1])
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', result['Config'].iloc[0])
        self.assertNotIn('sk-proj-abc123xyz', result['Config'].iloc[1])

    def test_multiple_patterns_in_same_cell(self):
        """Test that multiple sensitive patterns in the same cell are all masked."""
        # Create DataFrame with multiple secrets
        df = pd.DataFrame({
            'Tags': ['password=secret123,api_key=AKIAIOSFODNN7EXAMPLE,token=bearer123']
        })

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify all patterns are masked
        self.assertIn('***REDACTED***', result['Tags'].iloc[0])
        self.assertNotIn('secret123', result['Tags'].iloc[0])
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', result['Tags'].iloc[0])
        self.assertNotIn('bearer123', result['Tags'].iloc[0])

    def test_no_sensitive_data(self):
        """Test that DataFrames without sensitive data are unchanged."""
        # Create DataFrame with no sensitive data
        df = pd.DataFrame({
            'Tags': ['env=prod,app=web'],
            'Name': ['MyResource']
        })
        df_copy = df.copy()

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify DataFrame is unchanged
        pd.testing.assert_frame_equal(result, df_copy)

    def test_custom_patterns(self):
        """Test that custom sensitive patterns work correctly."""
        # Create DataFrame with custom sensitive data
        df = pd.DataFrame({
            'Config': ['ssn=123-45-6789,email=test@example.com']
        })

        # Define custom patterns
        custom_patterns = [r'(?i)(ssn)\s*[:=]\s*\S+', r'(?i)(email)\s*[:=]\s*\S+']

        # Sanitize with custom patterns
        result = utils.sanitize_for_export(df, sensitive_patterns=custom_patterns)

        # Verify custom patterns are masked
        self.assertIn('***REDACTED***', result['Config'].iloc[0])
        self.assertNotIn('123-45-6789', result['Config'].iloc[0])
        self.assertNotIn('test@example.com', result['Config'].iloc[0])

    def test_custom_mask_string(self):
        """Test that custom mask string works correctly."""
        # Create DataFrame with password
        df = pd.DataFrame({
            'Tags': ['password=secret123']
        })

        # Sanitize with custom mask
        result = utils.sanitize_for_export(df, mask_string='[HIDDEN]')

        # Verify custom mask is used
        self.assertIn('[HIDDEN]', result['Tags'].iloc[0])
        self.assertNotIn('***REDACTED***', result['Tags'].iloc[0])

    def test_empty_dataframe_handling(self):
        """Test that empty DataFrames are handled gracefully."""
        # Create empty DataFrame
        df = pd.DataFrame()

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify empty DataFrame is returned
        self.assertTrue(result.empty)

    def test_non_string_columns_ignored(self):
        """Test that non-string columns are not processed."""
        # Create DataFrame with mixed types
        df = pd.DataFrame({
            'int_col': [1, 2, 3],
            'str_col': ['password=secret', 'normal', 'api_key=key123']
        })

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify int column unchanged, string column sanitized
        self.assertEqual(result['int_col'].iloc[0], 1)
        self.assertIn('***REDACTED***', result['str_col'].iloc[0])

    def test_original_dataframe_not_modified(self):
        """Test that the original DataFrame is not modified."""
        # Create DataFrame
        df = pd.DataFrame({
            'Tags': ['password=secret123']
        })
        df_copy = df.copy()

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify original DataFrame is unchanged
        pd.testing.assert_frame_equal(df, df_copy)

    def test_case_insensitive_matching(self):
        """Test that pattern matching is case-insensitive."""
        # Create DataFrame with mixed case
        df = pd.DataFrame({
            'Config': [
                'PASSWORD=secret',
                'Password=secret',
                'password=secret'
            ]
        })

        # Sanitize for export
        result = utils.sanitize_for_export(df)

        # Verify all cases are masked
        for i in range(3):
            self.assertIn('***REDACTED***', result['Config'].iloc[i])
            self.assertNotIn('secret', result['Config'].iloc[i])


class TestIntegrationChaining(unittest.TestCase):
    """Integration tests for chaining both functions."""

    def setUp(self):
        """Set up test fixtures before each test."""
        if not PANDAS_AVAILABLE:
            self.skipTest("pandas not available")

    def test_chaining_both_functions(self):
        """Test that both functions can be chained together."""
        # Create DataFrame with both issues
        df = pd.DataFrame({
            'timestamp': [datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)],
            'config': ['password=secret123'],
            'value': [np.nan]
        })

        # Chain both functions
        result = utils.sanitize_for_export(
            utils.prepare_dataframe_for_export(df)
        )

        # Verify both transformations applied
        self.assertIn('***REDACTED***', result['config'].iloc[0])
        self.assertEqual(result['value'].iloc[0], 'N/A')
        if hasattr(result['timestamp'].iloc[0], 'tzinfo'):
            self.assertIsNone(result['timestamp'].iloc[0].tzinfo)

    def test_realistic_aws_data(self):
        """Test with realistic AWS EC2 tag data."""
        # Create DataFrame similar to EC2 export
        df = pd.DataFrame({
            'InstanceId': ['i-1234567890abcdef0'],
            'State': ['running'],
            'LaunchTime': [datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)],
            'Tags': ['Name=WebServer,Environment=prod,api_key=AKIAIOSFODNN7,password=dbpass123'],
            'Notes': ['Very long note that exceeds the truncation limit. ' * 100],
            'Cost': [np.nan]
        })

        # Apply full preparation pipeline
        result = utils.sanitize_for_export(
            utils.prepare_dataframe_for_export(df, truncate_strings=500)
        )

        # Verify all transformations
        self.assertIn('***REDACTED***', result['Tags'].iloc[0])
        self.assertNotIn('AKIAIOSFODNN7', result['Tags'].iloc[0])
        self.assertNotIn('dbpass123', result['Tags'].iloc[0])
        self.assertTrue(len(result['Notes'].iloc[0]) <= 503)  # 500 + '...'
        self.assertEqual(result['Cost'].iloc[0], 'N/A')


class TestExportFunctionIntegration(unittest.TestCase):
    """Test integration with save_dataframe_to_excel() function."""

    def setUp(self):
        """Set up test fixtures before each test."""
        if not PANDAS_AVAILABLE:
            self.skipTest("pandas not available")

    def test_prepare_parameter_exists(self):
        """Test that save_dataframe_to_excel() accepts prepare parameter."""
        # This test just verifies the parameter exists and doesn't cause errors
        import inspect

        # Check save_dataframe_to_excel signature
        sig = inspect.signature(utils.save_dataframe_to_excel)
        self.assertIn('prepare', sig.parameters)
        self.assertEqual(sig.parameters['prepare'].default, False)

    def test_save_multiple_prepare_parameter_exists(self):
        """Test that save_multiple_dataframes_to_excel() accepts prepare parameter."""
        import inspect

        # Check save_multiple_dataframes_to_excel signature
        sig = inspect.signature(utils.save_multiple_dataframes_to_excel)
        self.assertIn('prepare', sig.parameters)
        self.assertEqual(sig.parameters['prepare'].default, False)


def run_tests():
    """Run all test cases and print results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPrepareDataFrameForExport))
    suite.addTests(loader.loadTestsFromTestCase(TestSanitizeForExport))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegrationChaining))
    suite.addTests(loader.loadTestsFromTestCase(TestExportFunctionIntegration))

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == '__main__':
    import sys

    # Check dependencies
    if not PANDAS_AVAILABLE:
        print("ERROR: pandas is required to run these tests")
        print("Install with: pip install pandas numpy")
        sys.exit(1)

    # Run tests
    success = run_tests()
    sys.exit(0 if success else 1)
