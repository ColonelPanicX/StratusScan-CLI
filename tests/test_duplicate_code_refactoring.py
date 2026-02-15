#!/usr/bin/env python3
"""
Test Suite for Duplicate Code Refactoring Utilities

This test module validates the three new utility functions added to utils.py:
- ensure_dependencies()
- get_account_info()
- prompt_region_selection()

These functions eliminate 200-300 lines of duplicate code across StratusScan scripts.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock, call
from pathlib import Path

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    sys.path.append(str(script_dir))
    import utils


class TestEnsureDependencies(unittest.TestCase):
    """Test cases for ensure_dependencies() function."""

    @patch('builtins.__import__')
    @patch('utils.log_info')
    @patch('utils.log_success')
    def test_all_dependencies_installed(self, mock_log_success, mock_log_info, mock_import):
        """Test when all dependencies are already installed."""
        # All packages import successfully
        mock_import.side_effect = lambda pkg: None

        result = utils.ensure_dependencies('pandas', 'openpyxl', 'boto3')

        self.assertTrue(result)
        # Should log OK for each package (3 packages = 3 log_info calls)
        self.assertEqual(mock_log_info.call_count, 3)
        # Should have final success message
        mock_log_success.assert_called_once_with("All required dependencies are installed")

    @patch('builtins.__import__')
    @patch('builtins.input', return_value='n')
    @patch('utils.log_warning')
    @patch('utils.log_error')
    def test_missing_dependencies_user_declines(self, mock_log_error, mock_log_warning,
                                                mock_input, mock_import):
        """Test when dependencies are missing and user declines installation."""
        # pandas missing, others installed
        def import_side_effect(pkg):
            if pkg == 'pandas':
                raise ImportError(f"No module named '{pkg}'")
            return None

        mock_import.side_effect = import_side_effect

        result = utils.ensure_dependencies('pandas', 'openpyxl')

        self.assertFalse(result)
        mock_log_warning.assert_called()
        mock_log_error.assert_called_with("Cannot continue without required packages")

    @patch('builtins.__import__')
    @patch('builtins.input', return_value='y')
    @patch('utils.subprocess.check_call')
    @patch('utils.log_success')
    @patch('utils.log_info')
    def test_missing_dependencies_successful_install(self, mock_log_info, mock_log_success,
                                                     mock_subprocess, mock_input, mock_import):
        """Test successful installation of missing dependencies."""
        # First call: pandas missing, second call (after install): all present
        call_count = {'count': 0}

        def import_side_effect(pkg):
            if pkg == 'pandas' and call_count['count'] == 0:
                call_count['count'] += 1
                raise ImportError(f"No module named '{pkg}'")
            return None

        mock_import.side_effect = import_side_effect
        mock_subprocess.return_value = 0

        result = utils.ensure_dependencies('pandas', 'openpyxl')

        self.assertTrue(result)
        mock_subprocess.assert_called_once()
        # Should have success message for installation
        self.assertGreaterEqual(mock_log_success.call_count, 1)

    @patch('builtins.__import__')
    @patch('builtins.input', return_value='y')
    @patch('utils.subprocess.check_call')
    @patch('utils.log_error')
    def test_installation_fails(self, mock_log_error, mock_subprocess, mock_input, mock_import):
        """Test when package installation fails."""
        # pandas missing
        def import_side_effect(pkg):
            if pkg == 'pandas':
                raise ImportError(f"No module named '{pkg}'")
            return None

        mock_import.side_effect = import_side_effect
        mock_subprocess.side_effect = Exception("Installation failed")

        result = utils.ensure_dependencies('pandas')

        self.assertFalse(result)
        mock_log_error.assert_called()


class TestGetAccountInfo(unittest.TestCase):
    """Test cases for get_account_info() function."""

    def setUp(self):
        """Clear the LRU cache before each test."""
        utils.get_account_info.cache_clear()

    @patch('utils.get_boto3_client')
    @patch('utils.get_account_name')
    def test_successful_account_retrieval(self, mock_get_name, mock_client):
        """Test successful retrieval of account information."""
        # Mock STS client
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.return_value = mock_sts

        # Mock account name mapping
        mock_get_name.return_value = 'PROD-ACCOUNT'

        account_id, account_name = utils.get_account_info()

        self.assertEqual(account_id, '123456789012')
        self.assertEqual(account_name, 'PROD-ACCOUNT')
        mock_client.assert_called_once_with('sts')

    @patch('utils.get_boto3_client')
    @patch('utils.get_account_name')
    def test_account_info_caching(self, mock_get_name, mock_client):
        """Test that account info is cached (LRU cache)."""
        # Mock STS client
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.return_value = mock_sts
        mock_get_name.return_value = 'PROD-ACCOUNT'

        # Call twice
        result1 = utils.get_account_info()
        result2 = utils.get_account_info()

        # Should be same result
        self.assertEqual(result1, result2)
        # But boto3 client should only be called once (cached)
        mock_client.assert_called_once()

    @patch('utils.get_boto3_client')
    @patch('utils.log_error')
    def test_account_retrieval_failure(self, mock_log_error, mock_client):
        """Test handling of errors during account retrieval."""
        # Mock STS client failure
        mock_client.side_effect = Exception("No credentials")

        account_id, account_name = utils.get_account_info()

        self.assertEqual(account_id, 'UNKNOWN')
        self.assertEqual(account_name, 'UNKNOWN-ACCOUNT')
        mock_log_error.assert_called()


class TestPromptRegionSelection(unittest.TestCase):
    """Test cases for prompt_region_selection() function."""

    @patch('builtins.input', return_value='all')
    @patch('utils.get_default_regions')
    @patch('utils.log_info')
    def test_select_all_regions(self, mock_log_info, mock_get_regions, mock_input):
        """Test selecting all regions."""
        mock_get_regions.return_value = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1']

        regions = utils.prompt_region_selection()

        self.assertEqual(len(regions), 4)
        self.assertIn('us-east-1', regions)
        mock_log_info.assert_called()

    @patch('builtins.input', return_value='us-east-1')
    @patch('utils.validate_aws_region')
    @patch('utils.log_info')
    def test_select_single_valid_region(self, mock_log_info, mock_validate, mock_input):
        """Test selecting a single valid region."""
        mock_validate.return_value = True

        regions = utils.prompt_region_selection()

        self.assertEqual(regions, ['us-east-1'])
        mock_validate.assert_called_once_with('us-east-1')

    @patch('builtins.input', return_value='invalid-region')
    @patch('utils.validate_aws_region')
    @patch('utils.get_default_regions')
    @patch('utils.log_warning')
    def test_invalid_region_fallback(self, mock_log_warning, mock_get_regions,
                                    mock_validate, mock_input):
        """Test fallback to default regions when invalid region provided."""
        mock_validate.return_value = False
        mock_get_regions.return_value = ['us-east-1', 'us-west-2']

        regions = utils.prompt_region_selection()

        self.assertEqual(regions, ['us-east-1', 'us-west-2'])
        mock_log_warning.assert_called()

    @patch('builtins.input', return_value='all')
    def test_custom_default_regions(self, mock_input):
        """Test using custom default regions."""
        custom_regions = ['us-gov-west-1', 'us-gov-east-1']

        regions = utils.prompt_region_selection(default_regions=custom_regions)

        self.assertEqual(regions, custom_regions)

    @patch('builtins.input', return_value='us-west-2')
    @patch('utils.validate_aws_region')
    def test_disallow_all_option(self, mock_validate, mock_input):
        """Test when allow_all is False."""
        mock_validate.return_value = True

        regions = utils.prompt_region_selection(allow_all=False)

        self.assertEqual(regions, ['us-west-2'])

    @patch('builtins.input', return_value='eu-west-1')
    @patch('utils.validate_aws_region')
    @patch('utils.log_info')
    def test_custom_prompt_message(self, mock_log_info, mock_validate, mock_input):
        """Test custom prompt message."""
        mock_validate.return_value = True

        regions = utils.prompt_region_selection(
            prompt_message="Select region for RDS export:"
        )

        self.assertEqual(regions, ['eu-west-1'])


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple utility functions."""

    @patch('utils.get_boto3_client')
    @patch('utils.get_account_name')
    @patch('builtins.__import__')
    def test_typical_script_flow(self, mock_import, mock_get_name, mock_client):
        """Test typical script flow using all three utility functions."""
        # Clear cache
        utils.get_account_info.cache_clear()

        # Setup mocks
        mock_import.side_effect = lambda pkg: None  # All dependencies installed

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.return_value = mock_sts
        mock_get_name.return_value = 'TEST-ACCOUNT'

        # Typical script flow
        # 1. Check dependencies
        deps_ok = utils.ensure_dependencies('pandas', 'boto3')
        self.assertTrue(deps_ok)

        # 2. Get account info
        account_id, account_name = utils.get_account_info()
        self.assertEqual(account_id, '123456789012')
        self.assertEqual(account_name, 'TEST-ACCOUNT')

        # 3. Region selection would be interactive, so we skip it in this test


def run_tests():
    """Run all tests and return results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEnsureDependencies))
    suite.addTests(loader.loadTestsFromTestCase(TestGetAccountInfo))
    suite.addTests(loader.loadTestsFromTestCase(TestPromptRegionSelection))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == '__main__':
    print("=" * 80)
    print("STRATUSSCAN DUPLICATE CODE REFACTORING TEST SUITE")
    print("=" * 80)
    print("\nTesting three new utility functions:")
    print("  1. ensure_dependencies() - Dependency checking and installation")
    print("  2. get_account_info() - AWS account ID and name retrieval")
    print("  3. prompt_region_selection() - Interactive region selection")
    print("\n" + "=" * 80 + "\n")

    result = run_tests()

    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\nALL TESTS PASSED!")
        sys.exit(0)
    else:
        print("\nSOME TESTS FAILED!")
        sys.exit(1)
