#!/usr/bin/env python3
"""
Test suite for utils.py core utility functions.

Tests cover:
- Account name mapping
- File naming conventions
- Configuration loading
- Region validation
- Logging setup
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

# Add parent directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent.parent))
import utils
import sslib.config
import sslib.aws_client


class TestMaskAccountId:
    """Test mask_account_id() helper for safe log output."""

    def test_standard_account_id(self):
        assert utils.mask_account_id('123456789012') == '...9012'

    def test_short_id_returned_unchanged(self):
        assert utils.mask_account_id('123') == '123'

    def test_empty_string(self):
        assert utils.mask_account_id('') == ''

    def test_exactly_four_chars(self):
        assert utils.mask_account_id('1234') == '...1234'

    def test_last_four_are_used(self):
        assert utils.mask_account_id('000000009999') == '...9999'


class TestAccountMapping:
    """Test account ID to name mapping functions."""

    def test_get_account_name_with_mapping(self):
        """Test retrieval of account name when mapping exists."""
        with patch.object(sslib.config, 'ACCOUNT_MAPPINGS', {'123456789012': 'PROD-ACCOUNT'}):
            result = utils.get_account_name('123456789012')
            assert result == 'PROD-ACCOUNT'

    def test_get_account_name_with_default(self):
        """Test fallback to default when no mapping exists."""
        with patch.object(sslib.config, 'ACCOUNT_MAPPINGS', {}):
            result = utils.get_account_name('999999999999', default='TEST-DEFAULT')
            assert result == 'TEST-DEFAULT'

    def test_get_account_name_default_fallback(self):
        """Test default fallback value is used."""
        with patch.object(sslib.config, 'ACCOUNT_MAPPINGS', {}):
            result = utils.get_account_name('999999999999')
            assert result == 'UNKNOWN-ACCOUNT'


class TestFileNaming:
    """Test file naming convention functions."""

    def test_create_export_filename_basic(self):
        """Test basic filename generation."""
        # Test
        filename = utils.create_export_filename(
            account_name='PROD-ACCOUNT',
            resource_type='ec2',
            suffix='running'
        )

        # Verify structure
        assert 'PROD-ACCOUNT' in filename
        assert 'ec2' in filename
        assert 'running' in filename
        assert 'export' in filename
        assert filename.endswith('.xlsx')

    def test_create_export_filename_date_format(self):
        """Test filename includes date in MM.DD.YYYY format."""
        import re

        # Test
        filename = utils.create_export_filename(
            account_name='TEST',
            resource_type='s3',
            suffix=''
        )

        # Verify date format MM.DD.YYYY appears
        date_pattern = r'\d{2}\.\d{2}\.\d{4}'
        assert re.search(date_pattern, filename), f"Date pattern not found in: {filename}"

    def test_create_export_filename_no_suffix(self):
        """Test filename generation without suffix."""
        # Test
        filename = utils.create_export_filename(
            account_name='DEV',
            resource_type='vpc',
            suffix=''
        )

        # Verify
        assert 'DEV' in filename
        assert 'vpc' in filename
        assert 'export' in filename
        # Should not have double hyphens
        assert '--' not in filename


class TestRegionValidation:
    """Test AWS region validation functions."""

    def test_is_aws_region_valid_commercial(self):
        """Test validation of commercial AWS regions."""
        # Test valid commercial regions
        assert utils.is_aws_region('us-east-1') is True
        assert utils.is_aws_region('us-west-2') is True
        assert utils.is_aws_region('eu-west-1') is True

    def test_is_aws_region_invalid(self):
        """Test rejection of invalid region names."""
        # Test invalid regions
        assert utils.is_aws_region('invalid-region') is False
        assert utils.is_aws_region('us-east-99') is False
        assert utils.is_aws_region('') is False


class TestAccountInfo:
    """Test account information retrieval."""

    @patch('sslib.aws_client.get_boto3_client')
    def test_get_account_info_success(self, mock_get_client):
        """Test successful account info retrieval."""
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/test'
        }
        mock_get_client.return_value = mock_sts

        with patch.object(sslib.aws_client, '_account_info_cache', None), \
             patch.object(sslib.config, 'ACCOUNT_MAPPINGS', {'123456789012': 'TEST-ACCOUNT'}):
            account_id, account_name = utils.get_account_info()
            assert account_id == '123456789012'
            assert account_name == 'TEST-ACCOUNT'
            mock_sts.get_caller_identity.assert_called_once()

    @patch('sslib.aws_client.get_boto3_client')
    def test_get_account_info_with_fallback(self, mock_get_client):
        """Test account info with fallback for unmapped account."""
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {
            'Account': '999999999999',
            'Arn': 'arn:aws:iam::999999999999:user/test'
        }
        mock_get_client.return_value = mock_sts

        with patch.object(sslib.aws_client, '_account_info_cache', None), \
             patch.object(sslib.config, 'ACCOUNT_MAPPINGS', {}):
            account_id, account_name = utils.get_account_info()
            assert account_id == '999999999999'
            assert '999999999999' in account_name


class TestBoto3ClientCreation:
    """Test boto3 client creation with retry configuration."""

    @patch('sslib.aws_client.boto3.Session')
    def test_get_boto3_client_basic(self, mock_session):
        """Test basic client creation."""
        # Setup mock
        mock_boto_session = Mock()
        mock_client = Mock()
        mock_boto_session.client.return_value = mock_client
        mock_session.return_value = mock_boto_session

        # Test
        client = utils.get_boto3_client('ec2', region_name='us-east-1')

        # Verify
        mock_boto_session.client.assert_called_once()
        call_args = mock_boto_session.client.call_args

        # Check service name
        assert call_args[0][0] == 'ec2'

        # Check config was passed
        assert 'config' in call_args[1]

    @patch('sslib.aws_client.boto3.Session')
    def test_get_boto3_client_with_retries(self, mock_session):
        """Test client includes retry configuration."""
        # Setup mock
        mock_boto_session = Mock()
        mock_client = Mock()
        mock_boto_session.client.return_value = mock_client
        mock_session.return_value = mock_boto_session

        # Test
        client = utils.get_boto3_client('s3')

        # Verify config was created with retries
        call_args = mock_boto_session.client.call_args
        config = call_args[1]['config']

        assert config is not None
        assert hasattr(config, 'retries')


class TestLogging:
    """Test logging functions."""

    def test_log_info_callable(self):
        """Test that log_info function exists and is callable."""
        assert callable(utils.log_info)

    def test_log_error_callable(self):
        """Test that log_error function exists and is callable."""
        assert callable(utils.log_error)

    def test_log_warning_callable(self):
        """Test that log_warning function exists and is callable."""
        assert callable(utils.log_warning)

    def test_log_success_callable(self):
        """Test that log_success function exists and is callable."""
        assert callable(utils.log_success)


class TestPartitionDetection:
    """Test AWS partition detection."""

    def test_detect_partition_commercial(self):
        """Test detection of commercial AWS partition."""
        # Test commercial regions
        assert utils.detect_partition('us-east-1') == 'aws'
        assert utils.detect_partition('eu-west-1') == 'aws'
        assert utils.detect_partition('ap-southeast-1') == 'aws'

    def test_detect_partition_govcloud(self):
        """Test detection of GovCloud partition."""
        # Test GovCloud regions
        assert utils.detect_partition('us-gov-west-1') == 'aws-us-gov'
        assert utils.detect_partition('us-gov-east-1') == 'aws-us-gov'

    def test_detect_partition_default(self):
        """Test default partition when region is None."""
        # Should default to commercial
        result = utils.detect_partition(None)
        assert result in ['aws', 'aws-us-gov']  # Depends on environment


class TestARNBuilding:
    """Test ARN construction utilities."""

    def test_build_arn_basic(self):
        """Test basic ARN construction."""
        # Test
        arn = utils.build_arn(
            service='s3',
            resource='bucket/my-bucket',
            region='us-east-1',
            account_id='123456789012'
        )

        # Verify structure
        assert arn.startswith('arn:')
        assert ':s3:' in arn
        assert ':us-east-1:' in arn
        assert ':123456789012:' in arn
        assert 'bucket/my-bucket' in arn

    def test_build_arn_global_service(self):
        """Test ARN construction for global services (no region)."""
        # Test
        arn = utils.build_arn(
            service='iam',
            resource='user/testuser',
            region='',
            account_id='123456789012'
        )

        # Verify - should have empty region field
        parts = arn.split(':')
        assert parts[0] == 'arn'
        assert parts[2] == 'iam'
        assert parts[3] == ''  # Empty region for global service
        assert parts[4] == '123456789012'
