# Testing Guide for StratusScan-CLI

This document describes how to run tests, add new tests, and understand the testing infrastructure.

## Quick Start

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Or install with pip in editable mode (recommended)
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage report
pytest --cov=. --cov-report=html

# View coverage in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## Test Structure

```
stratusscan-cli/
├── tests/                          # Test directory
│   ├── __init__.py                 # Package marker
│   ├── test_utils.py               # Tests for utils.py
│   ├── test_error_handling.py      # Tests for error decorators
│   └── test_dataframe_export.py    # Tests for export functions
├── pytest.ini                      # Pytest configuration
└── pyproject.toml                  # Project config with test settings
```

## Running Tests

### Basic Commands

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_utils.py

# Run specific test class
pytest tests/test_utils.py::TestAccountMapping

# Run specific test
pytest tests/test_utils.py::TestAccountMapping::test_get_account_name_with_mapping

# Run with verbose output
pytest -v

# Run with output (print statements shown)
pytest -s

# Stop at first failure
pytest -x

# Run last failed tests only
pytest --lf
```

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=. --cov-report=html

# Generate terminal coverage report
pytest --cov=. --cov-report=term-missing

# Generate XML coverage (for CI/CD)
pytest --cov=. --cov-report=xml

# Set minimum coverage percentage (fail if below)
pytest --cov=. --cov-fail-under=70
```

### Filtering Tests

```bash
# Run only fast tests
pytest -m "not slow"

# Run only integration tests
pytest -m integration

# Run tests matching pattern
pytest -k "account"  # Runs tests with "account" in name
```

## Test Coverage

Current test coverage areas:

### utils.py Tests (`test_utils.py`)
- ✅ Account name mapping
- ✅ File naming conventions
- ✅ Region validation
- ✅ Account information retrieval
- ✅ Boto3 client creation with retry logic
- ✅ Logging functions
- ✅ Partition detection (Commercial vs GovCloud)
- ✅ ARN building utilities

### Error Handling Tests (`test_error_handling.py`)
- ✅ `@aws_error_handler` decorator
- ✅ NoCredentialsError handling
- ✅ ClientError handling with error codes
- ✅ Generic exception handling
- ✅ Default return values
- ✅ `handle_aws_operation` context manager
- ✅ Error recovery patterns
- ✅ Specific AWS error codes (Throttling, AccessDenied, etc.)

### DataFrame Export Tests (`test_dataframe_export.py`)
- ✅ `prepare_dataframe_for_export()` - timezone, NaN, truncation
- ✅ `sanitize_for_export()` - sensitive data masking
- ✅ Combined preparation and sanitization pipeline
- ✅ Excel export functions

## Writing New Tests

### Test File Template

```python
#!/usr/bin/env python3
"""
Test suite for [module name].

Tests cover:
- Feature 1
- Feature 2
"""

import pytest
from unittest.mock import Mock, patch
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
import utils


class TestFeatureName:
    """Test specific feature."""

    def test_basic_functionality(self):
        """Test basic behavior."""
        # Test
        result = utils.some_function()

        # Verify
        assert result == expected_value

    def test_error_handling(self):
        """Test error conditions."""
        with pytest.raises(ValueError):
            utils.some_function(invalid_input)
```

### Mocking AWS Services

```python
from unittest.mock import Mock, patch

@patch('utils.get_boto3_client')
def test_aws_operation(mock_get_client):
    """Test AWS operation with mocked client."""
    # Setup mock
    mock_client = Mock()
    mock_client.describe_instances.return_value = {
        'Reservations': [{'Instances': [{'InstanceId': 'i-12345'}]}]
    }
    mock_get_client.return_value = mock_client

    # Test
    result = collect_instances('us-east-1')

    # Verify
    assert len(result) == 1
    assert result[0]['InstanceId'] == 'i-12345'
```

### Testing Decorators

```python
def test_decorator_functionality():
    """Test decorator preserves function behavior."""

    @utils.aws_error_handler("Test", default_return=[])
    def my_function():
        return [1, 2, 3]

    # Verify decorator doesn't break normal operation
    assert my_function() == [1, 2, 3]
```

## Continuous Integration

Tests run automatically on:
- Every push to `main` or `develop` branches
- Every pull request to `main`
- Manual workflow dispatch

### GitHub Actions Workflow

Location: `.github/workflows/test.yml`

The CI pipeline:
1. **Linting** - Checks code style with ruff
2. **Formatting** - Verifies black formatting
3. **Type Checking** - Runs mypy (advisory)
4. **Testing** - Runs pytest with coverage
5. **Security Scanning** - Runs bandit and safety

### Viewing CI Results

1. Go to your GitHub repository
2. Click "Actions" tab
3. View workflow runs and results
4. Download test artifacts (coverage reports)

## Test Best Practices

### 1. Test Names Should Be Descriptive

```python
# Good
def test_get_account_name_returns_mapped_value_when_mapping_exists():
    ...

# Avoid
def test_account():
    ...
```

### 2. One Assertion Per Test (when possible)

```python
# Good - focused test
def test_account_id_is_correct():
    account_id, _ = utils.get_account_info()
    assert account_id == '123456789012'

def test_account_name_is_correct():
    _, account_name = utils.get_account_info()
    assert account_name == 'TEST-ACCOUNT'

# Avoid - multiple unrelated assertions
def test_account_info():
    account_id, account_name = utils.get_account_info()
    assert account_id == '123456789012'
    assert account_name == 'TEST-ACCOUNT'
    assert len(account_id) == 12  # Unrelated
```

### 3. Use Fixtures for Shared Setup

```python
# Create fixtures for reusable test data
@pytest.fixture
def sample_dataframe():
    """Provide sample DataFrame for tests."""
    return pd.DataFrame({
        'Name': ['test1', 'test2'],
        'Value': [100, 200]
    })

def test_preparation(sample_dataframe):
    """Test using fixture."""
    result = utils.prepare_dataframe_for_export(sample_dataframe)
    assert len(result) == 2
```

### 4. Mock External Dependencies

```python
# Always mock AWS API calls
@patch('utils.boto3.client')
def test_aws_call(mock_boto_client):
    # Mock the AWS service
    mock_sts = Mock()
    mock_boto_client.return_value = mock_sts
    ...
```

### 5. Test Both Success and Failure Cases

```python
def test_successful_operation():
    """Test normal successful path."""
    ...

def test_operation_handles_errors():
    """Test error conditions."""
    ...
```

## Troubleshooting

### Import Errors

If you get import errors when running tests:

```bash
# Make sure you're in the project root
cd /path/to/stratusscan-cli

# Install in editable mode
pip install -e ".[dev]"

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Missing Dependencies

```bash
# Install all dev dependencies
pip install -r requirements-dev.txt

# Or specific packages
pip install pytest pytest-cov pytest-mock moto
```

### Tests Pass Locally But Fail in CI

- Check Python version (CI uses 3.9, 3.10, 3.11, 3.12)
- Verify all dependencies in `pyproject.toml`
- Check for environment-specific code
- Review CI logs for detailed error messages

## Coverage Goals

**Current Coverage**: ~40-50% (initial tests for core utilities)

**Target Coverage**:
- **Phase 1** (Current): 40-50% - Core utilities tested
- **Phase 2** (Next): 60-70% - Add script-level tests
- **Phase 3** (Future): 80%+ - Comprehensive coverage

### Checking Coverage

```bash
# Generate coverage report
pytest --cov=. --cov-report=term-missing

# View detailed HTML report
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

## Adding Tests for New Features

When adding a new feature:

1. **Write tests first** (TDD approach)
2. **Run tests** - They should fail
3. **Implement feature**
4. **Run tests again** - They should pass
5. **Refactor** if needed
6. **Ensure coverage** meets minimum threshold

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Mocking Guide](https://docs.python.org/3/library/unittest.mock.html)
- [Moto (AWS Mocking)](https://docs.getmoto.org/)
- [Coverage.py](https://coverage.readthedocs.io/)

## Getting Help

If you encounter issues with tests:

1. Check this guide
2. Review existing test files for examples
3. Run tests with verbose output: `pytest -vv`
4. Check GitHub Actions logs for CI failures
5. Open an issue on GitHub

---

**Last Updated**: 2025-11-07
**Test Framework**: pytest 7.4+
**Coverage Tool**: pytest-cov 4.1+
