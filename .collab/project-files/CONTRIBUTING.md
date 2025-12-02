# Contributing to StratusScan-CLI

Thank you for your interest in contributing to StratusScan-CLI! This document provides guidelines and instructions for contributing to the project.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Script Development Guide](#script-development-guide)
- [Common Patterns](#common-patterns)

---

## 🤝 Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow:

- **Be respectful**: Treat all community members with respect and kindness
- **Be collaborative**: Work together to improve the project
- **Be constructive**: Provide helpful feedback and suggestions
- **Be professional**: Maintain a professional and welcoming environment

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** (tested on 3.9, 3.10, 3.11, 3.12)
- **AWS CLI** configured with valid credentials
- **Git** for version control

### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR-USERNAME/stratusscan-cli.git
cd stratusscan-cli
```

---

## 💻 Development Setup

### 1. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 2. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e ".[dev]"
```

This installs:
- **Production**: boto3, pandas, openpyxl, python-dateutil
- **Development**: pytest, pytest-cov, black, ruff, mypy, moto

### 3. Configure AWS Credentials

```bash
# Option 1: AWS CLI
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### 4. Run Configuration

```bash
# Set up account mappings and preferences
python configure.py
```

---

## 📁 Project Structure

```
stratusscan-cli/
├── stratusscan.py          # Main menu interface
├── configure.py            # Configuration setup tool
├── utils.py                # Shared utility functions (CORE MODULE)
│
├── scripts/                # Individual export scripts
│   ├── ec2-export.py
│   ├── rds-export.py
│   ├── s3-export.py
│   ├── iam-comprehensive-export.py
│   └── ... (30+ export scripts)
│
├── reference/              # Pricing reference data
│   ├── ec2-pricing.csv
│   └── ebsvol-pricing.csv
│
├── tests/                  # Test suite
│   ├── test_utils.py
│   ├── test_error_handling.py
│   └── test_dataframe_export.py
│
├── output/                 # Export output directory
├── logs/                   # Log files
├── .checkpoints/           # Progress checkpoints
│
├── config.json             # Account mappings and preferences
├── pyproject.toml          # Project configuration
├── pytest.ini              # Test configuration
├── .gitignore              # Git ignore rules
│
└── docs/                   # Documentation
    ├── README.md
    ├── TESTING.md
    ├── CONTRIBUTING.md (this file)
    └── CLAUDE.md (AI assistant instructions)
```

---

## 🎨 Coding Standards

### Python Version

- **Minimum**: Python 3.9
- **Target**: Python 3.9-3.12 compatibility

### Code Formatting

We use **Black** for code formatting:

```bash
# Format all Python files
black .

# Check formatting without changes
black --check .
```

**Configuration** (from pyproject.toml):
- Line length: 100 characters
- Target version: Python 3.9+

### Linting

We use **Ruff** for fast linting:

```bash
# Run linter
ruff check .

# Auto-fix issues
ruff check --fix .
```

**Enabled rules**:
- E, F, W: pycodestyle and pyflakes
- I: Import sorting
- N: PEP8 naming
- UP: pyupgrade
- B: flake8-bugbear
- A: flake8-builtins
- C4: flake8-comprehensions
- SIM: flake8-simplify

### Type Hints

We encourage type hints for better code clarity:

```python
from typing import Dict, List, Optional, Tuple, Any

def get_account_info() -> Tuple[str, str]:
    """Get AWS account ID and name."""
    ...

def collect_instances(region: str) -> List[Dict[str, Any]]:
    """Collect EC2 instances from region."""
    ...
```

Run type checking with **mypy**:

```bash
mypy . --ignore-missing-imports
```

---

## ✅ Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_utils.py

# Run specific test
pytest tests/test_utils.py::TestAccountMapping::test_get_account_name
```

### Writing Tests

**Test File Template**:

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
        result = utils.some_function()
        assert result == expected_value

    def test_error_handling(self):
        """Test error conditions."""
        with pytest.raises(ValueError):
            utils.some_function(invalid_input)

    @patch('utils.get_boto3_client')
    def test_aws_operation(self, mock_client):
        """Test AWS operation with mocked client."""
        mock_ec2 = Mock()
        mock_ec2.describe_instances.return_value = {'Reservations': []}
        mock_client.return_value = mock_ec2

        result = utils.some_aws_function('us-east-1')
        assert result == expected
```

**Testing Best Practices**:
- ✅ Test both success and failure cases
- ✅ Use descriptive test names
- ✅ Mock AWS API calls (don't make real API calls)
- ✅ One assertion per test when possible
- ✅ Use fixtures for shared test data
- ✅ Aim for >70% code coverage

---

## 🔄 Submitting Changes

### 1. Create Feature Branch

```bash
# Create branch from main
git checkout main
git pull origin main
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Changes

- Write code following our standards
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "Add feature: Brief description

- Detailed point 1
- Detailed point 2
- Related issue #123

🤖 Generated with Claude Code (https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Commit Message Guidelines**:
- Use present tense ("Add feature" not "Added feature")
- First line: Brief summary (50 chars or less)
- Blank line, then detailed description
- Reference related issues
- Include co-author attribution if using AI assistance

### 4. Run Tests and Checks

```bash
# Run tests
pytest

# Check formatting
black --check .

# Check linting
ruff check .

# Type checking
mypy . --ignore-missing-imports
```

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create Pull Request on GitHub
# Include description of changes and testing performed
```

**Pull Request Template**:

```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All existing tests pass
- [ ] Added new tests for changes
- [ ] Manually tested on AWS account

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-reviewed the code
- [ ] Commented complex sections
- [ ] Updated documentation
- [ ] No new warnings generated
```

---

## 📝 Script Development Guide

### Creating a New Export Script

Use this template when creating new export scripts:

```python
#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS [SERVICE] Data Export Script
Version: v1.0.0
Date: [DATE]

Description:
This script queries AWS [SERVICE] resources and exports detailed
information to an Excel spreadsheet.

Features:
- Multi-region support
- Comprehensive data export
- Cost calculation integration
- Error handling and logging
"""

import sys
from pathlib import Path

# Import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils


@utils.aws_error_handler("Collecting [RESOURCE] data", default_return=[])
def collect_resources(region: str):
    """
    Collect [RESOURCE] data from specified region.

    Args:
        region: AWS region name

    Returns:
        list: List of resource dictionaries
    """
    client = utils.get_boto3_client('[service]', region_name=region)
    resources = []

    try:
        # Use pagination for large result sets
        paginator = client.get_paginator('describe_[resources]')
        for page in paginator.paginate():
            for resource in page['[Resources]']:
                resource_data = {
                    'ResourceId': resource.get('ResourceId', 'N/A'),
                    'Name': resource.get('Name', 'N/A'),
                    'Region': region,
                    # Add more fields...
                }
                resources.append(resource_data)

    except Exception as e:
        utils.log_error(f"Error collecting resources in {region}", e)

    return resources


def main():
    """Main function to execute the script."""
    try:
        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
            return

        import pandas as pd

        # Get account info
        account_id, account_name = utils.get_account_info()

        # Setup logging
        utils.setup_logging('[script-name]')
        utils.log_script_start('[Script Name]', 'Export [SERVICE] resources')

        # Get regions
        regions = utils.prompt_region_selection(
            prompt_message="Select region(s) for [SERVICE] export:",
            allow_all=True
        )

        # Collect data
        all_resources = []
        for region in regions:
            utils.log_info(f"Collecting data from {region}")
            resources = collect_resources(region)
            all_resources.extend(resources)

        if not all_resources:
            utils.log_warning("No resources found")
            return

        # Create DataFrame
        df = pd.DataFrame(all_resources)

        # Prepare for export (sanitize if needed)
        df = utils.prepare_dataframe_for_export(df)

        # Validate before export
        is_valid, msg = utils.validate_export(
            df,
            resource_type='[SERVICE]',
            required_columns=['ResourceId']
        )

        if not is_valid:
            utils.log_error(f"Validation failed: {msg}")
            return

        # Export to Excel
        filename = utils.create_export_filename(
            account_name,
            '[service]',
            'all'
        )

        output_path = utils.save_dataframe_to_excel(df, filename)

        if output_path:
            utils.log_success(f"Export completed: {output_path}")
            utils.log_export_summary('[SERVICE]', len(all_resources), output_path)

    except KeyboardInterrupt:
        utils.log_warning("Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 🔧 Common Patterns

### 1. Error Handling

**Always use standardized error handlers**:

```python
# Option 1: Decorator for simple functions
@utils.aws_error_handler("Collecting EC2 instances", default_return=[])
def collect_instances(region):
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    return ec2.describe_instances()

# Option 2: Context manager for multi-step operations
with utils.handle_aws_operation("Multi-step process", suppress_errors=False):
    ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')
    vpc_id = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24')['Subnet']['SubnetId']
```

### 2. Session Management

**Always use `utils.get_boto3_client()` instead of `boto3.client()`**:

```python
# ✅ Correct - includes retry logic and standard config
ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')

# ❌ Avoid - no retry logic
import boto3
ec2 = boto3.client('ec2', region_name='us-east-1')
```

### 3. DataFrame Preparation

**Always prepare DataFrames before export**:

```python
import pandas as pd

# Collect data
data = collect_resources(region)
df = pd.DataFrame(data)

# Prepare for export (handles timezones, NaN values, long strings)
df = utils.prepare_dataframe_for_export(df)

# For security-sensitive data (tags, env vars, etc.)
df = utils.sanitize_for_export(df)

# Export
utils.save_dataframe_to_excel(df, filename)
```

### 4. Logging

**Use standardized logging functions**:

```python
# Setup logging at script start
utils.setup_logging('script-name')

# Log different levels
utils.log_info("Processing region: us-east-1")
utils.log_warning("No resources found in region")
utils.log_error("Failed to connect to AWS", exception_obj)
utils.log_success("Export completed successfully")
utils.log_debug("Detailed debug information")

# Log AWS operations for audit trail
utils.log_aws_operation('describe_instances', 'EC2', region='us-east-1')

# Log script lifecycle
utils.log_script_start('EC2 Export', 'Export EC2 instances')
utils.log_script_end('EC2 Export', start_time)
```

### 5. Cost Estimation

**Use built-in cost estimation utilities**:

```python
# RDS cost estimation
cost = utils.estimate_rds_monthly_cost(
    instance_class='db.t3.micro',
    engine='mysql',
    storage_gb=20,
    storage_type='gp2',
    multi_az=False
)
print(f"Monthly cost: ${cost['total']:.2f}")

# S3 cost estimation
cost = utils.estimate_s3_monthly_cost(
    total_size_gb=1000,
    storage_class='STANDARD'
)

# NAT Gateway cost
cost = utils.calculate_nat_gateway_monthly_cost(
    hours_per_month=730,
    data_processed_gb=500
)

# Get optimization recommendations
recs = utils.generate_cost_optimization_recommendations(
    resource_type='ec2',
    resource_data={'state': 'stopped', 'days_stopped': 30}
)
```

### 6. Progress Checkpointing

**For long-running operations**:

```python
# Initialize checkpoint
checkpoint = utils.ProgressCheckpoint('operation-name', total_items=1000)

# Check if already completed
if checkpoint.is_complete():
    utils.log_info("Already completed")
    return

# Resume from checkpoint
start_index = checkpoint.get_completed_count()

# Process with periodic saves
for i in range(start_index, total_items):
    process_item(items[i])

    if i % 10 == 0:
        checkpoint.save(current_index=i, data={'last_id': items[i]['id']})

# Mark complete and cleanup
checkpoint.mark_complete()
checkpoint.cleanup()
```

---

## 📚 Additional Resources

### Documentation

- **README.md**: Project overview and quick start
- **TESTING.md**: Comprehensive testing guide
- **CLAUDE.md**: AI assistant development guidelines
- **API Documentation**: (Coming soon)

### External Links

- [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Black Code Formatter](https://black.readthedocs.io/)
- [Ruff Linter](https://docs.astral.sh/ruff/)

---

## ❓ Getting Help

### Questions or Issues

- **GitHub Issues**: Report bugs or request features
- **Discussions**: Ask questions or share ideas
- **Documentation**: Check existing docs first

### Debugging Tips

1. **Enable debug logging**: Set log level in `utils.setup_logging()`
2. **Check logs**: Review `logs/` directory for detailed output
3. **Use dry-run**: Test with `validate_export(dry_run=True)`
4. **Incremental testing**: Test with single region first
5. **Check AWS credentials**: Verify with `aws sts get-caller-identity`

---

## 🎯 Quality Checklist

Before submitting a PR, verify:

- [ ] Code follows Black formatting (line length 100)
- [ ] No linting errors from Ruff
- [ ] Type hints added where appropriate
- [ ] All tests pass (`pytest`)
- [ ] Coverage maintained or improved
- [ ] Documentation updated
- [ ] Commit messages follow guidelines
- [ ] AWS API calls use `utils.get_boto3_client()`
- [ ] Error handling uses `@aws_error_handler` or `handle_aws_operation`
- [ ] DataFrames prepared with `prepare_dataframe_for_export()`
- [ ] Security-sensitive data sanitized with `sanitize_for_export()`
- [ ] Logging uses `utils.log_*()` functions
- [ ] No secrets or credentials in code

---

## 🙏 Thank You!

Thank you for contributing to StratusScan-CLI! Your efforts help make AWS security auditing and resource scanning more accessible to everyone.

**Happy Coding!** 🚀

---

*Last Updated: 2025-11-07*
*Version: 1.0.0*
