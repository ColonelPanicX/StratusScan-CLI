# StratusScan-CLI API Reference

Complete API reference for the StratusScan-CLI utility module (`utils.py`).

**Version**: 2.2.0
**Last Updated**: 2025-11-10

---

## Table of Contents

- [Logging](#logging)
- [Configuration](#configuration)
- [AWS Session Management](#aws-session-management)
- [Error Handling](#error-handling)
- [Account & Region Management](#account--region-management)
- [File Operations](#file-operations)
- [DataFrame Operations](#dataframe-operations)
- [Progress Checkpointing](#progress-checkpointing)
- [Cost Estimation](#cost-estimation)
- [Validation](#validation)
- [Utility Functions](#utility-functions)

---

## Logging

### `setup_logging(script_name, log_to_file=True)`

Setup comprehensive logging for StratusScan with both console and file output.

**Parameters**:
- `script_name` (str): Name of the script for log file naming
- `log_to_file` (bool): Whether to log to file in addition to console (default: True)

**Returns**: `logging.Logger` - Configured logger instance

**Example**:
```python
import utils

logger = utils.setup_logging('ec2-export')
# Creates: logs/logs-ec2-export-MM.DD.YYYY-HHMM.log
```

---

### `get_logger()`

Get the current logger instance, creating one if it doesn't exist.

**Returns**: `logging.Logger` - Logger instance

---

### Logging Functions

```python
utils.log_info(message: str)          # Informational messages
utils.log_warning(message: str)       # Warning messages
utils.log_error(message: str, exc: Exception = None)  # Error messages
utils.log_debug(message: str)         # Debug messages (file only)
utils.log_success(message: str)       # Success messages
```

### Specialized Logging

```python
utils.log_aws_operation(operation_name, service, region=None, details="")
utils.log_export_summary(resource_type, count, output_file)
utils.log_script_start(script_name, description="")
utils.log_script_end(script_name, start_time=None)
utils.log_section(section_name)
utils.log_menu_selection(menu_path, selection_name)
```

---

## Configuration

### `load_config()`

Load configuration from config.json file.

**Returns**: `Tuple[Dict[str, str], Dict[str, Any]]` - (ACCOUNT_MAPPINGS, CONFIG_DATA)

---

### `config_value(key, default=None, section=None)`

Get a value from the configuration.

**Parameters**:
- `key` (str): Configuration key
- `default` (Any): Default value if key not found
- `section` (str, optional): Optional section in configuration

**Returns**: Configuration value or default

**Example**:
```python
org_name = utils.config_value('organization_name', default='MY-ORG')
```

---

### Configuration Access Functions

```python
utils.get_default_regions() -> List[str]
utils.get_organization_name() -> str
utils.get_aws_environment() -> str
utils.get_resource_preference(resource_type, preference, default=None) -> Any
utils.is_service_enabled(service_name) -> bool
```

---

## AWS Session Management

### `get_boto3_client(service, region_name=None, **kwargs)`

Create boto3 client with standard configuration including retries.

**Parameters**:
- `service` (str): AWS service name (e.g., 'ec2', 'iam', 's3')
- `region_name` (str, optional): AWS region name
- `**kwargs`: Additional arguments to pass to client creation

**Returns**: `boto3.client` - Configured boto3 client with retry logic

**Example**:
```python
# Create EC2 client with automatic retries
ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')

# Create IAM client (global service)
iam = utils.get_boto3_client('iam', region_name='us-west-2')
```

**Features**:
- Automatic retry logic with adaptive backoff
- Proper timeout configuration
- Partition awareness for GovCloud support

---

### `get_aws_session(region_name=None, partition=None)`

Create reusable boto3 session with partition awareness.

**Parameters**:
- `region_name` (str, optional): AWS region
- `partition` (str, optional): AWS partition ('aws' or 'aws-us-gov')

**Returns**: `boto3.Session` - Configured session

---

### `detect_partition(region_name=None)`

Detect AWS partition from region or credentials.

**Parameters**:
- `region_name` (str, optional): Optional region to check

**Returns**: `str` - 'aws' or 'aws-us-gov'

---

### `build_arn(service, resource, region=None, account_id=None, partition=None)`

Build ARN with automatic partition detection.

**Parameters**:
- `service` (str): AWS service name
- `resource` (str): Resource identifier
- `region` (str, optional): AWS region
- `account_id` (str, optional): AWS account ID (auto-detected if not provided)
- `partition` (str, optional): AWS partition (auto-detected if not provided)

**Returns**: `str` - Properly formatted AWS ARN

**Example**:
```python
arn = utils.build_arn('ec2', 'instance/i-1234567890abcdef0', region='us-east-1')
# Result: arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0
```

---

## Error Handling

### `@aws_error_handler(operation_name, default_return=None, reraise=False)`

Decorator for standardized AWS error handling.

**Parameters**:
- `operation_name` (str): Human-readable operation description
- `default_return` (Any): Value to return on error
- `reraise` (bool): Whether to re-raise exceptions after logging

**Returns**: Decorator function

**Example**:
```python
@utils.aws_error_handler("Collecting EC2 instances", default_return=[])
def collect_instances(region: str) -> List[Dict]:
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    response = ec2.describe_instances()
    return response['Reservations']
```

---

### `handle_aws_operation(operation_name, default_return=None, suppress_errors=False)`

Context manager for AWS operations with standardized error handling.

**Parameters**:
- `operation_name` (str): Human-readable operation description
- `default_return` (Any): Value to return on error if suppress_errors=True
- `suppress_errors` (bool): Whether to suppress exceptions

**Example**:
```python
with utils.handle_aws_operation("Creating VPC", suppress_errors=False):
    ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')
    vpc_id = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']
    utils.log_info(f"Created VPC: {vpc_id}")
```

---

## Account & Region Management

### `get_account_info()`

Get AWS account ID and name with caching.

**Returns**: `Tuple[str, str]` - (account_id, account_name)

**Example**:
```python
account_id, account_name = utils.get_account_info()
# Returns: ('123456789012', 'PROD-ACCOUNT')
```

---

### `get_account_name(account_id, default="UNKNOWN-ACCOUNT")`

Get account name from account ID using configured mappings.

**Parameters**:
- `account_id` (str): The AWS account ID
- `default` (str): Default value if not found in mappings

**Returns**: `str` - Account name or default value

---

### `get_account_name_formatted(owner_id)`

Get formatted account name with ID.

**Parameters**:
- `owner_id` (str): AWS account owner ID

**Returns**: `str` - Formatted as "ACCOUNT-NAME (ID)" or just ID if no mapping

---

### Region Functions

```python
utils.is_aws_region(region: str) -> bool
utils.validate_aws_region(region: str) -> bool
utils.get_aws_regions() -> List[str]
utils.check_aws_region_access(region: str) -> bool
utils.get_available_aws_regions() -> List[str]
```

### `prompt_region_selection(prompt_message, allow_all=True, default_regions=None)`

Interactive region selection with validation.

**Parameters**:
- `prompt_message` (str): Custom message to display
- `allow_all` (bool): Whether to allow 'all' option
- `default_regions` (List[str], optional): Regions to use when 'all' selected

**Returns**: `List[str]` - List of AWS region names to scan

**Example**:
```python
regions = utils.prompt_region_selection(
    prompt_message="Select region(s) for EC2 scan:",
    allow_all=True
)
# User selects 'all' → returns ['us-east-1', 'us-west-2', ...]
```

---

## File Operations

### `get_stratusscan_root()`

Get the root directory of the StratusScan package.

**Returns**: `Path` - Path to StratusScan root directory

---

### `get_output_dir()`

Get path to output directory and create if doesn't exist.

**Returns**: `Path` - Path to output directory

---

### `get_output_filepath(filename)`

Get full path for a file in the output directory.

**Parameters**:
- `filename` (str): Name of the file

**Returns**: `Path` - Full path to file in output directory

---

### `create_export_filename(account_name, resource_type, suffix="", current_date=None)`

Create standardized filename for exported data.

**Parameters**:
- `account_name` (str): AWS account name
- `resource_type` (str): Type of resource (e.g., "ec2", "vpc")
- `suffix` (str, optional): Optional suffix (e.g., "running", "all")
- `current_date` (str, optional): Date to use (defaults to today)

**Returns**: `str` - Standardized filename

**Example**:
```python
filename = utils.create_export_filename('PROD-ACCOUNT', 'ec2', 'running')
# Returns: 'PROD-ACCOUNT-ec2-running-export-11.07.2025.xlsx'
```

---

## DataFrame Operations

### `prepare_dataframe_for_export(df, remove_timezone=True, fill_na='N/A', truncate_strings=1000, max_column_width=50)`

Prepare DataFrame for Excel export by standardizing data types and values.

**Parameters**:
- `df` (DataFrame): Input DataFrame to prepare
- `remove_timezone` (bool): Remove timezone info from datetime columns
- `fill_na` (str): String to replace NaN/None values
- `truncate_strings` (int, optional): Max string length before truncation
- `max_column_width` (int): Maximum column width for Excel

**Returns**: `DataFrame` - Cleaned DataFrame ready for export

**Example**:
```python
df = pd.DataFrame(instances)
df = utils.prepare_dataframe_for_export(df)
utils.save_dataframe_to_excel(df, filename)
```

---

### `sanitize_for_export(df, sensitive_patterns=None, mask_string='***REDACTED***')`

Sanitize potentially sensitive data in DataFrame before export.

**Parameters**:
- `df` (DataFrame): Input DataFrame to sanitize
- `sensitive_patterns` (List[str], optional): List of regex patterns to search for
- `mask_string` (str): String to replace sensitive data with

**Returns**: `DataFrame` - Sanitized DataFrame with sensitive data masked

**Default Patterns**:
- Passwords: `password`, `passwd`, `pwd`
- API keys: `api_key`, `apikey`
- Access keys: `access_key`, `accesskey`
- Secret keys: `secret_key`, `secretkey`
- Tokens: `token`
- Credentials: `credential`, `cred`
- Auth: `auth`

**Example**:
```python
df = collect_resources_with_tags()
df = utils.sanitize_for_export(df)
utils.save_dataframe_to_excel(df, filename)
```

---

### `save_dataframe_to_excel(df, filename, sheet_name="Data", auto_adjust_columns=True, prepare=False)`

Save DataFrame to Excel file in output directory.

**Parameters**:
- `df` (DataFrame): DataFrame to save
- `filename` (str): Name of file to save
- `sheet_name` (str): Name of sheet in Excel
- `auto_adjust_columns` (bool): Whether to auto-adjust column widths
- `prepare` (bool): If True, apply `prepare_dataframe_for_export()` before saving

**Returns**: `str` - Full path to saved file

---

### `save_multiple_dataframes_to_excel(dataframes_dict, filename, prepare=False)`

Save multiple DataFrames to single Excel file with multiple sheets.

**Parameters**:
- `dataframes_dict` (Dict[str, DataFrame]): Dictionary of {sheet_name: dataframe}
- `filename` (str): Name of file to save
- `prepare` (bool): If True, apply preparation to each DataFrame

**Returns**: `str` - Full path to saved file

**Example**:
```python
dataframes = {
    'Instances': ec2_df,
    'Volumes': ebs_df,
    'Summary': summary_df
}
utils.save_multiple_dataframes_to_excel(dataframes, 'ec2-comprehensive.xlsx')
```

---

## Progress Checkpointing

### `ProgressCheckpoint(operation_name, total_items=None, checkpoint_dir=None)`

Progress checkpointing system for long-running AWS operations.

**Parameters**:
- `operation_name` (str): Unique name for this operation
- `total_items` (int, optional): Total number of items to process
- `checkpoint_dir` (Path, optional): Directory to store checkpoints

**Methods**:

#### `save(current_index, data=None)`
Save current progress to checkpoint file.

**Parameters**:
- `current_index` (int): Current position in operation
- `data` (dict, optional): Additional data to save

#### `is_complete()`
Check if operation was previously completed.

**Returns**: `bool`

#### `mark_complete()`
Mark operation as complete.

#### `get_data(key, default=None)`
Get value from checkpoint data.

#### `get_completed_count()`
Get number of items already processed.

**Returns**: `int`

#### `cleanup()`
Remove checkpoint file after successful completion.

**Example**:
```python
checkpoint = utils.ProgressCheckpoint('ec2-export', total_items=1000)

if checkpoint.is_complete():
    print("Already completed")
    return

start_index = checkpoint.get_completed_count()

for i in range(start_index, 1000):
    process_item(items[i])

    if i % 10 == 0:
        checkpoint.save(current_index=i, data={'last_id': items[i]['id']})

checkpoint.mark_complete()
checkpoint.cleanup()
```

---

## Cost Estimation

### `estimate_rds_monthly_cost(instance_class, engine, storage_gb, storage_type='gp2', multi_az=False)`

Estimate monthly cost for RDS database instance.

**Parameters**:
- `instance_class` (str): RDS instance class (e.g., 'db.t3.micro')
- `engine` (str): Database engine (e.g., 'mysql', 'postgres')
- `storage_gb` (int): Allocated storage in GB
- `storage_type` (str): Storage type ('gp2', 'gp3', 'io1')
- `multi_az` (bool): Whether Multi-AZ deployment enabled

**Returns**: `Dict[str, Any]` - Cost breakdown

**Return Structure**:
```python
{
    'instance_cost': 12.41,      # Monthly instance cost
    'storage_cost': 2.30,        # Monthly storage cost
    'total': 14.71,              # Total monthly cost
    'multi_az_enabled': False,
    'note': 'Approximate estimate - see AWS Pricing Calculator for accurate costs'
}
```

**Example**:
```python
cost = utils.estimate_rds_monthly_cost('db.t3.micro', 'mysql', 20, 'gp2', False)
print(f"Total cost: ${cost['total']:.2f}/month")
```

---

### `estimate_s3_monthly_cost(total_size_gb, storage_class='STANDARD', requests_per_month=None)`

Estimate monthly cost for S3 storage.

**Parameters**:
- `total_size_gb` (float): Total storage size in GB
- `storage_class` (str): S3 storage class ('STANDARD', 'INTELLIGENT_TIERING', 'GLACIER', etc.)
- `requests_per_month` (int, optional): Number of requests per month

**Returns**: `Dict[str, Any]` - Cost breakdown

**Return Structure**:
```python
{
    'storage_cost': 23.0,
    'request_cost': 2.70,
    'monitoring_cost': 0.0,
    'total': 25.70,
    'storage_class': 'STANDARD',
    'note': 'Approximate estimate - does not include data transfer costs'
}
```

---

### `calculate_nat_gateway_monthly_cost(hours_per_month=730, data_processed_gb=0.0)`

Calculate monthly cost for NAT Gateway.

**Parameters**:
- `hours_per_month` (int): Number of hours running (default: 730 for full month)
- `data_processed_gb` (float): Amount of data processed in GB per month

**Returns**: `Dict[str, Any]` - Cost breakdown

**Return Structure**:
```python
{
    'hourly_cost': 32.85,
    'data_processing_cost': 22.50,
    'total': 55.35,
    'hours': 730,
    'data_processed_gb': 500,
    'warning': 'NAT Gateway costs can be significant - consider alternatives for dev/test environments'
}
```

---

### `generate_cost_optimization_recommendations(resource_type, resource_data)`

Generate cost optimization recommendations for AWS resources.

**Parameters**:
- `resource_type` (str): Type of resource ('ec2', 'rds', 's3', 'nat_gateway')
- `resource_data` (Dict[str, Any]): Dictionary containing resource configuration

**Returns**: `List[str]` - List of recommendation strings

**Example**:
```python
recs = utils.generate_cost_optimization_recommendations(
    'ec2',
    {'state': 'stopped', 'instance_type': 't2.large', 'days_stopped': 30}
)
# Returns: [
#     'Instance stopped for 30 days - consider terminating if no longer needed',
#     'Consider upgrading to t3 instance family for better price/performance'
# ]
```

---

## Validation

### `validate_export(df, resource_type, required_columns=None, dry_run=False)`

Validate DataFrame before export (supports dry-run mode).

**Parameters**:
- `df` (DataFrame): DataFrame to validate
- `resource_type` (str): Type of resource being exported
- `required_columns` (List[str], optional): List of columns that must be present
- `dry_run` (bool): If True, only validate without actually exporting

**Returns**: `Tuple[bool, str]` - (is_valid, error_message)

**Example**:
```python
df = collect_ec2_instances(region)
is_valid, error_msg = utils.validate_export(
    df,
    resource_type='EC2',
    required_columns=['InstanceId', 'State'],
    dry_run=True
)

if not is_valid:
    utils.log_error(f"Validation failed: {error_msg}")
    return

# Proceed with actual export
utils.save_dataframe_to_excel(df, filename)
```

---

## Utility Functions

### `ensure_dependencies(*packages)`

Check and optionally install required dependencies.

**Parameters**:
- `*packages` (str): Variable number of package names to check

**Returns**: `bool` - True if all dependencies satisfied

**Example**:
```python
if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
    sys.exit(1)
```

---

### `prompt_for_confirmation(message, default=True)`

Prompt user for confirmation.

**Parameters**:
- `message` (str): Message to display
- `default` (bool): Default response if user presses Enter

**Returns**: `bool` - True if confirmed

---

### `format_bytes(size_bytes)`

Format bytes to human-readable format.

**Parameters**:
- `size_bytes` (int): Size in bytes

**Returns**: `str` - Formatted size string (e.g., "1.23 GB")

**Example**:
```python
size = utils.format_bytes(1234567890)
# Returns: '1.15 GB'
```

---

### `get_current_timestamp()`

Get current timestamp in standardized format.

**Returns**: `str` - Formatted timestamp (YYYY-MM-DD HH:MM:SS)

---

### `is_valid_aws_account_id(account_id)`

Check if string is a valid AWS account ID.

**Parameters**:
- `account_id` (str): Account ID to check

**Returns**: `bool` - True if valid (12 digits)

---

### `add_account_mapping(account_id, account_name)`

Add new account mapping to configuration.

**Parameters**:
- `account_id` (str): AWS account ID
- `account_name` (str): Account name

**Returns**: `bool` - True if successful

---

### `validate_aws_credentials()`

Validate AWS credentials.

**Returns**: `Tuple[bool, Optional[str], Optional[str]]` - (is_valid, account_id, error_message)

---

### ARN Functions

```python
utils.parse_aws_arn(arn: str) -> Optional[Dict[str, str]]
utils.create_aws_arn(service, resource, region=None, account_id=None) -> str  # Deprecated
```

---

## Constants

```python
# AWS Commercial constants
DEFAULT_REGIONS = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1']
AWS_PARTITION = 'aws'

# Global configuration
ACCOUNT_MAPPINGS: Dict[str, str]  # Loaded from config.json
CONFIG_DATA: Dict[str, Any]        # Loaded from config.json
```

---

## Type Hints

The `utils.py` module uses comprehensive type hints:

```python
from typing import Dict, List, Optional, Tuple, Any, Union, Callable, TypeVar
```

For best IDE support, use type checking:

```bash
mypy . --ignore-missing-imports
```

---

## Error Handling Patterns

### Pattern 1: Decorator (Recommended)

Use for simple, single-operation functions:

```python
@utils.aws_error_handler("Collecting resources", default_return=[])
def collect_resources(region: str) -> List[Dict]:
    client = utils.get_boto3_client('service', region_name=region)
    return client.describe_resources()
```

### Pattern 2: Context Manager

Use for multi-step operations with custom logic:

```python
with utils.handle_aws_operation("Multi-step process", suppress_errors=False):
    client = utils.get_boto3_client('ec2', region_name='us-east-1')
    step1_result = client.create_vpc(CidrBlock='10.0.0.0/16')
    utils.log_info(f"Created VPC: {step1_result['Vpc']['VpcId']}")
    step2_result = client.create_subnet(VpcId=step1_result['Vpc']['VpcId'], CidrBlock='10.0.1.0/24')
    utils.log_info(f"Created subnet: {step2_result['Subnet']['SubnetId']}")
```

---

## Best Practices

1. **Always use `utils.get_boto3_client()`** instead of `boto3.client()` directly
2. **Always prepare DataFrames** with `prepare_dataframe_for_export()` before Excel export
3. **Sanitize security-sensitive data** with `sanitize_for_export()` for IAM, tags, configs
4. **Use error handlers** - either `@aws_error_handler` decorator or `handle_aws_operation` context manager
5. **Log operations** with appropriate log levels and structured logging functions
6. **Validate exports** with `validate_export()` before running expensive operations
7. **Use checkpointing** for operations processing >100 items across regions
8. **Cache account info** - `get_account_info()` is already cached with `@lru_cache`

---

## Version History

- **v2.2.0** (2025-11-10): Added 24 new export scripts across Advanced Security, AI/ML, and Developer Tools
- **v2.1.4** (2025-11-07): Added progress checkpointing, dry-run validation, cost estimation
- **v2.1.0** (2025-10-30): Added DataFrame sanitization and preparation utilities
- **v2.0.0** (2025-10-30): Added standardized error handling decorators
- **v1.1.0** (2025-08-19): Added session management with retry logic
- **v1.0.0** (Initial): Core utilities for AWS resource scanning

---

## See Also

- [README.md](README.md) - Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
- [TESTING.md](TESTING.md) - Testing documentation
- [CLAUDE.md](CLAUDE.md) - AI assistant instructions

---

*Last Updated: 2025-11-10*
*StratusScan-CLI API Reference v2.2.0*
