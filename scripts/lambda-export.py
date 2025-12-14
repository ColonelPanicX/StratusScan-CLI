#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Lambda Functions Export Tool
Version: v1.1.0
Date: NOV-15-2025

Description:
This script exports AWS Lambda function information from all regions into an Excel file with
multiple worksheets. The output includes function configurations, layers, event source mappings,
concurrency settings, and environment variables (sanitized).

Features:
- Lambda function overview with runtime, memory, and timeout
- Code size and deployment package information
- VPC configuration and security groups
- Environment variables (sanitized for security)
- Event source mappings (triggers)
- Layers and versions
- Concurrency settings (reserved and provisioned)
- IAM role associations

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()

    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))

    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

# Initialize logging
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("lambda-export")
utils.log_script_start("lambda-export.py", "AWS Lambda Functions Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("             AWS LAMBDA FUNCTIONS EXPORT TOOL")
    print("====================================================================")
    print("Version: v1.0.0                        Date: NOV-09-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get the current AWS account ID
    try:
        sts_client = utils.get_boto3_client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print("Could not determine account information.")
        utils.log_error("Error getting account information", e)
        account_id = "unknown"
        account_name = "unknown"

    print("====================================================================")
    return account_id, account_name


def get_aws_regions():
    """Get list of all available AWS regions for the current partition."""
    try:
        # Detect partition and get ALL regions for that partition
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


@utils.aws_error_handler("Collecting Lambda functions for region", default_return=[])
def collect_lambda_functions_for_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Lambda function information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with Lambda function information
    """
    functions = []

    if not utils.validate_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nProcessing region: {region}")

    lambda_client = utils.get_boto3_client('lambda', region_name=region)

    # Get Lambda functions
    paginator = lambda_client.get_paginator('list_functions')
    function_count = 0

    for page in paginator.paginate():
        page_functions = page.get('Functions', [])
        function_count += len(page_functions)

        for func in page_functions:
            function_name = func.get('FunctionName', '')
            print(f"  Processing function: {function_name}")

            # Basic information
            function_arn = func.get('FunctionArn', '')
            runtime = func.get('Runtime', 'N/A')
            handler = func.get('Handler', 'N/A')
            code_size = func.get('CodeSize', 0)
            description = func.get('Description', 'N/A')
            timeout = func.get('Timeout', 0)
            memory_size = func.get('MemorySize', 0)
            last_modified = func.get('LastModified', 'N/A')
            version = func.get('Version', '$LATEST')

            # Role
            role = func.get('Role', 'N/A')

            # VPC configuration
            vpc_config = func.get('VpcConfig', {})
            vpc_id = vpc_config.get('VpcId', 'N/A')
            subnet_ids = vpc_config.get('SubnetIds', [])
            security_group_ids = vpc_config.get('SecurityGroupIds', [])
            subnet_count = len(subnet_ids)
            sg_count = len(security_group_ids)

            # Environment variables (count only for security)
            env_vars = func.get('Environment', {}).get('Variables', {})
            env_var_count = len(env_vars)

            # Layers
            layers = func.get('Layers', [])
            layer_count = len(layers)
            layer_arns = [layer.get('Arn', '') for layer in layers]
            layers_str = ', '.join(layer_arns) if layer_arns else 'N/A'

            # Dead letter config
            dead_letter_config = func.get('DeadLetterConfig', {})
            dlq_arn = dead_letter_config.get('TargetArn', 'N/A')

            # Tracing config
            tracing_config = func.get('TracingConfig', {})
            tracing_mode = tracing_config.get('Mode', 'PassThrough')

            # Architecture
            architectures = func.get('Architectures', ['x86_64'])
            architecture = ', '.join(architectures)

            # Package type
            package_type = func.get('PackageType', 'Zip')

            # Ephemeral storage
            ephemeral_storage = func.get('EphemeralStorage', {})
            ephemeral_storage_size = ephemeral_storage.get('Size', 512)

            # Code repository
            code_sha256 = func.get('CodeSha256', 'N/A')

            # State and state reason
            state = func.get('State', 'N/A')
            state_reason = func.get('StateReason', 'N/A')

            functions.append({
                'Region': region,
                'Function Name': function_name,
                'Runtime': runtime,
                'Handler': handler,
                'State': state,
                'Memory (MB)': memory_size,
                'Timeout (s)': timeout,
                'Code Size (bytes)': code_size,
                'Package Type': package_type,
                'Architecture': architecture,
                'Ephemeral Storage (MB)': ephemeral_storage_size,
                'VPC ID': vpc_id,
                'Subnet Count': subnet_count,
                'Security Group Count': sg_count,
                'Environment Variables': env_var_count,
                'Layer Count': layer_count,
                'Layers': layers_str,
                'DLQ ARN': dlq_arn,
                'Tracing Mode': tracing_mode,
                'Role ARN': role,
                'Version': version,
                'Last Modified': last_modified,
                'Code SHA256': code_sha256,
                'State Reason': state_reason,
                'Description': description,
                'Function ARN': function_arn
            })

    print(f"  Found {function_count} Lambda functions")
    return functions

def collect_lambda_functions(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Lambda function information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with Lambda function information
    """
    print("\n=== COLLECTING LAMBDA FUNCTIONS ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_lambda_functions_for_region,
        show_progress=True
    )

    # Flatten results
    all_functions = []
    for funcs in region_results:
        all_functions.extend(funcs)

    utils.log_success(f"Total Lambda functions collected: {len(all_functions)}")
    return all_functions


@utils.aws_error_handler("Collecting event source mappings for region", default_return=[])
def collect_event_source_mappings_for_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Lambda event source mapping information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with event source mapping information
    """
    mappings = []

    if not utils.validate_aws_region(region):
        return []

    print(f"\nProcessing region: {region}")

    lambda_client = utils.get_boto3_client('lambda', region_name=region)

    # Get all functions first
    paginator = lambda_client.get_paginator('list_functions')

    for page in paginator.paginate():
        page_functions = page.get('Functions', [])

        for func in page_functions:
            function_name = func.get('FunctionName', '')

            try:
                # Get event source mappings for this function
                mapping_paginator = lambda_client.get_paginator('list_event_source_mappings')

                for mapping_page in mapping_paginator.paginate(FunctionName=function_name):
                    page_mappings = mapping_page.get('EventSourceMappings', [])

                    for mapping in page_mappings:
                        uuid = mapping.get('UUID', '')
                        event_source_arn = mapping.get('EventSourceArn', 'N/A')
                        state = mapping.get('State', '')
                        batch_size = mapping.get('BatchSize', 0)
                        maximum_batching_window = mapping.get('MaximumBatchingWindowInSeconds', 0)
                        starting_position = mapping.get('StartingPosition', 'N/A')

                        # Last modified
                        last_modified = mapping.get('LastModified', '')
                        if last_modified:
                            last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_modified, datetime.datetime) else str(last_modified)

                        mappings.append({
                            'Region': region,
                            'Function Name': function_name,
                            'UUID': uuid,
                            'Event Source ARN': event_source_arn,
                            'State': state,
                            'Batch Size': batch_size,
                            'Max Batching Window (s)': maximum_batching_window,
                            'Starting Position': starting_position,
                            'Last Modified': last_modified
                        })

            except Exception as e:
                utils.log_warning(f"Could not get event source mappings for {function_name}: {e}")

    return mappings

def collect_event_source_mappings(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Lambda event source mapping information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with event source mapping information
    """
    print("\n=== COLLECTING EVENT SOURCE MAPPINGS ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_event_source_mappings_for_region,
        show_progress=True
    )

    # Flatten results
    all_mappings = []
    for maps in region_results:
        all_mappings.extend(maps)

    utils.log_success(f"Total event source mappings collected: {len(all_mappings)}")
    return all_mappings


@utils.aws_error_handler("Collecting concurrency configurations for region", default_return=[])
def collect_concurrency_configs_for_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Lambda concurrency configuration information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with concurrency configuration information
    """
    configs = []

    if not utils.validate_aws_region(region):
        return []

    print(f"\nProcessing region: {region}")

    lambda_client = utils.get_boto3_client('lambda', region_name=region)

    # Get all functions
    paginator = lambda_client.get_paginator('list_functions')

    for page in paginator.paginate():
        page_functions = page.get('Functions', [])

        for func in page_functions:
            function_name = func.get('FunctionName', '')

            try:
                # Check for reserved concurrent executions
                concurrency_response = lambda_client.get_function_concurrency(
                    FunctionName=function_name
                )

                reserved_concurrent_executions = concurrency_response.get('ReservedConcurrentExecutions')

                if reserved_concurrent_executions is not None:
                    configs.append({
                        'Region': region,
                        'Function Name': function_name,
                        'Concurrency Type': 'Reserved',
                        'Concurrent Executions': reserved_concurrent_executions
                    })

            except lambda_client.exceptions.ResourceNotFoundException:
                # No reserved concurrency configured
                pass
            except Exception as e:
                utils.log_warning(f"Could not get concurrency for {function_name}: {e}")

            try:
                # Check for provisioned concurrency
                provisioned_response = lambda_client.list_provisioned_concurrency_configs(
                    FunctionName=function_name
                )

                provisioned_configs = provisioned_response.get('ProvisionedConcurrencyConfigs', [])

                for config in provisioned_configs:
                    qualifier = config.get('FunctionArn', '').split(':')[-1]
                    requested = config.get('RequestedProvisionedConcurrentExecutions', 0)
                    allocated = config.get('AllocatedProvisionedConcurrentExecutions', 0)
                    status = config.get('Status', '')

                    configs.append({
                        'Region': region,
                        'Function Name': function_name,
                        'Concurrency Type': 'Provisioned',
                        'Qualifier': qualifier,
                        'Requested': requested,
                        'Allocated': allocated,
                        'Status': status
                    })

            except Exception as e:
                utils.log_warning(f"Could not get provisioned concurrency for {function_name}: {e}")

    return configs

def collect_concurrency_configs(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Lambda concurrency configuration information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with concurrency configuration information
    """
    print("\n=== COLLECTING CONCURRENCY CONFIGURATIONS ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_concurrency_configs_for_region,
        show_progress=True
    )

    # Flatten results
    all_configs = []
    for configs in region_results:
        all_configs.extend(configs)

    utils.log_success(f"Total concurrency configurations collected: {len(all_configs)}")
    return all_configs


def export_lambda_data(account_id: str, account_name: str):
    """
    Export Lambda function information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition and set partition-aware example regions
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = get_aws_regions()
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        # Default regions
        regions = default_regions
        region_text = f"default AWS regions ({len(regions)} regions)"
        region_suffix = ""
    elif selection_int == 2:
        # All regions
        regions = all_available_regions
        region_text = f"all AWS regions ({len(regions)} regions)"
        region_suffix = ""
    else:  # selection_int == 3
        # Specific region - show numbered list
        print()
        print("=" * 68)
        print("AVAILABLE REGIONS")
        print("=" * 68)
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx}. {region}")
        print()

        while True:
            try:
                region_choice = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_choice) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_text = f"AWS region {selected_region}"
                    region_suffix = f"-{selected_region}"
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print("Please enter a valid number.")

    print(f"\nStarting Lambda export process for {region_text}...")
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Lambda functions
    functions = collect_lambda_functions(regions)
    if functions:
        data_frames['Lambda Functions'] = pd.DataFrame(functions)

    # STEP 2: Collect event source mappings
    mappings = collect_event_source_mappings(regions)
    if mappings:
        data_frames['Event Source Mappings'] = pd.DataFrame(mappings)

    # STEP 3: Collect concurrency configurations
    concurrency_configs = collect_concurrency_configs(regions)
    if concurrency_configs:
        data_frames['Concurrency Configurations'] = pd.DataFrame(concurrency_configs)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Lambda function data was collected. Nothing to export.")
        print("\nNo Lambda functions found in the selected region(s).")
        return

    # STEP 4: Prepare and sanitize all DataFrames for export
    for sheet_name in data_frames:
        # Apply sanitization to functions sheet (may contain env vars in description)
        if sheet_name == 'Lambda Functions':
            data_frames[sheet_name] = utils.sanitize_for_export(
                utils.prepare_dataframe_for_export(data_frames[sheet_name])
            )
        else:
            data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'lambda',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Lambda data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    """Main function to execute the script."""
    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Export Lambda data
        export_lambda_data(account_id, account_name)

        print("\nLambda export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("lambda-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
