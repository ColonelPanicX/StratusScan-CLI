#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Lambda Functions Export Tool
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

import datetime
import sys
from pathlib import Path
from typing import Any

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
args = utils.parse_script_args("Export Lambda functions to Excel")


def _build_function_row(func: dict[str, Any], region: str) -> dict[str, Any]:
    """
    Build the export row for a single Lambda function.

    Extracted so the per-function processing can be wrapped in try/except by
    the caller: a malformed function entry is logged and skipped rather than
    discarding the whole region's results. Every field is read with ``.get()``
    and a safe default for the same reason.

    Args:
        func: A single Functions entry from list_functions.
        region: AWS region name.

    Returns:
        dict: The assembled function row.
    """
    function_name = func.get('FunctionName', 'Unknown')

    # Basic information
    function_arn = func.get('FunctionArn', 'N/A')
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
    vpc_config = func.get('VpcConfig', {}) or {}
    vpc_id = vpc_config.get('VpcId', 'N/A')
    subnet_ids = vpc_config.get('SubnetIds', [])
    security_group_ids = vpc_config.get('SecurityGroupIds', [])
    subnet_count = len(subnet_ids)
    sg_count = len(security_group_ids)

    # Environment variables (count only for security)
    env_vars = (func.get('Environment', {}) or {}).get('Variables', {}) or {}
    env_var_count = len(env_vars)

    # Layers
    layers = func.get('Layers', []) or []
    layer_count = len(layers)
    layer_arns = [layer.get('Arn', '') for layer in layers]
    layers_str = ', '.join(layer_arns) if layer_arns else 'N/A'

    # Dead letter config
    dead_letter_config = func.get('DeadLetterConfig', {}) or {}
    dlq_arn = dead_letter_config.get('TargetArn', 'N/A')

    # Tracing config
    tracing_config = func.get('TracingConfig', {}) or {}
    tracing_mode = tracing_config.get('Mode', 'PassThrough')

    # Architecture
    architectures = func.get('Architectures', ['x86_64']) or ['x86_64']
    architecture = ', '.join(architectures)

    # Package type
    package_type = func.get('PackageType', 'Zip')

    # Ephemeral storage
    ephemeral_storage = func.get('EphemeralStorage', {}) or {}
    ephemeral_storage_size = ephemeral_storage.get('Size', 512)

    # Code repository
    code_sha256 = func.get('CodeSha256', 'N/A')

    # State and state reason
    state = func.get('State', 'N/A')
    state_reason = func.get('StateReason', 'N/A')

    return {
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
    }


def collect_lambda_functions_for_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Lambda function information from a single AWS region.

    Not wrapped in ``aws_error_handler``: a swallowed error here would return
    an empty list that the caller cannot distinguish from a genuinely empty
    region, producing silent data loss (no file written). Region-level
    failures are allowed to raise so ``scan_regions_concurrent`` can record
    the region as FAILED rather than empty. Per-function errors are
    contained internally (logged and skipped) via ``_build_function_row``.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with Lambda function information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    functions = []

    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nProcessing region: {region}")

    lambda_client = utils.get_boto3_client('lambda', region_name=region)

    # Get Lambda functions
    paginator = lambda_client.get_paginator('list_functions')
    function_count = 0
    skipped = 0

    for page in paginator.paginate():
        page_functions = page.get('Functions', [])
        function_count += len(page_functions)

        # Process each function. One malformed function must not sink the
        # region, so each is built inside try/except; failures are logged
        # and skipped.
        for func in page_functions:
            function_name = func.get('FunctionName', 'Unknown')
            print(f"  Processing function: {function_name}")

            try:
                functions.append(_build_function_row(func, region))
            except Exception as e:
                skipped += 1
                utils.log_error(
                    f"Skipping Lambda function '{function_name}' in {region} due to a processing error", e
                )
                continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {function_count} Lambda function(s) in {region} were skipped due to "
            "processing errors (see log above); the remaining functions were still collected."
        )

    print(f"  Found {function_count} Lambda functions")
    return functions

def collect_lambda_functions(regions: list[str]) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect Lambda function information from AWS regions (Phase 4B: concurrent).

    Uses ``collect_failures=True``: ``collect_lambda_functions_for_region``
    raises on a region-level failure so that failure is recorded and
    surfaced by the caller, never silently collapsed into "no functions"
    (see .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: (functions, failed_regions) where failed_regions is a list of
            (region, error_message) tuples for regions whose scan raised.
    """
    print("\n=== COLLECTING LAMBDA FUNCTIONS ===")

    # Use concurrent region scanning
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_lambda_functions_for_region,
        show_progress=True,
        collect_failures=True,
    )

    # Flatten results
    all_functions = []
    for funcs in region_results:
        all_functions.extend(funcs)

    utils.log_success(f"Total Lambda functions collected: {len(all_functions)}")
    return all_functions, failed_regions


@utils.aws_error_handler("Collecting event source mappings for region", default_return=[])
def collect_event_source_mappings_for_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Lambda event source mapping information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with event source mapping information
    """
    mappings = []

    if not utils.is_aws_region(region):
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

def collect_event_source_mappings(regions: list[str]) -> list[dict[str, Any]]:
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
def collect_concurrency_configs_for_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Lambda concurrency configuration information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with concurrency configuration information
    """
    configs = []

    if not utils.is_aws_region(region):
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
                provisioned_paginator = lambda_client.get_paginator('list_provisioned_concurrency_configs')
                provisioned_configs = []
                for prov_page in provisioned_paginator.paginate(FunctionName=function_name):
                    provisioned_configs.extend(prov_page.get('ProvisionedConcurrencyConfigs', []))

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

def collect_concurrency_configs(regions: list[str]) -> list[dict[str, Any]]:
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
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Lambda functions (scope collection — region failures
    # must propagate as failed_regions, never collapse into "empty").
    functions, failed_regions = collect_lambda_functions(regions)
    if functions:
        data_frames['Lambda Functions'] = pd.DataFrame(functions)

    # STEP 2: Collect event source mappings (enrichment — degrades
    # gracefully; a region-level failure here does not fail the whole export).
    mappings = collect_event_source_mappings(regions)
    if mappings:
        data_frames['Event Source Mappings'] = pd.DataFrame(mappings)

    # STEP 3: Collect concurrency configurations (enrichment — degrades
    # gracefully; a region-level failure here does not fail the whole export).
    concurrency_configs = collect_concurrency_configs(regions)
    if concurrency_configs:
        data_frames['Concurrency Configurations'] = pd.DataFrame(concurrency_configs)

    # Export whatever succeeded first — a partial export is required even
    # when some regions failed (see .collab/audit/07.16.2026-...).
    if data_frames:
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
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

                # Summary of exported data
                for sheet_name, df in data_frames.items():
                    utils.log_info(f"  - {sheet_name}: {len(df)} records")
                    print(f"  - {sheet_name}: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)
    elif not failed_regions:
        # Genuinely empty account: every region succeeded and returned nothing.
        utils.log_warning("No Lambda function data was collected. Nothing to export.")
        print("\nNo Lambda functions found in the selected region(s).")

    # If ANY region failed the Lambda Functions scope collection, make it
    # loud: write a marker and exit non-zero, even if some data (from this
    # scope or the enrichment sheets) was exported. A partial export that
    # looks complete is exactly the failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'lambda', failed_regions)
        print(
            "\nERROR: Lambda export completed with failures — data is incomplete. "
            "See the *-lambda-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("lambda-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("lambda-export.py", "AWS Lambda Functions Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS LAMBDA FUNCTIONS EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
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
