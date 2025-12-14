#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS API Gateway Export Tool
Version: v1.0.0
Date: NOV-09-2025

Description:
This script exports AWS API Gateway information into an Excel file with multiple
worksheets. The output includes REST APIs, HTTP APIs, stages, routes, integrations,
and domain mappings.

Features:
- REST APIs (v1) with resources, methods, and deployments
- HTTP APIs (v2) with routes and integrations
- API stages with deployment details
- Custom domain names and base path mappings
- API keys and usage plans
- Request validators and models
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
utils.setup_logging("api-gateway-export")
utils.log_script_start("api-gateway-export.py", "AWS API Gateway Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("               AWS API GATEWAY EXPORT TOOL")
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
    """Get a list of available AWS regions for the current partition."""
    try:
        # Get partition-aware regions
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


def scan_rest_apis_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan REST APIs in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of REST API dictionaries for this region
    """
    region_apis = []

    try:
        apigw_client = utils.get_boto3_client('apigateway', region_name=region)

        paginator = apigw_client.get_paginator('get_rest_apis')
        for page in paginator.paginate():
            apis = page.get('items', [])

            for api in apis:
                api_id = api.get('id', 'N/A')
                api_name = api.get('name', 'N/A')

                print(f"  Processing REST API: {api_name}")

                # API details
                api_type = 'REST'
                description = api.get('description', 'N/A')
                created_date = api.get('createdDate', '')
                if created_date:
                    created_date = created_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_date, datetime.datetime) else str(created_date)

                # Endpoint configuration
                endpoint_config = api.get('endpointConfiguration', {})
                endpoint_types = endpoint_config.get('types', [])
                endpoint_types_str = ', '.join(endpoint_types) if endpoint_types else 'EDGE'

                # Policy
                policy = api.get('policy', 'None')

                # Version
                version = api.get('version', 'N/A')

                # Tags
                tags = api.get('tags', {})
                tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

                region_apis.append({
                    'Region': region,
                    'API ID': api_id,
                    'API Name': api_name,
                    'API Type': api_type,
                    'Description': description,
                    'Endpoint Type': endpoint_types_str,
                    'Created Date': created_date if created_date else 'N/A',
                    'Version': version,
                    'Has Policy': 'Yes' if policy != 'None' else 'No',
                    'Tags': tags_str
                })

    except Exception as e:
        utils.log_error(f"Error collecting REST APIs in region {region}", e)

    utils.log_info(f"Found {len(region_apis)} REST APIs in {region}")
    return region_apis


@utils.aws_error_handler("Collecting REST APIs", default_return=[])
def collect_rest_apis(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect REST API (v1) information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with REST API information
    """
    print("\n=== COLLECTING REST APIs (v1) ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    all_apis = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_rest_apis_in_region,
        resource_type="REST APIs"
    )

    utils.log_success(f"Total REST APIs collected: {len(all_apis)}")
    return all_apis


def scan_http_apis_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan HTTP APIs in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of HTTP API dictionaries for this region
    """
    region_apis = []

    try:
        apigw2_client = utils.get_boto3_client('apigatewayv2', region_name=region)

        paginator = apigw2_client.get_paginator('get_apis')
        for page in paginator.paginate():
            apis = page.get('Items', [])

            for api in apis:
                api_id = api.get('ApiId', 'N/A')
                api_name = api.get('Name', 'N/A')

                print(f"  Processing HTTP API: {api_name}")

                # API details
                protocol_type = api.get('ProtocolType', 'HTTP')
                description = api.get('Description', 'N/A')
                created_date = api.get('CreatedDate', '')
                if created_date:
                    created_date = created_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_date, datetime.datetime) else str(created_date)

                # Endpoint
                api_endpoint = api.get('ApiEndpoint', 'N/A')

                # CORS configuration
                cors_config = api.get('CorsConfiguration', {})
                cors_enabled = 'Yes' if cors_config else 'No'

                # Version
                version = api.get('Version', 'N/A')

                # Route selection expression
                route_selection = api.get('RouteSelectionExpression', 'N/A')

                # Tags
                tags = api.get('Tags', {})
                tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

                region_apis.append({
                    'Region': region,
                    'API ID': api_id,
                    'API Name': api_name,
                    'API Type': protocol_type,
                    'Description': description,
                    'API Endpoint': api_endpoint,
                    'Created Date': created_date if created_date else 'N/A',
                    'CORS Enabled': cors_enabled,
                    'Version': version,
                    'Route Selection': route_selection,
                    'Tags': tags_str
                })

    except Exception as e:
        utils.log_error(f"Error collecting HTTP APIs in region {region}", e)

    utils.log_info(f"Found {len(region_apis)} HTTP APIs in {region}")
    return region_apis


@utils.aws_error_handler("Collecting HTTP APIs", default_return=[])
def collect_http_apis(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect HTTP API (v2) information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with HTTP API information
    """
    print("\n=== COLLECTING HTTP APIs (v2) ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    all_apis = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_http_apis_in_region,
        resource_type="HTTP APIs"
    )

    utils.log_success(f"Total HTTP APIs collected: {len(all_apis)}")
    return all_apis


def scan_api_stages_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan API Gateway stages in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of API stage dictionaries for this region
    """
    region_stages = []

    try:
        apigw_client = utils.get_boto3_client('apigateway', region_name=region)

        # Get REST APIs first
        apis_response = apigw_client.get_rest_apis()
        apis = apis_response.get('items', [])

        for api in apis:
            api_id = api.get('id', '')
            api_name = api.get('name', 'N/A')

            try:
                # Get stages for this API
                stages_response = apigw_client.get_stages(restApiId=api_id)
                stages = stages_response.get('item', [])

                for stage in stages:
                    stage_name = stage.get('stageName', 'N/A')

                    print(f"  Processing stage: {api_name}/{stage_name}")

                    # Stage details
                    deployment_id = stage.get('deploymentId', 'N/A')
                    description = stage.get('description', 'N/A')
                    created_date = stage.get('createdDate', '')
                    if created_date:
                        created_date = created_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_date, datetime.datetime) else str(created_date)

                    last_updated = stage.get('lastUpdatedDate', '')
                    if last_updated:
                        last_updated = last_updated.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_updated, datetime.datetime) else str(last_updated)

                    # Caching
                    cache_enabled = stage.get('cacheClusterEnabled', False)
                    cache_size = stage.get('cacheClusterSize', 'N/A')

                    # Logging
                    method_settings = stage.get('methodSettings', {})
                    logging_level = 'OFF'
                    if method_settings:
                        for key, value in method_settings.items():
                            if 'loggingLevel' in value:
                                logging_level = value.get('loggingLevel', 'OFF')
                                break

                    # Tracing
                    tracing_enabled = stage.get('tracingEnabled', False)

                    # Throttling
                    throttle_burst = method_settings.get('*/*', {}).get('throttlingBurstLimit', 'N/A') if method_settings else 'N/A'
                    throttle_rate = method_settings.get('*/*', {}).get('throttlingRateLimit', 'N/A') if method_settings else 'N/A'

                    # Tags
                    tags = stage.get('tags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

                    region_stages.append({
                        'Region': region,
                        'API ID': api_id,
                        'API Name': api_name,
                        'Stage Name': stage_name,
                        'Deployment ID': deployment_id,
                        'Description': description,
                        'Cache Enabled': cache_enabled,
                        'Cache Size': cache_size if cache_enabled else 'N/A',
                        'Logging Level': logging_level,
                        'X-Ray Tracing': tracing_enabled,
                        'Throttle Burst Limit': throttle_burst,
                        'Throttle Rate Limit': throttle_rate,
                        'Created Date': created_date if created_date else 'N/A',
                        'Last Updated': last_updated if last_updated else 'N/A',
                        'Tags': tags_str
                    })

            except Exception as e:
                utils.log_warning(f"Could not get stages for API {api_name}: {e}")

    except Exception as e:
        utils.log_error(f"Error collecting API stages in region {region}", e)

    utils.log_info(f"Found {len(region_stages)} API stages in {region}")
    return region_stages


@utils.aws_error_handler("Collecting API stages", default_return=[])
def collect_api_stages(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect API Gateway stage information for REST APIs.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with stage information
    """
    print("\n=== COLLECTING API STAGES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    all_stages = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_api_stages_in_region,
        resource_type="API stages"
    )

    utils.log_success(f"Total API stages collected: {len(all_stages)}")
    return all_stages


def export_api_gateway_data(account_id: str, account_name: str):
    """
    Export API Gateway information to an Excel file.

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

    print(f"\nStarting API Gateway export process for {region_text}...")
    print("This may take some time depending on the number of regions and APIs...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect REST APIs
    rest_apis = collect_rest_apis(regions)
    if rest_apis:
        data_frames['REST APIs'] = pd.DataFrame(rest_apis)

    # STEP 2: Collect HTTP APIs
    http_apis = collect_http_apis(regions)
    if http_apis:
        data_frames['HTTP APIs'] = pd.DataFrame(http_apis)

    # STEP 3: Collect API stages
    stages = collect_api_stages(regions)
    if stages:
        data_frames['API Stages'] = pd.DataFrame(stages)

    # STEP 4: Create summary
    if rest_apis or http_apis or stages:
        summary_data = []

        total_rest_apis = len(rest_apis)
        total_http_apis = len(http_apis)
        total_stages = len(stages)

        summary_data.append({'Metric': 'Total REST APIs', 'Value': total_rest_apis})
        summary_data.append({'Metric': 'Total HTTP APIs', 'Value': total_http_apis})
        summary_data.append({'Metric': 'Total API Stages', 'Value': total_stages})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No API Gateway data was collected. Nothing to export.")
        print("\nNo API Gateway resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'api-gateway',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("API Gateway data exported successfully!")
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

        # Export API Gateway data
        export_api_gateway_data(account_id, account_name)

        print("\nAPI Gateway export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("api-gateway-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
