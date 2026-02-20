#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS DynamoDB Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS DynamoDB information into an Excel file with multiple
worksheets. The output includes tables, global secondary indexes, backups,
point-in-time recovery status, and streams.

Features:
- DynamoDB tables with billing mode and capacity details
- Global Secondary Indexes (GSI) and Local Secondary Indexes (LSI)
- Backup configurations and available backups
- Point-in-time recovery (PITR) status
- DynamoDB Streams configurations
- Table encryption and tags
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


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("                 AWS DYNAMODB EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-09-2025")
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
def scan_dynamodb_tables_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan DynamoDB tables in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with table information from this region
    """
    regional_tables = []

    try:
        dynamodb_client = utils.get_boto3_client('dynamodb', region_name=region)

        # List tables
        paginator = dynamodb_client.get_paginator('list_tables')
        for page in paginator.paginate():
            table_names = page.get('TableNames', [])

            for table_name in table_names:
                print(f"  Processing table: {table_name}")

                try:
                    # Get table details
                    table_response = dynamodb_client.describe_table(TableName=table_name)
                    table = table_response.get('Table', {})

                    # Basic info
                    table_arn = table.get('TableArn', 'N/A')
                    table_status = table.get('TableStatus', 'UNKNOWN')
                    creation_date = table.get('CreationDateTime', '')
                    if creation_date:
                        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                    # Item count and size
                    item_count = table.get('ItemCount', 0)
                    table_size_bytes = table.get('TableSizeBytes', 0)
                    table_size_mb = round(table_size_bytes / (1024 * 1024), 2)

                    # Billing mode
                    billing_mode_summary = table.get('BillingModeSummary', {})
                    billing_mode = billing_mode_summary.get('BillingMode', 'PROVISIONED')

                    # Provisioned throughput
                    provisioned_throughput = table.get('ProvisionedThroughput', {})
                    read_capacity = provisioned_throughput.get('ReadCapacityUnits', 0)
                    write_capacity = provisioned_throughput.get('WriteCapacityUnits', 0)

                    # Key schema
                    key_schema = table.get('KeySchema', [])
                    partition_key = 'N/A'
                    sort_key = 'N/A'
                    for key in key_schema:
                        if key.get('KeyType') == 'HASH':
                            partition_key = key.get('AttributeName', 'N/A')
                        elif key.get('KeyType') == 'RANGE':
                            sort_key = key.get('AttributeName', 'N/A')

                    # Global Secondary Indexes
                    gsi_list = table.get('GlobalSecondaryIndexes', [])
                    gsi_count = len(gsi_list)

                    # Local Secondary Indexes
                    lsi_list = table.get('LocalSecondaryIndexes', [])
                    lsi_count = len(lsi_list)

                    # Stream specification
                    stream_spec = table.get('StreamSpecification', {})
                    stream_enabled = stream_spec.get('StreamEnabled', False)
                    stream_view_type = stream_spec.get('StreamViewType', 'N/A') if stream_enabled else 'N/A'

                    # SSE (encryption)
                    sse_description = table.get('SSEDescription', {})
                    sse_status = sse_description.get('Status', 'DISABLED')
                    sse_type = sse_description.get('SSEType', 'N/A') if sse_status == 'ENABLED' else 'N/A'
                    kms_key_arn = sse_description.get('KMSMasterKeyArn', 'N/A') if sse_type == 'KMS' else 'N/A'

                    # Point-in-time recovery
                    try:
                        pitr_response = dynamodb_client.describe_continuous_backups(TableName=table_name)
                        continuous_backups = pitr_response.get('ContinuousBackupsDescription', {})
                        pitr_status = continuous_backups.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus', 'DISABLED')
                    except Exception:
                        pitr_status = 'UNKNOWN'

                    # Table class
                    table_class_summary = table.get('TableClassSummary', {})
                    table_class = table_class_summary.get('TableClass', 'STANDARD')

                    # Tags
                    try:
                        tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
                        tags = tags_response.get('Tags', [])
                        tags_str = ', '.join([f"{t['Key']}={t['Value']}" for t in tags]) if tags else 'None'
                    except Exception:
                        tags_str = 'Error retrieving'

                    regional_tables.append({
                        'Region': region,
                        'Table Name': table_name,
                        'Status': table_status,
                        'Billing Mode': billing_mode,
                        'Read Capacity': read_capacity if billing_mode == 'PROVISIONED' else 'On-Demand',
                        'Write Capacity': write_capacity if billing_mode == 'PROVISIONED' else 'On-Demand',
                        'Item Count': item_count,
                        'Table Size (MB)': table_size_mb,
                        'Partition Key': partition_key,
                        'Sort Key': sort_key if sort_key != 'N/A' else 'None',
                        'GSI Count': gsi_count,
                        'LSI Count': lsi_count,
                        'Stream Enabled': stream_enabled,
                        'Stream View Type': stream_view_type,
                        'Encryption Status': sse_status,
                        'Encryption Type': sse_type,
                        'KMS Key ARN': kms_key_arn,
                        'PITR Status': pitr_status,
                        'Table Class': table_class,
                        'Created Date': creation_date if creation_date else 'N/A',
                        'Tags': tags_str,
                        'Table ARN': table_arn
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for table {table_name}: {e}")

        utils.log_info(f"Found {len(regional_tables)} DynamoDB tables in {region}")

    except Exception as e:
        utils.log_error(f"Error processing region {region} for DynamoDB tables", e)

    return regional_tables


@utils.aws_error_handler("Collecting DynamoDB tables", default_return=[])
def collect_dynamodb_tables(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect DynamoDB table information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with table information
    """
    print("\n=== COLLECTING DYNAMODB TABLES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_tables = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_dynamodb_tables_in_region,
        resource_type="DynamoDB tables"
    )

    utils.log_success(f"Total DynamoDB tables collected: {len(all_tables)}")
    return all_tables


def scan_global_secondary_indexes_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan DynamoDB Global Secondary Indexes in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with GSI information from this region
    """
    regional_gsis = []

    try:
        dynamodb_client = utils.get_boto3_client('dynamodb', region_name=region)

        # List tables
        paginator = dynamodb_client.get_paginator('list_tables')
        table_names = []
        for page in paginator.paginate():
            table_names.extend(page.get('TableNames', []))

        for table_name in table_names:
            try:
                # Get table details
                table_response = dynamodb_client.describe_table(TableName=table_name)
                table = table_response.get('Table', {})

                # Get GSIs
                gsi_list = table.get('GlobalSecondaryIndexes', [])

                for gsi in gsi_list:
                    gsi_name = gsi.get('IndexName', 'N/A')

                    print(f"  Processing GSI: {table_name}/{gsi_name}")

                    # Key schema
                    key_schema = gsi.get('KeySchema', [])
                    partition_key = 'N/A'
                    sort_key = 'N/A'
                    for key in key_schema:
                        if key.get('KeyType') == 'HASH':
                            partition_key = key.get('AttributeName', 'N/A')
                        elif key.get('KeyType') == 'RANGE':
                            sort_key = key.get('AttributeName', 'N/A')

                    # Projection
                    projection = gsi.get('Projection', {})
                    projection_type = projection.get('ProjectionType', 'N/A')

                    # Provisioned throughput
                    provisioned_throughput = gsi.get('ProvisionedThroughput', {})
                    read_capacity = provisioned_throughput.get('ReadCapacityUnits', 0)
                    write_capacity = provisioned_throughput.get('WriteCapacityUnits', 0)

                    # Status
                    index_status = gsi.get('IndexStatus', 'UNKNOWN')

                    # Size
                    index_size_bytes = gsi.get('IndexSizeBytes', 0)
                    index_size_mb = round(index_size_bytes / (1024 * 1024), 2)

                    # Item count
                    item_count = gsi.get('ItemCount', 0)

                    # ARN
                    index_arn = gsi.get('IndexArn', 'N/A')

                    regional_gsis.append({
                        'Region': region,
                        'Table Name': table_name,
                        'Index Name': gsi_name,
                        'Status': index_status,
                        'Partition Key': partition_key,
                        'Sort Key': sort_key if sort_key != 'N/A' else 'None',
                        'Projection Type': projection_type,
                        'Read Capacity': read_capacity,
                        'Write Capacity': write_capacity,
                        'Item Count': item_count,
                        'Index Size (MB)': index_size_mb,
                        'Index ARN': index_arn
                    })

            except Exception as e:
                utils.log_warning(f"Could not get GSIs for table {table_name}: {e}")

        utils.log_info(f"Found {len(regional_gsis)} Global Secondary Indexes in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting GSIs in region {region}", e)

    return regional_gsis


@utils.aws_error_handler("Collecting Global Secondary Indexes", default_return=[])
def collect_global_secondary_indexes(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect DynamoDB Global Secondary Index information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with GSI information
    """
    print("\n=== COLLECTING GLOBAL SECONDARY INDEXES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_gsis = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_global_secondary_indexes_in_region,
        resource_type="Global Secondary Indexes"
    )

    utils.log_success(f"Total Global Secondary Indexes collected: {len(all_gsis)}")
    return all_gsis


def scan_dynamodb_backups_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan DynamoDB backups in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with backup information from this region
    """
    regional_backups = []

    try:
        dynamodb_client = utils.get_boto3_client('dynamodb', region_name=region)

        # List backups
        paginator = dynamodb_client.get_paginator('list_backups')
        for page in paginator.paginate():
            backup_summaries = page.get('BackupSummaries', [])

            for backup_summary in backup_summaries:
                backup_name = backup_summary.get('BackupName', 'N/A')
                table_name = backup_summary.get('TableName', 'N/A')

                print(f"  Processing backup: {backup_name}")

                # Backup details
                backup_arn = backup_summary.get('BackupArn', 'N/A')
                backup_status = backup_summary.get('BackupStatus', 'UNKNOWN')
                backup_type = backup_summary.get('BackupType', 'N/A')

                # Dates
                backup_creation = backup_summary.get('BackupCreationDateTime', '')
                if backup_creation:
                    backup_creation = backup_creation.strftime('%Y-%m-%d %H:%M:%S') if isinstance(backup_creation, datetime.datetime) else str(backup_creation)

                backup_expiry = backup_summary.get('BackupExpiryDateTime', '')
                if backup_expiry:
                    backup_expiry = backup_expiry.strftime('%Y-%m-%d %H:%M:%S') if isinstance(backup_expiry, datetime.datetime) else str(backup_expiry)

                # Size
                backup_size_bytes = backup_summary.get('BackupSizeBytes', 0)
                backup_size_mb = round(backup_size_bytes / (1024 * 1024), 2)

                regional_backups.append({
                    'Region': region,
                    'Backup Name': backup_name,
                    'Table Name': table_name,
                    'Backup Status': backup_status,
                    'Backup Type': backup_type,
                    'Backup Size (MB)': backup_size_mb,
                    'Created Date': backup_creation if backup_creation else 'N/A',
                    'Expiry Date': backup_expiry if backup_expiry else 'Never',
                    'Backup ARN': backup_arn
                })

        utils.log_info(f"Found {len(regional_backups)} DynamoDB backups in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting DynamoDB backups in region {region}", e)

    return regional_backups


@utils.aws_error_handler("Collecting DynamoDB backups", default_return=[])
def collect_dynamodb_backups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect DynamoDB backup information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with backup information
    """
    print("\n=== COLLECTING DYNAMODB BACKUPS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_backups = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_dynamodb_backups_in_region,
        resource_type="DynamoDB backups"
    )

    utils.log_success(f"Total DynamoDB backups collected: {len(all_backups)}")
    return all_backups


def export_dynamodb_data(account_id: str, account_name: str):
    """
    Export DynamoDB information to an Excel file.

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
    all_available_regions = utils.get_aws_regions()
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

    print(f"\nStarting DynamoDB export process for {region_text}...")
    print("This may take some time depending on the number of regions and tables...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect tables
    tables = collect_dynamodb_tables(regions)
    if tables:
        data_frames['DynamoDB Tables'] = pd.DataFrame(tables)

    # STEP 2: Collect Global Secondary Indexes
    gsis = collect_global_secondary_indexes(regions)
    if gsis:
        data_frames['Global Secondary Indexes'] = pd.DataFrame(gsis)

    # STEP 3: Collect backups
    backups = collect_dynamodb_backups(regions)
    if backups:
        data_frames['Backups'] = pd.DataFrame(backups)

    # STEP 4: Create summary
    if tables or gsis or backups:
        summary_data = []

        total_tables = len(tables)
        total_gsis = len(gsis)
        total_backups = len(backups)

        # Table status
        active_tables = sum(1 for t in tables if t['Status'] == 'ACTIVE')

        # Billing modes
        provisioned_tables = sum(1 for t in tables if t['Billing Mode'] == 'PROVISIONED')
        on_demand_tables = sum(1 for t in tables if t['Billing Mode'] == 'PAY_PER_REQUEST')

        # Encryption
        encrypted_tables = sum(1 for t in tables if t['Encryption Status'] == 'ENABLED')

        # PITR
        pitr_enabled_tables = sum(1 for t in tables if t['PITR Status'] == 'ENABLED')

        # Total size
        total_size_mb = sum(float(t['Table Size (MB)']) for t in tables)

        # Total items
        total_items = sum(int(t['Item Count']) for t in tables)

        summary_data.append({'Metric': 'Total DynamoDB Tables', 'Value': total_tables})
        summary_data.append({'Metric': 'Active Tables', 'Value': active_tables})
        summary_data.append({'Metric': 'Provisioned Billing Mode', 'Value': provisioned_tables})
        summary_data.append({'Metric': 'On-Demand Billing Mode', 'Value': on_demand_tables})
        summary_data.append({'Metric': 'Encrypted Tables', 'Value': encrypted_tables})
        summary_data.append({'Metric': 'PITR Enabled Tables', 'Value': pitr_enabled_tables})
        summary_data.append({'Metric': 'Total Global Secondary Indexes', 'Value': total_gsis})
        summary_data.append({'Metric': 'Total Backups', 'Value': total_backups})
        summary_data.append({'Metric': 'Total Table Size (MB)', 'Value': round(total_size_mb, 2)})
        summary_data.append({'Metric': 'Total Items Across All Tables', 'Value': total_items})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No DynamoDB data was collected. Nothing to export.")
        print("\nNo DynamoDB resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'dynamodb',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("DynamoDB data exported successfully!")
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
    # Initialize logging
    utils.setup_logging("dynamodb-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("dynamodb-export.py", "AWS DynamoDB Export Tool")

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

        # Export DynamoDB data
        export_dynamodb_data(account_id, account_name)

        print("\nDynamoDB export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("dynamodb-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
