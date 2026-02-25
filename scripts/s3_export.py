#!/usr/bin/env python3

""" 
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS S3 Bucket Inventory Export
Date: NOV-15-2025

Description:
This script exports information about S3 buckets across AWS regions including
bucket name, region, creation date, and total object count. Bucket sizes are retrieved
using S3 Storage Lens where available. The data is exported to a spreadsheet file with
a standardized naming convention including AWS identifiers for compliance and audit purposes.

Phase 4B Update:
- Concurrent region scanning for CloudWatch metrics collection
- Automatic fallback to sequential on errors
"""

import os
import sys
import datetime
import argparse
from pathlib import Path

# Add path to import utils module
try:
    # Try to import directly (if utils.py is in Python path)
    import utils
except ImportError:
    # If import fails, try to find the module relative to this script
    script_dir = Path(__file__).parent.absolute()
    
    # Check if we're in the scripts directory
    if script_dir.name.lower() == 'scripts':
        # Add the parent directory (StratusScan root) to the path
        sys.path.append(str(script_dir.parent))
    else:
        # Add the current directory to the path
        sys.path.append(str(script_dir))
    
    # Try import again
    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region

    Args:
        region_name (str): The region name to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.is_aws_region(region_name)

@utils.aws_error_handler("Getting bucket region", default_return="unknown")
def get_bucket_region(bucket_name):
    """
    Determine the region of a specific S3 bucket

    Args:
        bucket_name (str): Name of the S3 bucket

    Returns:
        str: AWS region name of the bucket
    """
    # Create S3 client using utils
    s3_client = utils.get_boto3_client('s3')

    # Get the bucket's location
    response = s3_client.get_bucket_location(Bucket=bucket_name)
    location = response['LocationConstraint']

    # In AWS, handle the location constraint differently
    if location is None:
        # For AWS, None typically means us-west-2 (default AWS region)
        return 'us-west-2'
    return location

@utils.aws_error_handler("Getting bucket object count", default_return=0)
def get_bucket_object_count(bucket_name, region):
    """
    Get the total number of objects in a bucket

    Args:
        bucket_name (str): Name of the S3 bucket
        region (str): AWS region where the bucket is located

    Returns:
        int: Total number of objects in the bucket
    """
    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return 0

    # Create S3 client using utils
    s3_client = utils.get_boto3_client('s3', region_name=region)

    total_objects = 0

    # Use a paginator to handle buckets with many objects
    paginator = s3_client.get_paginator('list_objects_v2')

    # Paginate through all objects in the bucket
    for page in paginator.paginate(Bucket=bucket_name):
        if 'Contents' in page:
            total_objects += len(page['Contents'])

    return total_objects

def check_storage_lens_availability():
    """
    Check if S3 Storage Lens is configured and available in AWS
    
    Returns:
        bool: True if Storage Lens is available, False otherwise
    """
    try:
        # Create S3 Control client in a AWS region
        # S3Control is a global service - use partition-aware home region
        home_region = utils.get_partition_default_region()
        s3control_client = utils.get_boto3_client('s3control', region_name=home_region)
        
        # Get caller identity for Account ID
        account_id = utils.get_boto3_client('sts').get_caller_identity()["Account"]
        
        # List Storage Lens configurations
        response = s3control_client.list_storage_lens_configurations(
            AccountId=account_id
        )
        
        # Check if there are any Storage Lens configurations
        if 'StorageLensConfigurationList' in response and len(response['StorageLensConfigurationList']) > 0:
            utils.log_info("Found S3 Storage Lens configurations. Will attempt to use for bucket metrics.")
            return True
        else:
            utils.log_info("No S3 Storage Lens configurations found. Will use standard object counting for metrics.")
            return False
    except Exception as e:
        utils.log_warning(f"Error checking Storage Lens availability: {e}")
        utils.log_info("Will use standard object counting for metrics.")
        return False

def get_latest_storage_lens_data(account_id):
    """
    Get the latest available Storage Lens data from AWS

    Args:
        account_id (str): AWS account ID

    Returns:
        dict: Dictionary mapping bucket names to their metrics
    """
    try:
        # Create S3 Control client in AWS region
        # S3Control is a global service - use partition-aware home region
        home_region = utils.get_partition_default_region()
        s3control_client = utils.get_boto3_client('s3control', region_name=home_region)
        
        # List Storage Lens configurations
        configurations = s3control_client.list_storage_lens_configurations(
            AccountId=account_id
        )
        
        if 'StorageLensConfigurationList' not in configurations or len(configurations['StorageLensConfigurationList']) == 0:
            return {}
            
        # Get the first configuration ID (default configuration if available)
        config_id = configurations['StorageLensConfigurationList'][0]['Id']
        
        # Try to get data from CloudWatch metrics in AWS
        latest_data = {}
        
        # Try to get data for yesterday (Storage Lens data is available the next day)
        today = datetime.datetime.now()
        yesterday = today - datetime.timedelta(days=1)
        
        # Get list of all buckets (global S3 call)
        s3_client = utils.get_boto3_client('s3')
        all_bucket_names = [bucket['Name'] for bucket in s3_client.list_buckets()['Buckets']]

        # Define function to collect metrics for a single region (Phase 4B)
        def collect_cloudwatch_metrics_for_region(region):
            region_data = {}
            try:
                cw_client = utils.get_boto3_client('cloudwatch', region_name=region)

                for bucket_name in all_bucket_names:
                    # Skip if we already have data for this bucket
                    if bucket_name in latest_data:
                        continue

                    try:
                        # Get BucketSizeBytes metric
                        size_response = cw_client.get_metric_statistics(
                            Namespace='AWS/S3',
                            MetricName='BucketSizeBytes',
                            Dimensions=[
                                {'Name': 'BucketName', 'Value': bucket_name},
                                {'Name': 'StorageType', 'Value': 'StandardStorage'}
                            ],
                            StartTime=yesterday - datetime.timedelta(days=1),
                            EndTime=today,
                            Period=86400,
                            Statistics=['Average']
                        )

                        # Get NumberOfObjects metric
                        objects_response = cw_client.get_metric_statistics(
                            Namespace='AWS/S3',
                            MetricName='NumberOfObjects',
                            Dimensions=[
                                {'Name': 'BucketName', 'Value': bucket_name},
                                {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                            ],
                            StartTime=yesterday - datetime.timedelta(days=1),
                            EndTime=today,
                            Period=86400,
                            Statistics=['Average']
                        )

                        # Process metrics if available
                        size_bytes = 0
                        obj_count = 0

                        if 'Datapoints' in size_response and len(size_response['Datapoints']) > 0:
                            size_bytes = size_response['Datapoints'][0]['Average']

                        if 'Datapoints' in objects_response and len(objects_response['Datapoints']) > 0:
                            obj_count = int(objects_response['Datapoints'][0]['Average'])

                        if size_bytes > 0 or obj_count > 0:
                            region_data[bucket_name] = {
                                'size_bytes': size_bytes,
                                'object_count': obj_count
                            }

                    except Exception as e:
                        utils.log_warning(f"Error getting metrics for bucket {bucket_name} in region {region}: {e}")
                        continue

            except Exception as e:
                utils.log_warning(f"Error getting CloudWatch metrics in region {region}: {e}")

            return region_data

        # Use concurrent region scanning for CloudWatch metrics (Phase 4B)
        aws_regions = utils.get_aws_regions()
        region_results = utils.scan_regions_concurrent(
            regions=aws_regions,
            scan_function=collect_cloudwatch_metrics_for_region,
            show_progress=False  # Don't show progress for S3 metrics collection
        )

        # Merge all region data
        for region_data in region_results:
            latest_data.update(region_data)

        return latest_data
            
    except Exception as e:
        utils.log_error("Error retrieving Storage Lens data", e)
        return {}

def convert_to_mb(size_in_bytes):
    """
    Convert bytes to megabytes

    Args:
        size_in_bytes (int or str): Size in bytes or "Not Available"

    Returns:
        float: Size in MB rounded to 2 decimal places, or 0.0 if not available
    """
    if size_in_bytes == "Not Available" or size_in_bytes == 0:
        return 0.0

    # Convert bytes to MB (1 MB = 1024 * 1024 bytes)
    try:
        size_in_mb = float(size_in_bytes) / (1024 * 1024)
        return round(size_in_mb, 2)
    except (ValueError, TypeError):
        return 0.0

@utils.aws_error_handler("Collecting S3 buckets", default_return=[])
def get_s3_buckets_info(use_storage_lens=False, target_region=None):
    """
    Collect information about S3 buckets across AWS regions or a specific AWS region

    Args:
        use_storage_lens (bool): Whether to try using Storage Lens for size metrics
        target_region (str): Specific AWS region to target or None for all AWS regions

    Returns:
        list: List of dictionaries containing bucket information
    """
    # Initialize global S3 client to list all buckets
    s3_client = utils.get_boto3_client('s3')

    all_buckets_info = []
    storage_lens_data = {}

    # Get account ID
    account_id = utils.get_boto3_client('sts').get_caller_identity()["Account"]

    # Validate target region if specified
    if target_region and not utils.is_aws_region(target_region):
        utils.log_error(f"Invalid AWS region: {target_region}")
        return []

    # Try to get Storage Lens data if requested
    if use_storage_lens:
        storage_lens_data = get_latest_storage_lens_data(account_id)

    # Get the list of all buckets
    response = s3_client.list_buckets()

    # Filter the buckets based on the target AWS region
    buckets_to_process = []
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']

        # Get the bucket's region if we need to filter
        if target_region:
            region = get_bucket_region(bucket_name)

            # Only include buckets in the specified AWS region
            if region == target_region:
                buckets_to_process.append(bucket)
        else:
            # For all regions, check if bucket is in any AWS region
            region = get_bucket_region(bucket_name)
            if utils.is_aws_region(region):
                buckets_to_process.append(bucket)

    total_buckets = len(buckets_to_process)
    utils.log_info(f"Found {total_buckets} S3 buckets" +
          (f" in AWS region {target_region}" if target_region else " across all AWS regions") +
          ". Gathering details for each bucket...")

    # Process each bucket
    for i, bucket in enumerate(buckets_to_process, 1):
        bucket_name = bucket['Name']
        creation_date = bucket['CreationDate']

        progress = (i / total_buckets) * 100
        utils.log_info(f"[{progress:.1f}%] Processing bucket {i}/{total_buckets}: {bucket_name}")

        # Get the bucket's region if we haven't already
        if target_region:
            region = target_region
        else:
            region = get_bucket_region(bucket_name)

        # Initialize size and object count
        size_bytes = 0
        object_count = 0

        # Try to get info from Storage Lens if available
        if bucket_name in storage_lens_data:
            size_bytes = storage_lens_data[bucket_name]['size_bytes']
            object_count = storage_lens_data[bucket_name]['object_count']
            size_source = "Storage Lens/CloudWatch"
        else:
            # Fall back to counting objects directly
            object_count = get_bucket_object_count(bucket_name, region)
            size_source = "Not Available"

        # Convert size to MB
        size_mb = convert_to_mb(size_bytes)

        # Get owner information
        owner_id = utils.get_account_name_formatted(account_id)

        # Add bucket info to our list
        bucket_info = {
            'Bucket Name': bucket_name,
            'Region': region,
            'Creation Date': creation_date,
            'Object Count': object_count,
            'Size (MB)': size_mb,
            'Size Source': size_source,
            'Owner': owner_id
        }

        all_buckets_info.append(bucket_info)

    return all_buckets_info

def export_to_excel(buckets_info, account_name, target_region=None):
    """
    Export bucket information to an Excel file with AWS identifier

    Args:
        buckets_info (list): List of dictionaries with bucket information
        account_name (str): Name of the AWS account for file naming
        target_region (str): Specific AWS region being targeted (or None for all)

    Returns:
        str: Path to the created file
    """
    # Import pandas here to avoid issues if it's not installed
    import pandas as pd

    # Create a DataFrame from the bucket information
    df = pd.DataFrame(buckets_info)

    # Prepare and sanitize DataFrame (tags may contain secrets)
    df = utils.sanitize_for_export(
        utils.prepare_dataframe_for_export(df)
    )

    # Reorder columns for better readability
    column_order = [
        'Bucket Name', 
        'Region', 
        'Creation Date', 
        'Object Count',
        'Size (MB)',
        'Size Source',
        'Owner'
    ]
    
    # Reorder columns (only include columns that exist in the DataFrame)
    available_columns = [col for col in column_order if col in df.columns]
    df = df[available_columns]
    
    # Format the creation date to be more readable
    if 'Creation Date' in df.columns:
        df['Creation Date'] = df['Creation Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate filename with current date and AWS identifier
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    
    # Create region indicator if applicable
    region_suffix = target_region if target_region else None
    
    # Use utils to create filename and save data with AWS identifier
    filename = utils.create_export_filename(
        account_name, 
        "s3-buckets", 
        region_suffix, 
        current_date
    )
    
    # Use utils to save DataFrame to Excel
    output_path = utils.save_dataframe_to_excel(df, filename)
    
    if output_path:
        utils.log_success("AWS S3 data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        return output_path
    else:
        utils.log_error("Error creating Excel file. Attempting to save as CSV instead.")
        # Fallback to CSV if Excel fails
        return export_to_csv(buckets_info, account_name, target_region)

def export_to_csv(buckets_info, account_name, target_region=None):
    """
    Export bucket information to a CSV file with AWS identifier

    Args:
        buckets_info (list): List of dictionaries with bucket information
        account_name (str): Name of the AWS account for file naming
        target_region (str): Specific AWS region being targeted (or None for all)

    Returns:
        str: Path to the created file
    """
    # Import pandas here to avoid issues if it's not installed
    import pandas as pd

    # Create a DataFrame from the bucket information
    df = pd.DataFrame(buckets_info)

    # Prepare and sanitize DataFrame (tags may contain secrets)
    df = utils.sanitize_for_export(
        utils.prepare_dataframe_for_export(df)
    )

    # Reorder columns for better readability
    column_order = [
        'Bucket Name', 
        'Region', 
        'Creation Date', 
        'Object Count',
        'Size (MB)',
        'Size Source',
        'Owner'
    ]
    
    # Reorder columns (only include columns that exist in the DataFrame)
    available_columns = [col for col in column_order if col in df.columns]
    df = df[available_columns]
    
    # Format the creation date to be more readable
    if 'Creation Date' in df.columns:
        df['Creation Date'] = df['Creation Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate filename with current date
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    
    # Create region indicator if applicable
    region_suffix = f"-{target_region}" if target_region else ""
    
    # Use utils to get output filepath
    csv_filename = f"{account_name}-aws-s3-buckets{region_suffix}-export-{current_date}.csv"
    csv_path = utils.get_output_filepath(csv_filename)
    
    # Write data to CSV
    df.to_csv(csv_path, index=False)
    
    utils.log_success(f"AWS S3 data successfully exported to: {csv_path}")
    return str(csv_path)

def main():
    """
    Main function to execute the script
    """
    # Print script title and get account information
    utils.setup_logging("s3-export")
    account_id, account_name = utils.print_script_banner("AWS S3 BUCKET INVENTORY EXPORT")

    # Check if required dependencies are installed
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    
    # Create argument parser
    parser = argparse.ArgumentParser(description='Export AWS S3 bucket information')
    parser.add_argument('--format', choices=['xlsx', 'csv'], default='xlsx',
                        help='Output format (xlsx or csv)')
    parser.add_argument('--skip-size', action='store_true',
                        help='Skip retrieving bucket sizes (faster)')
    parser.add_argument('--non-interactive', action='store_true',
                        help='Run in non-interactive mode using environment variables')
    parser.add_argument('--region', type=str, default=None,
                        help='Specific AWS region to scan (default: all AWS regions)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Detect partition and set partition-appropriate region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Set target_region based on command line argument if provided
    if os.environ.get('STRATUSSCAN_AUTO_RUN') == '1':
        # Orchestrator/CI mode — S3 is global, always scan all regions
        target_region = None
    elif args.region:
        target_region = args.region if args.region.lower() != 'all' else None
    elif args.non_interactive:
        # Use environment variables for configuration in non-interactive mode
        region_input = os.environ.get('AWS_REGION', 'all')
        target_region = None if region_input.lower() == 'all' else region_input
    else:
        # Interactive mode: Display standardized region selection menu
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
        all_available_regions = utils.get_partition_regions(partition, all_regions=True)
        default_regions = utils.get_partition_regions(partition, all_regions=False)

        # Process selection
        if selection_int == 1:
            # Default regions - for S3, scan all regions by default
            target_region = None
            utils.log_info(f"Scanning all regions for S3 buckets")
        elif selection_int == 2:
            # All regions
            target_region = None
            utils.log_info(f"Scanning all {len(all_available_regions)} AWS regions")
        else:  # selection_int == 3
            # Display numbered list of regions
            print("\n" + "=" * 68)
            print("AVAILABLE AWS REGIONS")
            print("=" * 68)
            print()
            for idx, region in enumerate(all_available_regions, 1):
                print(f"{idx:2}. {region}")
            print()

            # Get region selection with validation
            while True:
                try:
                    region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                    region_idx = int(region_num) - 1
                    if 0 <= region_idx < len(all_available_regions):
                        selected_region = all_available_regions[region_idx]
                        target_region = selected_region
                        utils.log_info(f"Scanning region: {selected_region}")
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(all_available_regions)}.")
                except ValueError:
                    print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    # Validate region if a specific one was provided
    if target_region:
        if not is_valid_aws_region(target_region):
            utils.log_warning(f"'{target_region}' is not a valid AWS region.")
            utils.log_info(f"Valid AWS regions include: {example_regions}")
            utils.log_info("Checking all AWS regions instead.")
            target_region = None

    utils.log_info("Checking for S3 Storage Lens availability in AWS...")
    use_storage_lens = check_storage_lens_availability()
    
    utils.log_info(f"Collecting S3 bucket information" + 
          (f" for AWS region: {target_region}" if target_region else " across all AWS regions") + 
          "...")
    utils.log_info("This may take some time depending on the number of buckets...")
    
    # Get information about S3 buckets in AWS
    buckets_info = get_s3_buckets_info(use_storage_lens=use_storage_lens, target_region=target_region)
    
    # Check if we found any buckets
    if not buckets_info:
        utils.log_warning("No S3 buckets found in AWS regions or unable to retrieve bucket information.")
        return
    
    utils.log_success(f"Found {len(buckets_info)} S3 buckets" + 
          (f" in AWS region {target_region}." if target_region else " across all AWS regions."))
    
    # Export the data to the selected format
    if args.format == 'xlsx':
        output_file = export_to_excel(buckets_info, account_name, target_region)
    else:
        output_file = export_to_csv(buckets_info, account_name, target_region)
    
    if output_file:
        utils.log_info(f"Export contains data from AWS region(s)")
        utils.log_info(f"Total S3 buckets exported: {len(buckets_info)}")
        print("\nScript execution completed successfully.")
    else:
        utils.log_error("Failed to export data. Please check the logs.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
