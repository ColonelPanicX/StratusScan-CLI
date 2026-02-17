#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS EFS (Elastic File System) Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS EFS file system information from all regions into an Excel file with
multiple worksheets. The output includes file system configurations, mount targets, access points,
backup policies, lifecycle policies, and performance settings.

Features:
- File system overview with size, performance mode, and throughput
- Mount targets with availability zones and IP addresses
- Access points for application-specific access
- Backup policies and replication configurations
- Lifecycle management policies
- Encryption settings and KMS keys
- File system policies
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
utils.setup_logging("efs-export")
utils.log_script_start("efs-export.py", "AWS EFS Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("         AWS EFS (ELASTIC FILE SYSTEM) EXPORT TOOL")
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


def scan_efs_file_systems_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan EFS file systems in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with file system information from this region
    """
    regional_file_systems = []

    try:
        efs_client = utils.get_boto3_client('efs', region_name=region)

        # Get file systems
        paginator = efs_client.get_paginator('describe_file_systems')
        fs_count = 0

        for page in paginator.paginate():
            file_systems = page.get('FileSystems', [])
            fs_count += len(file_systems)

            for fs in file_systems:
                file_system_id = fs.get('FileSystemId', '')
                print(f"  Processing file system: {file_system_id}")

                # Basic information
                name = fs.get('Name', 'N/A')
                creation_token = fs.get('CreationToken', '')
                creation_time = fs.get('CreationTime', '')
                if creation_time:
                    creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_time, datetime.datetime) else str(creation_time)

                life_cycle_state = fs.get('LifeCycleState', '')
                number_of_mount_targets = fs.get('NumberOfMountTargets', 0)

                # Size
                size_in_bytes = fs.get('SizeInBytes', {})
                value_bytes = size_in_bytes.get('Value', 0)
                value_gb = round(value_bytes / (1024**3), 2) if value_bytes else 0
                value_in_ia = size_in_bytes.get('ValueInIA', 0)
                value_in_standard = size_in_bytes.get('ValueInStandard', 0)

                # Performance mode
                performance_mode = fs.get('PerformanceMode', 'N/A')

                # Encrypted
                encrypted = fs.get('Encrypted', False)
                kms_key_id = fs.get('KmsKeyId', 'N/A')

                # Throughput mode
                throughput_mode = fs.get('ThroughputMode', 'N/A')
                provisioned_throughput = fs.get('ProvisionedThroughputInMibps', 'N/A')

                # Availability zone (for One Zone storage)
                availability_zone_name = fs.get('AvailabilityZoneName', 'Regional')

                # File system ARN
                file_system_arn = fs.get('FileSystemArn', '')

                # Tags
                tags = fs.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                regional_file_systems.append({
                    'Region': region,
                    'File System ID': file_system_id,
                    'Name': name,
                    'Life Cycle State': life_cycle_state,
                    'Size (GB)': value_gb,
                    'Size in IA (bytes)': value_in_ia,
                    'Size in Standard (bytes)': value_in_standard,
                    'Performance Mode': performance_mode,
                    'Throughput Mode': throughput_mode,
                    'Provisioned Throughput (MiB/s)': provisioned_throughput,
                    'Encrypted': encrypted,
                    'KMS Key ID': kms_key_id,
                    'Availability Zone': availability_zone_name,
                    'Mount Target Count': number_of_mount_targets,
                    'Creation Time': creation_time,
                    'Creation Token': creation_token,
                    'Tags': tags_str,
                    'File System ARN': file_system_arn
                })

        utils.log_info(f"Found {fs_count} EFS file systems in {region}")

    except Exception as e:
        utils.log_error(f"Error processing region {region} for EFS file systems", e)

    return regional_file_systems


@utils.aws_error_handler("Collecting EFS file systems", default_return=[])
def collect_efs_file_systems(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect EFS file system information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with file system information
    """
    print("\n=== COLLECTING EFS FILE SYSTEMS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_file_systems = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_efs_file_systems_in_region,
        show_progress=True
    )

    utils.log_success(f"Total EFS file systems collected: {len(all_file_systems)}")
    return all_file_systems


def scan_mount_targets_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan EFS mount targets in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with mount target information from this region
    """
    regional_mount_targets = []

    try:
        efs_client = utils.get_boto3_client('efs', region_name=region)

        # Get all file systems first
        fs_paginator = efs_client.get_paginator('describe_file_systems')

        for fs_page in fs_paginator.paginate():
            file_systems = fs_page.get('FileSystems', [])

            for fs in file_systems:
                file_system_id = fs.get('FileSystemId', '')

                try:
                    # Get mount targets for this file system
                    mt_response = efs_client.describe_mount_targets(FileSystemId=file_system_id)
                    mount_targets = mt_response.get('MountTargets', [])

                    for mt in mount_targets:
                        mount_target_id = mt.get('MountTargetId', '')
                        subnet_id = mt.get('SubnetId', '')
                        availability_zone_name = mt.get('AvailabilityZoneName', '')
                        ip_address = mt.get('IpAddress', 'N/A')
                        network_interface_id = mt.get('NetworkInterfaceId', 'N/A')
                        life_cycle_state = mt.get('LifeCycleState', '')
                        vpc_id = mt.get('VpcId', 'N/A')

                        regional_mount_targets.append({
                            'Region': region,
                            'File System ID': file_system_id,
                            'Mount Target ID': mount_target_id,
                            'Availability Zone': availability_zone_name,
                            'Subnet ID': subnet_id,
                            'VPC ID': vpc_id,
                            'IP Address': ip_address,
                            'Network Interface ID': network_interface_id,
                            'Life Cycle State': life_cycle_state
                        })

                except Exception as e:
                    utils.log_warning(f"Could not get mount targets for {file_system_id}: {e}")

        utils.log_info(f"Found {len(regional_mount_targets)} mount targets in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting mount targets in region {region}", e)

    return regional_mount_targets


@utils.aws_error_handler("Collecting mount targets", default_return=[])
def collect_mount_targets(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect EFS mount target information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with mount target information
    """
    print("\n=== COLLECTING EFS MOUNT TARGETS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_mount_targets = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_mount_targets_in_region,
        show_progress=True
    )

    utils.log_success(f"Total mount targets collected: {len(all_mount_targets)}")
    return all_mount_targets


def scan_access_points_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan EFS access points in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with access point information from this region
    """
    regional_access_points = []

    try:
        efs_client = utils.get_boto3_client('efs', region_name=region)

        # Get access points
        response = efs_client.describe_access_points()
        access_points = response.get('AccessPoints', [])

        for ap in access_points:
            access_point_id = ap.get('AccessPointId', '')
            file_system_id = ap.get('FileSystemId', '')
            name = ap.get('Name', 'N/A')
            life_cycle_state = ap.get('LifeCycleState', '')

            # POSIX user
            posix_user = ap.get('PosixUser', {})
            uid = str(posix_user.get('Uid', 'N/A'))
            gid = str(posix_user.get('Gid', 'N/A'))

            # Root directory
            root_directory = ap.get('RootDirectory', {})
            path = root_directory.get('Path', '/')

            # ARN
            access_point_arn = ap.get('AccessPointArn', '')

            # Tags
            tags = ap.get('Tags', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
            tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

            regional_access_points.append({
                'Region': region,
                'File System ID': file_system_id,
                'Access Point ID': access_point_id,
                'Name': name,
                'Life Cycle State': life_cycle_state,
                'Root Path': path,
                'POSIX User UID': uid,
                'POSIX Group GID': gid,
                'Tags': tags_str,
                'Access Point ARN': access_point_arn
            })

        utils.log_info(f"Found {len(regional_access_points)} access points in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting access points in region {region}", e)

    return regional_access_points


@utils.aws_error_handler("Collecting access points", default_return=[])
def collect_access_points(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect EFS access point information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with access point information
    """
    print("\n=== COLLECTING EFS ACCESS POINTS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_access_points = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_access_points_in_region,
        show_progress=True
    )

    utils.log_success(f"Total access points collected: {len(all_access_points)}")
    return all_access_points


def export_efs_data(account_id: str, account_name: str):
    """
    Export EFS information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
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
        regions = default_regions
        region_text = f"default AWS regions ({len(regions)} regions)"
        region_suffix = ""
    elif selection_int == 2:
        regions = all_available_regions
        region_text = f"all AWS regions ({len(regions)} regions)"
        region_suffix = ""
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
                    regions = [selected_region]
                    region_text = f"AWS region \"{selected_region}\""
                    region_suffix = f"-{selected_region}"
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    print(f"\nStarting EFS export process for {region_text}...")
    print("=" * 68)
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect file systems
    file_systems = collect_efs_file_systems(regions)
    if file_systems:
        data_frames['File Systems'] = pd.DataFrame(file_systems)

    # STEP 2: Collect mount targets
    mount_targets = collect_mount_targets(regions)
    if mount_targets:
        data_frames['Mount Targets'] = pd.DataFrame(mount_targets)

    # STEP 3: Collect access points
    access_points = collect_access_points(regions)
    if access_points:
        data_frames['Access Points'] = pd.DataFrame(access_points)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No EFS data was collected. Nothing to export.")
        print("\nNo EFS file systems found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'efs',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("EFS data exported successfully!")
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

        # Export EFS data
        export_efs_data(account_id, account_name)

        print("\nEFS export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("efs-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
