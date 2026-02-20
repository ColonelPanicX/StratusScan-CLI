#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS FSx Export Tool
Date: NOV-09-2025

Description:
This script exports AWS FSx file system information from all regions into an Excel file.
Supports FSx for Windows File Server, FSx for Lustre, FSx for NetApp ONTAP, and FSx for OpenZFS.

Features:
- File system overview with type, size, and performance
- Windows File Server configurations with AD integration
- Lustre configurations with S3 integration
- NetApp ONTAP configurations with SVMs
- OpenZFS configurations with volumes
- Backup configurations and schedules
- Network and security settings
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
    print("                   AWS FSx EXPORT TOOL")
    print("====================================================================")
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
def _scan_fsx_file_systems_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for FSx file systems."""
    file_systems_data = []

    if not utils.validate_aws_region(region):
        return file_systems_data

    try:
        fsx_client = utils.get_boto3_client('fsx', region_name=region)

        # Get FSx file systems
        paginator = fsx_client.get_paginator('describe_file_systems')

        for page in paginator.paginate():
            file_systems = page.get('FileSystems', [])

            for fs in file_systems:
                file_system_id = fs.get('FileSystemId', '')

                # Basic information
                file_system_type = fs.get('FileSystemType', '')
                lifecycle = fs.get('Lifecycle', '')
                storage_capacity = fs.get('StorageCapacity', 0)
                storage_type = fs.get('StorageType', 'N/A')
                vpc_id = fs.get('VpcId', 'N/A')

                # Creation time
                creation_time = fs.get('CreationTime', '')
                if creation_time:
                    creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_time, datetime.datetime) else str(creation_time)

                # DNS name
                dns_name = fs.get('DNSName', 'N/A')

                # KMS key
                kms_key_id = fs.get('KmsKeyId', 'N/A')

                # Resource ARN
                resource_arn = fs.get('ResourceARN', '')

                # Subnet IDs
                subnet_ids = fs.get('SubnetIds', [])
                subnet_ids_str = ', '.join(subnet_ids) if subnet_ids else 'N/A'

                # Network interface IDs
                network_interface_ids = fs.get('NetworkInterfaceIds', [])
                eni_count = len(network_interface_ids)

                # File system type-specific configuration
                type_specific_config = 'N/A'
                deployment_type = 'N/A'
                throughput_capacity = 'N/A'

                if file_system_type == 'WINDOWS':
                    windows_config = fs.get('WindowsConfiguration', {})
                    deployment_type = windows_config.get('DeploymentType', 'N/A')
                    throughput_capacity = windows_config.get('ThroughputCapacity', 'N/A')
                    active_directory_id = windows_config.get('ActiveDirectoryId', 'N/A')
                    type_specific_config = f"AD: {active_directory_id}, Throughput: {throughput_capacity} MB/s"

                elif file_system_type == 'LUSTRE':
                    lustre_config = fs.get('LustreConfiguration', {})
                    deployment_type = lustre_config.get('DeploymentType', 'N/A')
                    per_unit_storage_throughput = lustre_config.get('PerUnitStorageThroughput', 'N/A')
                    data_repo_config = lustre_config.get('DataRepositoryConfiguration', {})
                    import_path = data_repo_config.get('ImportPath', 'N/A')
                    type_specific_config = f"S3: {import_path}, Throughput: {per_unit_storage_throughput} MB/s/TiB"

                elif file_system_type == 'ONTAP':
                    ontap_config = fs.get('OntapConfiguration', {})
                    deployment_type = ontap_config.get('DeploymentType', 'N/A')
                    throughput_capacity = ontap_config.get('ThroughputCapacity', 'N/A')
                    endpoint_ip_address_range = ontap_config.get('EndpointIpAddressRange', 'N/A')
                    type_specific_config = f"Endpoint Range: {endpoint_ip_address_range}, Throughput: {throughput_capacity} MB/s"

                elif file_system_type == 'OPENZFS':
                    openzfs_config = fs.get('OpenZFSConfiguration', {})
                    deployment_type = openzfs_config.get('DeploymentType', 'N/A')
                    throughput_capacity = openzfs_config.get('ThroughputCapacity', 'N/A')
                    type_specific_config = f"Throughput: {throughput_capacity} MB/s"

                # Tags
                tags = fs.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                file_systems_data.append({
                    'Region': region,
                    'File System ID': file_system_id,
                    'File System Type': file_system_type,
                    'Lifecycle': lifecycle,
                    'Storage Capacity (GB)': storage_capacity,
                    'Storage Type': storage_type,
                    'Deployment Type': deployment_type,
                    'Throughput Capacity': throughput_capacity,
                    'Type-Specific Config': type_specific_config,
                    'VPC ID': vpc_id,
                    'Subnet IDs': subnet_ids_str,
                    'Network Interface Count': eni_count,
                    'DNS Name': dns_name,
                    'KMS Key ID': kms_key_id,
                    'Creation Time': creation_time,
                    'Tags': tags_str,
                    'Resource ARN': resource_arn
                })

    except Exception as e:
        utils.log_error(f"Error collecting FSx file systems in {region}", e)

    return file_systems_data


@utils.aws_error_handler("Collecting FSx file systems", default_return=[])
def collect_fsx_file_systems(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect FSx file system information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with FSx file system information
    """
    print("\n=== COLLECTING FSx FILE SYSTEMS ===")
    results = utils.scan_regions_concurrent(regions, _scan_fsx_file_systems_region)
    all_file_systems = [fs for result in results for fs in result]
    utils.log_success(f"Total FSx file systems collected: {len(all_file_systems)}")
    return all_file_systems


def _scan_fsx_backups_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for FSx backups."""
    backups_data = []

    if not utils.validate_aws_region(region):
        return backups_data

    try:
        fsx_client = utils.get_boto3_client('fsx', region_name=region)

        # Get backups
        paginator = fsx_client.get_paginator('describe_backups')

        for page in paginator.paginate():
            backups = page.get('Backups', [])

            for backup in backups:
                backup_id = backup.get('BackupId', '')
                file_system_id = backup.get('FileSystem', {}).get('FileSystemId', 'N/A')
                backup_type = backup.get('Type', '')
                lifecycle = backup.get('Lifecycle', '')

                # Creation time
                creation_time = backup.get('CreationTime', '')
                if creation_time:
                    creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_time, datetime.datetime) else str(creation_time)

                # Progress percent
                progress_percent = backup.get('ProgressPercent', 0)

                # KMS key
                kms_key_id = backup.get('KmsKeyId', 'N/A')

                # Resource ARN
                resource_arn = backup.get('ResourceARN', '')

                # Tags
                tags = backup.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                backups_data.append({
                    'Region': region,
                    'Backup ID': backup_id,
                    'File System ID': file_system_id,
                    'Backup Type': backup_type,
                    'Lifecycle': lifecycle,
                    'Progress (%)': progress_percent,
                    'Creation Time': creation_time,
                    'KMS Key ID': kms_key_id,
                    'Tags': tags_str,
                    'Resource ARN': resource_arn
                })

    except Exception as e:
        utils.log_error(f"Error collecting FSx backups in {region}", e)

    return backups_data


@utils.aws_error_handler("Collecting FSx backups", default_return=[])
def collect_fsx_backups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect FSx backup information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with backup information
    """
    print("\n=== COLLECTING FSx BACKUPS ===")
    results = utils.scan_regions_concurrent(regions, _scan_fsx_backups_region)
    all_backups = [backup for result in results for backup in result]
    utils.log_success(f"Total FSx backups collected: {len(all_backups)}")
    return all_backups


def export_fsx_data(account_id: str, account_name: str):
    """
    Export FSx information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect file systems
    file_systems = collect_fsx_file_systems(regions)
    if file_systems:
        data_frames['File Systems'] = pd.DataFrame(file_systems)

    # STEP 2: Collect backups
    backups = collect_fsx_backups(regions)
    if backups:
        data_frames['Backups'] = pd.DataFrame(backups)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No FSx data was collected. Nothing to export.")
        print("\nNo FSx file systems found in the selected region(s).")
        return

    # STEP 3: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 4: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'fsx',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("FSx data exported successfully!")
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
    utils.setup_logging("fsx-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("fsx-export.py", "AWS FSx Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Export FSx data
        export_fsx_data(account_id, account_name)

        print("\nFSx export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("fsx-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
