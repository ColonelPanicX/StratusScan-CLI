#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS AMI (Amazon Machine Images) Export Tool
Version: v0.1.0
Date: NOV-15-2025

Description:
This script exports account-owned Amazon Machine Image (AMI) information from all regions
into an Excel file. The output includes AMI details, creation dates, architecture,
root device information, and associated EBS snapshots.

Features:
- Account-owned AMIs only (excludes marketplace and community AMIs)
- AMI ID, name, description, and state
- Creation date and architecture (x86_64, arm64)
- Virtualization type and root device type
- EBS snapshot IDs for backup tracking
- Public/Private status
- Platform details (Linux, Windows)
- Block device mappings
- Tags

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
utils.setup_logging("ami-export")
utils.log_script_start("ami-export.py", "AWS AMI Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("          AWS AMI (AMAZON MACHINE IMAGES) EXPORT TOOL")
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


@utils.aws_error_handler("Collecting AMIs from region", default_return=[])
def collect_amis_in_region(region: str, account_id: str) -> List[Dict[str, Any]]:
    """
    Collect account-owned AMI information from a single AWS region.

    Args:
        region: AWS region to scan
        account_id: AWS account ID to filter owned AMIs

    Returns:
        list: List of dictionaries with AMI information
    """
    region_amis = []

    if not utils.validate_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"  Processing region: {region}")

    try:
        ec2_client = utils.get_boto3_client('ec2', region_name=region)

        # Get AMIs owned by this account
        response = ec2_client.describe_images(Owners=['self'])
        amis = response.get('Images', [])

        print(f"  Found {len(amis)} account-owned AMIs")

        for ami in amis:
            ami_id = ami.get('ImageId', '')
            ami_name = ami.get('Name', 'N/A')
            description = ami.get('Description', 'N/A')
            state = ami.get('State', '')
            creation_date = ami.get('CreationDate', 'N/A')

            # Architecture
            architecture = ami.get('Architecture', 'N/A')

            # Virtualization type
            virtualization_type = ami.get('VirtualizationType', 'N/A')

            # Root device type and name
            root_device_type = ami.get('RootDeviceType', 'N/A')
            root_device_name = ami.get('RootDeviceName', 'N/A')

            # Platform (Windows or blank for Linux)
            platform = ami.get('Platform', 'Linux')
            platform_details = ami.get('PlatformDetails', 'N/A')

            # Public/Private
            is_public = ami.get('Public', False)
            visibility = 'Public' if is_public else 'Private'

            # Image location
            image_location = ami.get('ImageLocation', 'N/A')

            # EBS snapshots (from block device mappings)
            block_device_mappings = ami.get('BlockDeviceMappings', [])
            snapshot_ids = []
            total_volume_size = 0

            for bdm in block_device_mappings:
                ebs = bdm.get('Ebs', {})
                if ebs:
                    snapshot_id = ebs.get('SnapshotId', '')
                    volume_size = ebs.get('VolumeSize', 0)
                    if snapshot_id:
                        snapshot_ids.append(snapshot_id)
                    total_volume_size += volume_size

            snapshots_str = ', '.join(snapshot_ids) if snapshot_ids else 'N/A'

            # ENA support
            ena_support = ami.get('EnaSupport', False)

            # Kernel and ramdisk IDs (older AMIs)
            kernel_id = ami.get('KernelId', 'N/A')
            ramdisk_id = ami.get('RamdiskId', 'N/A')

            # Boot mode
            boot_mode = ami.get('BootMode', 'N/A')

            # Deprecation time
            deprecation_time = ami.get('DeprecationTime', 'N/A')

            # Tags
            tags = ami.get('Tags', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
            tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

            region_amis.append({
                'Region': region,
                'AMI ID': ami_id,
                'AMI Name': ami_name,
                'State': state,
                'Visibility': visibility,
                'Architecture': architecture,
                'Platform': platform,
                'Platform Details': platform_details,
                'Virtualization Type': virtualization_type,
                'Root Device Type': root_device_type,
                'Root Device Name': root_device_name,
                'Total Volume Size (GB)': total_volume_size,
                'Snapshot IDs': snapshots_str,
                'ENA Support': ena_support,
                'Boot Mode': boot_mode,
                'Creation Date': creation_date,
                'Deprecation Time': deprecation_time,
                'Image Location': image_location,
                'Kernel ID': kernel_id,
                'Ramdisk ID': ramdisk_id,
                'Description': description,
                'Tags': tags_str
            })

    except Exception as e:
        utils.log_error(f"Error processing region {region} for AMIs", e)

    return region_amis


def export_ami_data(account_id: str, account_name: str):
    """
    Export AMI information to an Excel file.

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

    print(f"\nStarting AMI export process for {region_text}...")
    print("This may take some time depending on the number of regions and AMIs...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Collect AMIs using concurrent region scanning (Phase 4B)
    print("\n=== COLLECTING ACCOUNT-OWNED AMIs ===")

    # Define region scan function
    def scan_region_amis(region):
        return collect_amis_in_region(region, account_id)

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_amis,
        show_progress=True
    )

    # Flatten results
    amis = []
    for region_amis in region_results:
        amis.extend(region_amis)

    utils.log_success(f"Total AMIs collected: {len(amis)}")

    # Check if we have any data
    if not amis:
        utils.log_warning("No AMI data was collected. Nothing to export.")
        print("\nNo account-owned AMIs found in the selected region(s).")
        return

    # Create DataFrame
    df = pd.DataFrame(amis)

    # Prepare DataFrame for export
    df = utils.prepare_dataframe_for_export(df)

    # Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'ami',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_dataframe_to_excel(df, final_excel_file, sheet_name='AMIs')

        if output_path:
            utils.log_success("AMI data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
            utils.log_info(f"Total AMIs: {len(df)} records")
            print(f"Total AMIs: {len(df)} records")
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

        # Export AMI data
        export_ami_data(account_id, account_name)

        print("\nAMI export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("ami-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
