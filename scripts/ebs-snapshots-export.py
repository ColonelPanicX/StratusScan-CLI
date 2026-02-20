#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS EBS Snapshots Export Tool
Version: v0.1.0
Date: NOV-15-2025

Description:
This script exports Amazon EBS snapshot information across AWS regions or a specific
AWS region into an Excel spreadsheet. The export includes snapshot name, ID,
description, size information, encryption status, storage tier, and creation date.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import sys
import datetime
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

def print_title():
    """
    Print the title banner and get account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                             ")
    print("====================================================================")
    print("AWS EBS SNAPSHOTS EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                                Date: AUG-19-2025")

    # Get account information using utils
    account_id, account_name = utils.get_account_info()

    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

    print(f"Environment: {partition_name}")
    print("====================================================================")
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")
    return account_id, account_name
def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region.

    Args:
        region_name (str): The region name to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_aws_region(region_name)

def get_snapshot_name(snapshot):
    """
    Extract the snapshot name from tags.
    
    Args:
        snapshot (dict): The snapshot object from the API response
        
    Returns:
        str: The name of the snapshot or 'N/A' if not present
    """
    if 'Tags' in snapshot:
        for tag in snapshot['Tags']:
            if tag['Key'] == 'Name':
                return tag['Value']
    return 'N/A'

def format_tags(tags):
    """
    Format snapshot tags in the format "Key1:Value1, Key2:Value2, etc..."
    
    Args:
        tags (list): List of tag dictionaries with Key and Value
        
    Returns:
        str: Formatted tags string or 'N/A' if no tags
    """
    if not tags:
        return 'N/A'
    
    formatted_tags = []
    for tag in tags:
        if 'Key' in tag and 'Value' in tag:
            formatted_tags.append(f"{tag['Key']}:{tag['Value']}")
    
    if formatted_tags:
        return ', '.join(formatted_tags)
    else:
        return 'N/A'

@utils.aws_error_handler("Collecting EBS snapshots", default_return=[])
def get_snapshots(region):
    """
    Get all EBS snapshots owned by the account in a specific AWS region.

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries with snapshot information
    """
    # Validate region is AWS
    if not utils.validate_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    snapshots_data = []

    # Create EC2 client using utils for proper retry logic
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Use pagination to handle large number of snapshots
    paginator = ec2_client.get_paginator('describe_snapshots')
    page_iterator = paginator.paginate(OwnerIds=['self'])

    for page in page_iterator:
        for snapshot in page['Snapshots']:
            # Get snapshot name from tags
            snapshot_name = get_snapshot_name(snapshot)

            # Extract standard snapshot attributes
            snapshot_id = snapshot['SnapshotId']
            volume_id = snapshot.get('VolumeId', 'N/A')
            description = snapshot.get('Description', 'N/A')
            volume_size = snapshot.get('VolumeSize', 0)  # Size in GB

            # Handle start time (convert to string without timezone)
            start_time = snapshot.get('StartTime', '')
            start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else 'N/A'

            # Get encryption status
            encryption = 'Yes' if snapshot.get('Encrypted', False) else 'No'

            # Get storage tier (Standard or Archive)
            storage_tier = snapshot.get('StorageTier', 'Standard')

            # Get state and progress
            state = snapshot.get('State', 'N/A')
            progress = snapshot.get('Progress', 'N/A')

            # Get owner ID with account name mapping
            owner_id = snapshot.get('OwnerId', 'N/A')
            owner_formatted = utils.get_account_name_formatted(owner_id)

            # Get KMS key ID if encrypted
            kms_key_id = snapshot.get('KmsKeyId', 'N/A') if snapshot.get('Encrypted', False) else 'N/A'

            # Format tags
            snapshot_tags = format_tags(snapshot.get('Tags', []))

            # Additional data processing for specific attributes
            # Full snapshot size is not directly available via standard API
            full_snapshot_size_gb = 'N/A'

            # Add to results
            snapshots_data.append({
                'Name': snapshot_name,
                'Snapshot ID': snapshot_id,
                'Volume ID': volume_id,
                'Description': description,
                'Volume Size (GB)': volume_size,
                'Full Snapshot Size': full_snapshot_size_gb,
                'Storage Tier': storage_tier,
                'State': state,
                'Progress': progress,
                'Started': start_time_str,
                'Encryption': encryption,
                'KMS Key ID': kms_key_id,
                'Owner ID': owner_formatted,
                'Region': region,
                'Tags': snapshot_tags
            })

    return snapshots_data

def main():
    """
    Main function to execute the script.
    """
    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)
        
        # Now import pandas (after dependency check)
        import pandas as pd
        
        if account_name == "UNKNOWN-ACCOUNT":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Detect partition and set partition-appropriate region examples
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
                        region_suffix = f"_{selected_region}"
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(all_available_regions)}.")
                except ValueError:
                    print(f"Please enter a valid number (1-{len(all_available_regions)}).")

        print(f"\nProcessing {region_text}...")
        print("=" * 68)
        
        # Collect snapshot data from all specified AWS regions (Phase 4B: concurrent)
        utils.log_info("Collecting EBS snapshot data from all regions...")

        # Define region scan function
        def scan_region_snapshots(region):
            utils.log_info(f"Processing AWS region: {region}")
            region_snapshots = get_snapshots(region)
            utils.log_info(f"Found {len(region_snapshots)} snapshots in {region}")
            return region_snapshots

        # Use concurrent region scanning
        region_results = utils.scan_regions_concurrent(
            regions=regions,
            scan_function=scan_region_snapshots,
            show_progress=True
        )

        # Flatten results
        all_snapshots = []
        for snapshots in region_results:
            all_snapshots.extend(snapshots)
        
        # Print summary
        total_snapshots = len(all_snapshots)
        utils.log_success(f"Total EBS snapshots found across all AWS regions: {total_snapshots}")
        
        if total_snapshots == 0:
            utils.log_warning("No snapshots found. Nothing to export.")
            sys.exit(0)
        
        # Create DataFrame from snapshot data
        utils.log_info("Preparing data for export to Excel format...")
        df = pd.DataFrame(all_snapshots)

        # Prepare and sanitize DataFrame (tags may contain secrets)
        df = utils.sanitize_for_export(
            utils.prepare_dataframe_for_export(df)
        )

        # Generate filename with region info
        region_suffix = "" if region_choice == "all" else f"-{region_choice}"

        # Use utils module to generate filename
        filename = utils.create_export_filename(
            account_name,
            "ebs-snapshots",
            region_suffix if region_suffix else None,
            datetime.datetime.now().strftime("%m.%d.%Y")
        )

        # Save the data using the utility function
        output_path = utils.save_dataframe_to_excel(df, filename)
        
        if output_path:
            utils.log_success("AWS EBS snapshots data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
            utils.log_info(f"Total snapshots exported: {total_snapshots}")
            print("\nScript execution completed.")
        else:
            utils.log_error("Error exporting data. Please check the logs.")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()