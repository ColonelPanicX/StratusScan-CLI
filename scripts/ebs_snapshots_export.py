#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS EBS Snapshots Export Tool
Date: NOV-15-2025

Description:
This script exports Amazon EBS snapshot information across AWS regions or a specific
AWS region into an Excel spreadsheet. The export includes snapshot name, ID,
description, size information, encryption status, storage tier, and creation date.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import datetime
import sys
import time
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
args = utils.parse_script_args("Export EBS snapshots to Excel")

def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region.

    Args:
        region_name (str): The region name to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.is_aws_region(region_name)

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

def _build_snapshot_row(snapshot, region):
    """
    Build the export row for a single EBS snapshot.

    Extracted so the per-snapshot processing can be wrapped in try/except by the
    caller: a malformed snapshot entry is logged and skipped rather than
    discarding the whole region's results. Every required field is read with
    ``.get()`` and a safe default for the same reason.

    Args:
        snapshot (dict): A single snapshot entry from describe_snapshots.
        region (str): AWS region name.

    Returns:
        dict: The assembled snapshot row.
    """
    # Get snapshot name from tags
    snapshot_name = get_snapshot_name(snapshot)

    # Extract standard snapshot attributes. Required fields read defensively:
    # a missing field yields 'N/A'/'Unknown', not a KeyError that would sink
    # the entire region (see the 07.15.2026 audit / 07.16.2026 blast-radius sweep).
    snapshot_id = snapshot.get('SnapshotId', 'Unknown')
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

    return {
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
    }


def get_snapshots(region):
    """
    Get all EBS snapshots owned by the account in a specific AWS region.

    Not wrapped in ``aws_error_handler``: a swallowed error here would return
    an empty list that ``main()`` cannot distinguish from a genuinely empty
    region, producing silent data loss (no file written). Region-level
    failures are allowed to raise so the caller can record the region as
    *failed* rather than *empty*. Per-snapshot errors are contained
    internally (logged and skipped).

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries with snapshot information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    snapshots_data = []

    # Create EC2 client using utils for proper retry logic
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Use pagination to handle large number of snapshots
    paginator = ec2_client.get_paginator('describe_snapshots')
    page_iterator = paginator.paginate(OwnerIds=['self'])

    skipped = 0
    total_processed = 0
    for page in page_iterator:
        for snapshot in page.get('Snapshots', []):
            total_processed += 1
            snapshot_id = snapshot.get('SnapshotId', 'Unknown')
            try:
                snapshot_row = _build_snapshot_row(snapshot, region)
            except Exception as e:
                skipped += 1
                utils.log_error(
                    f"Skipping EBS snapshot '{snapshot_id}' in {region} due to a processing error", e
                )
                continue

            snapshots_data.append(snapshot_row)
        # Inter-page delay to avoid throttling on large accounts
        time.sleep(0.1)
        # Heartbeat every 500 records so terminal stays alive
        collected = len(snapshots_data)
        if collected > 0 and collected % 500 == 0:
            print(f"  [{collected:,} snapshots collected — still running...]")

    if skipped:
        utils.log_warning(
            f"{skipped} of {total_processed} EBS snapshot(s) in {region} were skipped due to "
            "processing errors (see log above); the remaining snapshots were still collected."
        )

    return snapshots_data

def main():
    """
    Main function to execute the script.
    """
    try:
        # Print title and get account information
        utils.setup_logging("ebs-snapshots-export")
        account_id, account_name = utils.print_script_banner("AWS EBS SNAPSHOTS EXPORT")

        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Now import pandas (after dependency check)
        import pandas as pd

        if account_name == "UNKNOWN-ACCOUNT" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
            print("Exiting script...")
            sys.exit(0)

        regions = utils.prompt_region_selection()

        # Collect snapshot data from all specified AWS regions (Phase 4B: concurrent)
        utils.log_info("Collecting EBS snapshot data from all regions...")

        # Define region scan function
        def scan_region_snapshots(region):
            utils.log_info(f"Processing AWS region: {region}")
            region_snapshots = get_snapshots(region)
            utils.log_info(f"Found {len(region_snapshots)} snapshots in {region}")
            return region_snapshots

        # Use concurrent region scanning. collect_failures=True returns the
        # regions that raised so a failed collection is distinguishable from a
        # genuinely empty account (see Issue #233 blast-radius sweep).
        region_results, failed_regions = utils.scan_regions_concurrent(
            regions=regions,
            scan_function=scan_region_snapshots,
            max_workers=2,
            show_progress=True,
            collect_failures=True
        )

        # Flatten results
        all_snapshots = []
        for snapshots in region_results:
            all_snapshots.extend(snapshots)

        # Print summary
        total_snapshots = len(all_snapshots)
        utils.log_success(f"Total EBS snapshots found across all AWS regions: {total_snapshots}")

        if all_snapshots:
            # Create DataFrame from snapshot data
            utils.log_info("Preparing data for export to Excel format...")
            df = pd.DataFrame(all_snapshots)

            # Prepare and sanitize DataFrame (tags may contain secrets)
            df = utils.sanitize_for_export(
                utils.prepare_dataframe_for_export(df)
            )

            # Generate filename with region info
            region_suffix = regions[0] if len(regions) == 1 else 'all'

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
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
                utils.log_info(f"Total snapshots exported: {total_snapshots}")
                print("\nScript execution completed.")
            else:
                utils.log_error("Error exporting data. Please check the logs.")
                sys.exit(1)
        elif not failed_regions:
            # Genuinely empty account: every region succeeded and returned nothing.
            utils.log_warning("No snapshots found. Nothing to export.")

        # If ANY region failed, make it loud: write a marker and exit non-zero,
        # even if some data was exported. A partial export that looks complete
        # is exactly the failure mode this guards against.
        if failed_regions:
            utils.report_collection_failures(account_name, "ebs-snapshots", failed_regions)
            print(
                "\nERROR: EBS snapshots export completed with failures — data is incomplete. "
                "See the *-ebs-snapshots-FAILED-*.txt marker in the output directory."
            )
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
