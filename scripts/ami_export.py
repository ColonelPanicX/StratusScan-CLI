#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS AMI (Amazon Machine Images) Export Tool
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
- Ancestry: source instance, copy source, and the parent AMI inferred from
  snapshot descriptions (one hop — join the sheet to itself to walk lineage)
- Public/Private status
- Platform details (Linux, Windows)
- Block device mappings
- Tags

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import datetime
import re
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
args = utils.parse_script_args("Export Amazon Machine Images (AMIs) to Excel")


# ---------------------------------------------------------------------------
# AMI ancestry (Issue #270)
#
# The export described what an AMI *is* and nothing about where it came from.
# AWS exposes provenance through channels of differing reliability, and they
# are kept in separate columns rather than merged: a contractual field and a
# parsed description must never be indistinguishable to a reader who is filing
# the workbook as evidence.
#
# One hop, not a chain. Each row names its immediate ancestor; a consumer
# self-joins the sheet to walk lineage. Recursive resolution would mean
# describing images owned by other accounts, unbounded depth, and dead ends
# wherever an ancestor was deregistered.
# ---------------------------------------------------------------------------

# AWS writes this description when CreateImage snapshots a volume. It names
# both the source instance and the AMI the snapshot was taken for — the only
# route to a parent AMI for a locally built image. It is a *description
# string*, not a contractual field: AWS could reword it, and a user who edits
# the description breaks the parse for that AMI. Hence "(inferred)".
_CREATE_IMAGE_DESCRIPTION = re.compile(
    r"Created by CreateImage\((i-[0-9a-fA-F]+)\)\s+for\s+(ami-[0-9a-fA-F]+)"
)

# Distinct from 'N/A': the field is absent from this botocore's model, so AWS
# was never asked. Collapsing the two would repeat the mistake that made the
# scaling-policy alarm gap invisible (Issue #268).
_COPY_SOURCE_UNSUPPORTED = 'Unavailable (boto3 too old)'
_ANCESTRY_UNRESOLVED = 'Unresolved (snapshot lookup failed)'


def _copy_source_supported(ec2_client) -> bool:
    """
    Whether this botocore models ``SourceImageId`` on DescribeImages.

    The copy-source fields postdate the project's pinned boto3 floor (absent in
    1.34.46, present in 1.43.83), so the column has to distinguish "this AMI
    was not copied" from "this client cannot report copies at all" — see
    Issue #213 for the wider version-floor problem.
    """
    try:
        image_shape = (
            ec2_client.meta.service_model
            .operation_model('DescribeImages')
            .output_shape.members['Images'].member
        )
        return 'SourceImageId' in image_shape.members
    except Exception:  # noqa: BLE001 - unknown model shape; assume unsupported
        return False


def _resolve_snapshot_ancestry(ec2_client, snapshot_ids: list[str]) -> dict[str, dict[str, str]]:
    """
    Parse CreateImage provenance out of EBS snapshot descriptions.

    Returns ``{snapshot_id: {'source_instance': ..., 'parent_ami': ...}}`` for
    every snapshot whose description matches the CreateImage convention.

    Chunked **and** paginated: ``SnapshotIds`` bounds the request size while the
    response pages independently, and handling only one of the two silently
    drops results (Issue #268).

    Enrichment, not scope: a failure here yields unresolved columns rather than
    failing the region, since the AMIs themselves were collected successfully.
    """
    ancestry: dict[str, dict[str, str]] = {}
    ids = sorted({s for s in snapshot_ids if s})
    if not ids:
        return ancestry

    paginator = ec2_client.get_paginator('describe_snapshots')
    for index in range(0, len(ids), 100):
        chunk = ids[index:index + 100]
        for page in paginator.paginate(SnapshotIds=chunk):
            for snapshot in page.get('Snapshots', []):
                match = _CREATE_IMAGE_DESCRIPTION.search(snapshot.get('Description', '') or '')
                if not match:
                    continue
                ancestry[snapshot.get('SnapshotId', '')] = {
                    'source_instance': match.group(1),
                    'parent_ami': match.group(2),
                }
    return ancestry


def _ancestry_columns(
    ami: dict,
    snapshot_ancestry: dict[str, dict[str, str]],
    copy_source_supported: bool,
    lookup_failed: bool = False,
) -> dict[str, Any]:
    """
    Build the ancestry columns for one AMI.

    Contractual fields (``SourceInstanceId``, ``SourceImageId``) and the value
    inferred from snapshot descriptions are kept in separate columns. Nobody
    should be able to build a compliance claim on a parsed string without
    knowing that is what it is.

    Ancestry is partial by nature: an AMI imported via VM Import, built by a
    third party, or whose parent was deregistered has no resolvable ancestor.
    That is a correct result, not a collection failure.
    """
    if copy_source_supported:
        source_image_id = ami.get('SourceImageId') or 'N/A'
        source_image_region = ami.get('SourceImageRegion') or 'N/A'
    else:
        source_image_id = _COPY_SOURCE_UNSUPPORTED
        source_image_region = _COPY_SOURCE_UNSUPPORTED

    snapshot_ids = [
        (bdm.get('Ebs') or {}).get('SnapshotId')
        for bdm in ami.get('BlockDeviceMappings', [])
        if (bdm.get('Ebs') or {}).get('SnapshotId')
    ]

    parent_ami = 'N/A'
    if lookup_failed and snapshot_ids:
        parent_ami = _ANCESTRY_UNRESOLVED
    else:
        for snapshot_id in snapshot_ids:
            resolved = snapshot_ancestry.get(snapshot_id)
            if resolved:
                parent_ami = resolved['parent_ami']
                break

    return {
        'Source Instance ID': ami.get('SourceInstanceId') or 'N/A',
        'Source Image ID': source_image_id,
        'Source Image Region': source_image_region,
        'Parent AMI (inferred)': parent_ami,
    }


def _build_ami_row(ami: dict, region: str) -> dict[str, Any]:
    """Build a single AMI export row from a describe_images response item."""
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
    tag_dict = {tag.get('Key'): tag.get('Value') for tag in tags if tag.get('Key') and 'Value' in tag}
    tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

    return {
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
    }


def collect_amis_in_region(region: str, account_id: str) -> list[dict[str, Any]]:
    """
    Collect account-owned AMI information from a single AWS region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no AMIs" (the silent-collection-
    loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed AMIs are skipped (logged) rather than aborting the
    whole region.

    Args:
        region: AWS region to scan
        account_id: AWS account ID to filter owned AMIs

    Returns:
        list: List of dictionaries with AMI information
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"  Processing region: {region}")

    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get AMIs owned by this account
    paginator = ec2_client.get_paginator('describe_images')
    amis = []
    for page in paginator.paginate(Owners=['self']):
        amis.extend(page.get('Images', []))

    print(f"  Found {len(amis)} account-owned AMIs")

    # Resolve provenance before building rows (Issue #270). This is enrichment,
    # not scope: a failure yields unresolved columns rather than failing a
    # region whose AMIs were collected successfully.
    copy_source_supported = _copy_source_supported(ec2_client)
    snapshot_ids = [
        (bdm.get('Ebs') or {}).get('SnapshotId')
        for ami in amis
        for bdm in ami.get('BlockDeviceMappings', [])
        if (bdm.get('Ebs') or {}).get('SnapshotId')
    ]
    snapshot_ancestry = {}
    ancestry_lookup_failed = False
    try:
        snapshot_ancestry = _resolve_snapshot_ancestry(ec2_client, snapshot_ids)
    except Exception as e:
        ancestry_lookup_failed = True
        utils.log_warning(
            f"Could not resolve AMI ancestry from snapshots in {region} "
            f"(parent AMI will read unresolved): {e}"
        )

    region_amis = []
    for ami in amis:
        try:
            row = _build_ami_row(ami, region)
            row.update(_ancestry_columns(
                ami, snapshot_ancestry, copy_source_supported, ancestry_lookup_failed
            ))
            region_amis.append(row)
        except Exception as e:
            # One malformed AMI is skipped, not fatal to the region.
            utils.log_error(
                f"Skipping malformed AMI in {region}: {ami.get('ImageId', '<unknown>')}",
                e,
            )
            continue

    return region_amis


def collect_amis(regions: list[str], account_id: str) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AMI information across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(amis, failed_regions)`` where ``failed_regions`` is a list of
        ``(region, error_message)`` tuples.
    """
    def scan_region_amis(region):
        return collect_amis_in_region(region, account_id)

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_amis,
        show_progress=True,
        collect_failures=True,
    )
    all_amis = [ami for result in region_results for ami in result]
    return all_amis, failed_regions


def export_ami_data(account_id: str, account_name: str):
    """
    Export AMI information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition and set partition-aware example regions
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Collect AMIs using concurrent region scanning (Phase 4B). This is the
    # primary scope collector — region failures must propagate as
    # failed_regions, never collapse into "empty".
    print("\n=== COLLECTING ACCOUNT-OWNED AMIs ===")

    amis, failed_regions = collect_amis(regions, account_id)

    utils.log_success(f"Total AMIs collected: {len(amis)}")

    # Export whatever succeeded — a partial export is required even on
    # partial failure (see the silent-collection-failure blast-radius audit).
    if amis:
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
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
                utils.log_info(f"Total AMIs: {len(df)} records")
                print(f"Total AMIs: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)
    elif not failed_regions:
        # Genuinely empty account: every region succeeded and returned nothing.
        utils.log_warning("No AMI data was collected. Nothing to export.")
        print("\nNo account-owned AMIs found in the selected region(s).")

    # If ANY region failed the primary AMI scope collection, make it loud:
    # write a marker and exit non-zero, even if some data was exported. A
    # partial export that looks complete is exactly the failure mode this guards.
    if failed_regions:
        utils.report_collection_failures(account_name, 'ami', failed_regions)
        print(
            "\nERROR: AMI export completed with failures — data is incomplete. "
            "See the *-ami-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("ami-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("ami-export.py", "AWS AMI Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS AMI (AMAZON MACHINE IMAGES) EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
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
