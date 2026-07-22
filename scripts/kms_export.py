#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS KMS (Key Management Service) Export Tool
Date: NOV-09-2025

Description:
This script exports AWS KMS key information from all regions into an Excel file with
multiple worksheets. The output includes KMS keys, key metadata, aliases, grants, and
key policies.

Features:
- KMS keys with encryption algorithms and key states
- Key metadata including creation dates and rotation status
- Key aliases and their associations
- Key grants with grantee principals and operations
- Key policies for access control
- Multi-region key configurations
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
args = utils.parse_script_args("Export KMS keys and aliases to Excel")


def _build_key_row(kms_client, key: dict[str, Any], region: str) -> dict[str, Any]:
    """
    Build the export row for a single KMS key.

    Extracted so per-key processing can be wrapped in try/except by the
    caller: a malformed or unusual key (e.g. a key type/manager combination
    that omits a field another key type always sets) is logged and skipped
    rather than discarding the whole region's results. Every field is read
    with ``.get()`` and a safe default for the same reason.

    Args:
        kms_client: Boto3 KMS client for the region.
        key: A single entry from list_keys' ``Keys``.
        region: AWS region name.

    Returns:
        dict: The assembled key row.
    """
    key_id = key.get('KeyId', 'N/A')
    key_arn = key.get('KeyArn', 'N/A')

    metadata = kms_client.describe_key(KeyId=key_id)
    key_metadata = metadata.get('KeyMetadata', {})

    key_manager = key_metadata.get('KeyManager', 'N/A')
    key_state = key_metadata.get('KeyState', 'N/A')
    description = key_metadata.get('Description', 'N/A')
    creation_date = key_metadata.get('CreationDate', '')
    if creation_date:
        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)
    else:
        creation_date = 'N/A'

    enabled = key_metadata.get('Enabled', False)

    key_spec = key_metadata.get('KeySpec', 'N/A')
    key_usage = key_metadata.get('KeyUsage', 'N/A')

    encryption_algorithms = key_metadata.get('EncryptionAlgorithms', [])
    encryption_algorithms_str = ', '.join(encryption_algorithms) if encryption_algorithms else 'N/A'

    multi_region = key_metadata.get('MultiRegion', False)
    multi_region_config = 'N/A'
    if multi_region:
        multi_region_config = key_metadata.get('MultiRegionConfiguration', {}).get('MultiRegionKeyType', 'N/A')

    origin = key_metadata.get('Origin', 'N/A')
    custom_key_store_id = key_metadata.get('CustomKeyStoreId', 'N/A')
    cloud_hsm_cluster_id = key_metadata.get('CloudHsmClusterId', 'N/A')

    deletion_date = key_metadata.get('DeletionDate', '')
    if deletion_date:
        deletion_date = deletion_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(deletion_date, datetime.datetime) else str(deletion_date)
    else:
        deletion_date = 'N/A'

    # Check rotation status (only for customer managed keys)
    rotation_enabled = 'N/A'
    if key_manager == 'CUSTOMER' and key_state == 'Enabled':
        try:
            rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)
            rotation_enabled = rotation_status.get('KeyRotationEnabled', False)
        except Exception:
            rotation_enabled = 'N/A'

    return {
        'Region': region,
        'Key ID': key_id,
        'Key State': key_state,
        'Enabled': enabled,
        'Description': description,
        'Key Manager': key_manager,
        'Key Spec': key_spec,
        'Key Usage': key_usage,
        'Encryption Algorithms': encryption_algorithms_str,
        'Multi-Region': multi_region,
        'Multi-Region Type': multi_region_config,
        'Origin': origin,
        'Rotation Enabled': rotation_enabled,
        'Custom Key Store ID': custom_key_store_id,
        'CloudHSM Cluster ID': cloud_hsm_cluster_id,
        'Creation Date': creation_date,
        'Deletion Date': deletion_date,
        'Key ARN': key_arn
    }


def scan_kms_keys_in_region(region: str, account_id: str) -> list[dict[str, Any]]:
    """
    Scan KMS keys in a single region.

    Not wrapped in a swallow-all try/except: a region-level API error (e.g.
    throttling on list_keys) must propagate so the caller can record the
    region as FAILED rather than collapsing it into an empty/successful
    result -- silent data loss (see 07.16.2026 blast-radius audit). Per-key
    errors are contained internally (logged and skipped) so one malformed
    key does not sink the whole region's collection.

    Args:
        region: AWS region to scan
        account_id: AWS account ID (unused for filtering; kept for interface
            compatibility with collect_kms_keys)

    Returns:
        list: List of dictionaries with KMS key information from this region

    Raises:
        Exception: Any AWS/pagination error for the region.
    """
    kms_client = utils.get_boto3_client('kms', region_name=region)

    paginator = kms_client.get_paginator('list_keys')
    all_keys: list[dict[str, Any]] = []
    for page in paginator.paginate():
        all_keys.extend(page.get('Keys', []))

    total_keys = len(all_keys)
    if total_keys:
        utils.log_info(f"Found {total_keys} KMS keys in {region} to process")

    regional_keys = []
    skipped = 0
    for key in all_keys:
        key_id = key.get('KeyId', 'Unknown')
        try:
            regional_keys.append(_build_key_row(kms_client, key, region))
        except Exception as e:
            skipped += 1
            utils.log_error(f"Skipping KMS key '{key_id}' in {region} due to a processing error", e)
            continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {total_keys} KMS key(s) in {region} were skipped due to "
            "processing errors (see log above); the remaining keys were still collected."
        )

    utils.log_info(f"Found {len(regional_keys)} KMS keys in {region}")
    return regional_keys


def collect_kms_keys(
    regions: list[str], account_id: str
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect KMS key information from AWS regions using concurrent scanning.

    Not wrapped in ``aws_error_handler``: swallowing here would return an
    empty list indistinguishable from a genuinely empty account. Instead the
    per-region collector is allowed to raise and ``failed_regions`` is
    returned so the caller can surface a failed collection instead of
    masking it as "no keys".

    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID for filtering

    Returns:
        tuple: (list of KMS key dicts, list of (region, error_message) failures)
    """
    print("\n=== COLLECTING KMS KEYS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    def _scan(region: str) -> list[dict[str, Any]]:
        return scan_kms_keys_in_region(region, account_id)

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan,
        collect_failures=True,
    )

    all_keys: list[dict[str, Any]] = []
    for region_data in region_results:
        all_keys.extend(region_data)

    utils.log_success(f"Total KMS keys collected: {len(all_keys)}")
    return all_keys, failed_regions


def _build_alias_row(alias: dict[str, Any], region: str) -> dict[str, Any]:
    """
    Build the export row for a single KMS alias.

    Extracted so per-alias processing can be wrapped in try/except by the
    caller. Every field is read with ``.get()`` and a safe default.

    Args:
        alias: A single entry from list_aliases' ``Aliases``.
        region: AWS region name.

    Returns:
        dict: The assembled alias row.
    """
    alias_name = alias.get('AliasName', 'N/A')
    alias_arn = alias.get('AliasArn', 'N/A')
    target_key_id = alias.get('TargetKeyId', 'N/A')

    creation_date = alias.get('CreationDate', '')
    if creation_date:
        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)
    else:
        creation_date = 'N/A'

    last_updated_date = alias.get('LastUpdatedDate', '')
    if last_updated_date:
        last_updated_date = last_updated_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_updated_date, datetime.datetime) else str(last_updated_date)
    else:
        last_updated_date = 'N/A'

    return {
        'Region': region,
        'Alias Name': alias_name,
        'Target Key ID': target_key_id,
        'Creation Date': creation_date,
        'Last Updated Date': last_updated_date,
        'Alias ARN': alias_arn
    }


def scan_kms_aliases_in_region(region: str) -> list[dict[str, Any]]:
    """
    Scan KMS aliases in a single region.

    Not wrapped in a swallow-all try/except; a region-level API error must
    propagate so the caller can record the region as FAILED (see
    scan_kms_keys_in_region for the full rationale). Per-alias errors are
    contained internally (logged and skipped).

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with alias information from this region

    Raises:
        Exception: Any AWS/pagination error for the region.
    """
    kms_client = utils.get_boto3_client('kms', region_name=region)

    paginator = kms_client.get_paginator('list_aliases')
    all_aliases: list[dict[str, Any]] = []
    for page in paginator.paginate():
        all_aliases.extend(page.get('Aliases', []))

    regional_aliases = []
    skipped = 0
    for alias in all_aliases:
        alias_name = alias.get('AliasName', 'Unknown')
        try:
            regional_aliases.append(_build_alias_row(alias, region))
        except Exception as e:
            skipped += 1
            utils.log_error(f"Skipping KMS alias '{alias_name}' in {region} due to a processing error", e)
            continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {len(all_aliases)} KMS alias(es) in {region} were skipped due to "
            "processing errors (see log above); the remaining aliases were still collected."
        )

    utils.log_info(f"Found {len(regional_aliases)} KMS aliases in {region}")
    return regional_aliases


def collect_kms_aliases(
    regions: list[str],
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect KMS key alias information from AWS regions using concurrent scanning.

    Not wrapped in ``aws_error_handler``; see collect_kms_keys for rationale.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: (list of alias dicts, list of (region, error_message) failures)
    """
    print("\n=== COLLECTING KMS ALIASES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_kms_aliases_in_region,
        collect_failures=True,
    )

    all_aliases: list[dict[str, Any]] = []
    for region_data in region_results:
        all_aliases.extend(region_data)

    utils.log_success(f"Total KMS aliases collected: {len(all_aliases)}")
    return all_aliases, failed_regions


def _build_grant_row(grant: dict[str, Any], key_id: str, region: str) -> dict[str, Any]:
    """
    Build the export row for a single KMS grant.

    Extracted so per-grant processing can be wrapped in try/except by the
    caller. Every field is read with ``.get()`` and a safe default.

    Args:
        grant: A single entry from list_grants' ``Grants``.
        key_id: The KMS key ID the grant belongs to.
        region: AWS region name.

    Returns:
        dict: The assembled grant row.
    """
    grant_id = grant.get('GrantId', 'N/A')
    grant_name = grant.get('Name', 'N/A')
    grantee_principal = grant.get('GranteePrincipal', 'N/A')

    operations = grant.get('Operations', [])
    operations_str = ', '.join(operations) if operations else 'N/A'

    creation_date = grant.get('CreationDate', '')
    if creation_date:
        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)
    else:
        creation_date = 'N/A'

    retiring_principal = grant.get('RetiringPrincipal', 'N/A')
    grant_tokens = grant.get('GrantTokens', [])
    grant_token_count = len(grant_tokens)

    return {
        'Region': region,
        'Key ID': key_id,
        'Grant ID': grant_id,
        'Grant Name': grant_name,
        'Grantee Principal': grantee_principal,
        'Operations': operations_str,
        'Retiring Principal': retiring_principal,
        'Grant Token Count': grant_token_count,
        'Creation Date': creation_date
    }


def scan_kms_grants_in_region(region: str) -> list[dict[str, Any]]:
    """
    Scan KMS grants in a single region.

    The initial key listing is a region-level operation and is NOT wrapped in
    a swallow-all try/except: it must propagate so the caller can record the
    region as FAILED (see scan_kms_keys_in_region for the full rationale).

    Grant lookups are performed per-key. A single key whose grants cannot be
    listed (e.g. pending deletion, access denied for that specific key) is
    logged and skipped -- that is genuine per-item enrichment scoped to one
    key and must not sink the whole region's grant collection.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with grant information from this region

    Raises:
        Exception: Any AWS/pagination error while listing keys for the region.
    """
    kms_client = utils.get_boto3_client('kms', region_name=region)

    key_paginator = kms_client.get_paginator('list_keys')
    all_keys: list[dict[str, Any]] = []
    for key_page in key_paginator.paginate():
        all_keys.extend(key_page.get('Keys', []))

    regional_grants = []
    skipped_keys = 0
    for key in all_keys:
        key_id = key.get('KeyId', 'Unknown')
        try:
            grant_paginator = kms_client.get_paginator('list_grants')
            for grant_page in grant_paginator.paginate(KeyId=key_id):
                for grant in grant_page.get('Grants', []):
                    regional_grants.append(_build_grant_row(grant, key_id, region))
        except Exception as e:
            skipped_keys += 1
            utils.log_warning(f"Could not list grants for KMS key '{key_id}' in {region} (skipping): {e}")
            continue

    if skipped_keys:
        utils.log_warning(
            f"Grants could not be listed for {skipped_keys} of {len(all_keys)} KMS key(s) in "
            f"{region}; grants for the remaining keys were still collected."
        )

    utils.log_info(f"Found {len(regional_grants)} KMS grants in {region}")
    return regional_grants


def collect_kms_grants(
    regions: list[str],
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect KMS grant information from AWS regions using concurrent scanning.

    Not wrapped in ``aws_error_handler``; see collect_kms_keys for rationale.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: (list of grant dicts, list of (region, error_message) failures)
    """
    print("\n=== COLLECTING KMS GRANTS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_kms_grants_in_region,
        collect_failures=True,
    )

    all_grants: list[dict[str, Any]] = []
    for region_data in region_results:
        all_grants.extend(region_data)

    utils.log_success(f"Total KMS grants collected: {len(all_grants)}")
    return all_grants, failed_regions


def export_kms_data(account_id: str, account_name: str):
    """
    Export KMS information to an Excel file.

    All three collectors (keys, aliases, grants) now report failed regions
    instead of silently swallowing them. A partial export (some sheets/rows
    present) is still written when possible, but any failed scope is
    recorded via a failure marker and the script exits non-zero -- a partial
    result that looks complete is exactly the silent-data-loss failure mode
    this guards against (see 07.16.2026 blast-radius audit).

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Ask for region selection
    print("\n" + "=" * 60)
    # Detect partition and set partition-aware example regions
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}
    all_failed_regions: list[tuple[str, str]] = []

    # STEP 1: Collect KMS keys
    keys, failed = collect_kms_keys(regions, account_id)
    all_failed_regions.extend((f"{failed_region} (keys)", err) for failed_region, err in failed)
    if keys:
        data_frames['KMS Keys'] = pd.DataFrame(keys)

    # STEP 2: Collect aliases
    aliases, failed = collect_kms_aliases(regions)
    all_failed_regions.extend((f"{failed_region} (aliases)", err) for failed_region, err in failed)
    if aliases:
        data_frames['Key Aliases'] = pd.DataFrame(aliases)

    # STEP 3: Collect grants
    grants, failed = collect_kms_grants(regions)
    all_failed_regions.extend((f"{failed_region} (grants)", err) for failed_region, err in failed)
    if grants:
        data_frames['Key Grants'] = pd.DataFrame(grants)

    # Check if we have any data
    if not data_frames:
        if not all_failed_regions:
            # Genuinely empty account: every region/sub-resource succeeded
            # and returned nothing. No file is exported.
            utils.log_warning("No KMS data was collected. Nothing to export.")
            print("\nNo KMS keys found in the selected region(s).")
        else:
            utils.log_error(
                "No KMS data was collected and one or more regions failed to collect."
            )
    else:
        # STEP 4: Prepare all DataFrames for export
        for sheet_name in data_frames:
            data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

        # STEP 5: Create filename and export
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        final_excel_file = utils.create_export_filename(
            account_name,
            'kms',
            region_suffix,
            current_date
        )

        # Save using utils module for consistent formatting. Partial export
        # (some sheets missing/incomplete due to failed_regions above) is
        # written deliberately -- whatever succeeded is still useful data.
        try:
            output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

            if output_path:
                utils.log_success("KMS data exported successfully!")
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

    # If ANY region/sub-resource failed, make it loud: write a marker and
    # exit non-zero, even if some data was exported. A partial export that
    # looks complete is exactly the failure mode this guards against.
    if all_failed_regions:
        utils.report_collection_failures(account_name, "kms", all_failed_regions)
        print(
            "\nERROR: KMS export completed with failures — data is incomplete. "
            "See the *-kms-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("kms-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("kms-export.py", "AWS KMS Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS KMS (KEY MANAGEMENT SERVICE) EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
            print("Exiting script...")
            sys.exit(0)

        # Export KMS data
        export_kms_data(account_id, account_name)

        print("\nKMS export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("kms-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
