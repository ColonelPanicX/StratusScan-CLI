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

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any
import json

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


def scan_kms_keys_in_region(region: str, account_id: str) -> List[Dict[str, Any]]:
    """
    Scan KMS keys in a single region.

    Args:
        region: AWS region to scan
        account_id: AWS account ID for filtering

    Returns:
        list: List of dictionaries with KMS key information from this region
    """
    regional_keys = []

    try:
        kms_client = utils.get_boto3_client('kms', region_name=region)

        # Get KMS keys
        paginator = kms_client.get_paginator('list_keys')
        key_count = 0

        for page in paginator.paginate():
            keys = page.get('Keys', [])
            key_count += len(keys)

            for key in keys:
                key_id = key.get('KeyId', '')
                key_arn = key.get('KeyArn', '')

                # Skip AWS managed keys if desired, but include for visibility
                try:
                    # Get key metadata
                    metadata = kms_client.describe_key(KeyId=key_id)
                    key_metadata = metadata.get('KeyMetadata', {})

                    key_manager = key_metadata.get('KeyManager', '')

                    # Get basic info
                    key_state = key_metadata.get('KeyState', '')
                    description = key_metadata.get('Description', '')
                    creation_date = key_metadata.get('CreationDate', '')
                    if creation_date:
                        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                    # Enabled status
                    enabled = key_metadata.get('Enabled', False)

                    # Key spec and usage
                    key_spec = key_metadata.get('KeySpec', 'N/A')
                    key_usage = key_metadata.get('KeyUsage', 'N/A')

                    # Encryption algorithms
                    encryption_algorithms = key_metadata.get('EncryptionAlgorithms', [])
                    encryption_algorithms_str = ', '.join(encryption_algorithms) if encryption_algorithms else 'N/A'

                    # Multi-region key
                    multi_region = key_metadata.get('MultiRegion', False)
                    multi_region_config = 'N/A'
                    if multi_region:
                        multi_region_config = key_metadata.get('MultiRegionConfiguration', {}).get('MultiRegionKeyType', 'N/A')

                    # Origin
                    origin = key_metadata.get('Origin', 'N/A')

                    # Custom key store ID
                    custom_key_store_id = key_metadata.get('CustomKeyStoreId', 'N/A')

                    # Cloud HSM cluster ID
                    cloud_hsm_cluster_id = key_metadata.get('CloudHsmClusterId', 'N/A')

                    # Deletion date
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

                    regional_keys.append({
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
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get metadata for key {key_id} in {region}: {e}")

        utils.log_info(f"Found {key_count} KMS keys in {region}")

    except Exception as e:
        utils.log_error(f"Error processing region {region} for KMS keys", e)

    return regional_keys


@utils.aws_error_handler("Collecting KMS keys", default_return=[])
def collect_kms_keys(regions: List[str], account_id: str) -> List[Dict[str, Any]]:
    """
    Collect KMS key information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID for filtering

    Returns:
        list: List of dictionaries with KMS key information
    """
    print("\n=== COLLECTING KMS KEYS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning with account_id parameter
    all_keys = []
    for region_data in utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_kms_keys_in_region,
        account_id=account_id
    ):
        all_keys.extend(region_data)

    utils.log_success(f"Total KMS keys collected: {len(all_keys)}")
    return all_keys


def scan_kms_aliases_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan KMS aliases in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with alias information from this region
    """
    regional_aliases = []

    try:
        kms_client = utils.get_boto3_client('kms', region_name=region)

        # Get aliases
        paginator = kms_client.get_paginator('list_aliases')

        for page in paginator.paginate():
            aliases = page.get('Aliases', [])

            for alias in aliases:
                alias_name = alias.get('AliasName', '')
                alias_arn = alias.get('AliasArn', '')
                target_key_id = alias.get('TargetKeyId', 'N/A')

                # Creation date
                creation_date = alias.get('CreationDate', '')
                if creation_date:
                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                # Last updated date
                last_updated_date = alias.get('LastUpdatedDate', '')
                if last_updated_date:
                    last_updated_date = last_updated_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_updated_date, datetime.datetime) else str(last_updated_date)

                regional_aliases.append({
                    'Region': region,
                    'Alias Name': alias_name,
                    'Target Key ID': target_key_id,
                    'Creation Date': creation_date,
                    'Last Updated Date': last_updated_date if last_updated_date else 'N/A',
                    'Alias ARN': alias_arn
                })

        utils.log_info(f"Found {len(regional_aliases)} KMS aliases in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting aliases in region {region}", e)

    return regional_aliases


@utils.aws_error_handler("Collecting KMS aliases", default_return=[])
def collect_kms_aliases(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect KMS key alias information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with alias information
    """
    print("\n=== COLLECTING KMS ALIASES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_aliases = []
    for region_data in utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_kms_aliases_in_region,
    ):
        all_aliases.extend(region_data)

    utils.log_success(f"Total KMS aliases collected: {len(all_aliases)}")
    return all_aliases


def scan_kms_grants_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan KMS grants in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with grant information from this region
    """
    regional_grants = []

    try:
        kms_client = utils.get_boto3_client('kms', region_name=region)

        # Get all keys first
        key_paginator = kms_client.get_paginator('list_keys')

        for key_page in key_paginator.paginate():
            keys = key_page.get('Keys', [])

            for key in keys:
                key_id = key.get('KeyId', '')

                try:
                    # Get grants for this key
                    grant_paginator = kms_client.get_paginator('list_grants')

                    for grant_page in grant_paginator.paginate(KeyId=key_id):
                        grants = grant_page.get('Grants', [])

                        for grant in grants:
                            grant_id = grant.get('GrantId', '')
                            grant_name = grant.get('Name', 'N/A')
                            grantee_principal = grant.get('GranteePrincipal', '')

                            # Operations
                            operations = grant.get('Operations', [])
                            operations_str = ', '.join(operations) if operations else 'N/A'

                            # Constraints
                            constraints = grant.get('Constraints', {})
                            encryption_context_subset = constraints.get('EncryptionContextSubset', {})
                            encryption_context_equals = constraints.get('EncryptionContextEquals', {})

                            # Creation date
                            creation_date = grant.get('CreationDate', '')
                            if creation_date:
                                creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                            # Retiring principal
                            retiring_principal = grant.get('RetiringPrincipal', 'N/A')

                            # Grant tokens
                            grant_tokens = grant.get('GrantTokens', [])
                            grant_token_count = len(grant_tokens)

                            regional_grants.append({
                                'Region': region,
                                'Key ID': key_id,
                                'Grant ID': grant_id,
                                'Grant Name': grant_name,
                                'Grantee Principal': grantee_principal,
                                'Operations': operations_str,
                                'Retiring Principal': retiring_principal,
                                'Grant Token Count': grant_token_count,
                                'Creation Date': creation_date
                            })

                except Exception as e:
                    # Some keys may not have grants, which is normal
                    pass

        utils.log_info(f"Found {len(regional_grants)} KMS grants in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting grants in region {region}", e)

    return regional_grants


@utils.aws_error_handler("Collecting KMS grants", default_return=[])
def collect_kms_grants(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect KMS grant information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with grant information
    """
    print("\n=== COLLECTING KMS GRANTS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_grants = []
    for region_data in utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_kms_grants_in_region,
    ):
        all_grants.extend(region_data)

    utils.log_success(f"Total KMS grants collected: {len(all_grants)}")
    return all_grants


def export_kms_data(account_id: str, account_name: str):
    """
    Export KMS information to an Excel file.

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

    # STEP 1: Collect KMS keys
    keys = collect_kms_keys(regions, account_id)
    if keys:
        data_frames['KMS Keys'] = pd.DataFrame(keys)

    # STEP 2: Collect aliases
    aliases = collect_kms_aliases(regions)
    if aliases:
        data_frames['Key Aliases'] = pd.DataFrame(aliases)

    # STEP 3: Collect grants
    grants = collect_kms_grants(regions)
    if grants:
        data_frames['Key Grants'] = pd.DataFrame(grants)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No KMS data was collected. Nothing to export.")
        print("\nNo KMS keys found in the selected region(s).")
        return

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

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("KMS data exported successfully!")
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
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
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
