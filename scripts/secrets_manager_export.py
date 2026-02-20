#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Secrets Manager Export Tool
Date: NOV-09-2025

Description:
This script exports AWS Secrets Manager secret information from all regions into an Excel
file with multiple worksheets. The output includes secret metadata, rotation configurations,
and resource policies (without exposing actual secret values).

Features:
- Secret metadata with creation and last accessed dates
- Rotation configurations and schedules
- Resource policies for access control
- KMS encryption key associations
- Replication configurations for multi-region secrets
- Version information and staging labels

SECURITY NOTE:
This script NEVER exports actual secret values. It only exports metadata and
configuration information for inventory and compliance purposes.
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


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("            AWS SECRETS MANAGER EXPORT TOOL")
    print("====================================================================")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")
    print("SECURITY: This tool DOES NOT export secret values, only metadata")
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
def scan_secrets_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Secrets Manager secrets in a single region.

    SECURITY: This function does NOT retrieve secret values, only metadata.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with secret metadata from this region
    """
    regional_secrets = []

    try:
        secrets_client = utils.get_boto3_client('secretsmanager', region_name=region)

        # Get secrets (metadata only, no values)
        paginator = secrets_client.get_paginator('list_secrets')

        for page in paginator.paginate():
            secrets = page.get('SecretList', [])

            for secret in secrets:
                secret_name = secret.get('Name', '')
                secret_arn = secret.get('ARN', '')

                # Description
                description = secret.get('Description', 'N/A')

                # KMS key
                kms_key_id = secret.get('KmsKeyId', 'N/A')

                # Rotation enabled
                rotation_enabled = secret.get('RotationEnabled', False)

                # Rotation Lambda ARN
                rotation_lambda_arn = secret.get('RotationLambdaARN', 'N/A')

                # Rotation rules
                rotation_rules = secret.get('RotationRules', {})
                automatically_after_days = rotation_rules.get('AutomaticallyAfterDays', 'N/A')

                # Last rotated date
                last_rotated_date = secret.get('LastRotatedDate', '')
                if last_rotated_date:
                    last_rotated_date = last_rotated_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_rotated_date, datetime.datetime) else str(last_rotated_date)
                else:
                    last_rotated_date = 'Never'

                # Last changed date
                last_changed_date = secret.get('LastChangedDate', '')
                if last_changed_date:
                    last_changed_date = last_changed_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_changed_date, datetime.datetime) else str(last_changed_date)

                # Last accessed date
                last_accessed_date = secret.get('LastAccessedDate', '')
                if last_accessed_date:
                    last_accessed_date = last_accessed_date.strftime('%Y-%m-%d') if isinstance(last_accessed_date, datetime.datetime) else str(last_accessed_date)
                else:
                    last_accessed_date = 'Never'

                # Deleted date
                deleted_date = secret.get('DeletedDate', '')
                if deleted_date:
                    deleted_date = deleted_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(deleted_date, datetime.datetime) else str(deleted_date)
                else:
                    deleted_date = 'N/A'

                # Created date
                created_date = secret.get('CreatedDate', '')
                if created_date:
                    created_date = created_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_date, datetime.datetime) else str(created_date)

                # Primary region (for replicated secrets)
                primary_region = secret.get('PrimaryRegion', region)

                # Tags
                tags = secret.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                # Owning service
                owning_service = secret.get('OwningService', 'N/A')

                regional_secrets.append({
                    'Region': region,
                    'Secret Name': secret_name,
                    'Description': description,
                    'Rotation Enabled': rotation_enabled,
                    'Rotation Interval (days)': automatically_after_days,
                    'Rotation Lambda ARN': rotation_lambda_arn,
                    'Last Rotated': last_rotated_date,
                    'Last Changed': last_changed_date,
                    'Last Accessed': last_accessed_date,
                    'KMS Key ID': kms_key_id,
                    'Primary Region': primary_region,
                    'Owning Service': owning_service,
                    'Deleted Date': deleted_date,
                    'Created Date': created_date,
                    'Tags': tags_str,
                    'Secret ARN': secret_arn
                })

        utils.log_info(f"Found {len(regional_secrets)} secrets in {region}")

    except Exception as e:
        utils.log_error(f"Error processing region {region} for secrets", e)

    return regional_secrets


@utils.aws_error_handler("Collecting Secrets Manager secrets", default_return=[])
def collect_secrets(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Secrets Manager secret information from AWS regions using concurrent scanning.

    SECURITY: This function does NOT retrieve secret values, only metadata.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with secret metadata
    """
    print("\n=== COLLECTING SECRETS MANAGER SECRETS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_secrets = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_secrets_in_region,
        resource_type="Secrets Manager secrets"
    )

    utils.log_success(f"Total secrets collected: {len(all_secrets)}")
    return all_secrets


def scan_secret_versions_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan secret versions in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with version information from this region
    """
    regional_versions = []

    try:
        secrets_client = utils.get_boto3_client('secretsmanager', region_name=region)

        # Get all secrets first
        secret_paginator = secrets_client.get_paginator('list_secrets')

        for secret_page in secret_paginator.paginate():
            secrets = secret_page.get('SecretList', [])

            for secret in secrets:
                secret_name = secret.get('Name', '')
                secret_arn = secret.get('ARN', '')

                try:
                    # List versions for this secret
                    version_response = secrets_client.list_secret_version_ids(
                        SecretId=secret_arn,
                        MaxResults=100
                    )

                    versions = version_response.get('Versions', [])

                    for version in versions:
                        version_id = version.get('VersionId', '')

                        # Version stages (AWSCURRENT, AWSPREVIOUS, etc.)
                        version_stages = version.get('VersionStages', [])
                        version_stages_str = ', '.join(version_stages) if version_stages else 'N/A'

                        # Created date
                        created_date = version.get('CreatedDate', '')
                        if created_date:
                            created_date = created_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_date, datetime.datetime) else str(created_date)

                        # Last accessed date
                        last_accessed_date = version.get('LastAccessedDate', '')
                        if last_accessed_date:
                            last_accessed_date = last_accessed_date.strftime('%Y-%m-%d') if isinstance(last_accessed_date, datetime.datetime) else str(last_accessed_date)
                        else:
                            last_accessed_date = 'Never'

                        regional_versions.append({
                            'Region': region,
                            'Secret Name': secret_name,
                            'Version ID': version_id,
                            'Version Stages': version_stages_str,
                            'Created Date': created_date,
                            'Last Accessed': last_accessed_date
                        })

                except Exception as e:
                    utils.log_warning(f"Could not get versions for secret {secret_name} in {region}: {e}")

        utils.log_info(f"Found {len(regional_versions)} secret versions in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting secret versions in region {region}", e)

    return regional_versions


@utils.aws_error_handler("Collecting secret versions", default_return=[])
def collect_secret_versions(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect secret version information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with version information
    """
    print("\n=== COLLECTING SECRET VERSIONS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_versions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_secret_versions_in_region,
        resource_type="secret versions"
    )

    utils.log_success(f"Total secret versions collected: {len(all_versions)}")
    return all_versions


def scan_secret_replications_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan secret replications in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with replication configuration from this region
    """
    regional_replications = []

    try:
        secrets_client = utils.get_boto3_client('secretsmanager', region_name=region)

        # Get all secrets first
        secret_paginator = secrets_client.get_paginator('list_secrets')

        for secret_page in secret_paginator.paginate():
            secrets = secret_page.get('SecretList', [])

            for secret in secrets:
                secret_name = secret.get('Name', '')
                secret_arn = secret.get('ARN', '')

                # Check for replication status
                replication_status = secret.get('ReplicationStatus', [])

                if replication_status:
                    for replication in replication_status:
                        replica_region = replication.get('Region', '')
                        kms_key_id = replication.get('KmsKeyId', 'N/A')
                        status = replication.get('Status', '')
                        status_message = replication.get('StatusMessage', 'N/A')

                        # Last accessed date
                        last_accessed_date = replication.get('LastAccessedDate', '')
                        if last_accessed_date:
                            last_accessed_date = last_accessed_date.strftime('%Y-%m-%d') if isinstance(last_accessed_date, datetime.datetime) else str(last_accessed_date)
                        else:
                            last_accessed_date = 'Never'

                        regional_replications.append({
                            'Source Region': region,
                            'Secret Name': secret_name,
                            'Replica Region': replica_region,
                            'Status': status,
                            'Status Message': status_message,
                            'KMS Key ID': kms_key_id,
                            'Last Accessed': last_accessed_date
                        })

        utils.log_info(f"Found {len(regional_replications)} secret replications in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting secret replications in region {region}", e)

    return regional_replications


@utils.aws_error_handler("Collecting secret replications", default_return=[])
def collect_secret_replications(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect secret replication information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with replication configuration
    """
    print("\n=== COLLECTING SECRET REPLICATIONS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_replications = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_secret_replications_in_region,
        resource_type="secret replications"
    )

    utils.log_success(f"Total secret replications collected: {len(all_replications)}")
    return all_replications


def export_secrets_data(account_id: str, account_name: str):
    """
    Export Secrets Manager information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Ask for region selection
    print("\n" + "=" * 60)
    print("AWS Region Selection:")

    # Detect partition and set partition-aware example regions
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect secrets
    secrets = collect_secrets(regions)
    if secrets:
        data_frames['Secrets'] = pd.DataFrame(secrets)

    # STEP 2: Collect versions
    versions = collect_secret_versions(regions)
    if versions:
        data_frames['Secret Versions'] = pd.DataFrame(versions)

    # STEP 3: Collect replications
    replications = collect_secret_replications(regions)
    if replications:
        data_frames['Replications'] = pd.DataFrame(replications)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Secrets Manager data was collected. Nothing to export.")
        print("\nNo secrets found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'secrets-manager',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Secrets Manager data exported successfully!")
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
    utils.setup_logging("secrets-manager-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("secrets-manager-export.py", "AWS Secrets Manager Export Tool")

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

        # Export Secrets Manager data
        export_secrets_data(account_id, account_name)

        print("\nSecrets Manager export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("secrets-manager-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
