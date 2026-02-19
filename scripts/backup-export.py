#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Backup Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS Backup information from all regions into an Excel file with
multiple worksheets. The output includes backup vaults, backup plans, recovery points,
and backup selections.

Features:
- Backup vaults with recovery point counts
- Backup plans with rules and schedules
- Recovery points by resource type
- Backup selections (resource assignments to plans)
- Vault access policies
- Vault lock configurations
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
utils.setup_logging("backup-export")
utils.log_script_start("backup-export.py", "AWS Backup Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("                  AWS BACKUP EXPORT TOOL")
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


def _scan_backup_vaults_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for backup vaults."""
    vaults_data = []

    if not utils.validate_aws_region(region):
        return vaults_data

    try:
        backup_client = utils.get_boto3_client('backup', region_name=region)
        paginator = backup_client.get_paginator('list_backup_vaults')

        for page in paginator.paginate():
            vaults = page.get('BackupVaultList', [])

            for vault in vaults:
                vault_name = vault.get('BackupVaultName', '')
                vault_arn = vault.get('BackupVaultArn', '')
                creation_date = vault.get('CreationDate', '')
                if creation_date:
                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                encryption_key_arn = vault.get('EncryptionKeyArn', 'N/A')
                creator_request_id = vault.get('CreatorRequestId', 'N/A')
                number_of_recovery_points = vault.get('NumberOfRecoveryPoints', 0)
                locked = vault.get('Locked', False)
                min_retention_days = vault.get('MinRetentionDays', 'N/A')
                max_retention_days = vault.get('MaxRetentionDays', 'N/A')

                lock_date = vault.get('LockDate', '')
                if lock_date:
                    lock_date = lock_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(lock_date, datetime.datetime) else str(lock_date)

                vaults_data.append({
                    'Region': region,
                    'Vault Name': vault_name,
                    'Recovery Point Count': number_of_recovery_points,
                    'Locked': locked,
                    'Min Retention (days)': min_retention_days,
                    'Max Retention (days)': max_retention_days,
                    'Lock Date': lock_date if lock_date else 'N/A',
                    'Encryption Key ARN': encryption_key_arn,
                    'Creation Date': creation_date,
                    'Creator Request ID': creator_request_id,
                    'Vault ARN': vault_arn
                })
    except Exception as e:
        utils.log_error(f"Error scanning backup vaults in {region}", e)

    return vaults_data


@utils.aws_error_handler("Collecting backup vaults", default_return=[])
def collect_backup_vaults(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect AWS Backup vault information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with backup vault information
    """
    print("\n=== COLLECTING BACKUP VAULTS ===")

    # Use concurrent scanning for better performance
    results = utils.scan_regions_concurrent(regions, _scan_backup_vaults_region)
    all_vaults = [vault for result in results for vault in result]

    utils.log_success(f"Total backup vaults collected: {len(all_vaults)}")
    return all_vaults


def _scan_backup_plans_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for backup plans."""
    plans_data = []

    if not utils.validate_aws_region(region):
        return plans_data

    try:
        backup_client = utils.get_boto3_client('backup', region_name=region)
        paginator = backup_client.get_paginator('list_backup_plans')

        for page in paginator.paginate():
            plans = page.get('BackupPlansList', [])

            for plan_summary in plans:
                plan_id = plan_summary.get('BackupPlanId', '')
                plan_name = plan_summary.get('BackupPlanName', '')

                try:
                    plan_response = backup_client.get_backup_plan(BackupPlanId=plan_id)
                    plan = plan_response.get('BackupPlan', {})

                    rules = plan.get('Rules', [])
                    rule_count = len(rules)

                    rule_summaries = []
                    for rule in rules:
                        rule_name = rule.get('RuleName', '')
                        target_vault = rule.get('TargetBackupVaultName', '')
                        schedule = rule.get('ScheduleExpression', 'N/A')
                        rule_summaries.append(f"{rule_name} -> {target_vault} ({schedule})")

                    rules_str = '; '.join(rule_summaries) if rule_summaries else 'N/A'
                    advanced_backup_settings = plan.get('AdvancedBackupSettings', [])
                    advanced_count = len(advanced_backup_settings)

                    creation_date = plan_summary.get('CreationDate', '')
                    if creation_date:
                        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                    last_execution_date = plan_summary.get('LastExecutionDate', '')
                    if last_execution_date:
                        last_execution_date = last_execution_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_execution_date, datetime.datetime) else str(last_execution_date)

                    version_id = plan_response.get('VersionId', 'N/A')
                    plan_arn = plan_summary.get('BackupPlanArn', '')

                    plans_data.append({
                        'Region': region,
                        'Plan Name': plan_name,
                        'Plan ID': plan_id,
                        'Rule Count': rule_count,
                        'Rules Summary': rules_str,
                        'Advanced Settings': advanced_count,
                        'Version ID': version_id,
                        'Creation Date': creation_date,
                        'Last Execution': last_execution_date if last_execution_date else 'Never',
                        'Plan ARN': plan_arn
                    })
                except Exception as e:
                    utils.log_warning(f"Could not get details for backup plan {plan_id}: {e}")
    except Exception as e:
        utils.log_error(f"Error scanning backup plans in {region}", e)

    return plans_data


@utils.aws_error_handler("Collecting backup plans", default_return=[])
def collect_backup_plans(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect AWS Backup plan information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with backup plan information
    """
    print("\n=== COLLECTING BACKUP PLANS ===")

    # Use concurrent scanning for better performance
    results = utils.scan_regions_concurrent(regions, _scan_backup_plans_region)
    all_plans = [plan for result in results for plan in result]

    utils.log_success(f"Total backup plans collected: {len(all_plans)}")
    return all_plans


def _scan_backup_selections_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for backup selections."""
    selections_data = []

    if not utils.validate_aws_region(region):
        return selections_data

    try:
        backup_client = utils.get_boto3_client('backup', region_name=region)
        plan_paginator = backup_client.get_paginator('list_backup_plans')

        for plan_page in plan_paginator.paginate():
            plans = plan_page.get('BackupPlansList', [])

            for plan_summary in plans:
                plan_id = plan_summary.get('BackupPlanId', '')
                plan_name = plan_summary.get('BackupPlanName', '')

                try:
                    selection_paginator = backup_client.get_paginator('list_backup_selections')

                    for selection_page in selection_paginator.paginate(BackupPlanId=plan_id):
                        selections = selection_page.get('BackupSelectionsList', [])

                        for selection_summary in selections:
                            selection_id = selection_summary.get('SelectionId', '')
                            selection_name = selection_summary.get('SelectionName', '')
                            iam_role_arn = selection_summary.get('IamRoleArn', 'N/A')

                            creation_date = selection_summary.get('CreationDate', '')
                            if creation_date:
                                creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime.datetime) else str(creation_date)

                            creator_request_id = selection_summary.get('CreatorRequestId', 'N/A')

                            selections_data.append({
                                'Region': region,
                                'Plan Name': plan_name,
                                'Selection Name': selection_name,
                                'Selection ID': selection_id,
                                'IAM Role ARN': iam_role_arn,
                                'Creation Date': creation_date,
                                'Creator Request ID': creator_request_id
                            })
                except Exception as e:
                    utils.log_warning(f"Could not get selections for plan {plan_id}: {e}")
    except Exception as e:
        utils.log_error(f"Error scanning backup selections in {region}", e)

    return selections_data


@utils.aws_error_handler("Collecting backup selections", default_return=[])
def collect_backup_selections(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect AWS Backup selection information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with backup selection information
    """
    print("\n=== COLLECTING BACKUP SELECTIONS ===")

    # Use concurrent scanning for better performance
    results = utils.scan_regions_concurrent(regions, _scan_backup_selections_region)
    all_selections = [selection for result in results for selection in result]

    utils.log_success(f"Total backup selections collected: {len(all_selections)}")
    return all_selections


def export_backup_data(account_id: str, account_name: str):
    """
    Export AWS Backup information to an Excel file.

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

    print(f"\nStarting AWS Backup export process for {region_text}...")
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect backup vaults
    vaults = collect_backup_vaults(regions)
    if vaults:
        data_frames['Backup Vaults'] = pd.DataFrame(vaults)

    # STEP 2: Collect backup plans
    plans = collect_backup_plans(regions)
    if plans:
        data_frames['Backup Plans'] = pd.DataFrame(plans)

    # STEP 3: Collect backup selections
    selections = collect_backup_selections(regions)
    if selections:
        data_frames['Backup Selections'] = pd.DataFrame(selections)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No AWS Backup data was collected. Nothing to export.")
        print("\nNo AWS Backup resources found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'aws-backup',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("AWS Backup data exported successfully!")
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

        # Export AWS Backup data
        export_backup_data(account_id, account_name)

        print("\nAWS Backup export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("backup-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
