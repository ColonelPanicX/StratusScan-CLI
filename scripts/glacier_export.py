#!/usr/bin/env python3
"""
AWS Glacier Vaults Export Script for StratusScan

Exports comprehensive AWS Glacier vault information including:
- Vaults with inventory metadata (archives, size)
- Vault access policies and lock policies
- Vault notifications (SNS topic configurations)
- Vault tags

Note: This is for the original Glacier vault service, separate from S3 Glacier storage classes.

Output: Multi-worksheet Excel file with Glacier resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)
def _scan_vaults_region(region: str) -> List[Dict[str, Any]]:
    """Scan Glacier vaults in a single region."""
    regional_vaults = []
    glacier_client = utils.get_boto3_client('glacier', region_name=region)

    try:
        paginator = glacier_client.get_paginator('list_vaults')
        for page in paginator.paginate():
            vaults = page.get('VaultList', [])

            for vault in vaults:
                vault_name = vault.get('VaultName', 'N/A')
                vault_arn = vault.get('VaultARN', 'N/A')

                # Get vault access policy
                vault_policy = 'N/A'
                try:
                    policy_response = glacier_client.get_vault_access_policy(vaultName=vault_name)
                    vault_policy = policy_response.get('policy', {}).get('Policy', 'N/A')
                except Exception:
                    pass

                # Get vault lock policy
                lock_policy = 'N/A'
                lock_state = 'N/A'
                try:
                    lock_response = glacier_client.get_vault_lock(vaultName=vault_name)
                    lock_policy = lock_response.get('Policy', 'N/A')
                    lock_state = lock_response.get('State', 'N/A')
                except Exception:
                    pass

                # Get vault notifications
                notification_config = 'N/A'
                sns_topic = 'N/A'
                events_str = 'N/A'
                try:
                    notif_response = glacier_client.get_vault_notifications(vaultName=vault_name)
                    notification_cfg = notif_response.get('vaultNotificationConfig', {})
                    sns_topic = notification_cfg.get('SNSTopic', 'N/A')
                    events = notification_cfg.get('Events', [])
                    events_str = ', '.join(events) if events else 'N/A'
                    notification_config = f"Topic: {sns_topic}, Events: {events_str}" if events else 'None'
                except Exception:
                    pass

                # Get vault tags
                tags_str = 'None'
                try:
                    tags_response = glacier_client.list_tags_for_vault(vaultName=vault_name)
                    tags = tags_response.get('Tags', {})
                    if tags:
                        tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()])
                except Exception:
                    pass

                creation_date = vault.get('CreationDate', 'N/A')
                if creation_date != 'N/A':
                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')

                last_inventory = vault.get('LastInventoryDate', 'N/A')
                if last_inventory != 'N/A':
                    last_inventory = last_inventory.strftime('%Y-%m-%d %H:%M:%S')

                size_bytes = vault.get('SizeInBytes', 0)
                size_gb = round(size_bytes / (1024**3), 2) if size_bytes else 0

                regional_vaults.append({
                    'Region': region,
                    'Vault Name': vault_name,
                    'Number of Archives': vault.get('NumberOfArchives', 0),
                    'Size (GB)': size_gb,
                    'Size (Bytes)': size_bytes,
                    'Created': creation_date,
                    'Last Inventory': last_inventory,
                    'Has Access Policy': 'Yes' if vault_policy != 'N/A' else 'No',
                    'Has Lock Policy': 'Yes' if lock_policy != 'N/A' else 'No',
                    'Lock State': lock_state,
                    'Has Notifications': 'Yes' if sns_topic != 'N/A' else 'No',
                    'SNS Topic': sns_topic,
                    'Notification Events': events_str,
                    'Tags': tags_str,
                    'ARN': vault_arn
                })

    except Exception as e:
        utils.log_warning(f"Error listing vaults in {region}: {str(e)}")

    return regional_vaults


@utils.aws_error_handler("Collecting Glacier vaults", default_return=[])
def collect_vaults(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Glacier vault information from AWS regions."""
    print("\n=== COLLECTING GLACIER VAULTS ===")
    results = utils.scan_regions_concurrent(regions, _scan_vaults_region)
    all_vaults = [vault for result in results for vault in result]
    utils.log_success(f"Total vaults collected: {len(all_vaults)}")
    return all_vaults


def generate_summary(vaults: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Glacier resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Vaults summary
    total_vaults = len(vaults)
    total_archives = sum(v.get('Number of Archives', 0) for v in vaults)
    total_size_gb = sum(v.get('Size (GB)', 0) for v in vaults)

    vaults_with_policies = sum(1 for v in vaults if v.get('Has Access Policy', '') == 'Yes')
    vaults_with_locks = sum(1 for v in vaults if v.get('Has Lock Policy', '') == 'Yes')
    vaults_with_notifications = sum(1 for v in vaults if v.get('Has Notifications', '') == 'Yes')

    summary.append({
        'Metric': 'Total Glacier Vaults',
        'Count': total_vaults,
        'Details': f'Policies: {vaults_with_policies}, Locks: {vaults_with_locks}, Notifications: {vaults_with_notifications}'
    })

    summary.append({
        'Metric': 'Total Archives',
        'Count': total_archives,
        'Details': 'Combined across all vaults'
    })

    summary.append({
        'Metric': 'Total Storage (GB)',
        'Count': round(total_size_gb, 2),
        'Details': 'Combined vault storage size'
    })

    summary.append({
        'Metric': 'Vaults with Access Policies',
        'Count': vaults_with_policies,
        'Details': 'Vaults with resource-based access policies'
    })

    summary.append({
        'Metric': 'Vaults with Lock Policies',
        'Count': vaults_with_locks,
        'Details': 'Vaults with compliance lock policies'
    })

    summary.append({
        'Metric': 'Vaults with SNS Notifications',
        'Count': vaults_with_notifications,
        'Details': 'Vaults configured for job completion notifications'
    })

    # Regional distribution
    if vaults:
        df = pd.DataFrame(vaults)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Vaults in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS Glacier Vaults Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Note about Glacier service
    print("\nNote: This exports original Glacier vaults (separate from S3 Glacier storage classes)")
    print("Glacier is a regional service. Vault inventories are updated every 24 hours.")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting Glacier vault data...")

    vaults = collect_vaults(regions)
    summary = generate_summary(vaults)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if vaults:
        df_vaults = pd.DataFrame(vaults)
        df_vaults = utils.prepare_dataframe_for_export(df_vaults)
        dataframes['All Vaults'] = df_vaults

        # Filtered views
        df_with_policies = df_vaults[df_vaults['Has Access Policy'] == 'Yes']
        if not df_with_policies.empty:
            dataframes['Vaults with Policies'] = df_with_policies

        df_with_locks = df_vaults[df_vaults['Has Lock Policy'] == 'Yes']
        if not df_with_locks.empty:
            dataframes['Vaults with Locks'] = df_with_locks

        df_with_notifications = df_vaults[df_vaults['Has Notifications'] == 'Yes']
        if not df_with_notifications.empty:
            dataframes['Vaults with Notifications'] = df_with_notifications

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'glacier', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Glacier Vaults': len(vaults)
        })
    else:
        utils.log_warning("No Glacier vaults found to export")

    utils.log_success("Glacier export completed successfully")


if __name__ == "__main__":
    main()
