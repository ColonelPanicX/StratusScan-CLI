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
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils
args = utils.parse_script_args("Export S3 Glacier vaults to Excel")

def _build_vault_row(vault: dict[str, Any], region: str, glacier_client) -> dict[str, Any]:
    """
    Build a single Glacier vault export row.

    Per-vault enrichment calls (access policy, lock policy, notifications,
    tags) remain best-effort: each is wrapped in its own try/except so a
    missing/denied enrichment call degrades gracefully instead of losing the
    whole vault.
    """
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
    sns_topic = 'N/A'
    events_str = 'N/A'
    try:
        notif_response = glacier_client.get_vault_notifications(vaultName=vault_name)
        notification_cfg = notif_response.get('vaultNotificationConfig', {})
        sns_topic = notification_cfg.get('SNSTopic', 'N/A')
        events = notification_cfg.get('Events', [])
        events_str = ', '.join(events) if events else 'N/A'
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
    if creation_date != 'N/A' and isinstance(creation_date, datetime):
        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')

    last_inventory = vault.get('LastInventoryDate', 'N/A')
    if last_inventory != 'N/A' and isinstance(last_inventory, datetime):
        last_inventory = last_inventory.strftime('%Y-%m-%d %H:%M:%S')

    size_bytes = vault.get('SizeInBytes', 0)
    size_gb = round(size_bytes / (1024**3), 2) if size_bytes else 0

    return {
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
    }


def _scan_vaults_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Glacier vaults from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no vaults" (the silent-
    collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed vaults are skipped (logged) rather than aborting the
    whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_vaults = []
    glacier_client = utils.get_boto3_client('glacier', region_name=region)

    paginator = glacier_client.get_paginator('list_vaults')
    for page in paginator.paginate():
        vaults = page.get('VaultList', [])

        for vault in vaults:
            try:
                regional_vaults.append(_build_vault_row(vault, region, glacier_client))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Glacier vault in {region}: "
                    f"{vault.get('VaultName', '<unknown>')}",
                    e,
                )
                continue

    return regional_vaults


def collect_vaults(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Glacier vault information across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(vaults, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING GLACIER VAULTS ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_vaults_region,
        show_progress=True,
        collect_failures=True,
    )
    all_vaults = [vault for result in results for vault in result]
    utils.log_success(f"Total vaults collected: {len(all_vaults)}")
    return all_vaults, failed_regions


def generate_summary(vaults: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    global pd
    import pandas as pd
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    account_id, account_name = utils.print_script_banner("AWS GLACIER VAULTS EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Note about Glacier service
    print("\nNote: This exports original Glacier vaults (separate from S3 Glacier storage classes)")
    print("Glacier is a regional service. Vault inventories are updated every 24 hours.")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting Glacier vault data...")

    vaults, failed_regions = collect_vaults(regions)
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
        utils.log_export_summary('Glacier Vaults', len(vaults), filename)
    else:
        utils.log_warning("No Glacier vaults found to export")

    utils.log_success("Glacier export completed successfully")

    # If ANY region failed the primary vault scope collection, make it loud:
    # write a marker and exit non-zero, even though the Summary sheet (and
    # any collected data) was still exported above. A complete-looking
    # workbook with silently zero/partial rows is exactly the failure mode
    # this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'glacier', failed_regions)
        print(
            "\nERROR: Glacier export completed with failures — data is incomplete. "
            "See the *-glacier-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
