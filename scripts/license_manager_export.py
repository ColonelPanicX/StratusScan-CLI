#!/usr/bin/env python3
"""
License Manager Export Script

Exports AWS License Manager resources for software license tracking:
- License configurations
- License usage and consumption
- License rules and associations
- Grants and acceptances
- License conversion tasks
- License type conversions (BYOL to License Included)
- Resource inventory associations

Features:
- Complete license configuration inventory
- License usage tracking and limits
- Grant management (issued and received)
- Resource inventory integration
- Multi-region license tracking
- Comprehensive multi-worksheet export

Note: Requires license-manager:List* and license-manager:Get* permissions
"""

import sys
from pathlib import Path
from typing import Any

# Standard utils import pattern
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils
args = utils.parse_script_args("Export AWS License Manager configurations to Excel")

def _build_config_row(item: dict, region: str) -> dict[str, Any]:
    """
    Build a single license configuration export row.

    Extracted so the per-configuration processing can be wrapped in
    try/except by the caller: a malformed configuration entry is logged and
    skipped rather than discarding the whole region's results. Every field is
    read with ``.get()`` and a safe default for the same reason.
    """
    # Extract consumption details
    consumed = item.get('ConsumedLicenses', 0)
    limit = item.get('LicenseCount', 'N/A')

    # Calculate usage percentage
    usage_pct = 'N/A'
    if isinstance(limit, int) and limit > 0:
        usage_pct = f"{(consumed / limit * 100):.1f}%"

    # Extract rules
    rules = []
    for rule in item.get('LicenseRules', []):
        rules.append(rule)

    # Extract automated discovery info
    auto_discovery = item.get('AutomatedDiscoveryInformation', {})

    return {
        'Region': region,
        'LicenseConfigurationId': item.get('LicenseConfigurationId', 'N/A'),
        'LicenseConfigurationArn': item.get('LicenseConfigurationArn', 'N/A'),
        'Name': item.get('Name', 'N/A'),
        'Description': item.get('Description', 'N/A'),
        'LicenseCountingType': item.get('LicenseCountingType', 'N/A'),
        'LicenseCount': limit,
        'LicenseCountHardLimit': item.get('LicenseCountHardLimit', False),
        'ConsumedLicenses': consumed,
        'UsagePercentage': usage_pct,
        'Status': item.get('Status', 'N/A'),
        'OwnerAccountId': item.get('OwnerAccountId', 'N/A'),
        'LicenseRules': ', '.join(rules) if rules else 'N/A',
        'AutoDiscoveryEnabled': auto_discovery.get('LastRunTime') is not None,
        'LastDiscoveryRun': auto_discovery.get('LastRunTime', 'N/A'),
        'ManagedResourceSummaries': str(item.get('ManagedResourceSummaryList', [])),
    }


def _scan_license_configurations_region(region: str) -> list[dict[str, Any]]:
    """
    Collect license configurations from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no license configurations" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed configurations are skipped (logged) rather than
    aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    lm = utils.get_boto3_client('license-manager', region_name=region)
    configs = []

    paginator = lm.get_paginator('list_license_configurations')
    for page in paginator.paginate():
        for item in page.get('LicenseConfigurations', []):
            try:
                configs.append(_build_config_row(item, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed license configuration in {region}: "
                    f"{item.get('LicenseConfigurationId', '<unknown>')}",
                    e,
                )
                continue

    return configs


def collect_license_configurations(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect license configurations across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(configs, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_license_configurations_region,
        show_progress=True,
        collect_failures=True,
    )
    all_configs = [config for result in region_results for config in result]
    return all_configs, failed_regions


@utils.aws_error_handler("Collecting license usage", default_return=[])
def collect_license_usage(region: str, config_arn: str) -> list[dict[str, Any]]:
    """Collect usage information for a specific license configuration."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    usage_list = []

    try:
        paginator = lm.get_paginator('list_usage_for_license_configuration')
        for page in paginator.paginate(LicenseConfigurationArn=config_arn):
            for usage in page.get('LicenseConfigurationUsageList', []):
                usage_list.append({
                    'Region': region,
                    'LicenseConfigurationArn': config_arn,
                    'ResourceArn': usage.get('ResourceArn', 'N/A'),
                    'ResourceType': usage.get('ResourceType', 'N/A'),
                    'ResourceStatus': usage.get('ResourceStatus', 'N/A'),
                    'ResourceOwnerId': usage.get('ResourceOwnerId', 'N/A'),
                    'AssociationTime': usage.get('AssociationTime', 'N/A'),
                    'ConsumedLicenses': usage.get('ConsumedLicenses', 0),
                })
    except Exception:
        # Some configurations may not have usage data
        pass

    return usage_list


@utils.aws_error_handler("Collecting grants", default_return=[])
def collect_grants(region: str) -> list[dict[str, Any]]:
    """Collect license grants (both issued and received)."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    grants = []

    try:
        next_token = None
        while True:
            params = {}
            params['MaxResults'] = 50
            if next_token:
                params['NextToken'] = next_token
            page = lm.list_received_grants(**params)
            for grant in page.get('Grants', []):
                grants.append({
                    'Region': region,
                    'GrantType': 'Received',
                    'GrantArn': grant.get('GrantArn', 'N/A'),
                    'GrantName': grant.get('GrantName', 'N/A'),
                    'GrantStatus': grant.get('GrantStatus', 'N/A'),
                    'GranteePrincipalArn': grant.get('GranteePrincipalArn', 'N/A'),
                    'LicenseArn': grant.get('LicenseArn', 'N/A'),
                    'ParentArn': grant.get('ParentArn', 'N/A'),
                    'Version': grant.get('Version', 'N/A'),
                    'StatusReason': grant.get('StatusReason', 'N/A'),
                })
            next_token = page.get('NextToken')
            if not next_token:
                break
    except Exception:
        pass

    try:
        next_token = None
        while True:
            params = {}
            params['MaxResults'] = 50
            if next_token:
                params['NextToken'] = next_token
            page = lm.list_distributed_grants(**params)
            for grant in page.get('Grants', []):
                grants.append({
                    'Region': region,
                    'GrantType': 'Distributed',
                    'GrantArn': grant.get('GrantArn', 'N/A'),
                    'GrantName': grant.get('GrantName', 'N/A'),
                    'GrantStatus': grant.get('GrantStatus', 'N/A'),
                    'GranteePrincipalArn': grant.get('GranteePrincipalArn', 'N/A'),
                    'LicenseArn': grant.get('LicenseArn', 'N/A'),
                    'ParentArn': grant.get('ParentArn', 'N/A'),
                    'Version': grant.get('Version', 'N/A'),
                    'StatusReason': grant.get('StatusReason', 'N/A'),
                })
            next_token = page.get('NextToken')
            if not next_token:
                break
    except Exception:
        pass

    return grants


@utils.aws_error_handler("Collecting licenses", default_return=[])
def collect_licenses(region: str) -> list[dict[str, Any]]:
    """Collect managed licenses."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    licenses = []

    try:
        next_token = None
        while True:
            params = {}
            params['MaxResults'] = 50
            if next_token:
                params['NextToken'] = next_token
            page = lm.list_licenses(**params)
            for license_obj in page.get('Licenses', []):
                # Extract entitlements
                entitlements = []
                for ent in license_obj.get('Entitlements', []):
                    entitlements.append(f"{ent.get('Name')}: {ent.get('Value')} {ent.get('Unit', '')}")

                licenses.append({
                    'Region': region,
                    'LicenseArn': license_obj.get('LicenseArn', 'N/A'),
                    'LicenseName': license_obj.get('LicenseName', 'N/A'),
                    'ProductName': license_obj.get('ProductName', 'N/A'),
                    'ProductSKU': license_obj.get('ProductSKU', 'N/A'),
                    'Status': license_obj.get('Status', 'N/A'),
                    'Beneficiary': license_obj.get('Beneficiary', 'N/A'),
                    'Issuer': license_obj.get('Issuer', {}).get('Name', 'N/A'),
                    'HomeRegion': license_obj.get('HomeRegion', 'N/A'),
                    'Validity': f"{license_obj.get('Validity', {}).get('Begin', 'N/A')} to {license_obj.get('Validity', {}).get('End', 'N/A')}",
                    'Entitlements': ', '.join(entitlements) if entitlements else 'N/A',
                    'ConsumptionConfiguration': str(license_obj.get('ConsumptionConfiguration', {})),
                    'Version': license_obj.get('Version', 'N/A'),
                })
            next_token = page.get('NextToken')
            if not next_token:
                break
    except Exception:
        pass

    return licenses


@utils.aws_error_handler("Collecting resource inventory", default_return=[])
def collect_resource_inventory(region: str) -> list[dict[str, Any]]:
    """Collect resource inventory tracked by License Manager."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    inventory = []

    try:
        paginator = lm.get_paginator('list_resource_inventory')
        for page in paginator.paginate():
            for resource in page.get('ResourceInventoryList', []):
                # Extract platform details
                platform = resource.get('Platform', 'N/A')
                platform_version = resource.get('PlatformVersion', 'N/A')

                inventory.append({
                    'Region': region,
                    'ResourceId': resource.get('ResourceId', 'N/A'),
                    'ResourceType': resource.get('ResourceType', 'N/A'),
                    'ResourceArn': resource.get('ResourceArn', 'N/A'),
                    'Platform': platform,
                    'PlatformVersion': platform_version,
                    'ResourceOwningAccountId': resource.get('ResourceOwningAccountId', 'N/A'),
                })
    except Exception:
        pass

    return inventory


def _run_export(account_id: str, account_name: str, regions: list) -> None:
    """Collect License Manager data and write the Excel export."""
    utils.log_info(f"Scanning {len(regions)} region(s) for License Manager resources...")

    # PRIMARY SCOPE: license configurations. Region failures must propagate
    # as failed_regions, never collapse into "empty" (see the silent-
    # collection-failure blast-radius audit).
    all_configs, failed_regions = collect_license_configurations(regions)
    if all_configs:
        utils.log_info(f"Found {len(all_configs)} license configuration(s) total")

    all_usage = []
    all_grants = []
    all_licenses = []
    all_inventory = []

    for idx, region in enumerate(regions, 1):
        utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

        # Collect usage for the first 10 configurations found in this region
        # (enrichment — degrades gracefully; failures here do not fail the
        # whole export).
        region_configs = [c for c in all_configs if c.get('Region') == region]
        for config in region_configs[:10]:
            config_arn = config['LicenseConfigurationArn']
            usage = collect_license_usage(region, config_arn)
            all_usage.extend(usage)

        # Collect grants
        grants = collect_grants(region)
        if grants:
            utils.log_info(f"  Found {len(grants)} grant(s)")
            all_grants.extend(grants)

        # Collect licenses
        licenses = collect_licenses(region)
        if licenses:
            utils.log_info(f"  Found {len(licenses)} license(s)")
            all_licenses.extend(licenses)

        # Collect resource inventory
        inventory = collect_resource_inventory(region)
        if inventory:
            utils.log_info(f"  Found {len(inventory)} inventory item(s)")
            all_inventory.extend(inventory)

    if not all_configs and not all_licenses and not all_grants:
        if not failed_regions:
            # Genuinely empty account: every region succeeded and returned
            # nothing.
            utils.log_warning("No License Manager resources found in any selected region.")
        utils.log_info("Creating empty export file...")

    utils.log_info(f"Total license configurations found: {len(all_configs)}")
    utils.log_info(f"Total licenses found: {len(all_licenses)}")
    utils.log_info(f"Total grants found: {len(all_grants)}")

    # Create DataFrames
    df_configs = utils.prepare_dataframe_for_export(pd.DataFrame(all_configs))
    df_usage = utils.prepare_dataframe_for_export(pd.DataFrame(all_usage))
    df_grants = utils.prepare_dataframe_for_export(pd.DataFrame(all_grants))
    df_licenses = utils.prepare_dataframe_for_export(pd.DataFrame(all_licenses))
    df_inventory = utils.prepare_dataframe_for_export(pd.DataFrame(all_inventory))

    # Create summary
    summary_data = []
    summary_data.append({'Metric': 'Total License Configurations', 'Value': len(all_configs)})
    summary_data.append({'Metric': 'Total Licenses', 'Value': len(all_licenses)})
    summary_data.append({'Metric': 'Total Grants', 'Value': len(all_grants)})
    summary_data.append({'Metric': 'Total Usage Records', 'Value': len(all_usage)})
    summary_data.append({'Metric': 'Total Inventory Items', 'Value': len(all_inventory)})
    summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

    if not df_configs.empty:
        active_configs = len(df_configs[df_configs['Status'] == 'AVAILABLE'])
        disabled_configs = len(df_configs[df_configs['Status'] == 'DISABLED'])

        summary_data.append({'Metric': 'Active Configurations', 'Value': active_configs})
        summary_data.append({'Metric': 'Disabled Configurations', 'Value': disabled_configs})

        # Calculate total license consumption
        total_consumed = df_configs['ConsumedLicenses'].sum() if 'ConsumedLicenses' in df_configs.columns else 0
        summary_data.append({'Metric': 'Total Licenses Consumed', 'Value': int(total_consumed)})

    if not df_grants.empty:
        received_grants = len(df_grants[df_grants['GrantType'] == 'Received'])
        distributed_grants = len(df_grants[df_grants['GrantType'] == 'Distributed'])

        summary_data.append({'Metric': 'Received Grants', 'Value': received_grants})
        summary_data.append({'Metric': 'Distributed Grants', 'Value': distributed_grants})

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create filtered views
    df_active_configs = pd.DataFrame()
    df_over_limit = pd.DataFrame()

    if not df_configs.empty:
        df_active_configs = df_configs[df_configs['Status'] == 'AVAILABLE']

        # Find configurations near or over limit
        if 'LicenseCount' in df_configs.columns and 'ConsumedLicenses' in df_configs.columns:
            df_over_limit = df_configs[
                (df_configs['LicenseCount'] != 'N/A') &
                (df_configs['ConsumedLicenses'] >= df_configs['LicenseCount'] * 0.8)
            ]

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'license-manager', 'all')

    sheets = {
        'Summary': df_summary,
        'License Configurations': df_configs,
        'Active Configurations': df_active_configs,
        'Near Limit': df_over_limit,
        'Licenses': df_licenses,
        'Grants': df_grants,
        'License Usage': df_usage,
        'Resource Inventory': df_inventory,
    }

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    utils.log_info(f"  License Configurations: {len(all_configs)}")
    utils.log_info(f"  Licenses: {len(all_licenses)}")
    utils.log_info(f"  Grants: {len(all_grants)}")
    utils.log_info(f"  Usage Records: {len(all_usage)}")
    utils.log_info(f"  Inventory Items: {len(all_inventory)}")

    utils.log_success("License Manager export completed successfully!")

    # If ANY region failed the license configurations scope collection, make
    # it loud: write a marker and exit non-zero, even though the Summary
    # sheet (and any partial data) was already exported above. A
    # complete-looking workbook with silently zero-row data is exactly the
    # failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'license-manager', failed_regions)
        print(
            "\nERROR: License Manager export completed with failures — data is incomplete. "
            "See the *-license-manager-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    """Main function — 3-step state machine with b/x navigation."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        global pd
        import pandas as pd
        utils.setup_logging("license-manager-export")
        account_id, account_name = utils.print_script_banner("AWS LICENSE MANAGER EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="License Manager")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = ', '.join(regions) if len(regions) <= 3 else f"{len(regions)} regions"
                msg = f"Ready to export License Manager data ({region_str})."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                _run_export(account_id, account_name, regions)
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
