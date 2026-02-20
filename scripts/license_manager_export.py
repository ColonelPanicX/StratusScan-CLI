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
from typing import List, Dict, Any
import pandas as pd

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

# Check required packages
utils.check_required_packages(['boto3', 'pandas', 'openpyxl'])

# Setup logging
logger = utils.setup_logging('license-manager-export')
utils.log_script_start('license-manager-export', 'Export AWS License Manager configurations and usage')


@utils.aws_error_handler("Collecting license configurations", default_return=[])
def collect_license_configurations(region: str) -> List[Dict[str, Any]]:
    """Collect all license configurations in a region."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    configs = []

    paginator = lm.get_paginator('list_license_configurations')
    for page in paginator.paginate():
        for config in page.get('LicenseConfigurations', []):
            # Extract consumption details
            consumed = config.get('ConsumedLicenses', 0)
            limit = config.get('LicenseCount', 'N/A')

            # Calculate usage percentage
            usage_pct = 'N/A'
            if isinstance(limit, int) and limit > 0:
                usage_pct = f"{(consumed / limit * 100):.1f}%"

            # Extract rules
            rules = []
            for rule in config.get('LicenseRules', []):
                rules.append(rule)

            # Extract automated discovery info
            auto_discovery = config.get('AutomatedDiscoveryInformation', {})

            configs.append({
                'Region': region,
                'LicenseConfigurationId': config.get('LicenseConfigurationId', 'N/A'),
                'LicenseConfigurationArn': config.get('LicenseConfigurationArn', 'N/A'),
                'Name': config.get('Name', 'N/A'),
                'Description': config.get('Description', 'N/A'),
                'LicenseCountingType': config.get('LicenseCountingType', 'N/A'),
                'LicenseCount': limit,
                'LicenseCountHardLimit': config.get('LicenseCountHardLimit', False),
                'ConsumedLicenses': consumed,
                'UsagePercentage': usage_pct,
                'Status': config.get('Status', 'N/A'),
                'OwnerAccountId': config.get('OwnerAccountId', 'N/A'),
                'LicenseRules': ', '.join(rules) if rules else 'N/A',
                'AutoDiscoveryEnabled': auto_discovery.get('LastRunTime') is not None,
                'LastDiscoveryRun': auto_discovery.get('LastRunTime', 'N/A'),
                'ManagedResourceSummaries': str(config.get('ManagedResourceSummaryList', [])),
            })

    return configs


@utils.aws_error_handler("Collecting license usage", default_return=[])
def collect_license_usage(region: str, config_arn: str) -> List[Dict[str, Any]]:
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
def collect_grants(region: str) -> List[Dict[str, Any]]:
    """Collect license grants (both issued and received)."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    grants = []

    try:
        paginator = lm.get_paginator('list_received_grants')
        for page in paginator.paginate():
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
    except Exception:
        pass

    try:
        paginator = lm.get_paginator('list_distributed_grants')
        for page in paginator.paginate():
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
    except Exception:
        pass

    return grants


@utils.aws_error_handler("Collecting licenses", default_return=[])
def collect_licenses(region: str) -> List[Dict[str, Any]]:
    """Collect managed licenses."""
    lm = utils.get_boto3_client('license-manager', region_name=region)
    licenses = []

    try:
        paginator = lm.get_paginator('list_licenses')
        for page in paginator.paginate():
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
    except Exception:
        pass

    return licenses


@utils.aws_error_handler("Collecting resource inventory", default_return=[])
def collect_resource_inventory(region: str) -> List[Dict[str, Any]]:
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


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting License Manager resources for account: {account_name} ({account_id})")

        # Prompt for regions
        utils.log_info("License Manager is a regional service.")
        regions = utils.prompt_region_selection(
            service_name="License Manager",
            default_to_all=False
        )

        if not regions:
            utils.log_error("No regions selected. Exiting.")
            return

        utils.log_info(f"Scanning {len(regions)} region(s) for License Manager resources...")

        # Collect all resources
        all_configs = []
        all_usage = []
        all_grants = []
        all_licenses = []
        all_inventory = []

        for idx, region in enumerate(regions, 1):
            utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

            # Collect license configurations
            configs = collect_license_configurations(region)
            if configs:
                utils.log_info(f"  Found {len(configs)} license configuration(s)")
                all_configs.extend(configs)

                # Collect usage for first 10 configurations
                for config in configs[:10]:
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
        utils.log_export_summary(
            total_items=len(all_configs) + len(all_licenses) + len(all_grants),
            item_type='License Manager Resources',
            filename=filename
        )

        utils.log_info(f"  License Configurations: {len(all_configs)}")
        utils.log_info(f"  Licenses: {len(all_licenses)}")
        utils.log_info(f"  Grants: {len(all_grants)}")
        utils.log_info(f"  Usage Records: {len(all_usage)}")
        utils.log_info(f"  Inventory Items: {len(all_inventory)}")

        utils.log_success("License Manager export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export License Manager resources: {str(e)}")
        raise


if __name__ == "__main__":
    main()
