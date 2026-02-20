#!/usr/bin/env python3
"""
AWS X-Ray Export Script for StratusScan

Exports comprehensive AWS X-Ray tracing configuration including:
- Sampling rules (custom and default)
- Groups (trace filter expressions)
- Encryption configuration
- Insights configuration
- Resource policies

Output: Multi-worksheet Excel file with X-Ray resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import json

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
def _scan_sampling_rules_region(region: str) -> List[Dict[str, Any]]:
    """Scan X-Ray sampling rules in a single region."""
    regional_rules = []
    xray_client = utils.get_boto3_client('xray', region_name=region)

    try:
        # Get sampling rules
        response = xray_client.get_sampling_rules()
        sampling_rules = response.get('SamplingRuleRecords', [])

        for rule_record in sampling_rules:
            rule = rule_record.get('SamplingRule', {})
            created_at = rule_record.get('CreatedAt', 'N/A')
            modified_at = rule_record.get('ModifiedAt', 'N/A')

            if created_at != 'N/A':
                created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')
            if modified_at != 'N/A':
                modified_at = modified_at.strftime('%Y-%m-%d %H:%M:%S')

            rule_name = rule.get('RuleName', 'N/A')
            rule_arn = rule.get('RuleARN', 'N/A')
            priority = rule.get('Priority', 'N/A')
            fixed_rate = rule.get('FixedRate', 0)
            reservoir_size = rule.get('ReservoirSize', 0)
            service_name = rule.get('ServiceName', '*')
            service_type = rule.get('ServiceType', '*')
            host = rule.get('Host', '*')
            http_method = rule.get('HTTPMethod', '*')
            url_path = rule.get('URLPath', '*')
            resource_arn = rule.get('ResourceARN', '*')
            version = rule.get('Version', 1)

            # Attributes
            attributes = rule.get('Attributes', {})
            attributes_str = json.dumps(attributes) if attributes else 'None'

            regional_rules.append({
                'Region': region,
                'Rule Name': rule_name,
                'Priority': priority,
                'Fixed Rate': fixed_rate,
                'Reservoir Size': reservoir_size,
                'Service Name': service_name,
                'Service Type': service_type,
                'Host': host,
                'HTTP Method': http_method,
                'URL Path': url_path,
                'Resource ARN': resource_arn,
                'Version': version,
                'Attributes': attributes_str,
                'Created': created_at,
                'Modified': modified_at,
                'Rule ARN': rule_arn
            })

    except Exception as e:
        utils.log_warning(f"Error getting sampling rules in {region}: {str(e)}")

    return regional_rules


@utils.aws_error_handler("Collecting X-Ray sampling rules", default_return=[])
def collect_sampling_rules(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect X-Ray sampling rule information from AWS regions."""
    print("\n=== COLLECTING X-RAY SAMPLING RULES ===")
    results = utils.scan_regions_concurrent(regions, _scan_sampling_rules_region)
    all_rules = [rule for result in results for rule in result]
    utils.log_success(f"Total sampling rules collected: {len(all_rules)}")
    return all_rules


def _scan_groups_region(region: str) -> List[Dict[str, Any]]:
    """Scan X-Ray groups in a single region."""
    regional_groups = []
    xray_client = utils.get_boto3_client('xray', region_name=region)

    try:
        # Get groups
        paginator = xray_client.get_paginator('get_groups')
        for page in paginator.paginate():
            groups = page.get('Groups', [])

            for group in groups:
                group_name = group.get('GroupName', 'N/A')
                group_arn = group.get('GroupARN', 'N/A')
                filter_expression = group.get('FilterExpression', 'N/A')
                insights_configuration = group.get('InsightsConfiguration', {})
                insights_enabled = insights_configuration.get('InsightsEnabled', False)
                notifications_enabled = insights_configuration.get('NotificationsEnabled', False)

                regional_groups.append({
                    'Region': region,
                    'Group Name': group_name,
                    'Filter Expression': filter_expression,
                    'Insights Enabled': insights_enabled,
                    'Notifications Enabled': notifications_enabled,
                    'Group ARN': group_arn
                })

    except Exception as e:
        utils.log_warning(f"Error getting groups in {region}: {str(e)}")

    return regional_groups


@utils.aws_error_handler("Collecting X-Ray groups", default_return=[])
def collect_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect X-Ray group information from AWS regions."""
    print("\n=== COLLECTING X-RAY GROUPS ===")
    results = utils.scan_regions_concurrent(regions, _scan_groups_region)
    all_groups = [group for result in results for group in result]
    utils.log_success(f"Total groups collected: {len(all_groups)}")
    return all_groups


@utils.aws_error_handler("Collecting encryption configuration", default_return=[])
def collect_encryption_config(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect X-Ray encryption configuration from AWS regions."""
    print("\n=== COLLECTING ENCRYPTION CONFIGURATION ===")
    all_configs = []

    for region in regions:
        xray_client = utils.get_boto3_client('xray', region_name=region)

        try:
            # Get encryption config
            response = xray_client.get_encryption_config()
            config = response.get('EncryptionConfig', {})

            encryption_type = config.get('Type', 'N/A')
            key_id = config.get('KeyId', 'N/A')
            status = config.get('Status', 'N/A')

            all_configs.append({
                'Region': region,
                'Encryption Type': encryption_type,
                'KMS Key ID': key_id,
                'Status': status
            })

        except Exception as e:
            utils.log_warning(f"Error getting encryption config in {region}: {str(e)}")
            continue

    utils.log_success(f"Total encryption configs collected: {len(all_configs)}")
    return all_configs


def generate_summary(sampling_rules: List[Dict[str, Any]],
                     groups: List[Dict[str, Any]],
                     encryption_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for X-Ray resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Sampling rules summary
    total_rules = len(sampling_rules)
    default_rules = sum(1 for r in sampling_rules if r.get('Rule Name', '') == 'Default')
    custom_rules = total_rules - default_rules

    summary.append({
        'Metric': 'Total Sampling Rules',
        'Count': total_rules,
        'Details': f'Default: {default_rules}, Custom: {custom_rules}'
    })

    if sampling_rules:
        # Average fixed rate
        avg_fixed_rate = sum(r.get('Fixed Rate', 0) for r in sampling_rules) / len(sampling_rules)
        summary.append({
            'Metric': 'Average Sampling Fixed Rate',
            'Count': round(avg_fixed_rate, 4),
            'Details': 'Average rate across all sampling rules'
        })

        # Total reservoir size
        total_reservoir = sum(r.get('Reservoir Size', 0) for r in sampling_rules)
        summary.append({
            'Metric': 'Total Reservoir Size',
            'Count': total_reservoir,
            'Details': 'Combined reservoir across all rules'
        })

    # Groups summary
    total_groups = len(groups)
    groups_with_insights = sum(1 for g in groups if g.get('Insights Enabled', False))
    groups_with_notifications = sum(1 for g in groups if g.get('Notifications Enabled', False))

    summary.append({
        'Metric': 'Total Groups',
        'Count': total_groups,
        'Details': f'With Insights: {groups_with_insights}, With Notifications: {groups_with_notifications}'
    })

    # Encryption summary
    if encryption_configs:
        kms_encrypted = sum(1 for c in encryption_configs if c.get('Encryption Type', '') == 'KMS')
        summary.append({
            'Metric': 'Regions with KMS Encryption',
            'Count': kms_encrypted,
            'Details': f'Out of {len(encryption_configs)} regions checked'
        })

    # Regional distribution
    if sampling_rules:
        df = pd.DataFrame(sampling_rules)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Sampling Rules in {region}',
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
    print("AWS X-Ray Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting X-Ray configuration data...")

    sampling_rules = collect_sampling_rules(regions)
    groups = collect_groups(regions)
    encryption_configs = collect_encryption_config(regions)
    summary = generate_summary(sampling_rules, groups, encryption_configs)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if sampling_rules:
        df_sampling_rules = pd.DataFrame(sampling_rules)
        df_sampling_rules = utils.prepare_dataframe_for_export(df_sampling_rules)
        dataframes['Sampling Rules'] = df_sampling_rules

    if groups:
        df_groups = pd.DataFrame(groups)
        df_groups = utils.prepare_dataframe_for_export(df_groups)
        dataframes['Groups'] = df_groups

    if encryption_configs:
        df_encryption = pd.DataFrame(encryption_configs)
        df_encryption = utils.prepare_dataframe_for_export(df_encryption)
        dataframes['Encryption Config'] = df_encryption

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'xray', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Sampling Rules': len(sampling_rules),
            'Groups': len(groups),
            'Encryption Configs': len(encryption_configs)
        })
    else:
        utils.log_warning("No X-Ray data found to export")

    utils.log_success("X-Ray export completed successfully")


if __name__ == "__main__":
    main()
