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

import json
import sys
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
args = utils.parse_script_args("Export AWS X-Ray groups and sampling rules to Excel")

def _build_sampling_rule_row(rule_record: dict, region: str) -> dict[str, Any]:
    """Build a single X-Ray sampling rule export row from a get_sampling_rules record."""
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

    return {
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
    }


def _scan_sampling_rules_region(region: str) -> list[dict[str, Any]]:
    """
    Collect X-Ray sampling rules from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no sampling rules" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed sampling rules are skipped (logged) rather than
    aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_rules = []
    xray_client = utils.get_boto3_client('xray', region_name=region)

    # Get sampling rules (manual NextToken loop — no boto3 paginator for get_sampling_rules)
    sampling_rules = []
    kwargs = {}
    while True:
        response = xray_client.get_sampling_rules(**kwargs)
        sampling_rules.extend(response.get('SamplingRuleRecords', []))
        next_token = response.get('NextToken')
        if not next_token:
            break
        kwargs = {'NextToken': next_token}

    for rule_record in sampling_rules:
        try:
            regional_rules.append(_build_sampling_rule_row(rule_record, region))
        except Exception as e:
            # One malformed sampling rule is skipped, not fatal to the region.
            rule_name = rule_record.get('SamplingRule', {}).get('RuleName', '<unknown>')
            utils.log_error(
                f"Skipping malformed X-Ray sampling rule in {region}: {rule_name}",
                e,
            )
            continue

    return regional_rules


def collect_sampling_rules(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect X-Ray sampling rule information across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(rules, failed_regions)`` where ``failed_regions`` is a list of
        ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING X-RAY SAMPLING RULES ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_sampling_rules_region,
        show_progress=True,
        collect_failures=True,
    )
    all_rules = [rule for result in region_results for rule in result]
    utils.log_success(f"Total sampling rules collected: {len(all_rules)}")
    return all_rules, failed_regions


def _scan_groups_region(region: str) -> list[dict[str, Any]]:
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
def collect_groups(regions: list[str]) -> list[dict[str, Any]]:
    """Collect X-Ray group information from AWS regions."""
    print("\n=== COLLECTING X-RAY GROUPS ===")
    results = utils.scan_regions_concurrent(regions, _scan_groups_region)
    all_groups = [group for result in results for group in result]
    utils.log_success(f"Total groups collected: {len(all_groups)}")
    return all_groups


@utils.aws_error_handler("Collecting encryption configuration", default_return=[])
def collect_encryption_config(regions: list[str]) -> list[dict[str, Any]]:
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


def generate_summary(sampling_rules: list[dict[str, Any]],
                     groups: list[dict[str, Any]],
                     encryption_configs: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    global pd
    import pandas as pd
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    account_id, account_name = utils.print_script_banner("AWS X-RAY EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting X-Ray configuration data...")

    # STEP 1: Collect sampling rules (primary scope — region failures must
    # propagate as failed_regions, never collapse into "empty").
    sampling_rules, failed_regions = collect_sampling_rules(regions)
    # Groups and encryption config are enrichment: they already degrade
    # gracefully (per-region try/except) and do not affect failed_regions.
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

    # Export to Excel — the Summary sheet is forced above, so a workbook is
    # always written even when the primary scope collected nothing (partial
    # export is preferred over no file; see the silent-collection-failure
    # blast-radius audit).
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'xray', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

    else:
        utils.log_warning("No X-Ray data found to export")

    # If ANY region failed the sampling rules scope collection, make it loud:
    # write a marker and exit non-zero, even though a workbook was still
    # written above. A complete-looking file with silently zero-row data is
    # exactly the failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'xray', failed_regions)
        print(
            "\nERROR: X-Ray export completed with failures — data is incomplete. "
            "See the *-xray-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)

    utils.log_success("X-Ray export completed successfully")


if __name__ == "__main__":
    main()
