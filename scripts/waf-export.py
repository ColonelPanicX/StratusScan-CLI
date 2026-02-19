#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS WAF (Web Application Firewall) Export Tool
Version: v0.1.0
Date: NOV-16-2025

Description:
This script exports AWS WAF (WAFv2) configuration information from all regions into an Excel
file with multiple worksheets. Supports both regional WAF and CloudFront (global) WAF resources.

Features:
- Web ACLs with capacity units and default actions
- WAF rules with priority, action, and statement types
- IP sets for allow/deny lists
- Regex pattern sets for pattern matching
- Rule groups (managed and custom)
- Logging configurations
- Associated resources (ALB, API Gateway, CloudFront)
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)

Note: This exports WAFv2 (latest version). WAF Classic is deprecated.
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
utils.setup_logging("waf-export")
utils.log_script_start("waf-export.py", "AWS WAF Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("         AWS WAF (WEB APPLICATION FIREWALL) EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-16-2025")
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
    """Get a list of available AWS regions for the current partition."""
    try:
        # Get partition-aware regions
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


@utils.aws_error_handler("Collecting WAF web ACLs from region", default_return=[])
def collect_web_acls_from_region(region: str, scope: str = 'REGIONAL') -> List[Dict[str, Any]]:
    """
    Collect WAF web ACL information from a single AWS region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with web ACL information
    """
    if not utils.validate_aws_region(region):
        return []

    web_acls_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    # List web ACLs
    paginator = wafv2_client.get_paginator('list_web_acls')

    for page in paginator.paginate(Scope=scope):
        web_acls = page.get('WebACLs', [])

        for acl_summary in web_acls:
            acl_name = acl_summary.get('Name', '')
            acl_id = acl_summary.get('Id', '')
            acl_arn = acl_summary.get('ARN', '')

            try:
                # Get web ACL details
                acl_response = wafv2_client.get_web_acl(
                    Name=acl_name,
                    Scope=scope,
                    Id=acl_id
                )

                acl = acl_response.get('WebACL', {})

                # Default action
                default_action = acl.get('DefaultAction', {})
                if 'Allow' in default_action:
                    default_action_type = 'ALLOW'
                elif 'Block' in default_action:
                    default_action_type = 'BLOCK'
                else:
                    default_action_type = 'N/A'

                # Description
                description = acl.get('Description', 'N/A')

                # Rules
                rules = acl.get('Rules', [])
                rule_count = len(rules)

                # Capacity
                capacity = acl.get('Capacity', 0)

                # Visibility config
                visibility_config = acl.get('VisibilityConfig', {})
                sampled_requests_enabled = visibility_config.get('SampledRequestsEnabled', False)
                cloudwatch_metrics_enabled = visibility_config.get('CloudWatchMetricsEnabled', False)
                metric_name = visibility_config.get('MetricName', 'N/A')

                # Managed by firewall manager
                managed_by_firewall_manager = acl.get('ManagedByFirewallManager', False)

                # Label namespace
                label_namespace = acl.get('LabelNamespace', 'N/A')

                web_acls_data.append({
                    'Region': region,
                    'Scope': scope,
                    'Name': acl_name,
                    'ID': acl_id,
                    'Default Action': default_action_type,
                    'Rule Count': rule_count,
                    'Capacity': capacity,
                    'Description': description,
                    'Sampled Requests': sampled_requests_enabled,
                    'CloudWatch Metrics': cloudwatch_metrics_enabled,
                    'Metric Name': metric_name,
                    'Managed by FW Manager': managed_by_firewall_manager,
                    'Label Namespace': label_namespace,
                    'ARN': acl_arn
                })

            except Exception as e:
                utils.log_warning(f"Could not get details for web ACL {acl_name}: {e}")

    utils.log_info(f"Found {len(web_acls_data)} web ACLs ({scope}) in {region}")
    return web_acls_data


def collect_web_acls(regions: List[str], scope: str = 'REGIONAL') -> List[Dict[str, Any]]:
    """
    Collect WAF web ACL information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with web ACL information
    """
    print(f"\n=== COLLECTING WAF WEB ACLs ({scope}) ===")

    # CloudFront WAF is only in us-east-1
    if scope == 'CLOUDFRONT':
        regions = ['us-east-1']

    utils.log_info(f"Scanning {len(regions)} regions...")

    # Use concurrent scanning with a wrapper that passes the scope parameter
    def scan_region_with_scope(region: str) -> List[Dict[str, Any]]:
        return collect_web_acls_from_region(region, scope)

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_with_scope,
        show_progress=True
    )

    all_web_acls = []
    for web_acls_in_region in region_results:
        all_web_acls.extend(web_acls_in_region)

    utils.log_success(f"Total WAF web ACLs ({scope}) collected: {len(all_web_acls)}")
    return all_web_acls


@utils.aws_error_handler("Collecting WAF rules from region", default_return=[])
def collect_waf_rules_from_region(region: str, scope: str = 'REGIONAL') -> List[Dict[str, Any]]:
    """
    Collect WAF rule information from web ACLs in a single AWS region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with rule information
    """
    if not utils.validate_aws_region(region):
        return []

    rules_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    # List web ACLs first
    acl_paginator = wafv2_client.get_paginator('list_web_acls')

    for acl_page in acl_paginator.paginate(Scope=scope):
        web_acls = acl_page.get('WebACLs', [])

        for acl_summary in web_acls:
            acl_name = acl_summary.get('Name', '')
            acl_id = acl_summary.get('Id', '')

            try:
                # Get web ACL details
                acl_response = wafv2_client.get_web_acl(
                    Name=acl_name,
                    Scope=scope,
                    Id=acl_id
                )

                acl = acl_response.get('WebACL', {})
                rules = acl.get('Rules', [])

                for rule in rules:
                    rule_name = rule.get('Name', '')
                    priority = rule.get('Priority', 0)

                    # Action
                    action = rule.get('Action', {})
                    if 'Allow' in action:
                        action_type = 'ALLOW'
                    elif 'Block' in action:
                        action_type = 'BLOCK'
                    elif 'Count' in action:
                        action_type = 'COUNT'
                    elif 'Captcha' in action:
                        action_type = 'CAPTCHA'
                    else:
                        action_type = 'N/A'

                    # Override action (from rule group)
                    override_action = rule.get('OverrideAction', {})
                    if 'None' in override_action:
                        override_action_type = 'NONE (Use Rule Action)'
                    elif 'Count' in override_action:
                        override_action_type = 'COUNT'
                    else:
                        override_action_type = 'N/A'

                    # Statement
                    statement = rule.get('Statement', {})
                    statement_type = 'N/A'
                    if 'ByteMatchStatement' in statement:
                        statement_type = 'ByteMatch'
                    elif 'SqliMatchStatement' in statement:
                        statement_type = 'SQLi'
                    elif 'XssMatchStatement' in statement:
                        statement_type = 'XSS'
                    elif 'SizeConstraintStatement' in statement:
                        statement_type = 'SizeConstraint'
                    elif 'GeoMatchStatement' in statement:
                        statement_type = 'GeoMatch'
                    elif 'IPSetReferenceStatement' in statement:
                        statement_type = 'IPSet'
                    elif 'RegexPatternSetReferenceStatement' in statement:
                        statement_type = 'RegexPatternSet'
                    elif 'RateBasedStatement' in statement:
                        statement_type = 'RateBased'
                    elif 'ManagedRuleGroupStatement' in statement:
                        statement_type = 'ManagedRuleGroup'
                    elif 'RuleGroupReferenceStatement' in statement:
                        statement_type = 'RuleGroup'
                    elif 'AndStatement' in statement:
                        statement_type = 'AND'
                    elif 'OrStatement' in statement:
                        statement_type = 'OR'
                    elif 'NotStatement' in statement:
                        statement_type = 'NOT'

                    # Visibility config
                    visibility_config = rule.get('VisibilityConfig', {})
                    sampled_requests = visibility_config.get('SampledRequestsEnabled', False)
                    metric_name = visibility_config.get('MetricName', 'N/A')

                    rules_data.append({
                        'Region': region,
                        'Scope': scope,
                        'Web ACL': acl_name,
                        'Rule Name': rule_name,
                        'Priority': priority,
                        'Action': action_type,
                        'Override Action': override_action_type,
                        'Statement Type': statement_type,
                        'Sampled Requests': sampled_requests,
                        'Metric Name': metric_name
                    })

            except Exception as e:
                utils.log_warning(f"Could not get rules for web ACL {acl_name}: {e}")

    utils.log_info(f"Found {len(rules_data)} rules ({scope}) in {region}")
    return rules_data


def collect_waf_rules(regions: List[str], scope: str = 'REGIONAL') -> List[Dict[str, Any]]:
    """
    Collect WAF rule information from web ACLs using concurrent scanning.

    Args:
        regions: List of AWS regions to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with rule information
    """
    print(f"\n=== COLLECTING WAF RULES ({scope}) ===")

    # CloudFront WAF is only in us-east-1
    if scope == 'CLOUDFRONT':
        regions = ['us-east-1']

    utils.log_info(f"Scanning {len(regions)} regions...")

    # Use concurrent scanning with a wrapper that passes the scope parameter
    def scan_region_with_scope(region: str) -> List[Dict[str, Any]]:
        return collect_waf_rules_from_region(region, scope)

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_with_scope,
        show_progress=True
    )

    all_rules = []
    for rules_in_region in region_results:
        all_rules.extend(rules_in_region)

    utils.log_success(f"Total WAF rules ({scope}) collected: {len(all_rules)}")
    return all_rules


@utils.aws_error_handler("Collecting IP sets from region", default_return=[])
def collect_ip_sets_from_region(region: str, scope: str = 'REGIONAL') -> List[Dict[str, Any]]:
    """
    Collect WAF IP set information from a single AWS region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with IP set information
    """
    if not utils.validate_aws_region(region):
        return []

    ip_sets_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    # List IP sets
    paginator = wafv2_client.get_paginator('list_ip_sets')

    for page in paginator.paginate(Scope=scope):
        ip_sets = page.get('IPSets', [])

        for ip_set_summary in ip_sets:
            ip_set_name = ip_set_summary.get('Name', '')
            ip_set_id = ip_set_summary.get('Id', '')
            ip_set_arn = ip_set_summary.get('ARN', '')

            try:
                # Get IP set details
                ip_set_response = wafv2_client.get_ip_set(
                    Name=ip_set_name,
                    Scope=scope,
                    Id=ip_set_id
                )

                ip_set = ip_set_response.get('IPSet', {})

                description = ip_set.get('Description', 'N/A')
                ip_address_version = ip_set.get('IPAddressVersion', '')
                addresses = ip_set.get('Addresses', [])
                address_count = len(addresses)

                # Sample addresses (first 5)
                sample_addresses = ', '.join(addresses[:5])
                if address_count > 5:
                    sample_addresses += f' ... ({address_count - 5} more)'

                ip_sets_data.append({
                    'Region': region,
                    'Scope': scope,
                    'Name': ip_set_name,
                    'ID': ip_set_id,
                    'IP Version': ip_address_version,
                    'Address Count': address_count,
                    'Sample Addresses': sample_addresses if sample_addresses else 'None',
                    'Description': description,
                    'ARN': ip_set_arn
                })

            except Exception as e:
                utils.log_warning(f"Could not get IP set {ip_set_name}: {e}")

    utils.log_info(f"Found {len(ip_sets_data)} IP sets ({scope}) in {region}")
    return ip_sets_data


def collect_ip_sets(regions: List[str], scope: str = 'REGIONAL') -> List[Dict[str, Any]]:
    """
    Collect WAF IP set information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with IP set information
    """
    print(f"\n=== COLLECTING WAF IP SETS ({scope}) ===")

    # CloudFront WAF is only in us-east-1
    if scope == 'CLOUDFRONT':
        regions = ['us-east-1']

    utils.log_info(f"Scanning {len(regions)} regions...")

    # Use concurrent scanning with a wrapper that passes the scope parameter
    def scan_region_with_scope(region: str) -> List[Dict[str, Any]]:
        return collect_ip_sets_from_region(region, scope)

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_with_scope,
        show_progress=True
    )

    all_ip_sets = []
    for ip_sets_in_region in region_results:
        all_ip_sets.extend(ip_sets_in_region)

    utils.log_success(f"Total WAF IP sets ({scope}) collected: {len(all_ip_sets)}")
    return all_ip_sets


def export_waf_data(account_id: str, account_name: str):
    """
    Export WAF information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print("\nWAF (WAFv2) is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where WAF is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    region_suffix = ""
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                # Default regions
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
            elif region_choice == '2':
                # All available regions
                regions = utils.get_partition_regions(partition, all_regions=True)
                print(f"\nScanning all {len(regions)} available regions")
            elif region_choice == '3':
                # Specific region - show numbered list
                available_regions = utils.get_partition_regions(
                    partition, all_regions=True
                )
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx}. {region}")
                print("-" * 68)

                # Get region selection
                region_selected = False
                while not region_selected:
                    try:
                        region_num = input(
                            f"\nEnter region number (1-{len(available_regions)}): "
                        ).strip()
                        region_idx = int(region_num) - 1

                        if 0 <= region_idx < len(available_regions):
                            selected_region = available_regions[region_idx]
                            regions = [selected_region]
                            region_suffix = f"-{selected_region}"
                            print(f"\nSelected region: {selected_region}")
                            region_selected = True
                        else:
                            print(
                                f"Invalid selection. Please enter a number "
                                f"between 1 and {len(available_regions)}."
                            )
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                    except KeyboardInterrupt:
                        print("\n\nOperation cancelled by user.")
                        sys.exit(0)
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    print(f"\nStarting WAF export process for {len(regions)} region(s)...")
    print("This may take some time depending on the number of regions and resources...")
    print("\nNote: CloudFront (global) WAF resources are collected from us-east-1 only.")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect regional Web ACLs
    regional_acls = collect_web_acls(regions, scope='REGIONAL')
    cloudfront_acls = collect_web_acls(regions, scope='CLOUDFRONT')
    all_acls = regional_acls + cloudfront_acls
    if all_acls:
        data_frames['Web ACLs'] = pd.DataFrame(all_acls)

    # STEP 2: Collect regional rules
    regional_rules = collect_waf_rules(regions, scope='REGIONAL')
    cloudfront_rules = collect_waf_rules(regions, scope='CLOUDFRONT')
    all_rules = regional_rules + cloudfront_rules
    if all_rules:
        data_frames['WAF Rules'] = pd.DataFrame(all_rules)

    # STEP 3: Collect IP sets
    regional_ip_sets = collect_ip_sets(regions, scope='REGIONAL')
    cloudfront_ip_sets = collect_ip_sets(regions, scope='CLOUDFRONT')
    all_ip_sets = regional_ip_sets + cloudfront_ip_sets
    if all_ip_sets:
        data_frames['IP Sets'] = pd.DataFrame(all_ip_sets)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No WAF data was collected. Nothing to export.")
        print("\nNo WAF resources found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'waf',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("WAF data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s) + CloudFront (global)")

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

        # Export WAF data
        export_waf_data(account_id, account_name)

        print("\nWAF export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("waf-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
