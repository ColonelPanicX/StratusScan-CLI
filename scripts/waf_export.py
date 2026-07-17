#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS WAF (Web Application Firewall) Export Tool
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

import datetime
import sys
from pathlib import Path
from typing import Any

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
args = utils.parse_script_args("Export AWS WAF web ACLs and rules to Excel")


def _build_web_acl_row(acl_summary: dict, region: str, scope: str, wafv2_client) -> dict[str, Any]:
    """
    Build the export row for a single WAF web ACL, including its detail call
    (get_web_acl).

    Extracted so per-item processing can be wrapped in try/except by the
    caller: a malformed/inaccessible web ACL is logged and skipped rather
    than discarding the whole region's results.

    Args:
        acl_summary: A single WebACLs entry from list_web_acls.
        region: AWS region name.
        scope: REGIONAL or CLOUDFRONT.
        wafv2_client: A wafv2 client for ``region``.

    Returns:
        dict: The assembled web ACL row.
    """
    acl_name = acl_summary.get('Name', '')
    acl_id = acl_summary.get('Id', '')
    acl_arn = acl_summary.get('ARN', '')

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

    return {
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
    }


def collect_web_acls_from_region(region: str, scope: str = 'REGIONAL') -> list[dict[str, Any]]:
    """
    Collect WAF web ACL information from a single AWS region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no web ACLs" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed/inaccessible web ACLs are skipped (logged) rather
    than aborting the whole region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with web ACL information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records
            it as a failed region and surfaces it; it is never masked as
            empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    web_acls_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    # List web ACLs
    next_marker = None
    while True:
        params = {'Scope': scope}
        params['Limit'] = 100
        if next_marker:
            params['NextMarker'] = next_marker
        page = wafv2_client.list_web_acls(**params)
        web_acls = page.get('WebACLs', [])

        # Process each web ACL. One malformed/inaccessible web ACL must not
        # sink the region, so each is built inside try/except; failures are
        # logged and skipped.
        for acl_summary in web_acls:
            acl_name = acl_summary.get('Name', '')

            try:
                web_acls_data.append(_build_web_acl_row(acl_summary, region, scope, wafv2_client))
            except Exception as e:
                utils.log_error(
                    f"Skipping web ACL '{acl_name}' ({scope}) in {region} due to a processing error", e
                )
                continue

        next_marker = page.get('NextMarker')
        if not next_marker:
            break

    utils.log_info(f"Found {len(web_acls_data)} web ACLs ({scope}) in {region}")
    return web_acls_data


def collect_web_acls(regions: list[str], scope: str = 'REGIONAL') -> tuple[list[dict[str, Any]], list]:
    """
    Collect WAF web ACL information, surfacing failures.

    REGIONAL scope uses ``collect_failures=True`` so a region whose
    collection errors is reported as a failed scope rather than silently
    collapsed into an empty result.

    CLOUDFRONT scope is a single global call (CloudFront WAF only exists in
    us-east-1) — a single call, not region-scanned — so there is no
    per-region loop to attach a failed-region tuple to. A collection error
    there is instead reported as a single ``('cloudfront-global', error)``
    entry, using the same ``(scope, error)`` contract as the regional scope
    so the caller can merge them into one combined failed list (see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Args:
        regions: List of AWS regions to scan (ignored for CLOUDFRONT scope)
        scope: REGIONAL or CLOUDFRONT

    Returns:
        tuple: ``(web_acls, failed_scopes)`` where ``failed_scopes`` is
        either a list of ``(region, error_message)`` tuples (REGIONAL) or
        ``[]``/``[('cloudfront-global', error_message)]`` (CLOUDFRONT).
    """
    print(f"\n=== COLLECTING WAF WEB ACLs ({scope}) ===")

    if scope == 'CLOUDFRONT':
        utils.log_info("Scanning CloudFront (global) scope...")
        try:
            web_acls = collect_web_acls_from_region('us-east-1', scope='CLOUDFRONT')
            utils.log_success(f"Total WAF web ACLs (CLOUDFRONT) collected: {len(web_acls)}")
            return web_acls, []
        except Exception as e:
            # The CLOUDFRONT scope call itself failed (e.g. throttling,
            # access denied). Surface it as a failed global scope rather
            # than swallowing it into an empty list indistinguishable from
            # "no CloudFront web ACLs configured".
            utils.log_error("Error collecting CloudFront (global) WAF web ACLs", e)
            return [], [('cloudfront-global', str(e))]

    utils.log_info(f"Scanning {len(regions)} regions...")

    # Use concurrent scanning with a wrapper that passes the scope parameter
    def scan_region_with_scope(region: str) -> list[dict[str, Any]]:
        return collect_web_acls_from_region(region, scope)

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_with_scope,
        show_progress=True,
        collect_failures=True,
    )

    all_web_acls = []
    for web_acls_in_region in region_results:
        all_web_acls.extend(web_acls_in_region)

    utils.log_success(f"Total WAF web ACLs ({scope}) collected: {len(all_web_acls)}")
    return all_web_acls, failed_regions


@utils.aws_error_handler("Collecting WAF rules from region", default_return=[])
def collect_waf_rules_from_region(region: str, scope: str = 'REGIONAL') -> list[dict[str, Any]]:
    """
    Collect WAF rule information from web ACLs in a single AWS region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with rule information
    """
    if not utils.is_aws_region(region):
        return []

    rules_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    # List web ACLs first
    next_marker = None
    while True:
        params = {'Scope': scope}
        params['Limit'] = 100
        if next_marker:
            params['NextMarker'] = next_marker
        acl_page = wafv2_client.list_web_acls(**params)
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

        next_marker = acl_page.get('NextMarker')
        if not next_marker:
            break

    utils.log_info(f"Found {len(rules_data)} rules ({scope}) in {region}")
    return rules_data


def collect_waf_rules(regions: list[str], scope: str = 'REGIONAL') -> list[dict[str, Any]]:
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
    def scan_region_with_scope(region: str) -> list[dict[str, Any]]:
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
def collect_ip_sets_from_region(region: str, scope: str = 'REGIONAL') -> list[dict[str, Any]]:
    """
    Collect WAF IP set information from a single AWS region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with IP set information
    """
    if not utils.is_aws_region(region):
        return []

    ip_sets_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    # List IP sets
    next_marker = None
    while True:
        params = {'Scope': scope}
        params['Limit'] = 100
        if next_marker:
            params['NextMarker'] = next_marker
        page = wafv2_client.list_ip_sets(**params)
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

        next_marker = page.get('NextMarker')
        if not next_marker:
            break

    utils.log_info(f"Found {len(ip_sets_data)} IP sets ({scope}) in {region}")
    return ip_sets_data


def collect_ip_sets(regions: list[str], scope: str = 'REGIONAL') -> list[dict[str, Any]]:
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
    def scan_region_with_scope(region: str) -> list[dict[str, Any]]:
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


@utils.aws_error_handler("Collecting rule groups from region", default_return=[])
def collect_rule_groups_from_region(region: str, scope: str = 'REGIONAL') -> list[dict[str, Any]]:
    """
    Collect WAF rule group information from a single AWS region.

    Args:
        region: AWS region to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with rule group information
    """
    if not utils.is_aws_region(region):
        return []

    rule_groups_data = []
    wafv2_client = utils.get_boto3_client('wafv2', region_name=region)

    next_marker = None
    while True:
        params = {'Scope': scope}
        params['Limit'] = 100
        if next_marker:
            params['NextMarker'] = next_marker
        page = wafv2_client.list_rule_groups(**params)
        rule_groups = page.get('RuleGroups', [])

        for rg_summary in rule_groups:
            rg_name = rg_summary.get('Name', '')
            rg_id = rg_summary.get('Id', '')
            rg_arn = rg_summary.get('ARN', '')

            try:
                rg_response = wafv2_client.get_rule_group(
                    Name=rg_name,
                    Scope=scope,
                    Id=rg_id
                )
                rg = rg_response.get('RuleGroup', {})

                description = rg.get('Description', 'N/A')
                capacity = rg.get('Capacity', 0)
                rules = rg.get('Rules', [])
                rule_count = len(rules)

                visibility_config = rg.get('VisibilityConfig', {})
                metric_name = visibility_config.get('MetricName', 'N/A')
                cloudwatch_metrics_enabled = visibility_config.get('CloudWatchMetricsEnabled', False)

                rule_groups_data.append({
                    'Region': region,
                    'Scope': scope,
                    'Name': rg_name,
                    'ID': rg_id,
                    'Rule Count': rule_count,
                    'Capacity': capacity,
                    'Description': description,
                    'CloudWatch Metrics': cloudwatch_metrics_enabled,
                    'Metric Name': metric_name,
                    'ARN': rg_arn
                })

            except Exception as e:
                utils.log_warning(f"Could not get rule group {rg_name}: {e}")

        next_marker = page.get('NextMarker')
        if not next_marker:
            break

    utils.log_info(f"Found {len(rule_groups_data)} rule groups ({scope}) in {region}")
    return rule_groups_data


def collect_rule_groups(regions: list[str], scope: str = 'REGIONAL') -> list[dict[str, Any]]:
    """
    Collect WAF rule group information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan
        scope: REGIONAL or CLOUDFRONT

    Returns:
        list: List of dictionaries with rule group information
    """
    print(f"\n=== COLLECTING WAF RULE GROUPS ({scope}) ===")

    if scope == 'CLOUDFRONT':
        regions = ['us-east-1']

    utils.log_info(f"Scanning {len(regions)} regions...")

    def scan_region_with_scope(region: str) -> list[dict[str, Any]]:
        return collect_rule_groups_from_region(region, scope)

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_with_scope,
        show_progress=True
    )

    all_rule_groups = []
    for rule_groups_in_region in region_results:
        all_rule_groups.extend(rule_groups_in_region)

    utils.log_success(f"Total WAF rule groups ({scope}) collected: {len(all_rule_groups)}")
    return all_rule_groups


def export_waf_data(account_id: str, account_name: str):
    """
    Export WAF information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Web ACLs (primary scope — REGIONAL failures must
    # propagate as failed_regions, never collapse into "empty"; the
    # CLOUDFRONT global scope's failure is surfaced as a single
    # ('cloudfront-global', error) entry).
    regional_acls, failed_regions = collect_web_acls(regions, scope='REGIONAL')
    cloudfront_acls, cloudfront_failed = collect_web_acls(regions, scope='CLOUDFRONT')
    all_acls = regional_acls + cloudfront_acls
    if all_acls:
        data_frames['Web ACLs'] = pd.DataFrame(all_acls)

    # Merge failed scopes: regional failures from the primary Web ACLs scope
    # + the CLOUDFRONT (global) scope (if it failed).
    failed = list(failed_regions) + list(cloudfront_failed)

    # STEP 2: Collect regional rules (enrichment — degrades gracefully)
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

    # STEP 4: Collect rule groups
    regional_rule_groups = collect_rule_groups(regions, scope='REGIONAL')
    cloudfront_rule_groups = collect_rule_groups(regions, scope='CLOUDFRONT')
    all_rule_groups = regional_rule_groups + cloudfront_rule_groups
    if all_rule_groups:
        data_frames['Rule Groups'] = pd.DataFrame(all_rule_groups)

    # Export whatever succeeded first — a partial export is required even
    # when some scopes failed (see the silent-collection-failure
    # blast-radius audit).
    if data_frames:
        # STEP 5: Prepare all DataFrames for export
        for sheet_name in data_frames:
            data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

        # STEP 6: Create filename and export
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
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s) + CloudFront (global)")

                # Summary of exported data
                for sheet_name, df in data_frames.items():
                    utils.log_info(f"  - {sheet_name}: {len(df)} records")
                    print(f"  - {sheet_name}: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)
    elif not failed:
        # Genuinely empty account: every scope succeeded and returned nothing.
        utils.log_warning("No WAF data was collected. Nothing to export.")
        print("\nNo WAF resources found in the selected region(s).")

    # If ANY scope failed the Web ACLs collection (regional or the
    # CLOUDFRONT global scope), make it loud: write a marker and exit
    # non-zero, even if some data was exported. A partial export that looks
    # complete is exactly the failure mode this guards against.
    if failed:
        utils.report_collection_failures(account_name, 'waf', failed)
        print(
            "\nERROR: WAF export completed with failures — data is incomplete. "
            "See the *-waf-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("waf-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("waf-export.py", "AWS WAF Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS WAF (WEB APPLICATION FIREWALL) EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
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
