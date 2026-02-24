#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Access Analyzer Export Tool
Date: NOV-16-2025

Description:
This script exports AWS IAM Access Analyzer information from all regions into an Excel
file with multiple worksheets. The output includes analyzers, findings, and archive rules.

Features:
- Access Analyzers with status and configuration
- Active findings with severity and resource details
- Archived findings for historical analysis
- Archive rules for automated finding management
- Finding details with evidence and recommended actions
- External access detection for S3, IAM, KMS, Lambda, SQS, Secrets Manager
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
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


@utils.aws_error_handler("Collecting Access Analyzers from region", default_return=[])
def collect_analyzers_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect IAM Access Analyzer information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with analyzer information
    """
    if not utils.is_aws_region(region):
        return []

    analyzers_data = []

    aa_client = utils.get_boto3_client('accessanalyzer', region_name=region)

    # Get analyzers
    paginator = aa_client.get_paginator('list_analyzers')

    for page in paginator.paginate():
        analyzers = page.get('analyzers', [])

        for analyzer in analyzers:
            analyzer_name = analyzer.get('name', '')
            analyzer_arn = analyzer.get('arn', '')

            # Type (ACCOUNT or ORGANIZATION)
            analyzer_type = analyzer.get('type', '')

            # Status
            status = analyzer.get('status', '')

            # Created at
            created_at = analyzer.get('createdAt', '')
            if created_at:
                created_at = created_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_at, datetime.datetime) else str(created_at)

            # Last resource analyzed
            last_resource_analyzed = analyzer.get('lastResourceAnalyzed', 'N/A')

            # Last resource analyzed at
            last_resource_analyzed_at = analyzer.get('lastResourceAnalyzedAt', '')
            if last_resource_analyzed_at:
                last_resource_analyzed_at = last_resource_analyzed_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_resource_analyzed_at, datetime.datetime) else str(last_resource_analyzed_at)
            else:
                last_resource_analyzed_at = 'Never'

            # Tags
            tags = analyzer.get('tags', {})
            tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

            # Status reason
            status_reason = analyzer.get('statusReason', {})
            status_reason_code = status_reason.get('code', 'N/A')

            analyzers_data.append({
                'Region': region,
                'Analyzer Name': analyzer_name,
                'Type': analyzer_type,
                'Status': status,
                'Status Reason': status_reason_code,
                'Last Resource Analyzed': last_resource_analyzed,
                'Last Analysis Time': last_resource_analyzed_at,
                'Created At': created_at,
                'Tags': tags_str,
                'Analyzer ARN': analyzer_arn
            })

    utils.log_info(f"Found {len(analyzers_data)} analyzers in {region}")
    return analyzers_data


def collect_analyzers(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect IAM Access Analyzer information using concurrent scanning."""
    print("\n=== COLLECTING ACCESS ANALYZERS ===")
    utils.log_info(f"Scanning {len(regions)} regions for Access Analyzers...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_analyzers_from_region,
        show_progress=True
    )

    # Flatten results
    all_analyzers = []
    for analyzers_in_region in region_results:
        all_analyzers.extend(analyzers_in_region)

    utils.log_success(f"Total Access Analyzers collected: {len(all_analyzers)}")
    return all_analyzers


@utils.aws_error_handler("Collecting active findings from region", default_return=[])
def collect_active_findings_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect active Access Analyzer findings from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with finding information
    """
    if not utils.is_aws_region(region):
        return []

    findings_data = []

    aa_client = utils.get_boto3_client('accessanalyzer', region_name=region)

    # Get all analyzers first
    analyzer_paginator = aa_client.get_paginator('list_analyzers')

    for analyzer_page in analyzer_paginator.paginate():
        analyzers = analyzer_page.get('analyzers', [])

        for analyzer in analyzers:
            analyzer_arn = analyzer.get('arn', '')
            analyzer_name = analyzer.get('name', '')

            try:
                # Get findings for this analyzer (active only)
                finding_paginator = aa_client.get_paginator('list_findings')

                for finding_page in finding_paginator.paginate(
                    analyzerArn=analyzer_arn,
                    filter={'status': {'eq': ['ACTIVE']}}
                ):
                    findings = finding_page.get('findings', [])

                    for finding in findings:
                        finding_id = finding.get('id', '')
                        resource_type = finding.get('resourceType', '')
                        resource = finding.get('resource', '')

                        # Condition
                        condition = finding.get('condition', {})
                        condition_str = str(condition) if condition else 'N/A'

                        # Created at
                        created_at = finding.get('createdAt', '')
                        if created_at:
                            created_at = created_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_at, datetime.datetime) else str(created_at)

                        # Analyzed at
                        analyzed_at = finding.get('analyzedAt', '')
                        if analyzed_at:
                            analyzed_at = analyzed_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(analyzed_at, datetime.datetime) else str(analyzed_at)

                        # Updated at
                        updated_at = finding.get('updatedAt', '')
                        if updated_at:
                            updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(updated_at, datetime.datetime) else str(updated_at)

                        # Status
                        status = finding.get('status', '')

                        # Resource owner account
                        resource_owner_account = finding.get('resourceOwnerAccount', '')

                        # Error
                        error = finding.get('error', 'N/A')

                        # Action
                        action = finding.get('action', [])
                        action_str = ', '.join(action) if action else 'N/A'

                        # Principal
                        principal = finding.get('principal', {})
                        # Extract AWS principals
                        aws_principal = principal.get('AWS', 'N/A')
                        if isinstance(aws_principal, dict):
                            aws_principal = str(aws_principal)
                        elif isinstance(aws_principal, list):
                            aws_principal = ', '.join(aws_principal)

                        findings_data.append({
                            'Region': region,
                            'Analyzer Name': analyzer_name,
                            'Finding ID': finding_id,
                            'Status': status,
                            'Resource Type': resource_type,
                            'Resource': resource,
                            'Resource Owner Account': resource_owner_account,
                            'Principal': aws_principal,
                            'Action': action_str,
                            'Condition': condition_str,
                            'Error': error,
                            'Created At': created_at,
                            'Updated At': updated_at,
                            'Analyzed At': analyzed_at
                        })

            except Exception as e:
                utils.log_warning(f"Could not get findings for analyzer {analyzer_arn}: {e}")

    utils.log_info(f"Found {len(findings_data)} active findings in {region}")
    return findings_data


def collect_active_findings(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect active Access Analyzer findings using concurrent scanning."""
    print("\n=== COLLECTING ACTIVE FINDINGS ===")
    utils.log_info(f"Scanning {len(regions)} regions for active findings...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_active_findings_from_region,
        show_progress=True
    )

    # Flatten results
    all_findings = []
    for findings_in_region in region_results:
        all_findings.extend(findings_in_region)

    utils.log_success(f"Total active findings collected: {len(all_findings)}")
    return all_findings


@utils.aws_error_handler("Collecting archived findings from region", default_return=[])
def collect_archived_findings_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect archived Access Analyzer findings from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with archived finding information
    """
    if not utils.is_aws_region(region):
        return []

    findings_data = []

    aa_client = utils.get_boto3_client('accessanalyzer', region_name=region)

    # Get all analyzers first
    analyzer_paginator = aa_client.get_paginator('list_analyzers')

    for analyzer_page in analyzer_paginator.paginate():
        analyzers = analyzer_page.get('analyzers', [])

        for analyzer in analyzers:
            analyzer_arn = analyzer.get('arn', '')
            analyzer_name = analyzer.get('name', '')

            try:
                # Get archived findings for this analyzer
                finding_paginator = aa_client.get_paginator('list_findings')

                for finding_page in finding_paginator.paginate(
                    analyzerArn=analyzer_arn,
                    filter={'status': {'eq': ['ARCHIVED']}}
                ):
                    findings = finding_page.get('findings', [])

                    for finding in findings:
                        finding_id = finding.get('id', '')
                        resource_type = finding.get('resourceType', '')
                        resource = finding.get('resource', '')

                        # Status
                        status = finding.get('status', '')

                        # Created at
                        created_at = finding.get('createdAt', '')
                        if created_at:
                            created_at = created_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_at, datetime.datetime) else str(created_at)

                        # Updated at
                        updated_at = finding.get('updatedAt', '')
                        if updated_at:
                            updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(updated_at, datetime.datetime) else str(updated_at)

                        # Resource owner account
                        resource_owner_account = finding.get('resourceOwnerAccount', '')

                        findings_data.append({
                            'Region': region,
                            'Analyzer Name': analyzer_name,
                            'Finding ID': finding_id,
                            'Status': status,
                            'Resource Type': resource_type,
                            'Resource': resource,
                            'Resource Owner Account': resource_owner_account,
                            'Created At': created_at,
                            'Updated At': updated_at
                        })

            except Exception as e:
                utils.log_warning(f"Could not get archived findings for analyzer {analyzer_arn}: {e}")

    utils.log_info(f"Found {len(findings_data)} archived findings in {region}")
    return findings_data


def collect_archived_findings(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect archived Access Analyzer findings using concurrent scanning."""
    print("\n=== COLLECTING ARCHIVED FINDINGS ===")
    utils.log_info(f"Scanning {len(regions)} regions for archived findings...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_archived_findings_from_region,
        show_progress=True
    )

    # Flatten results
    all_findings = []
    for findings_in_region in region_results:
        all_findings.extend(findings_in_region)

    utils.log_success(f"Total archived findings collected: {len(all_findings)}")
    return all_findings


@utils.aws_error_handler("Collecting archive rules from region", default_return=[])
def collect_archive_rules_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Access Analyzer archive rules from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with archive rule information
    """
    if not utils.is_aws_region(region):
        return []

    rules_data = []

    aa_client = utils.get_boto3_client('accessanalyzer', region_name=region)

    # Get all analyzers first
    analyzer_paginator = aa_client.get_paginator('list_analyzers')

    for analyzer_page in analyzer_paginator.paginate():
        analyzers = analyzer_page.get('analyzers', [])

        for analyzer in analyzers:
            analyzer_name = analyzer.get('name', '')

            try:
                # Get archive rules for this analyzer
                rule_paginator = aa_client.get_paginator('list_archive_rules')

                for rule_page in rule_paginator.paginate(analyzerName=analyzer_name):
                    archive_rules = rule_page.get('archiveRules', [])

                    for rule in archive_rules:
                        rule_name = rule.get('ruleName', '')

                        # Filter
                        filter_criteria = rule.get('filter', {})
                        filter_str = str(filter_criteria) if filter_criteria else 'N/A'

                        # Created at
                        created_at = rule.get('createdAt', '')
                        if created_at:
                            created_at = created_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_at, datetime.datetime) else str(created_at)

                        # Updated at
                        updated_at = rule.get('updatedAt', '')
                        if updated_at:
                            updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(updated_at, datetime.datetime) else str(updated_at)

                        rules_data.append({
                            'Region': region,
                            'Analyzer Name': analyzer_name,
                            'Rule Name': rule_name,
                            'Filter Criteria': filter_str,
                            'Created At': created_at,
                            'Updated At': updated_at
                        })

            except Exception as e:
                utils.log_warning(f"Could not get archive rules for analyzer {analyzer_name}: {e}")

    utils.log_info(f"Found {len(rules_data)} archive rules in {region}")
    return rules_data


def collect_archive_rules(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Access Analyzer archive rules using concurrent scanning."""
    print("\n=== COLLECTING ARCHIVE RULES ===")
    utils.log_info(f"Scanning {len(regions)} regions for archive rules...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_archive_rules_from_region,
        show_progress=True
    )

    # Flatten results
    all_rules = []
    for rules_in_region in region_results:
        all_rules.extend(rules_in_region)

    utils.log_success(f"Total archive rules collected: {len(all_rules)}")
    return all_rules


def export_access_analyzer_data(account_id: str, account_name: str):
    """
    Export Access Analyzer information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition and set partition-aware example regions
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect analyzers
    analyzers = collect_analyzers(regions)
    if analyzers:
        data_frames['Analyzers'] = pd.DataFrame(analyzers)

    # STEP 2: Collect active findings
    active_findings = collect_active_findings(regions)
    if active_findings:
        data_frames['Active Findings'] = pd.DataFrame(active_findings)

    # STEP 3: Collect archived findings
    archived_findings = collect_archived_findings(regions)
    if archived_findings:
        data_frames['Archived Findings'] = pd.DataFrame(archived_findings)

    # STEP 4: Collect archive rules
    archive_rules = collect_archive_rules(regions)
    if archive_rules:
        data_frames['Archive Rules'] = pd.DataFrame(archive_rules)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Access Analyzer data was collected. Nothing to export.")
        print("\nNo Access Analyzers found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'access-analyzer',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Access Analyzer data exported successfully!")
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
    utils.setup_logging("access-analyzer-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("access-analyzer-export.py", "AWS IAM Access Analyzer Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS IAM ACCESS ANALYZER EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Export Access Analyzer data
        export_access_analyzer_data(account_id, account_name)

        print("\nAccess Analyzer export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("access-analyzer-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
