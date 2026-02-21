#!/usr/bin/env python3
"""
AWS CodeBuild Export Script for StratusScan

Exports comprehensive AWS CodeBuild CI/CD information including:
- Build projects with source and artifact configurations
- Recent builds with status and duration
- Source credentials and webhooks
- Report groups for test and code coverage reports

Output: Multi-worksheet Excel file with CodeBuild resources
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
def _scan_projects_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for CodeBuild projects."""
    projects_data = []

    try:
        codebuild_client = utils.get_boto3_client('codebuild', region_name=region)

        # List all projects
        paginator = codebuild_client.get_paginator('list_projects')
        project_names = []
        for page in paginator.paginate():
            project_names.extend(page.get('projects', []))

        # Batch get project details (100 at a time)
        for i in range(0, len(project_names), 100):
            batch = project_names[i:i+100]
            projects_response = codebuild_client.batch_get_projects(names=batch)
            projects = projects_response.get('projects', [])

            for project in projects:
                created = project.get('created', 'N/A')
                if created != 'N/A':
                    created = created.strftime('%Y-%m-%d %H:%M:%S')
                last_modified = project.get('lastModified', 'N/A')
                if last_modified != 'N/A':
                    last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                source = project.get('source', {})
                environment = project.get('environment', {})
                artifacts = project.get('artifacts', {})
                cache = project.get('cache', {})
                vpc_config = project.get('vpcConfig', {})
                vpc_id = vpc_config.get('vpcId', 'N/A')
                logs_config = project.get('logsConfig', {})

                projects_data.append({
                    'Region': region,
                    'Project Name': project.get('name', 'N/A'),
                    'ARN': project.get('arn', 'N/A'),
                    'Description': project.get('description', 'N/A'),
                    'Created': created,
                    'Last Modified': last_modified,
                    'Source Type': source.get('type', 'N/A'),
                    'Source Location': source.get('location', 'N/A'),
                    'Buildspec': source.get('buildspec', 'Inline/Default'),
                    'Git Clone Depth': source.get('gitCloneDepth', 'N/A'),
                    'Environment Type': environment.get('type', 'N/A'),
                    'Compute Type': environment.get('computeType', 'N/A'),
                    'Image': environment.get('image', 'N/A'),
                    'Privileged Mode': environment.get('privilegedMode', False),
                    'Service Role': project.get('serviceRole', 'N/A'),
                    'Artifacts Type': artifacts.get('type', 'N/A'),
                    'Artifacts Location': artifacts.get('location', 'N/A'),
                    'Cache Type': cache.get('type', 'NO_CACHE'),
                    'Cache Location': cache.get('location', 'N/A'),
                    'VPC Enabled': 'Yes' if vpc_id != 'N/A' else 'No',
                    'VPC ID': vpc_id,
                    'Timeout (minutes)': project.get('timeoutInMinutes', 'N/A'),
                    'Queued Timeout (minutes)': project.get('queuedTimeoutInMinutes', 'N/A'),
                    'Badge Enabled': project.get('badge', {}).get('badgeEnabled', False),
                    'CloudWatch Logs': logs_config.get('cloudWatchLogs', {}).get('status', 'DISABLED'),
                    'S3 Logs': logs_config.get('s3Logs', {}).get('status', 'DISABLED'),
                    'Webhook URL': project.get('webhook', {}).get('url', 'N/A')
                })
    except Exception as e:
        utils.log_error(f"Error scanning CodeBuild projects in {region}", e)

    return projects_data


@utils.aws_error_handler("Collecting CodeBuild projects", default_return=[])
def collect_projects(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodeBuild project information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_projects_region)
    all_projects = [p for result in results for p in result]
    utils.log_info(f"Collected {len(all_projects)} CodeBuild projects")
    return all_projects


def _scan_builds_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for recent CodeBuild builds."""
    builds_data = []

    try:
        codebuild_client = utils.get_boto3_client('codebuild', region_name=region)

        # List build IDs (sorted by start time descending, limited to 50)
        build_ids = []
        paginator = codebuild_client.get_paginator('list_builds')
        for page in paginator.paginate(sortOrder='DESCENDING'):
            build_ids.extend(page.get('ids', []))
            if len(build_ids) >= 50:
                break
        build_ids = build_ids[:50]

        if not build_ids:
            return builds_data

        # Batch get build details (100 at a time)
        for i in range(0, len(build_ids), 100):
            batch = build_ids[i:i+100]
            builds_response = codebuild_client.batch_get_builds(ids=batch)

            for build in builds_response.get('builds', []):
                start_time = build.get('startTime', 'N/A')
                if start_time != 'N/A':
                    start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')
                end_time = build.get('endTime', 'N/A')
                if end_time != 'N/A':
                    end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

                # Duration calculation
                if build.get('buildComplete', False):
                    start_dt = build.get('startTime')
                    end_dt = build.get('endTime')
                    duration_str = f"{((end_dt - start_dt).total_seconds() / 60):.1f} minutes" if start_dt and end_dt else 'N/A'
                else:
                    duration_str = 'In Progress'

                source = build.get('source', {})
                environment = build.get('environment', {})

                builds_data.append({
                    'Region': region,
                    'Build ID': build.get('id', 'N/A'),
                    'Build Number': build.get('buildNumber', 'N/A'),
                    'Project Name': build.get('projectName', 'N/A'),
                    'Status': build.get('buildStatus', 'N/A'),
                    'Current Phase': build.get('currentPhase', 'N/A'),
                    'Started': start_time,
                    'Ended': end_time,
                    'Duration': duration_str,
                    'Source Type': source.get('type', 'N/A'),
                    'Source Location': source.get('location', 'N/A'),
                    'Source Version': build.get('sourceVersion', 'N/A'),
                    'Resolved Source Version': build.get('resolvedSourceVersion', 'N/A'),
                    'Initiator': build.get('initiator', 'N/A'),
                    'Compute Type': environment.get('computeType', 'N/A'),
                    'Image': environment.get('image', 'N/A'),
                    'Logs': build.get('logs', {}).get('deepLink', 'N/A')
                })
    except Exception as e:
        utils.log_error(f"Error scanning builds in {region}", e)

    return builds_data


@utils.aws_error_handler("Collecting CodeBuild builds", default_return=[])
def collect_builds(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect recent CodeBuild build information (limited to 50 most recent per region)."""
    results = utils.scan_regions_concurrent(regions, _scan_builds_region)
    all_builds = [b for result in results for b in result]
    utils.log_info(f"Collected {len(all_builds)} builds (limited to 50 most recent per region)")
    return all_builds


def _scan_report_groups_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for CodeBuild report groups."""
    groups_data = []

    try:
        codebuild_client = utils.get_boto3_client('codebuild', region_name=region)
        paginator = codebuild_client.get_paginator('list_report_groups')
        report_group_arns = []
        for page in paginator.paginate():
            report_group_arns.extend(page.get('reportGroups', []))

        if not report_group_arns:
            return groups_data

        # Batch get report group details (100 at a time)
        for i in range(0, len(report_group_arns), 100):
            batch = report_group_arns[i:i+100]
            groups_response = codebuild_client.batch_get_report_groups(reportGroupArns=batch)

            for group in groups_response.get('reportGroups', []):
                created = group.get('created', 'N/A')
                if created != 'N/A':
                    created = created.strftime('%Y-%m-%d %H:%M:%S')
                last_modified = group.get('lastModified', 'N/A')
                if last_modified != 'N/A':
                    last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                export_config = group.get('exportConfig', {})
                s3_destination = export_config.get('s3Destination', {})

                groups_data.append({
                    'Region': region,
                    'Name': group.get('name', 'N/A'),
                    'ARN': group.get('arn', 'N/A'),
                    'Type': group.get('type', 'N/A'),
                    'Status': group.get('status', 'N/A'),
                    'Created': created,
                    'Last Modified': last_modified,
                    'Export Type': export_config.get('exportConfigType', 'N/A'),
                    'S3 Bucket': s3_destination.get('bucket', 'N/A'),
                    'S3 Path': s3_destination.get('path', 'N/A')
                })
    except Exception as e:
        utils.log_error(f"Error scanning report groups in {region}", e)

    return groups_data


@utils.aws_error_handler("Collecting CodeBuild report groups", default_return=[])
def collect_report_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodeBuild report group information."""
    results = utils.scan_regions_concurrent(regions, _scan_report_groups_region)
    all_report_groups = [g for result in results for g in result]
    utils.log_info(f"Collected {len(all_report_groups)} report groups")
    return all_report_groups


def generate_summary(projects: List[Dict[str, Any]],
                     builds: List[Dict[str, Any]],
                     report_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for CodeBuild resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Projects summary
    total_projects = len(projects)
    summary.append({
        'Metric': 'Total Build Projects',
        'Count': total_projects,
        'Details': 'CodeBuild CI/CD projects'
    })

    # Source types
    if projects:
        df = pd.DataFrame(projects)
        source_types = df['Source Type'].value_counts().to_dict()
        for source_type, count in source_types.items():
            summary.append({
                'Metric': f'Projects - {source_type}',
                'Count': count,
                'Details': 'Source repository type'
            })

    # VPC enabled
    vpc_enabled = sum(1 for p in projects if p.get('VPC Enabled', 'No') == 'Yes')
    if vpc_enabled > 0:
        summary.append({
            'Metric': 'Projects with VPC',
            'Count': vpc_enabled,
            'Details': 'Projects running in VPC for private resource access'
        })

    # Privileged mode
    privileged_projects = sum(1 for p in projects if p.get('Privileged Mode', False))
    if privileged_projects > 0:
        summary.append({
            'Metric': '⚠️ Projects with Privileged Mode',
            'Count': privileged_projects,
            'Details': 'SECURITY: Docker privileged mode enabled - review necessity'
        })

    # Builds summary
    total_builds = len(builds)
    succeeded_builds = sum(1 for b in builds if b.get('Status', '') == 'SUCCEEDED')
    failed_builds = sum(1 for b in builds if b.get('Status', '') == 'FAILED')
    in_progress = sum(1 for b in builds if b.get('Status', '') == 'IN_PROGRESS')

    summary.append({
        'Metric': 'Recent Builds (Sample)',
        'Count': total_builds,
        'Details': f'Succeeded: {succeeded_builds}, Failed: {failed_builds}, In Progress: {in_progress}'
    })

    # Report groups
    total_report_groups = len(report_groups)
    summary.append({
        'Metric': 'Total Report Groups',
        'Count': total_report_groups,
        'Details': 'Test and code coverage report configurations'
    })

    # Regional distribution
    if projects:
        df = pd.DataFrame(projects)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Projects in {region}',
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
    print("AWS CodeBuild Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting AWS CodeBuild data...")

    projects = collect_projects(regions)
    builds = collect_builds(regions)
    report_groups = collect_report_groups(regions)
    summary = generate_summary(projects, builds, report_groups)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if projects:
        df_projects = pd.DataFrame(projects)
        df_projects = utils.prepare_dataframe_for_export(df_projects)
        dataframes['Build Projects'] = df_projects

    if builds:
        df_builds = pd.DataFrame(builds)
        df_builds = utils.prepare_dataframe_for_export(df_builds)
        dataframes['Recent Builds'] = df_builds

    if report_groups:
        df_report_groups = pd.DataFrame(report_groups)
        df_report_groups = utils.prepare_dataframe_for_export(df_report_groups)
        dataframes['Report Groups'] = df_report_groups

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'codebuild', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Build Projects': len(projects),
            'Recent Builds': len(builds),
            'Report Groups': len(report_groups)
        })
    else:
        utils.log_warning("No AWS CodeBuild data found to export")

    utils.log_success("AWS CodeBuild export completed successfully")


if __name__ == "__main__":
    main()
