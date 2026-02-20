#!/usr/bin/env python3
"""
AWS CodeDeploy Export Script for StratusScan

Exports comprehensive AWS CodeDeploy deployment automation information including:
- Applications with compute platforms
- Deployment groups with configurations
- Recent deployments with status and timing
- Deployment configurations (strategies)

Output: Multi-worksheet Excel file with CodeDeploy resources
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
@utils.aws_error_handler("Collecting CodeDeploy applications", default_return=[])
def collect_applications(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodeDeploy application information from AWS regions."""
    all_applications = []

    for region in regions:
        utils.log_info(f"Collecting CodeDeploy applications in {region}...")
        codedeploy_client = utils.get_boto3_client('codedeploy', region_name=region)

        try:
            # List all applications
            paginator = codedeploy_client.get_paginator('list_applications')
            for page in paginator.paginate():
                app_names = page.get('applications', [])

                # Batch get application details
                if app_names:
                    apps_response = codedeploy_client.batch_get_applications(applicationNames=app_names)
                    applications = apps_response.get('applicationsInfo', [])

                    for app in applications:
                        app_name = app.get('applicationName', 'N/A')
                        app_id = app.get('applicationId', 'N/A')
                        compute_platform = app.get('computePlatform', 'N/A')

                        created_time = app.get('createTime', 'N/A')
                        if created_time != 'N/A':
                            created_time = created_time.strftime('%Y-%m-%d %H:%M:%S')

                        # Linked to GitHub
                        linked_to_github = app.get('linkedToGitHub', False)
                        github_account_name = app.get('gitHubAccountName', 'N/A')

                        all_applications.append({
                            'Region': region,
                            'Application Name': app_name,
                            'Application ID': app_id,
                            'Compute Platform': compute_platform,
                            'Created': created_time,
                            'Linked to GitHub': linked_to_github,
                            'GitHub Account': github_account_name
                        })

        except Exception as e:
            utils.log_warning(f"Error collecting CodeDeploy applications in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_applications)} CodeDeploy applications")
    return all_applications


@utils.aws_error_handler("Collecting deployment groups", default_return=[])
def collect_deployment_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodeDeploy deployment group information."""
    all_deployment_groups = []

    for region in regions:
        utils.log_info(f"Collecting deployment groups in {region}...")
        codedeploy_client = utils.get_boto3_client('codedeploy', region_name=region)

        try:
            # List all applications first
            app_paginator = codedeploy_client.get_paginator('list_applications')
            for app_page in app_paginator.paginate():
                app_names = app_page.get('applications', [])

                for app_name in app_names:
                    # List deployment groups for this application
                    try:
                        dg_paginator = codedeploy_client.get_paginator('list_deployment_groups')
                        for dg_page in dg_paginator.paginate(applicationName=app_name):
                            dg_names = dg_page.get('deploymentGroups', [])

                            # Batch get deployment group details
                            if dg_names:
                                dgs_response = codedeploy_client.batch_get_deployment_groups(
                                    applicationName=app_name,
                                    deploymentGroupNames=dg_names
                                )
                                deployment_groups = dgs_response.get('deploymentGroupsInfo', [])

                                for dg in deployment_groups:
                                    dg_name = dg.get('deploymentGroupName', 'N/A')
                                    dg_id = dg.get('deploymentGroupId', 'N/A')
                                    service_role_arn = dg.get('serviceRoleArn', 'N/A')

                                    # Deployment config
                                    deployment_config_name = dg.get('deploymentConfigName', 'N/A')

                                    # Target info
                                    compute_platform = dg.get('computePlatform', 'N/A')

                                    # EC2 tag filters
                                    ec2_tag_filters = dg.get('ec2TagFilters', [])
                                    ec2_tag_set = dg.get('ec2TagSet', {})
                                    ec2_tags_count = len(ec2_tag_filters)

                                    # Auto Scaling groups
                                    auto_scaling_groups = dg.get('autoScalingGroups', [])
                                    asg_count = len(auto_scaling_groups)

                                    # ECS config
                                    ecs_services = dg.get('ecsServices', [])
                                    ecs_count = len(ecs_services)

                                    # Lambda config
                                    target_revision = dg.get('targetRevision', {})
                                    revision_type = target_revision.get('revisionType', 'N/A')

                                    # Blue/Green deployment config
                                    blue_green_config = dg.get('blueGreenDeploymentConfiguration', {})
                                    terminate_blue_instances = blue_green_config.get('terminateBlueInstancesOnDeploymentSuccess', {})
                                    terminate_action = terminate_blue_instances.get('action', 'N/A')

                                    # Load balancer info
                                    load_balancer_info = dg.get('loadBalancerInfo', {})
                                    elb_info_list = load_balancer_info.get('elbInfoList', [])
                                    target_group_info_list = load_balancer_info.get('targetGroupInfoList', [])
                                    lb_count = len(elb_info_list) + len(target_group_info_list)

                                    # Alarm configuration
                                    alarm_config = dg.get('alarmConfiguration', {})
                                    alarms = alarm_config.get('alarms', [])
                                    alarm_count = len(alarms)

                                    # Auto rollback
                                    auto_rollback_config = dg.get('autoRollbackConfiguration', {})
                                    auto_rollback_enabled = auto_rollback_config.get('enabled', False)

                                    # Outdated instances strategy
                                    outdated_instances_strategy = dg.get('outdatedInstancesStrategy', 'N/A')

                                    all_deployment_groups.append({
                                        'Region': region,
                                        'Application Name': app_name,
                                        'Deployment Group Name': dg_name,
                                        'Deployment Group ID': dg_id,
                                        'Compute Platform': compute_platform,
                                        'Deployment Config': deployment_config_name,
                                        'Service Role ARN': service_role_arn,
                                        'EC2 Tag Filters': ec2_tags_count,
                                        'Auto Scaling Groups': asg_count,
                                        'ECS Services': ecs_count,
                                        'Load Balancers': lb_count,
                                        'CloudWatch Alarms': alarm_count,
                                        'Auto Rollback Enabled': auto_rollback_enabled,
                                        'Blue/Green Terminate Action': terminate_action,
                                        'Outdated Instances Strategy': outdated_instances_strategy,
                                        'Revision Type': revision_type
                                    })

                    except Exception as e:
                        utils.log_warning(f"Could not get deployment groups for application {app_name}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error collecting deployment groups in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_deployment_groups)} deployment groups")
    return all_deployment_groups


@utils.aws_error_handler("Collecting deployments", default_return=[])
def collect_deployments(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect recent deployment information (limited to 30 most recent per region)."""
    all_deployments = []

    for region in regions:
        utils.log_info(f"Collecting recent deployments in {region}...")
        codedeploy_client = utils.get_boto3_client('codedeploy', region_name=region)

        try:
            # List deployments (sorted by create time descending)
            deployment_ids = []
            paginator = codedeploy_client.get_paginator('list_deployments')
            for page in paginator.paginate(
                includeOnlyStatuses=['Created', 'Queued', 'InProgress', 'Succeeded', 'Failed', 'Stopped', 'Ready']
            ):
                deployment_ids.extend(page.get('deployments', []))
                if len(deployment_ids) >= 30:
                    break

            # Limit to 30 most recent
            deployment_ids = deployment_ids[:30]

            if not deployment_ids:
                continue

            utils.log_info(f"Found {len(deployment_ids)} recent deployments in {region}")

            # Batch get deployment details (25 at a time)
            for i in range(0, len(deployment_ids), 25):
                batch = deployment_ids[i:i+25]
                deployments_response = codedeploy_client.batch_get_deployments(deploymentIds=batch)
                deployments = deployments_response.get('deploymentsInfo', [])

                for deployment in deployments:
                    deployment_id = deployment.get('deploymentId', 'N/A')
                    app_name = deployment.get('applicationName', 'N/A')
                    dg_name = deployment.get('deploymentGroupName', 'N/A')
                    status = deployment.get('status', 'N/A')
                    creator = deployment.get('creator', 'N/A')

                    # Times
                    create_time = deployment.get('createTime', 'N/A')
                    if create_time != 'N/A':
                        create_time = create_time.strftime('%Y-%m-%d %H:%M:%S')

                    start_time = deployment.get('startTime', 'N/A')
                    if start_time != 'N/A':
                        start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')

                    complete_time = deployment.get('completeTime', 'N/A')
                    if complete_time != 'N/A':
                        complete_time = complete_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Duration
                    if deployment.get('startTime') and deployment.get('completeTime'):
                        duration_seconds = (deployment.get('completeTime') - deployment.get('startTime')).total_seconds()
                        duration_minutes = duration_seconds / 60
                        duration_str = f"{duration_minutes:.1f} minutes"
                    else:
                        duration_str = 'N/A'

                    # Deployment config
                    deployment_config_name = deployment.get('deploymentConfigName', 'N/A')

                    # Revision
                    revision = deployment.get('revision', {})
                    revision_type = revision.get('revisionType', 'N/A')
                    revision_location = 'N/A'
                    if revision_type == 'S3':
                        s3_location = revision.get('s3Location', {})
                        bucket = s3_location.get('bucket', 'N/A')
                        key = s3_location.get('key', 'N/A')
                        revision_location = f"s3://{bucket}/{key}"
                    elif revision_type == 'GitHub':
                        github_location = revision.get('gitHubLocation', {})
                        repository = github_location.get('repository', 'N/A')
                        commit_id = github_location.get('commitId', 'N/A')
                        revision_location = f"{repository}@{commit_id[:8]}"

                    # Overview
                    overview = deployment.get('deploymentOverview', {})
                    succeeded = overview.get('Succeeded', 0)
                    failed = overview.get('Failed', 0)
                    skipped = overview.get('Skipped', 0)
                    in_progress = overview.get('InProgress', 0)
                    pending = overview.get('Pending', 0)

                    # Error info
                    error_info = deployment.get('errorInformation', {})
                    error_code = error_info.get('code', 'None')
                    error_message = error_info.get('message', 'None')

                    all_deployments.append({
                        'Region': region,
                        'Deployment ID': deployment_id,
                        'Application Name': app_name,
                        'Deployment Group': dg_name,
                        'Status': status,
                        'Created': create_time,
                        'Started': start_time,
                        'Completed': complete_time,
                        'Duration': duration_str,
                        'Deployment Config': deployment_config_name,
                        'Revision Type': revision_type,
                        'Revision Location': revision_location,
                        'Creator': creator,
                        'Succeeded': succeeded,
                        'Failed': failed,
                        'Skipped': skipped,
                        'In Progress': in_progress,
                        'Pending': pending,
                        'Error Code': error_code,
                        'Error Message': error_message
                    })

        except Exception as e:
            utils.log_warning(f"Error collecting deployments in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_deployments)} deployments (limited to 30 most recent per region)")
    return all_deployments


def generate_summary(applications: List[Dict[str, Any]],
                     deployment_groups: List[Dict[str, Any]],
                     deployments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for CodeDeploy resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Applications summary
    total_apps = len(applications)
    summary.append({
        'Metric': 'Total Applications',
        'Count': total_apps,
        'Details': 'CodeDeploy applications'
    })

    # Compute platforms
    if applications:
        df = pd.DataFrame(applications)
        platforms = df['Compute Platform'].value_counts().to_dict()
        for platform, count in platforms.items():
            summary.append({
                'Metric': f'Applications - {platform}',
                'Count': count,
                'Details': 'Compute platform type'
            })

    # Deployment groups
    total_dgs = len(deployment_groups)
    summary.append({
        'Metric': 'Total Deployment Groups',
        'Count': total_dgs,
        'Details': 'Deployment group configurations'
    })

    # Auto rollback enabled
    auto_rollback_count = sum(1 for dg in deployment_groups if dg.get('Auto Rollback Enabled', False))
    summary.append({
        'Metric': 'Deployment Groups with Auto Rollback',
        'Count': auto_rollback_count,
        'Details': 'Groups configured to automatically rollback on failure'
    })

    # Deployments summary
    total_deployments = len(deployments)
    succeeded_deployments = sum(1 for d in deployments if d.get('Status', '') == 'Succeeded')
    failed_deployments = sum(1 for d in deployments if d.get('Status', '') == 'Failed')
    in_progress_deployments = sum(1 for d in deployments if d.get('Status', '') == 'InProgress')

    summary.append({
        'Metric': 'Recent Deployments (Sample)',
        'Count': total_deployments,
        'Details': f'Succeeded: {succeeded_deployments}, Failed: {failed_deployments}, In Progress: {in_progress_deployments}'
    })

    # Regional distribution
    if applications:
        df = pd.DataFrame(applications)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Applications in {region}',
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
    print("AWS CodeDeploy Export Tool")
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
    print("\nCollecting AWS CodeDeploy data...")

    applications = collect_applications(regions)
    deployment_groups = collect_deployment_groups(regions)
    deployments = collect_deployments(regions)
    summary = generate_summary(applications, deployment_groups, deployments)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if applications:
        df_applications = pd.DataFrame(applications)
        df_applications = utils.prepare_dataframe_for_export(df_applications)
        dataframes['Applications'] = df_applications

    if deployment_groups:
        df_deployment_groups = pd.DataFrame(deployment_groups)
        df_deployment_groups = utils.prepare_dataframe_for_export(df_deployment_groups)
        dataframes['Deployment Groups'] = df_deployment_groups

    if deployments:
        df_deployments = pd.DataFrame(deployments)
        df_deployments = utils.prepare_dataframe_for_export(df_deployments)
        dataframes['Recent Deployments'] = df_deployments

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'codedeploy', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Applications': len(applications),
            'Deployment Groups': len(deployment_groups),
            'Recent Deployments': len(deployments)
        })
    else:
        utils.log_warning("No AWS CodeDeploy data found to export")

    utils.log_success("AWS CodeDeploy export completed successfully")


if __name__ == "__main__":
    main()
