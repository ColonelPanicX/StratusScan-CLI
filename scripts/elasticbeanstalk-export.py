#!/usr/bin/env python3
"""
AWS Elastic Beanstalk Export Script for StratusScan
Version: v0.1.0
Date: NOV-16-2025

Exports comprehensive AWS Elastic Beanstalk PaaS information including applications,
environments, application versions, and configuration settings.

Features:
- Applications: Beanstalk application containers
- Environments: Application environments with platform info and health
- Application Versions: Deployable application versions and source bundles
- Configuration Templates: Saved environment configurations
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
- Summary: Application and environment counts with status distribution

Output: Excel file with 5 worksheets
"""

import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

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
    utils.log_error("pandas library is required but not installed")
    utils.log_error("Install with: pip install pandas")
    sys.exit(1)


@utils.aws_error_handler("Collecting Elastic Beanstalk applications from region", default_return=[])
def collect_applications_from_region(region: str) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk application information from a single AWS region."""
    applications = []
    eb_client = utils.get_boto3_client('elasticbeanstalk', region_name=region)

    response = eb_client.describe_applications()
    apps = response.get('Applications', [])

    for app in apps:
        app_name = app.get('ApplicationName', 'N/A')
        description = app.get('Description', 'N/A')

        # Resource lifecycle config
        resource_lifecycle_config = app.get('ResourceLifecycleConfig', {})
        service_role = resource_lifecycle_config.get('ServiceRole', 'N/A')
        version_lifecycle_config = resource_lifecycle_config.get('VersionLifecycleConfig', {})
        max_count = version_lifecycle_config.get('MaxCountRule', {}).get('MaxCount', 'N/A')
        max_age_days = version_lifecycle_config.get('MaxAgeRule', {}).get('MaxAgeInDays', 'N/A')

        # Extract role name
        role_name = 'N/A'
        if service_role != 'N/A' and '/' in service_role:
            role_name = service_role.split('/')[-1]

        # Date created
        date_created = app.get('DateCreated')
        if date_created:
            date_created_str = date_created.strftime('%Y-%m-%d %H:%M:%S')
        else:
            date_created_str = 'N/A'

        # Date updated
        date_updated = app.get('DateUpdated')
        if date_updated:
            date_updated_str = date_updated.strftime('%Y-%m-%d %H:%M:%S')
        else:
            date_updated_str = 'N/A'

        # Versions count
        versions = app.get('Versions', [])
        version_count = len(versions)

        # Configuration templates
        config_templates = app.get('ConfigurationTemplates', [])
        config_template_count = len(config_templates)

        applications.append({
            'Region': region,
            'Application Name': app_name,
            'Description': description,
            'Version Count': version_count,
            'Config Template Count': config_template_count,
            'Service Role': role_name,
            'Max Versions': max_count,
            'Max Age (Days)': max_age_days,
            'Created': date_created_str,
            'Updated': date_updated_str,
        })

    return applications


def collect_applications(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk application information using concurrent scanning."""
    print("\n=== COLLECTING ELASTIC BEANSTALK APPLICATIONS ===")
    utils.log_info(f"Scanning {len(regions)} regions...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_applications_from_region,
        show_progress=True
    )

    all_applications = []
    for apps_in_region in region_results:
        all_applications.extend(apps_in_region)

    utils.log_success(f"Total applications collected: {len(all_applications)}")
    return all_applications


@utils.aws_error_handler("Collecting Elastic Beanstalk environments from region", default_return=[])
def collect_environments_from_region(region: str) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk environment information from a single AWS region."""
    environments = []
    eb_client = utils.get_boto3_client('elasticbeanstalk', region_name=region)

    response = eb_client.describe_environments()
    envs = response.get('Environments', [])

    for env in envs:
        env_name = env.get('EnvironmentName', 'N/A')
        env_id = env.get('EnvironmentId', 'N/A')
        app_name = env.get('ApplicationName', 'N/A')

        # Status and health
        status = env.get('Status', 'N/A')
        health = env.get('Health', 'N/A')
        health_status = env.get('HealthStatus', 'N/A')

        # Platform
        platform_arn = env.get('PlatformArn', 'N/A')
        solution_stack_name = env.get('SolutionStackName', 'N/A')

        # Extract platform name
        platform_name = solution_stack_name if solution_stack_name != 'N/A' else 'N/A'
        if platform_arn != 'N/A' and '/' in platform_arn:
            platform_name = platform_arn.split('/')[-1]

        # Tier (WebServer or Worker)
        tier = env.get('Tier', {})
        tier_name = tier.get('Name', 'N/A')
        tier_type = tier.get('Type', 'N/A')

        # Endpoint URL
        endpoint_url = env.get('EndpointURL', 'N/A')
        cname = env.get('CNAME', 'N/A')

        # Version label
        version_label = env.get('VersionLabel', 'N/A')

        # Template name
        template_name = env.get('TemplateName', 'N/A')

        # Description
        description = env.get('Description', 'N/A')

        # Date created and updated
        date_created = env.get('DateCreated')
        if date_created:
            date_created_str = date_created.strftime('%Y-%m-%d %H:%M:%S')
        else:
            date_created_str = 'N/A'

        date_updated = env.get('DateUpdated')
        if date_updated:
            date_updated_str = date_updated.strftime('%Y-%m-%d %H:%M:%S')
        else:
            date_updated_str = 'N/A'

        # Resources (load balancer info)
        resources = env.get('Resources', {})
        load_balancer = resources.get('LoadBalancer', {})
        lb_name = load_balancer.get('LoadBalancerName', 'N/A') if load_balancer else 'N/A'

        # Environment links (for composite environments)
        env_links = env.get('EnvironmentLinks', [])
        linked_env_names = [link.get('LinkName', '') for link in env_links]
        linked_envs_str = ', '.join(linked_env_names) if linked_env_names else 'None'

        # Abortable operation in progress
        abortable_operation_in_progress = env.get('AbortableOperationInProgress', False)

        environments.append({
            'Region': region,
            'Environment Name': env_name,
            'Environment ID': env_id,
            'Application': app_name,
            'Status': status,
            'Health': health,
            'Health Status': health_status,
            'Platform': platform_name,
            'Tier Name': tier_name,
            'Tier Type': tier_type,
            'Endpoint URL': endpoint_url,
            'CNAME': cname,
            'Version Label': version_label,
            'Template Name': template_name,
            'Load Balancer': lb_name,
            'Linked Environments': linked_envs_str,
            'Operation In Progress': 'Yes' if abortable_operation_in_progress else 'No',
            'Description': description,
            'Created': date_created_str,
            'Updated': date_updated_str,
        })

    return environments


def collect_environments(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk environment information using concurrent scanning."""
    print("\n=== COLLECTING ELASTIC BEANSTALK ENVIRONMENTS ===")
    utils.log_info(f"Scanning {len(regions)} regions...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_environments_from_region,
        show_progress=True
    )

    all_environments = []
    for envs_in_region in region_results:
        all_environments.extend(envs_in_region)

    utils.log_success(f"Total environments collected: {len(all_environments)}")
    return all_environments


@utils.aws_error_handler("Collecting Elastic Beanstalk application versions from region", default_return=[])
def collect_application_versions_from_region(region: str) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk application version information from a single AWS region."""
    versions = []
    eb_client = utils.get_boto3_client('elasticbeanstalk', region_name=region)

    # First get all applications
    apps_response = eb_client.describe_applications()
    applications = apps_response.get('Applications', [])

    for app in applications:
        app_name = app.get('ApplicationName', '')

        # Get versions for this application
        try:
            versions_response = eb_client.describe_application_versions(ApplicationName=app_name)
            app_versions = versions_response.get('ApplicationVersions', [])

            for version in app_versions:
                version_label = version.get('VersionLabel', 'N/A')
                description = version.get('Description', 'N/A')
                status = version.get('Status', 'N/A')

                # Source bundle
                source_bundle = version.get('SourceBundle', {})
                s3_bucket = source_bundle.get('S3Bucket', 'N/A')
                s3_key = source_bundle.get('S3Key', 'N/A')
                source_location = f"s3://{s3_bucket}/{s3_key}" if s3_bucket != 'N/A' else 'N/A'

                # Build ARN (for CodeBuild)
                build_arn = version.get('BuildArn', 'N/A')

                # Date created
                date_created = version.get('DateCreated')
                if date_created:
                    date_created_str = date_created.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    date_created_str = 'N/A'

                # Date updated
                date_updated = version.get('DateUpdated')
                if date_updated:
                    date_updated_str = date_updated.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    date_updated_str = 'N/A'

                versions.append({
                    'Region': region,
                    'Application': app_name,
                    'Version Label': version_label,
                    'Status': status,
                    'Source Location': source_location,
                    'Build ARN': build_arn,
                    'Description': description,
                    'Created': date_created_str,
                    'Updated': date_updated_str,
                })

        except Exception as e:
            utils.log_warning(f"Could not get versions for application {app_name}: {str(e)}")
            continue

    return versions


def collect_application_versions(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk application version information using concurrent scanning."""
    print("\n=== COLLECTING ELASTIC BEANSTALK APPLICATION VERSIONS ===")
    utils.log_info(f"Scanning {len(regions)} regions...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_application_versions_from_region,
        show_progress=True
    )

    all_versions = []
    for versions_in_region in region_results:
        all_versions.extend(versions_in_region)

    utils.log_success(f"Total application versions collected: {len(all_versions)}")
    return all_versions


@utils.aws_error_handler("Collecting Elastic Beanstalk configuration templates from region", default_return=[])
def collect_configuration_templates_from_region(region: str) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk configuration template information from a single AWS region."""
    templates = []
    eb_client = utils.get_boto3_client('elasticbeanstalk', region_name=region)

    # First get all applications
    apps_response = eb_client.describe_applications()
    applications = apps_response.get('Applications', [])

    for app in applications:
        app_name = app.get('ApplicationName', '')
        config_templates = app.get('ConfigurationTemplates', [])

        for template_name in config_templates:
            try:
                # Get template details
                template_response = eb_client.describe_configuration_settings(
                    ApplicationName=app_name,
                    TemplateName=template_name
                )
                config_settings = template_response.get('ConfigurationSettings', [])

                for config in config_settings:
                    solution_stack_name = config.get('SolutionStackName', 'N/A')
                    platform_arn = config.get('PlatformArn', 'N/A')
                    description = config.get('Description', 'N/A')
                    deployment_status = config.get('DeploymentStatus', 'N/A')

                    # Date created and updated
                    date_created = config.get('DateCreated')
                    if date_created:
                        date_created_str = date_created.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        date_created_str = 'N/A'

                    date_updated = config.get('DateUpdated')
                    if date_updated:
                        date_updated_str = date_updated.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        date_updated_str = 'N/A'

                    # Extract platform name
                    platform_name = solution_stack_name if solution_stack_name != 'N/A' else 'N/A'
                    if platform_arn != 'N/A' and '/' in platform_arn:
                        platform_name = platform_arn.split('/')[-1]

                    templates.append({
                        'Region': region,
                        'Application': app_name,
                        'Template Name': template_name,
                        'Platform': platform_name,
                        'Deployment Status': deployment_status,
                        'Description': description,
                        'Created': date_created_str,
                        'Updated': date_updated_str,
                    })

            except Exception as e:
                utils.log_warning(f"Could not get template {template_name} for application {app_name}: {str(e)}")
                continue

    return templates


def collect_configuration_templates(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Elastic Beanstalk configuration template information using concurrent scanning."""
    print("\n=== COLLECTING ELASTIC BEANSTALK CONFIGURATION TEMPLATES ===")
    utils.log_info(f"Scanning {len(regions)} regions...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_configuration_templates_from_region,
        show_progress=True
    )

    all_templates = []
    for templates_in_region in region_results:
        all_templates.extend(templates_in_region)

    utils.log_success(f"Total configuration templates collected: {len(all_templates)}")
    return all_templates


def generate_summary(applications: List[Dict[str, Any]],
                     environments: List[Dict[str, Any]],
                     versions: List[Dict[str, Any]],
                     templates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Elastic Beanstalk resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total Applications',
        'Count': len(applications),
        'Details': f"{len(applications)} Elastic Beanstalk applications"
    })

    summary.append({
        'Metric': 'Total Environments',
        'Count': len(environments),
        'Details': f"{len([e for e in environments if e['Status'] == 'Ready'])} ready"
    })

    summary.append({
        'Metric': 'Total Application Versions',
        'Count': len(versions),
        'Details': f"{len(versions)} deployable versions"
    })

    summary.append({
        'Metric': 'Total Configuration Templates',
        'Count': len(templates),
        'Details': f"{len(templates)} saved configurations"
    })

    # Environment health distribution
    if environments:
        health_statuses = {}
        for env in environments:
            health = env['Health Status']
            health_statuses[health] = health_statuses.get(health, 0) + 1

        health_details = ', '.join([f"{health}: {count}" for health, count in sorted(health_statuses.items())])
        summary.append({
            'Metric': 'Environment Health Distribution',
            'Count': len(health_statuses),
            'Details': health_details
        })

    # Environment tiers
    if environments:
        tiers = {}
        for env in environments:
            tier = env['Tier Name']
            tiers[tier] = tiers.get(tier, 0) + 1

        tier_details = ', '.join([f"{tier}: {count}" for tier, count in sorted(tiers.items())])
        summary.append({
            'Metric': 'Environment Tier Distribution',
            'Count': len(tiers),
            'Details': tier_details
        })

    # Platforms used
    if environments:
        platforms = {}
        for env in environments:
            platform = env['Platform']
            # Simplify platform name
            if 'running' in platform.lower():
                platform_short = platform.split('running')[1].strip().split()[0] if len(platform.split('running')) > 1 else platform
            else:
                platform_short = platform.split()[0] if platform != 'N/A' else 'N/A'
            platforms[platform_short] = platforms.get(platform_short, 0) + 1

        top_platforms = sorted(platforms.items(), key=lambda x: x[1], reverse=True)[:5]
        platform_details = ', '.join([f"{plat}: {count}" for plat, count in top_platforms])
        summary.append({
            'Metric': 'Top 5 Platforms',
            'Count': len(platforms),
            'Details': platform_details
        })

    # Environments by region
    if environments:
        regions = {}
        for env in environments:
            region = env['Region']
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'Environments by Region',
            'Count': len(regions),
            'Details': region_details
        })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    # Check dependencies
    if not utils.check_dependencies(['pandas', 'openpyxl', 'boto3']):
        utils.log_error("Required dependencies not installed")
        return

    # Get account information
    account_id, account_name = utils.get_account_info()
    utils.log_info(f"Account: {account_name} ({account_id})")

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
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = utils.get_all_aws_regions('elasticbeanstalk')
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        utils.log_info(f"Scanning {len(regions)} default AWS regions")
    elif selection_int == 2:
        regions = all_available_regions
        utils.log_info(f"Scanning all {len(regions)} AWS regions")
    else:  # selection_int == 3
        # Display numbered list of regions
        print("\n" + "=" * 68)
        print("AVAILABLE AWS REGIONS")
        print("=" * 68)
        print()
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx:2}. {region}")
        print()

        # Get region selection with validation
        while True:
            try:
                region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_num) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    # Collect data
    print("\n=== Collecting Elastic Beanstalk Data ===")
    applications = collect_applications(regions)
    environments = collect_environments(regions)
    versions = collect_application_versions(regions)
    templates = collect_configuration_templates(regions)

    # Generate summary
    summary = generate_summary(applications, environments, versions, templates)

    # Convert to DataFrames
    applications_df = pd.DataFrame(applications) if applications else pd.DataFrame()
    environments_df = pd.DataFrame(environments) if environments else pd.DataFrame()
    versions_df = pd.DataFrame(versions) if versions else pd.DataFrame()
    templates_df = pd.DataFrame(templates) if templates else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not applications_df.empty:
        applications_df = utils.prepare_dataframe_for_export(applications_df)
    if not environments_df.empty:
        environments_df = utils.prepare_dataframe_for_export(environments_df)
    if not versions_df.empty:
        versions_df = utils.prepare_dataframe_for_export(versions_df)
    if not templates_df.empty:
        templates_df = utils.prepare_dataframe_for_export(templates_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'elasticbeanstalk', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'Applications': applications_df,
        'Environments': environments_df,
        'Application Versions': versions_df,
        'Config Templates': templates_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(applications) + len(environments) + len(versions) + len(templates),
            details={
                'Applications': len(applications),
                'Environments': len(environments),
                'Versions': len(versions),
                'Templates': len(templates)
            }
        )

    utils.log_script_end(script_name)


if __name__ == "__main__":
    main()
