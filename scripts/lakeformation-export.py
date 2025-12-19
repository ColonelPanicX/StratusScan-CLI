#!/usr/bin/env python3
"""
AWS Lake Formation Export Script for StratusScan

Exports comprehensive AWS Lake Formation data lake governance and security information
including registered resources, permissions, data lake settings, and tag-based access control.

Features:
- Registered Resources: S3 locations registered with Lake Formation
- Data Lake Permissions: Resource-level permissions and grants
- Data Lake Settings: Administrative settings and catalog configurations
- LF-Tags: Tag-based access control (TBAC) resources and assignments
- Summary: Resource counts and governance metrics

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




def _scan_lakeformation_resources_region(region: str) -> List[Dict[str, Any]]:
    """Scan Lake Formation resources in a single region."""
    regional_resources = []
    try:
        lf_client = utils.get_boto3_client('lakeformation', region_name=region)
        paginator = lf_client.get_paginator('list_resources')
        for page in paginator.paginate():
            resources = page.get('ResourceInfoList', [])

            for resource in resources:
                resource_arn = resource.get('ResourceArn', 'N/A')
                role_arn = resource.get('RoleArn', 'N/A')

                # Extract S3 path from ARN
                if resource_arn.startswith('arn:aws:s3:::'):
                    s3_path = resource_arn.replace('arn:aws:s3:::', 's3://')
                else:
                    s3_path = resource_arn

                # Extract role name from ARN
                role_name = 'N/A'
                if role_arn != 'N/A' and '/' in role_arn:
                    role_name = role_arn.split('/')[-1]

                # Last modified timestamp
                last_modified = resource.get('LastModified')
                if last_modified:
                    last_modified_str = last_modified.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_modified_str = 'N/A'

                regional_resources.append({
                    'Region': region,
                    'S3 Path': s3_path,
                    'Resource ARN': resource_arn,
                    'Role Name': role_name,
                    'Role ARN': role_arn,
                    'Last Modified': last_modified_str,
                })
    except Exception as e:
        utils.log_error(f"Error collecting Lake Formation resources in {region}", e)
    return regional_resources


def _scan_lakeformation_permissions_region(region: str) -> List[Dict[str, Any]]:
    """Scan Lake Formation permissions in a single region."""
    regional_permissions = []
    try:
        lf_client = utils.get_boto3_client('lakeformation', region_name=region)
        paginator = lf_client.get_paginator('list_permissions')
        for page in paginator.paginate():
            permissions = page.get('PrincipalResourcePermissions', [])

            for perm in permissions:
                # Principal (who has access)
                principal = perm.get('Principal', {})
                data_lake_principal_id = principal.get('DataLakePrincipalIdentifier', 'N/A')

                # Extract principal name
                principal_name = 'N/A'
                if data_lake_principal_id != 'N/A':
                    if '/' in data_lake_principal_id:
                        principal_name = data_lake_principal_id.split('/')[-1]
                    elif ':' in data_lake_principal_id:
                        parts = data_lake_principal_id.split(':')
                        principal_name = parts[-1] if len(parts) > 0 else 'N/A'
                    else:
                        principal_name = data_lake_principal_id

                # Resource (what they have access to)
                resource = perm.get('Resource', {})

                # Determine resource type and details
                resource_type = 'Unknown'
                resource_details = 'N/A'

                if 'Catalog' in resource:
                    resource_type = 'Catalog'
                    resource_details = 'Data Catalog'
                elif 'Database' in resource:
                    resource_type = 'Database'
                    db_name = resource.get('Database', {}).get('Name', 'N/A')
                    resource_details = db_name
                elif 'Table' in resource:
                    resource_type = 'Table'
                    table_info = resource.get('Table', {})
                    db_name = table_info.get('DatabaseName', 'N/A')
                    table_name = table_info.get('Name', 'N/A')
                    resource_details = f"{db_name}.{table_name}"
                elif 'TableWithColumns' in resource:
                    resource_type = 'Table with Columns'
                    table_info = resource.get('TableWithColumns', {})
                    db_name = table_info.get('DatabaseName', 'N/A')
                    table_name = table_info.get('Name', 'N/A')
                    columns = table_info.get('ColumnNames', [])
                    columns_str = ', '.join(columns[:3]) if columns else 'All'
                    if len(columns) > 3:
                        columns_str += f' (+{len(columns) - 3} more)'
                    resource_details = f"{db_name}.{table_name} ({columns_str})"
                elif 'DataLocation' in resource:
                    resource_type = 'Data Location'
                    resource_arn = resource.get('DataLocation', {}).get('ResourceArn', 'N/A')
                    if resource_arn.startswith('arn:aws:s3:::'):
                        resource_details = resource_arn.replace('arn:aws:s3:::', 's3://')
                    else:
                        resource_details = resource_arn
                elif 'LFTag' in resource:
                    resource_type = 'LF-Tag'
                    tag_key = resource.get('LFTag', {}).get('TagKey', 'N/A')
                    tag_values = resource.get('LFTag', {}).get('TagValues', [])
                    tag_values_str = ', '.join(tag_values[:3]) if tag_values else 'N/A'
                    if len(tag_values) > 3:
                        tag_values_str += f' (+{len(tag_values) - 3} more)'
                    resource_details = f"{tag_key}={tag_values_str}"

                # Permissions granted
                permissions_list = perm.get('Permissions', [])
                permissions_str = ', '.join(permissions_list) if permissions_list else 'None'

                # Grantable permissions
                permissions_with_grant = perm.get('PermissionsWithGrantOption', [])
                grant_permissions_str = ', '.join(permissions_with_grant) if permissions_with_grant else 'None'

                regional_permissions.append({
                    'Region': region,
                    'Principal': principal_name,
                    'Principal ARN': data_lake_principal_id,
                    'Resource Type': resource_type,
                    'Resource': resource_details,
                    'Permissions': permissions_str,
                    'Grant Permissions': grant_permissions_str,
                })
    except Exception as e:
        utils.log_error(f"Error collecting Lake Formation permissions in {region}", e)
    return regional_permissions


def _scan_lakeformation_settings_region(region: str) -> List[Dict[str, Any]]:
    """Scan Lake Formation settings in a single region."""
    regional_settings = []
    try:
        lf_client = utils.get_boto3_client('lakeformation', region_name=region)
        
        # Get data lake settings
        settings_response = lf_client.get_data_lake_settings()
        settings = settings_response.get('DataLakeSettings', {})

        # Data lake admins
        admins = settings.get('DataLakeAdmins', [])
        admin_arns = [admin.get('DataLakePrincipalIdentifier', '') for admin in admins]
        admin_names = []
        for arn in admin_arns:
            if '/' in arn:
                admin_names.append(arn.split('/')[-1])
            elif ':' in arn:
                parts = arn.split(':')
                admin_names.append(parts[-1] if len(parts) > 0 else arn)
            else:
                admin_names.append(arn)
        admins_str = ', '.join(admin_names) if admin_names else 'None'

        # Create database default permissions
        create_db_default_perms = settings.get('CreateDatabaseDefaultPermissions', [])
        create_db_perms_str = 'N/A'
        if create_db_default_perms:
            perms_list = []
            for perm_entry in create_db_default_perms:
                principal = perm_entry.get('Principal', {}).get('DataLakePrincipalIdentifier', '')
                permissions = perm_entry.get('Permissions', [])
                perms_list.append(f"{principal}: {', '.join(permissions)}")
            create_db_perms_str = ' | '.join(perms_list) if perms_list else 'Default'

        # Create table default permissions
        create_table_default_perms = settings.get('CreateTableDefaultPermissions', [])
        create_table_perms_str = 'N/A'
        if create_table_default_perms:
            perms_list = []
            for perm_entry in create_table_default_perms:
                principal = perm_entry.get('Principal', {}).get('DataLakePrincipalIdentifier', '')
                permissions = perm_entry.get('Permissions', [])
                perms_list.append(f"{principal}: {', '.join(permissions)}")
            create_table_perms_str = ' | '.join(perms_list) if perms_list else 'Default'

        # Trusted resource owners
        trusted_owners = settings.get('TrustedResourceOwners', [])
        trusted_owners_str = ', '.join(trusted_owners) if trusted_owners else 'None'

        regional_settings.append({
            'Region': region,
            'Data Lake Admins': admins_str,
            'Trusted Resource Owners': trusted_owners_str,
            'Create Database Default Permissions': create_db_perms_str,
            'Create Table Default Permissions': create_table_perms_str,
        })
    except Exception as e:
        utils.log_error(f"Error collecting Lake Formation settings in {region}", e)
    return regional_settings


def _scan_lakeformation_tags_region(region: str) -> List[Dict[str, Any]]:
    """Scan Lake Formation LF-Tags in a single region."""
    regional_tags = []
    try:
        lf_client = utils.get_boto3_client('lakeformation', region_name=region)
        paginator = lf_client.get_paginator('list_lf_tags')
        for page in paginator.paginate():
            lf_tags = page.get('LFTags', [])

            for tag in lf_tags:
                tag_key = tag.get('TagKey', 'N/A')
                tag_values = tag.get('TagValues', [])
                tag_values_str = ', '.join(tag_values) if tag_values else 'None'

                # Catalog ID
                catalog_id = tag.get('CatalogId', 'N/A')

                regional_tags.append({
                    'Region': region,
                    'Tag Key': tag_key,
                    'Tag Values': tag_values_str,
                    'Value Count': len(tag_values),
                    'Catalog ID': catalog_id,
                })
    except Exception as e:
        utils.log_error(f"Error collecting Lake Formation LF-Tags in {region}", e)
    return regional_tags


@utils.aws_error_handler("Collecting Lake Formation resources", default_return=[])
def collect_lakeformation_resources(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Lake Formation registered resource information from AWS regions."""
    print("\n=== COLLECTING LAKE FORMATION RESOURCES ===")
    results = utils.scan_regions_concurrent(regions, _scan_lakeformation_resources_region)
    all_resources = [res for result in results for res in result]
    utils.log_success(f"Total Lake Formation resources collected: {len(all_resources)}")
    return all_resources


@utils.aws_error_handler("Collecting Lake Formation permissions", default_return=[])
def collect_lakeformation_permissions(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Lake Formation permissions information from AWS regions."""
    print("\n=== COLLECTING LAKE FORMATION PERMISSIONS ===")
    results = utils.scan_regions_concurrent(regions, _scan_lakeformation_permissions_region)
    all_permissions = [perm for result in results for perm in result]
    utils.log_success(f"Total Lake Formation permissions collected: {len(all_permissions)}")
    return all_permissions


@utils.aws_error_handler("Collecting Lake Formation settings", default_return=[])
def collect_lakeformation_settings(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Lake Formation data lake settings from AWS regions."""
    print("\n=== COLLECTING LAKE FORMATION SETTINGS ===")
    results = utils.scan_regions_concurrent(regions, _scan_lakeformation_settings_region)
    all_settings = [setting for result in results for setting in result]
    utils.log_success(f"Total Lake Formation settings collected: {len(all_settings)}")
    return all_settings


@utils.aws_error_handler("Collecting Lake Formation tags", default_return=[])
def collect_lakeformation_tags(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Lake Formation LF-Tag information from AWS regions."""
    print("\n=== COLLECTING LAKE FORMATION LF-TAGS ===")
    results = utils.scan_regions_concurrent(regions, _scan_lakeformation_tags_region)
    all_tags = [tag for result in results for tag in result]
    utils.log_success(f"Total Lake Formation LF-Tags collected: {len(all_tags)}")
    return all_tags


def generate_summary(resources: List[Dict[str, Any]],
                     permissions: List[Dict[str, Any]],
                     settings: List[Dict[str, Any]],
                     tags: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Lake Formation resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total Registered Resources',
        'Count': len(resources),
        'Details': f"{len(resources)} S3 locations registered"
    })

    summary.append({
        'Metric': 'Total Permission Grants',
        'Count': len(permissions),
        'Details': f"{len(permissions)} permission entries"
    })

    summary.append({
        'Metric': 'Total LF-Tags',
        'Count': len(tags),
        'Details': f"{len(tags)} tag-based access control tags"
    })

    summary.append({
        'Metric': 'Regions Configured',
        'Count': len(settings),
        'Details': f"{len(settings)} regions with Lake Formation settings"
    })

    # Permissions by resource type
    if permissions:
        resource_types = {}
        for perm in permissions:
            res_type = perm['Resource Type']
            resource_types[res_type] = resource_types.get(res_type, 0) + 1

        type_details = ', '.join([f"{rtype}: {count}" for rtype, count in sorted(resource_types.items())])
        summary.append({
            'Metric': 'Permissions by Resource Type',
            'Count': len(resource_types),
            'Details': type_details
        })

    # Most common permissions
    if permissions:
        all_perms = []
        for perm in permissions:
            perms_str = perm['Permissions']
            if perms_str and perms_str != 'None':
                all_perms.extend([p.strip() for p in perms_str.split(',')])

        perm_counts = {}
        for p in all_perms:
            perm_counts[p] = perm_counts.get(p, 0) + 1

        top_perms = sorted(perm_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        perm_details = ', '.join([f"{perm}: {count}" for perm, count in top_perms])
        summary.append({
            'Metric': 'Top 5 Permissions',
            'Count': len(perm_counts),
            'Details': perm_details
        })

    # Tag-based access control usage
    if tags:
        total_tag_values = sum(t['Value Count'] for t in tags if isinstance(t['Value Count'], int))
        summary.append({
            'Metric': 'Total Tag Values',
            'Count': total_tag_values,
            'Details': f"{total_tag_values} values across {len(tags)} tags"
        })

    # Resources by region
    if resources:
        regions = {}
        for resource in resources:
            region = resource['Region']
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'Resources by Region',
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
    if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
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
    all_available_regions = utils.get_all_aws_regions('lakeformation')
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
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
    print("\n=== Collecting Lake Formation Data ===")
    resources = collect_lakeformation_resources(regions)
    permissions = collect_lakeformation_permissions(regions)
    settings = collect_lakeformation_settings(regions)
    tags = collect_lakeformation_tags(regions)

    # Generate summary
    summary = generate_summary(resources, permissions, settings, tags)

    # Convert to DataFrames
    resources_df = pd.DataFrame(resources) if resources else pd.DataFrame()
    permissions_df = pd.DataFrame(permissions) if permissions else pd.DataFrame()
    settings_df = pd.DataFrame(settings) if settings else pd.DataFrame()
    tags_df = pd.DataFrame(tags) if tags else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not resources_df.empty:
        resources_df = utils.prepare_dataframe_for_export(resources_df)
    if not permissions_df.empty:
        permissions_df = utils.prepare_dataframe_for_export(permissions_df)
    if not settings_df.empty:
        settings_df = utils.prepare_dataframe_for_export(settings_df)
    if not tags_df.empty:
        tags_df = utils.prepare_dataframe_for_export(tags_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'lakeformation', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'Registered Resources': resources_df,
        'Permissions': permissions_df,
        'Data Lake Settings': settings_df,
        'LF-Tags': tags_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(resources) + len(permissions) + len(settings) + len(tags),
            details={
                'Registered Resources': len(resources),
                'Permissions': len(permissions),
                'Settings': len(settings),
                'LF-Tags': len(tags)
            }
        )

    utils.log_script_end(script_name)


if __name__ == "__main__":
    main()
