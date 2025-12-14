#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS S3 Access Points Comprehensive Export
Version: v1.0.0
Date: NOV-13-2025

Description:
This script exports comprehensive information about S3 Access Points across AWS regions including:
- Standard Access Points (per-bucket access points with VPC configurations)
- Multi-Region Access Points (MRAP - global endpoints)
- Object Lambda Access Points (transform data on retrieval)

The data is exported to a multi-sheet Excel file with standardized naming convention
including AWS identifiers for compliance and audit purposes.
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils


def print_title() -> tuple:
    """
    Prints a formatted title banner for the script to the console and validates AWS environment

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                              ")
    print("====================================================================")
    print("AWS S3 ACCESS POINTS COMPREHENSIVE EXPORT SCRIPT")
    print("====================================================================")
    print("Version: v1.0.0                       Date: NOV-13-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information using utils
    account_id, account_name = utils.get_account_info()

    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name


@utils.aws_error_handler("Collecting standard access points", default_return=[])
def collect_standard_access_points(region: str, account_id: str) -> List[Dict[str, Any]]:
    """
    Collect standard S3 Access Points for a specific region

    Args:
        region: AWS region name
        account_id: AWS account ID

    Returns:
        List of dictionaries containing access point information
    """
    s3control = utils.get_boto3_client('s3control', region_name=region)

    access_points = []
    next_token = None

    utils.log_info(f"Collecting standard access points in {region}...")

    while True:
        # Build paginated request
        kwargs = {'AccountId': account_id}
        if next_token:
            kwargs['NextToken'] = next_token

        response = s3control.list_access_points(**kwargs)

        # Process each access point
        for ap in response.get('AccessPointList', []):
            ap_name = ap.get('Name', 'N/A')

            try:
                # Get detailed configuration for this access point
                details = s3control.get_access_point(
                    AccountId=account_id,
                    Name=ap_name
                )

                # Get block public access settings
                try:
                    public_access_block = s3control.get_public_access_block(
                        AccountId=account_id,
                        PublicAccessBlockConfiguration={}
                    )
                    block_settings = public_access_block.get('PublicAccessBlockConfiguration', {})
                except Exception:
                    # If GetPublicAccessBlock fails, use defaults
                    block_settings = {}

                # Get access point policy status
                try:
                    policy_status = s3control.get_access_point_policy_status(
                        AccountId=account_id,
                        Name=ap_name
                    )
                    has_policy = policy_status.get('PolicyStatus', {}).get('IsPublic', False)
                except Exception:
                    has_policy = False

                # Extract VPC configuration
                vpc_config = ap.get('VpcConfiguration', {})
                vpc_id = vpc_config.get('VpcId', 'N/A')

                access_point_info = {
                    'AccessPointName': ap_name,
                    'AccessPointARN': ap.get('AccessPointArn', 'N/A'),
                    'Alias': ap.get('Alias', 'N/A'),
                    'BucketName': ap.get('Bucket', 'N/A'),
                    'NetworkOrigin': ap.get('NetworkOrigin', 'N/A'),
                    'VpcId': vpc_id,
                    'Region': region,
                    'CreationDate': details.get('CreationDate', 'N/A'),
                    'HasCustomPolicy': 'Yes' if has_policy else 'No',
                    'BlockPublicAcls': block_settings.get('BlockPublicAcls', True),
                    'IgnorePublicAcls': block_settings.get('IgnorePublicAcls', True),
                    'BlockPublicPolicy': block_settings.get('BlockPublicPolicy', True),
                    'RestrictPublicBuckets': block_settings.get('RestrictPublicBuckets', True),
                    'BucketAccountId': ap.get('BucketAccountId', account_id)
                }

                access_points.append(access_point_info)

            except Exception as e:
                utils.log_warning(f"Could not get details for access point {ap_name}: {e}")
                # Add basic info even if details fail
                access_points.append({
                    'AccessPointName': ap_name,
                    'AccessPointARN': ap.get('AccessPointArn', 'N/A'),
                    'Alias': ap.get('Alias', 'N/A'),
                    'BucketName': ap.get('Bucket', 'N/A'),
                    'NetworkOrigin': ap.get('NetworkOrigin', 'N/A'),
                    'VpcId': vpc_config.get('VpcId', 'N/A'),
                    'Region': region,
                    'CreationDate': 'N/A',
                    'HasCustomPolicy': 'Unknown',
                    'BlockPublicAcls': 'Unknown',
                    'IgnorePublicAcls': 'Unknown',
                    'BlockPublicPolicy': 'Unknown',
                    'RestrictPublicBuckets': 'Unknown',
                    'BucketAccountId': ap.get('BucketAccountId', account_id)
                })

        # Check if there are more results
        next_token = response.get('NextToken')
        if not next_token:
            break

    utils.log_info(f"Found {len(access_points)} standard access points in {region}")
    return access_points


@utils.aws_error_handler("Collecting multi-region access points", default_return=[])
def collect_multi_region_access_points(account_id: str) -> List[Dict[str, Any]]:
    """
    Collect Multi-Region Access Points (always queried from us-west-2)

    Args:
        account_id: AWS account ID

    Returns:
        List of dictionaries containing MRAP information
    """
    # Multi-Region Access Points are always accessed via us-west-2
    # S3Control is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    s3control = utils.get_boto3_client('s3control', region_name=home_region)

    mraps = []
    next_token = None

    utils.log_info("Collecting Multi-Region Access Points (from us-west-2)...")

    while True:
        # Build paginated request
        kwargs = {'AccountId': account_id}
        if next_token:
            kwargs['NextToken'] = next_token

        response = s3control.list_multi_region_access_points(**kwargs)

        # Process each MRAP
        for mrap in response.get('AccessPoints', []):
            mrap_name = mrap.get('Name', 'N/A')

            try:
                # Get detailed configuration for this MRAP
                details = s3control.get_multi_region_access_point(
                    AccountId=account_id,
                    Name=mrap_name
                )

                mrap_details = details.get('AccessPoint', {})

                # Extract regions and buckets
                regions_info = mrap_details.get('Regions', [])
                regions_list = [r.get('Region', 'N/A') for r in regions_info]
                buckets_list = [r.get('Bucket', 'N/A') for r in regions_info]

                # Extract public access block settings
                public_access_block = mrap_details.get('PublicAccessBlock', {})

                mrap_info = {
                    'MRAPName': mrap_name,
                    'MRAPARN': mrap.get('Alias', 'N/A'),  # Alias is the ARN-style identifier
                    'Alias': mrap_details.get('Alias', 'N/A'),
                    'Status': mrap_details.get('Status', 'N/A'),
                    'CreationDate': mrap.get('CreatedAt', 'N/A'),
                    'Regions': ', '.join(regions_list),
                    'RegionCount': len(regions_list),
                    'Buckets': ', '.join(buckets_list),
                    'BlockPublicAcls': public_access_block.get('BlockPublicAcls', True),
                    'IgnorePublicAcls': public_access_block.get('IgnorePublicAcls', True),
                    'BlockPublicPolicy': public_access_block.get('BlockPublicPolicy', True),
                    'RestrictPublicBuckets': public_access_block.get('RestrictPublicBuckets', True)
                }

                mraps.append(mrap_info)

            except Exception as e:
                utils.log_warning(f"Could not get details for MRAP {mrap_name}: {e}")
                # Add basic info even if details fail
                mraps.append({
                    'MRAPName': mrap_name,
                    'MRAPARN': mrap.get('Alias', 'N/A'),
                    'Alias': mrap.get('Alias', 'N/A'),
                    'Status': 'Unknown',
                    'CreationDate': mrap.get('CreatedAt', 'N/A'),
                    'Regions': 'N/A',
                    'RegionCount': 0,
                    'Buckets': 'N/A',
                    'BlockPublicAcls': 'Unknown',
                    'IgnorePublicAcls': 'Unknown',
                    'BlockPublicPolicy': 'Unknown',
                    'RestrictPublicBuckets': 'Unknown'
                })

        # Check if there are more results
        next_token = response.get('NextToken')
        if not next_token:
            break

    utils.log_info(f"Found {len(mraps)} Multi-Region Access Points")
    return mraps


@utils.aws_error_handler("Collecting Object Lambda Access Points", default_return=[])
def collect_object_lambda_access_points(region: str, account_id: str) -> List[Dict[str, Any]]:
    """
    Collect Object Lambda Access Points for a specific region

    Args:
        region: AWS region name
        account_id: AWS account ID

    Returns:
        List of dictionaries containing Object Lambda access point information
    """
    s3control = utils.get_boto3_client('s3control', region_name=region)

    ol_access_points = []
    next_token = None

    utils.log_info(f"Collecting Object Lambda Access Points in {region}...")

    while True:
        # Build paginated request
        kwargs = {'AccountId': account_id}
        if next_token:
            kwargs['NextToken'] = next_token

        try:
            response = s3control.list_access_points_for_object_lambda(**kwargs)
        except Exception as e:
            # Object Lambda may not be available in all regions
            utils.log_debug(f"Object Lambda not available in {region}: {e}")
            break

        # Process each Object Lambda access point
        for ol_ap in response.get('ObjectLambdaAccessPointList', []):
            ol_name = ol_ap.get('Name', 'N/A')

            try:
                # Get detailed configuration for this Object Lambda access point
                details = s3control.get_access_point_configuration_for_object_lambda(
                    AccountId=account_id,
                    Name=ol_name
                )

                config = details.get('Configuration', {})

                # Extract transformation configurations
                transformations = config.get('TransformationConfigurations', [])
                lambda_arns = []
                allowed_features = []

                for transform in transformations:
                    content_transform = transform.get('ContentTransformation', {})
                    if 'AwsLambda' in content_transform:
                        lambda_arns.append(content_transform['AwsLambda'].get('FunctionArn', 'N/A'))

                    actions = transform.get('Actions', [])
                    allowed_features.extend(actions)

                ol_info = {
                    'ObjectLambdaName': ol_name,
                    'ObjectLambdaARN': ol_ap.get('ObjectLambdaAccessPointArn', 'N/A'),
                    'SupportingAccessPoint': config.get('SupportingAccessPoint', 'N/A'),
                    'LambdaFunctions': ', '.join(lambda_arns) if lambda_arns else 'N/A',
                    'AllowedFeatures': ', '.join(set(allowed_features)) if allowed_features else 'N/A',
                    'CloudWatchMetricsEnabled': config.get('CloudWatchMetricsEnabled', False),
                    'Region': region,
                    'Alias': ol_ap.get('Alias', 'N/A')
                }

                ol_access_points.append(ol_info)

            except Exception as e:
                utils.log_warning(f"Could not get details for Object Lambda AP {ol_name}: {e}")
                # Add basic info even if details fail
                ol_access_points.append({
                    'ObjectLambdaName': ol_name,
                    'ObjectLambdaARN': ol_ap.get('ObjectLambdaAccessPointArn', 'N/A'),
                    'SupportingAccessPoint': 'N/A',
                    'LambdaFunctions': 'N/A',
                    'AllowedFeatures': 'N/A',
                    'CloudWatchMetricsEnabled': 'Unknown',
                    'Region': region,
                    'Alias': ol_ap.get('Alias', 'N/A')
                })

        # Check if there are more results
        next_token = response.get('NextToken')
        if not next_token:
            break

    utils.log_info(f"Found {len(ol_access_points)} Object Lambda Access Points in {region}")
    return ol_access_points


def create_summary_sheet(
    standard_aps: List[Dict[str, Any]],
    mraps: List[Dict[str, Any]],
    ol_aps: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Create a summary sheet with counts and statistics

    Args:
        standard_aps: List of standard access points
        mraps: List of multi-region access points
        ol_aps: List of Object Lambda access points

    Returns:
        Dictionary containing summary information
    """
    # Count by network origin for standard APs
    vpc_count = sum(1 for ap in standard_aps if ap.get('NetworkOrigin') == 'VPC')
    internet_count = sum(1 for ap in standard_aps if ap.get('NetworkOrigin') == 'Internet')

    # Count MRAPs by status
    mrap_ready = sum(1 for mrap in mraps if mrap.get('Status') == 'READY')
    mrap_other = len(mraps) - mrap_ready

    # Count regions for standard APs
    regions = set(ap.get('Region', 'Unknown') for ap in standard_aps)

    summary = {
        'Metric': [
            'Total Standard Access Points',
            'VPC-Restricted Access Points',
            'Internet-Accessible Access Points',
            'Total Multi-Region Access Points',
            'MRAP Status: READY',
            'MRAP Status: Other',
            'Total Object Lambda Access Points',
            'Regions with Access Points',
            'Total Access Points (All Types)'
        ],
        'Count': [
            len(standard_aps),
            vpc_count,
            internet_count,
            len(mraps),
            mrap_ready,
            mrap_other,
            len(ol_aps),
            len(regions),
            len(standard_aps) + len(mraps) + len(ol_aps)
        ]
    }

    return summary


def export_to_excel(
    standard_aps: List[Dict[str, Any]],
    mraps: List[Dict[str, Any]],
    ol_aps: List[Dict[str, Any]],
    account_name: str
) -> Optional[str]:
    """
    Export all access point data to a multi-sheet Excel file

    Args:
        standard_aps: List of standard access points
        mraps: List of multi-region access points
        ol_aps: List of Object Lambda access points
        account_name: Name of the AWS account for file naming

    Returns:
        Path to the created file or None on error
    """
    import pandas as pd

    # Create summary sheet
    summary_data = create_summary_sheet(standard_aps, mraps, ol_aps)
    summary_df = pd.DataFrame(summary_data)

    # Create DataFrames for each type
    standard_df = pd.DataFrame(standard_aps) if standard_aps else pd.DataFrame()
    mraps_df = pd.DataFrame(mraps) if mraps else pd.DataFrame()
    ol_df = pd.DataFrame(ol_aps) if ol_aps else pd.DataFrame()

    # Filter for VPC and Public access points
    vpc_aps = [ap for ap in standard_aps if ap.get('NetworkOrigin') == 'VPC']
    vpc_df = pd.DataFrame(vpc_aps) if vpc_aps else pd.DataFrame()

    public_aps = [ap for ap in standard_aps if ap.get('NetworkOrigin') == 'Internet']
    public_df = pd.DataFrame(public_aps) if public_aps else pd.DataFrame()

    # Prepare all DataFrames for export
    dataframes = {
        'Summary': summary_df,
        'Standard Access Points': standard_df,
        'Multi-Region APs': mraps_df,
        'Object Lambda APs': ol_df,
        'VPC Access Points': vpc_df,
        'Public Access Points': public_df
    }

    # Generate filename
    filename = utils.create_export_filename(account_name, 's3-accesspoints', 'all')

    # Save to Excel with multiple sheets
    output_path = utils.save_multiple_dataframes_to_excel(
        dataframes,
        filename,
        prepare=True
    )

    if output_path:
        utils.log_success("S3 Access Points data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        return output_path
    else:
        utils.log_error("Error creating Excel file")
        return None


def main():
    """
    Main function to execute the script
    """
    # Setup logging
    utils.setup_logging("s3-accesspoints-export")
    utils.log_script_start("S3 Access Points Export", "Export comprehensive S3 Access Points data")

    # Print script title and get account information
    account_id, account_name = print_title()

    # Check dependencies
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return

    # Prompt for region selection
    print("\nThis script will collect S3 Access Points data:")
    print("- Standard Access Points are regional")
    print("- Multi-Region Access Points are global (queried from us-west-2)")
    print("- Object Lambda Access Points are regional")

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
    all_available_regions = utils.get_partition_regions(partition, all_regions=True)
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_suffix = ""
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
    elif selection_int == 2:
        regions = all_available_regions
        region_suffix = ""
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
                    region_suffix = selected_region
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")
            region_suffix = ""

    # Collect all access points
    all_standard_aps = []
    all_ol_aps = []

    utils.log_info(f"Scanning {len(regions)} region(s) for Access Points...")

    # Collect standard and Object Lambda access points from each region
    for i, region in enumerate(regions, 1):
        progress = (i / len(regions)) * 100
        utils.log_info(f"[{progress:.1f}%] Processing region {i}/{len(regions)}: {region}")

        # Standard Access Points
        standard_aps = collect_standard_access_points(region, account_id)
        all_standard_aps.extend(standard_aps)

        # Object Lambda Access Points
        ol_aps = collect_object_lambda_access_points(region, account_id)
        all_ol_aps.extend(ol_aps)

    # Collect Multi-Region Access Points (only once, from us-west-2)
    mraps = collect_multi_region_access_points(account_id)

    # Log collection summary
    utils.log_info("=" * 60)
    utils.log_info("Collection Summary:")
    utils.log_info(f"  Standard Access Points: {len(all_standard_aps)}")
    utils.log_info(f"  Multi-Region Access Points: {len(mraps)}")
    utils.log_info(f"  Object Lambda Access Points: {len(all_ol_aps)}")
    utils.log_info(f"  Total Access Points: {len(all_standard_aps) + len(mraps) + len(all_ol_aps)}")
    utils.log_info("=" * 60)

    # Check if we found any access points
    if not all_standard_aps and not mraps and not all_ol_aps:
        utils.log_warning("No S3 Access Points found in the selected regions")
        utils.log_info("This is normal if Access Points are not configured in your account")
        return

    # Export to Excel
    utils.log_info("Exporting data to Excel...")
    output_file = export_to_excel(all_standard_aps, mraps, all_ol_aps, account_name)

    if output_file:
        utils.log_export_summary(
            "S3 Access Points",
            len(all_standard_aps) + len(mraps) + len(all_ol_aps),
            output_file
        )
        print("\nScript execution completed successfully.")
    else:
        utils.log_error("Failed to export data. Please check the logs.")

    utils.log_script_end("S3 Access Points Export")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
