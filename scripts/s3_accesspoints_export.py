#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS S3 Access Points Comprehensive Export
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
from pathlib import Path
from typing import Any, Optional

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
args = utils.parse_script_args("Export S3 access points to Excel")


def _build_access_point_row(ap: dict, region: str, account_id: str, s3control) -> dict[str, Any]:
    """
    Build the export row for a single Standard S3 Access Point, including its
    detail calls (creation date, public access block, policy status).

    Extracted so per-access-point processing can be wrapped in try/except by
    the caller: a malformed/inaccessible access point is logged and skipped
    rather than discarding the whole region's results.

    Args:
        ap: A single AccessPointList entry from list_access_points.
        region: AWS region name.
        account_id: AWS account ID.
        s3control: An s3control client for ``region``.

    Returns:
        dict: The assembled access point row.
    """
    ap_name = ap.get('Name', 'N/A')

    # Get detailed configuration for this access point
    details = s3control.get_access_point(AccountId=account_id, Name=ap_name)

    # Get block public access settings
    try:
        public_access_block = s3control.get_public_access_block(AccountId=account_id)
        block_settings = public_access_block.get('PublicAccessBlockConfiguration', {})
    except Exception:
        # If GetPublicAccessBlock fails, use defaults
        block_settings = {}

    # Get access point policy status
    try:
        policy_status = s3control.get_access_point_policy_status(
            AccountId=account_id, Name=ap_name
        )
        has_policy = policy_status.get('PolicyStatus', {}).get('IsPublic', False)
    except Exception:
        has_policy = False

    # Extract VPC configuration
    vpc_config = ap.get('VpcConfiguration', {}) or {}
    vpc_id = vpc_config.get('VpcId', 'N/A')

    return {
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


def _scan_standard_access_points_region(region: str, account_id: str) -> list[dict[str, Any]]:
    """
    Collect standard S3 Access Points from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no access points" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed/inaccessible access points are skipped (logged)
    rather than aborting the whole region.

    Args:
        region: AWS region name
        account_id: AWS account ID

    Returns:
        List of dictionaries containing access point information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records
            it as a failed region and surfaces it; it is never masked as
            empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

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

        # Process each access point. One malformed/inaccessible access point
        # must not sink the region, so each is built inside try/except;
        # failures are logged and skipped.
        for ap in response.get('AccessPointList', []):
            ap_name = ap.get('Name', 'N/A')

            try:
                access_points.append(_build_access_point_row(ap, region, account_id, s3control))
            except Exception as e:
                utils.log_error(
                    f"Skipping standard access point '{ap_name}' in {region} due to a processing error", e
                )
                continue

        # Check if there are more results
        next_token = response.get('NextToken')
        if not next_token:
            break

    utils.log_info(f"Found {len(access_points)} standard access points in {region}")
    return access_points


def collect_standard_access_points(regions: list[str], account_id: str) -> tuple[list[dict[str, Any]], list]:
    """
    Collect standard S3 Access Point information across regions, surfacing
    failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID

    Returns:
        tuple: ``(access_points, failed_regions)`` where ``failed_regions``
        is a list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: _scan_standard_access_points_region(r, account_id),
        show_progress=True,
        collect_failures=True,
    )
    all_aps = [ap for result in region_results for ap in result]
    return all_aps, failed_regions


def _build_mrap_row(mrap: dict, account_id: str, s3control) -> dict[str, Any]:
    """
    Build the export row for a single Multi-Region Access Point.

    Args:
        mrap: A single AccessPoints entry from list_multi_region_access_points.
        account_id: AWS account ID.
        s3control: An s3control client (us-west-2).

    Returns:
        dict: The assembled MRAP row.
    """
    mrap_name = mrap.get('Name', 'N/A')

    # Get detailed configuration for this MRAP
    details = s3control.get_multi_region_access_point(AccountId=account_id, Name=mrap_name)
    mrap_details = details.get('AccessPoint', {})

    # Extract regions and buckets
    regions_info = mrap_details.get('Regions', [])
    regions_list = [r.get('Region', 'N/A') for r in regions_info]
    buckets_list = [r.get('Bucket', 'N/A') for r in regions_info]

    # Extract public access block settings
    public_access_block = mrap_details.get('PublicAccessBlock', {})

    return {
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


def collect_multi_region_access_points(account_id: str) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Multi-Region Access Points (always queried from us-west-2).

    This is a GLOBAL scope — a single call, not region-scanned — so there is
    no per-region loop to attach a failed-region tuple to. A collection
    error here is instead reported as a single ``('global', error)`` entry
    in the returned failed-scopes list, using the same ``(scope, error)``
    contract as the regional scopes so the caller can merge them into one
    combined failed list (see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Args:
        account_id: AWS account ID

    Returns:
        tuple: ``(mraps, failed_scopes)`` where ``failed_scopes`` is either
        ``[]`` or ``[('global', error_message)]``.
    """
    # Multi-Region Access Points are only available in commercial us-west-2.
    # The API rejects calls from any other region with PermanentRedirect.
    partition = utils.detect_partition()
    if partition == "aws-us-gov":
        utils.log_info("Multi-Region Access Points are not available in GovCloud — skipping.")
        return [], []

    utils.log_info("Collecting Multi-Region Access Points (from us-west-2)...")

    try:
        s3control = utils.get_boto3_client('s3control', region_name='us-west-2')

        mraps = []
        next_token = None

        while True:
            # Build paginated request
            kwargs = {'AccountId': account_id}
            if next_token:
                kwargs['NextToken'] = next_token

            response = s3control.list_multi_region_access_points(**kwargs)

            # Process each MRAP. One malformed/inaccessible MRAP must not
            # sink the whole scope; failures are logged and skipped.
            for mrap in response.get('AccessPoints', []):
                mrap_name = mrap.get('Name', 'N/A')

                try:
                    mraps.append(_build_mrap_row(mrap, account_id, s3control))
                except Exception as e:
                    utils.log_error(
                        f"Skipping Multi-Region Access Point '{mrap_name}' due to a processing error", e
                    )
                    continue

            # Check if there are more results
            next_token = response.get('NextToken')
            if not next_token:
                break

        utils.log_info(f"Found {len(mraps)} Multi-Region Access Points")
        return mraps, []

    except Exception as e:
        # The MRAP scope call itself failed (e.g. throttling, access denied).
        # Surface it as a failed 'global' scope rather than swallowing it
        # into an empty list indistinguishable from "no MRAPs configured".
        utils.log_error("Error collecting Multi-Region Access Points", e)
        return [], [('global', str(e))]


def _build_object_lambda_row(ol_ap: dict, region: str, account_id: str, s3control) -> dict[str, Any]:
    """
    Build the export row for a single Object Lambda Access Point.

    Args:
        ol_ap: A single ObjectLambdaAccessPointList entry from
            list_access_points_for_object_lambda.
        region: AWS region name.
        account_id: AWS account ID.
        s3control: An s3control client for ``region``.

    Returns:
        dict: The assembled Object Lambda access point row.
    """
    ol_name = ol_ap.get('Name', 'N/A')

    # Get detailed configuration for this Object Lambda access point
    details = s3control.get_access_point_configuration_for_object_lambda(
        AccountId=account_id, Name=ol_name
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

    return {
        'ObjectLambdaName': ol_name,
        'ObjectLambdaARN': ol_ap.get('ObjectLambdaAccessPointArn', 'N/A'),
        'SupportingAccessPoint': config.get('SupportingAccessPoint', 'N/A'),
        'LambdaFunctions': ', '.join(lambda_arns) if lambda_arns else 'N/A',
        'AllowedFeatures': ', '.join(set(allowed_features)) if allowed_features else 'N/A',
        'CloudWatchMetricsEnabled': config.get('CloudWatchMetricsEnabled', False),
        'Region': region,
        'Alias': ol_ap.get('Alias', 'N/A')
    }


def _scan_object_lambda_access_points_region(region: str, account_id: str) -> list[dict[str, Any]]:
    """
    Collect Object Lambda Access Points from a single region.

    Object Lambda support varies by region/partition, and the API can
    respond to an unsupported region with an error rather than an empty
    list. That "not available here" error cannot be reliably distinguished
    from a genuine collection failure (throttling, access denied), so —
    unlike the standard access points primary scope — it is deliberately
    still caught and treated as "no Object Lambda access points in this
    region" rather than raised. Per-item failures are logged and skipped
    individually either way.

    Args:
        region: AWS region name
        account_id: AWS account ID

    Returns:
        List of dictionaries containing Object Lambda access point information
    """
    if not utils.is_aws_region(region):
        return []

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
                ol_access_points.append(
                    _build_object_lambda_row(ol_ap, region, account_id, s3control)
                )
            except Exception as e:
                utils.log_error(
                    f"Skipping Object Lambda access point '{ol_name}' in {region} due to a processing error", e
                )
                continue

        # Check if there are more results
        next_token = response.get('NextToken')
        if not next_token:
            break

    utils.log_info(f"Found {len(ol_access_points)} Object Lambda Access Points in {region}")
    return ol_access_points


def collect_object_lambda_access_points(regions: list[str], account_id: str) -> list[dict[str, Any]]:
    """
    Collect Object Lambda Access Point information across regions.

    Enrichment-style regional scope: it degrades gracefully per region (see
    ``_scan_object_lambda_access_points_region``), so it is scanned without
    ``collect_failures`` and does not contribute to the failed-scopes list.

    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID

    Returns:
        list: List of dictionaries with Object Lambda access point information
    """
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: _scan_object_lambda_access_points_region(r, account_id),
        show_progress=True,
    )
    all_ol_aps = [ap for result in region_results for ap in result]
    utils.log_success(f"Total Object Lambda Access Points collected: {len(all_ol_aps)}")
    return all_ol_aps


def create_summary_sheet(
    standard_aps: list[dict[str, Any]],
    mraps: list[dict[str, Any]],
    ol_aps: list[dict[str, Any]]
) -> dict[str, Any]:
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
    regions = {ap.get('Region', 'Unknown') for ap in standard_aps}

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
    standard_aps: list[dict[str, Any]],
    mraps: list[dict[str, Any]],
    ol_aps: list[dict[str, Any]],
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
        utils.log_success(f"File location: {output_path}")
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
    account_id, account_name = utils.print_script_banner("AWS S3 ACCESS POINTS COMPREHENSIVE EXPORT")

    # Check dependencies
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return

    # Prompt for region selection
    print("\nThis script will collect S3 Access Points data:")
    print("- Standard Access Points are regional")
    print("- Multi-Region Access Points are global (queried from us-west-2)")
    print("- Object Lambda Access Points are regional")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()

    utils.log_info(f"Scanning {len(regions)} region(s) for Access Points...")

    # STEP 1: Collect standard access points (primary scope — region
    # failures must propagate as failed_regions, never collapse into
    # "empty").
    all_standard_aps, failed_regions = collect_standard_access_points(regions, account_id)

    # STEP 2: Collect Object Lambda Access Points (enrichment-style regional
    # scope — degrades gracefully; see
    # collect_object_lambda_access_points()/_scan_object_lambda_access_points_region()).
    all_ol_aps = collect_object_lambda_access_points(regions, account_id)

    # STEP 3: Collect Multi-Region Access Points (global scope, queried once
    # from us-west-2; a failure here is reported as a 'global' scope).
    mraps, mrap_failed = collect_multi_region_access_points(account_id)

    # Merge failed scopes: regional failures from the primary scope + the
    # global MRAP scope (if it failed).
    failed = list(failed_regions) + list(mrap_failed)

    # Log collection summary
    utils.log_info("=" * 60)
    utils.log_info("Collection Summary:")
    utils.log_info(f"  Standard Access Points: {len(all_standard_aps)}")
    utils.log_info(f"  Multi-Region Access Points: {len(mraps)}")
    utils.log_info(f"  Object Lambda Access Points: {len(all_ol_aps)}")
    utils.log_info(f"  Total Access Points: {len(all_standard_aps) + len(mraps) + len(all_ol_aps)}")
    utils.log_info("=" * 60)

    if all_standard_aps or mraps or all_ol_aps:
        # Export whatever succeeded — a partial export is required even
        # when some scopes failed (see the silent-collection-failure
        # blast-radius audit).
        utils.log_info("Exporting data to Excel...")
        output_file = export_to_excel(all_standard_aps, mraps, all_ol_aps, account_name)

        if output_file:
            print("\nScript execution completed successfully.")
        else:
            utils.log_error("Failed to export data. Please check the logs.")
    elif not failed:
        # Genuinely empty account: every scope succeeded and returned
        # nothing.
        utils.log_warning("No S3 Access Points found in the selected regions")
        utils.log_info("This is normal if Access Points are not configured in your account")

    # If ANY scope failed collection, make it loud: write a marker and exit
    # non-zero, even if some data was exported. A partial export that looks
    # complete is exactly the failure mode this guards against.
    if failed:
        utils.report_collection_failures(account_name, 's3-accesspoints', failed)
        print(
            "\nERROR: S3 Access Points export completed with failures — data is incomplete. "
            "See the *-s3-accesspoints-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)

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
