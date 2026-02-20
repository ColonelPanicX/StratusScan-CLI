#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS CloudFront Distribution Export Tool
Date: NOV-09-2025

Description:
This script exports CloudFront distribution information from AWS into an Excel file with
multiple worksheets. The output includes distribution configurations, origins, behaviors,
geo-restrictions, SSL/TLS settings, and WAF associations. CloudFront is a global service,
so all distributions are retrieved from a single API call.

Features:
- Distribution overview with status and domain names
- Origin configurations (S3, custom origins, origin groups)
- Cache behaviors (default and custom)
- Geographic restrictions
- SSL/TLS certificate information
- WAF Web ACL associations
- Lambda@Edge and CloudFront Functions
- Price class and cost optimization insights
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


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("         AWS CLOUDFRONT DISTRIBUTION EXPORT TOOL")
    print("====================================================================")
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


@utils.aws_error_handler("Collecting CloudFront distributions", default_return=[])
def collect_cloudfront_distributions() -> List[Dict[str, Any]]:
    """
    Collect CloudFront distribution information.
    CloudFront is a global service, so we don't need to iterate regions.

    Returns:
        list: List of dictionaries with distribution information
    """
    print("\n=== COLLECTING CLOUDFRONT DISTRIBUTIONS ===")
    utils.log_info("CloudFront is a global service - collecting from global endpoint")

    distributions = []

    # CloudFront is global, but we need to specify a region for the client
    # us-east-1 is the standard region for global services
    # Cloudfront is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    cloudfront = utils.get_boto3_client('cloudfront', region_name=home_region)

    # Use paginator to handle large numbers of distributions
    paginator = cloudfront.get_paginator('list_distributions')

    total_count = 0
    for page in paginator.paginate():
        dist_list = page.get('DistributionList', {})
        items = dist_list.get('Items', [])
        total_count += len(items)

        for dist_summary in items:
            dist_id = dist_summary.get('Id', '')
            domain_name = dist_summary.get('DomainName', '')

            print(f"  Processing distribution: {dist_id} ({domain_name})")

            # Get detailed distribution configuration
            try:
                dist_detail = cloudfront.get_distribution(Id=dist_id)
                dist_config = dist_detail['Distribution']['DistributionConfig']
                dist_info = dist_detail['Distribution']

                # Extract basic information
                status = dist_info.get('Status', '')
                enabled = dist_config.get('Enabled', False)
                comment = dist_config.get('Comment', '')
                price_class = dist_config.get('PriceClass', '')

                # Get alternate domain names (CNAMEs)
                aliases = dist_config.get('Aliases', {}).get('Items', [])
                alias_list = ', '.join(aliases) if aliases else 'N/A'

                # Get default root object
                default_root_object = dist_config.get('DefaultRootObject', 'N/A')

                # Get origin information (count and types)
                origins = dist_config.get('Origins', {}).get('Items', [])
                origin_count = len(origins)

                # Categorize origins
                s3_origins = []
                custom_origins = []
                for origin in origins:
                    if '.s3' in origin.get('DomainName', ''):
                        s3_origins.append(origin.get('Id', ''))
                    else:
                        custom_origins.append(origin.get('Id', ''))

                origin_summary = f"S3: {len(s3_origins)}, Custom: {len(custom_origins)}"

                # Get cache behavior count
                default_cache_behavior = dist_config.get('DefaultCacheBehavior', {})
                cache_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
                behavior_count = 1 + len(cache_behaviors)  # 1 default + custom behaviors

                # Get SSL/TLS information
                viewer_cert = dist_config.get('ViewerCertificate', {})
                ssl_support = viewer_cert.get('SSLSupportMethod', 'N/A')
                acm_cert_arn = viewer_cert.get('ACMCertificateArn', 'N/A')
                iam_cert_id = viewer_cert.get('IAMCertificateId', 'N/A')
                cert_source = 'CloudFront Default' if viewer_cert.get('CloudFrontDefaultCertificate') else 'Custom'

                # Get WAF Web ACL ID
                web_acl_id = dist_config.get('WebACLId', 'N/A')

                # Get viewer protocol policy from default cache behavior
                viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', 'N/A')

                # Get HTTP versions
                http_version = dist_config.get('HttpVersion', 'N/A')

                # Get IPv6 enabled
                ipv6_enabled = dist_config.get('IsIPV6Enabled', False)

                # Get geographic restrictions
                geo_restriction = dist_config.get('Restrictions', {}).get('GeoRestriction', {})
                geo_restriction_type = geo_restriction.get('RestrictionType', 'none')
                geo_locations = geo_restriction.get('Items', [])
                geo_summary = f"{geo_restriction_type.upper()}: {len(geo_locations)} countries" if geo_locations else geo_restriction_type

                # Get logging configuration
                logging = dist_config.get('Logging', {})
                logging_enabled = logging.get('Enabled', False)
                log_bucket = logging.get('Bucket', 'N/A') if logging_enabled else 'Disabled'

                # Get Lambda@Edge and CloudFront Functions
                lambda_associations = default_cache_behavior.get('LambdaFunctionAssociations', {}).get('Items', [])
                function_associations = default_cache_behavior.get('FunctionAssociations', {}).get('Items', [])
                edge_functions = f"Lambda: {len(lambda_associations)}, Functions: {len(function_associations)}"

                # Get last modified time
                last_modified = dist_info.get('LastModifiedTime', '')
                if last_modified:
                    last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_modified, datetime.datetime) else str(last_modified)

                distributions.append({
                    'Distribution ID': dist_id,
                    'Domain Name': domain_name,
                    'Status': status,
                    'Enabled': enabled,
                    'Aliases (CNAMEs)': alias_list,
                    'Comment': comment if comment else 'N/A',
                    'Price Class': price_class,
                    'Default Root Object': default_root_object,
                    'Origin Count': origin_count,
                    'Origin Types': origin_summary,
                    'Cache Behavior Count': behavior_count,
                    'Viewer Protocol Policy': viewer_protocol_policy,
                    'HTTP Version': http_version,
                    'IPv6 Enabled': ipv6_enabled,
                    'SSL/TLS Support': ssl_support,
                    'Certificate Source': cert_source,
                    'ACM Certificate ARN': acm_cert_arn,
                    'IAM Certificate ID': iam_cert_id,
                    'WAF Web ACL': web_acl_id,
                    'Geographic Restrictions': geo_summary,
                    'Logging': log_bucket,
                    'Edge Functions': edge_functions,
                    'Last Modified': last_modified
                })

            except Exception as e:
                utils.log_error(f"Error getting details for distribution {dist_id}", e)
                # Add minimal info if we can't get full details
                distributions.append({
                    'Distribution ID': dist_id,
                    'Domain Name': domain_name,
                    'Status': dist_summary.get('Status', 'Unknown'),
                    'Enabled': dist_summary.get('Enabled', 'Unknown'),
                    'Error': f'Could not retrieve full details: {str(e)}'
                })

    print(f"\nTotal distributions found: {total_count}")
    utils.log_success(f"Total CloudFront distributions collected: {total_count}")

    return distributions


@utils.aws_error_handler("Collecting origin details", default_return=[])
def collect_origin_details() -> List[Dict[str, Any]]:
    """
    Collect detailed origin information for all distributions.

    Returns:
        list: List of dictionaries with origin details
    """
    print("\n=== COLLECTING ORIGIN DETAILS ===")

    origins_data = []
    cloudfront = utils.get_boto3_client('cloudfront', region_name=home_region)

    paginator = cloudfront.get_paginator('list_distributions')

    for page in paginator.paginate():
        dist_list = page.get('DistributionList', {})
        items = dist_list.get('Items', [])

        for dist_summary in items:
            dist_id = dist_summary.get('Id', '')

            try:
                dist_detail = cloudfront.get_distribution(Id=dist_id)
                dist_config = dist_detail['Distribution']['DistributionConfig']

                origins = dist_config.get('Origins', {}).get('Items', [])

                for origin in origins:
                    origin_id = origin.get('Id', '')
                    domain_name = origin.get('DomainName', '')
                    origin_path = origin.get('OriginPath', 'N/A')

                    # Determine origin type
                    if '.s3' in domain_name:
                        origin_type = 'S3'
                        # Check if using Origin Access Control or Origin Access Identity
                        s3_config = origin.get('S3OriginConfig', {})
                        origin_access_identity = s3_config.get('OriginAccessIdentity', 'N/A')
                        origin_access_control = origin.get('OriginAccessControlId', 'N/A')

                        if origin_access_control != 'N/A':
                            access_method = f"OAC: {origin_access_control}"
                        elif origin_access_identity:
                            access_method = f"OAI: {origin_access_identity}"
                        else:
                            access_method = "Public"
                    else:
                        origin_type = 'Custom'
                        custom_origin = origin.get('CustomOriginConfig', {})
                        http_port = custom_origin.get('HTTPPort', 80)
                        https_port = custom_origin.get('HTTPSPort', 443)
                        protocol_policy = custom_origin.get('OriginProtocolPolicy', 'N/A')
                        ssl_protocols = custom_origin.get('OriginSslProtocols', {}).get('Items', [])

                        access_method = f"{protocol_policy} (HTTP:{http_port}, HTTPS:{https_port})"

                    # Connection settings
                    connection_attempts = origin.get('ConnectionAttempts', 3)
                    connection_timeout = origin.get('ConnectionTimeout', 10)

                    # Custom headers
                    custom_headers = origin.get('CustomHeaders', {}).get('Items', [])
                    header_count = len(custom_headers)

                    origins_data.append({
                        'Distribution ID': dist_id,
                        'Origin ID': origin_id,
                        'Origin Type': origin_type,
                        'Domain Name': domain_name,
                        'Origin Path': origin_path,
                        'Access Method': access_method,
                        'Connection Attempts': connection_attempts,
                        'Connection Timeout (s)': connection_timeout,
                        'Custom Header Count': header_count
                    })

            except Exception as e:
                utils.log_error(f"Error collecting origins for distribution {dist_id}", e)

    utils.log_success(f"Total origins collected: {len(origins_data)}")
    return origins_data


@utils.aws_error_handler("Collecting cache behavior details", default_return=[])
def collect_cache_behaviors() -> List[Dict[str, Any]]:
    """
    Collect cache behavior information for all distributions.

    Returns:
        list: List of dictionaries with cache behavior details
    """
    print("\n=== COLLECTING CACHE BEHAVIOR DETAILS ===")

    behaviors_data = []
    cloudfront = utils.get_boto3_client('cloudfront', region_name=home_region)

    paginator = cloudfront.get_paginator('list_distributions')

    for page in paginator.paginate():
        dist_list = page.get('DistributionList', {})
        items = dist_list.get('Items', [])

        for dist_summary in items:
            dist_id = dist_summary.get('Id', '')

            try:
                dist_detail = cloudfront.get_distribution(Id=dist_id)
                dist_config = dist_detail['Distribution']['DistributionConfig']

                # Process default cache behavior
                default_behavior = dist_config.get('DefaultCacheBehavior', {})
                behaviors_data.append(process_cache_behavior(dist_id, 'Default (*)', default_behavior))

                # Process custom cache behaviors
                custom_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
                for behavior in custom_behaviors:
                    path_pattern = behavior.get('PathPattern', '')
                    behaviors_data.append(process_cache_behavior(dist_id, path_pattern, behavior))

            except Exception as e:
                utils.log_error(f"Error collecting cache behaviors for distribution {dist_id}", e)

    utils.log_success(f"Total cache behaviors collected: {len(behaviors_data)}")
    return behaviors_data


def process_cache_behavior(dist_id: str, path_pattern: str, behavior: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a single cache behavior into a dictionary.

    Args:
        dist_id: Distribution ID
        path_pattern: Path pattern for the behavior
        behavior: Cache behavior configuration

    Returns:
        dict: Processed cache behavior data
    """
    target_origin_id = behavior.get('TargetOriginId', '')
    viewer_protocol_policy = behavior.get('ViewerProtocolPolicy', '')

    # Allowed HTTP methods
    allowed_methods = behavior.get('AllowedMethods', {}).get('Items', [])
    allowed_methods_str = ', '.join(allowed_methods) if allowed_methods else 'N/A'

    # Cached HTTP methods
    cached_methods = behavior.get('AllowedMethods', {}).get('CachedMethods', {}).get('Items', [])
    cached_methods_str = ', '.join(cached_methods) if cached_methods else 'N/A'

    # Cache policy
    cache_policy_id = behavior.get('CachePolicyId', 'N/A')

    # Origin request policy
    origin_request_policy_id = behavior.get('OriginRequestPolicyId', 'N/A')

    # Response headers policy
    response_headers_policy_id = behavior.get('ResponseHeadersPolicyId', 'N/A')

    # Compress
    compress = behavior.get('Compress', False)

    # Field level encryption
    field_level_encryption_id = behavior.get('FieldLevelEncryptionId', 'N/A')

    # TTL settings (legacy, before cache policies)
    min_ttl = behavior.get('MinTTL', 'N/A')
    max_ttl = behavior.get('MaxTTL', 'N/A')
    default_ttl = behavior.get('DefaultTTL', 'N/A')

    # Function associations
    lambda_assoc = behavior.get('LambdaFunctionAssociations', {}).get('Items', [])
    func_assoc = behavior.get('FunctionAssociations', {}).get('Items', [])

    functions_summary = []
    for assoc in lambda_assoc:
        event_type = assoc.get('EventType', '')
        functions_summary.append(f"Lambda@{event_type}")
    for assoc in func_assoc:
        event_type = assoc.get('EventType', '')
        functions_summary.append(f"Function@{event_type}")

    functions_str = ', '.join(functions_summary) if functions_summary else 'None'

    return {
        'Distribution ID': dist_id,
        'Path Pattern': path_pattern,
        'Target Origin': target_origin_id,
        'Viewer Protocol Policy': viewer_protocol_policy,
        'Allowed Methods': allowed_methods_str,
        'Cached Methods': cached_methods_str,
        'Cache Policy ID': cache_policy_id,
        'Origin Request Policy ID': origin_request_policy_id,
        'Response Headers Policy ID': response_headers_policy_id,
        'Compress Objects': compress,
        'Min TTL': min_ttl,
        'Default TTL': default_ttl,
        'Max TTL': max_ttl,
        'Field Level Encryption': field_level_encryption_id,
        'Edge Functions': functions_str
    }


def export_cloudfront_data(account_id: str, account_name: str):
    """
    Export CloudFront distribution information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    print("\n" + "=" * 60)
    print("Starting CloudFront export process...")
    print("=" * 60)

    utils.log_info("Beginning CloudFront data collection")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect distribution overview
    distributions = collect_cloudfront_distributions()
    if distributions:
        data_frames['Distributions'] = pd.DataFrame(distributions)

    # STEP 2: Collect origin details
    origins = collect_origin_details()
    if origins:
        data_frames['Origins'] = pd.DataFrame(origins)

    # STEP 3: Collect cache behaviors
    behaviors = collect_cache_behaviors()
    if behaviors:
        data_frames['Cache Behaviors'] = pd.DataFrame(behaviors)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No CloudFront data was collected. Nothing to export.")
        print("\nNo CloudFront distributions found in this account.")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'cloudfront',
        '',  # No region suffix for global service
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("CloudFront data exported successfully!")
            utils.log_info(f"File location: {output_path}")

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
    utils.setup_logging("cloudfront-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("cloudfront-export.py", "AWS CloudFront Distribution Export Tool")

    try:
        # Check if running in GovCloud partition
        partition = utils.detect_partition()
        if partition == 'aws-us-gov':
            print(f"\nERROR: CloudFront is not available in AWS GovCloud")
            print("This service operates outside the GovCloud boundary")
            utils.log_error(f"CloudFront is not supported in GovCloud partition")
            sys.exit(1)

        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Export CloudFront data
        export_cloudfront_data(account_id, account_name)

        print("\nCloudFront export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("cloudfront-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
