#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Verified Access Export Script
Date: NOV-11-2025

Description:
This script performs a comprehensive export of AWS Verified Access resources from AWS environments.
AWS Verified Access provides secure access to applications without a VPN, using zero-trust principles
with Cedar policy language for fine-grained authorization.

Collected information includes: Verified Access Instances, Trust Providers (user and device),
Verified Access Groups, Endpoints (load-balancer and network-interface types), Access Logs
configurations, and Cedar policy documents.

Note: AWS Verified Access is a regional service. This script scans all configured regions.
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
    import utils

def format_tags(tags: List[Dict[str, str]]) -> str:
    """Format tags for display."""
    if not tags:
        return "None"
    tag_strings = [f"{tag['Key']}={tag['Value']}" for tag in tags]
    return ", ".join(tag_strings)

@utils.aws_error_handler("Collecting Verified Access Instances", default_return=[])
def collect_verified_access_instances(region: str) -> List[Dict[str, Any]]:
    """Collect Verified Access Instances in a region."""
    utils.log_info(f"Collecting Verified Access Instances in {region}...")

    va_client = utils.get_boto3_client('verifiedaccess', region_name=region)
    instances = []

    try:
        # List all instances
        paginator = va_client.get_paginator('describe_verified_access_instances')

        for page in paginator.paginate():
            for instance in page.get('VerifiedAccessInstances', []):
                instance_id = instance.get('VerifiedAccessInstanceId', 'N/A')
                utils.log_info(f"Processing instance: {instance_id}")

                instance_info = {
                    'Region': region,
                    'Instance ID': instance_id,
                    'Description': instance.get('Description', 'N/A'),
                    'Creation Time': instance.get('CreationTime', 'N/A'),
                    'Last Updated Time': instance.get('LastUpdatedTime', 'N/A'),
                    'Trust Provider Count': len(instance.get('VerifiedAccessTrustProviders', [])),
                    'Tags': format_tags(instance.get('Tags', []))
                }

                instances.append(instance_info)

        if instances:
            utils.log_success(f"Found {len(instances)} Verified Access instances in {region}")

    except Exception as e:
        utils.log_warning(f"No instances found in {region} or service not available: {e}")

    return instances

@utils.aws_error_handler("Collecting Trust Providers", default_return=[])
def collect_trust_providers(region: str) -> List[Dict[str, Any]]:
    """Collect Verified Access Trust Providers in a region."""
    utils.log_info(f"Collecting Trust Providers in {region}...")

    va_client = utils.get_boto3_client('verifiedaccess', region_name=region)
    trust_providers = []

    try:
        # List all trust providers
        paginator = va_client.get_paginator('describe_verified_access_trust_providers')

        for page in paginator.paginate():
            for provider in page.get('VerifiedAccessTrustProviders', []):
                provider_id = provider.get('VerifiedAccessTrustProviderId', 'N/A')
                utils.log_info(f"Processing trust provider: {provider_id}")

                # Extract trust provider type and configuration
                trust_provider_type = provider.get('TrustProviderType', 'N/A')
                policy_reference_name = provider.get('PolicyReferenceName', 'N/A')
                device_trust_provider_type = provider.get('DeviceTrustProviderType', 'N/A')

                # OIDC configuration
                oidc_options = provider.get('OidcOptions', {})
                oidc_issuer = oidc_options.get('Issuer', 'N/A')
                oidc_client_id = oidc_options.get('ClientId', 'N/A')

                # Device options
                device_options = provider.get('DeviceOptions', {})
                tenant_id = device_options.get('TenantId', 'N/A')

                provider_info = {
                    'Region': region,
                    'Trust Provider ID': provider_id,
                    'Trust Provider ARN': provider.get('VerifiedAccessTrustProviderArn', 'N/A'),
                    'Instance ID': provider.get('VerifiedAccessInstanceId', 'N/A'),
                    'Trust Provider Type': trust_provider_type,
                    'Device Trust Provider Type': device_trust_provider_type,
                    'Policy Reference Name': policy_reference_name,
                    'OIDC Issuer': oidc_issuer if trust_provider_type == 'user' else 'N/A',
                    'OIDC Client ID': oidc_client_id if trust_provider_type == 'user' else 'N/A',
                    'Device Tenant ID': tenant_id if trust_provider_type == 'device' else 'N/A',
                    'Description': provider.get('Description', 'N/A'),
                    'Creation Time': provider.get('CreationTime', 'N/A'),
                    'Last Updated Time': provider.get('LastUpdatedTime', 'N/A'),
                    'Tags': format_tags(provider.get('Tags', []))
                }

                trust_providers.append(provider_info)

        if trust_providers:
            utils.log_success(f"Found {len(trust_providers)} trust providers in {region}")

    except Exception as e:
        utils.log_warning(f"No trust providers found in {region} or service not available: {e}")

    return trust_providers

@utils.aws_error_handler("Collecting Verified Access Groups", default_return=[])
def collect_verified_access_groups(region: str) -> List[Dict[str, Any]]:
    """Collect Verified Access Groups in a region."""
    utils.log_info(f"Collecting Verified Access Groups in {region}...")

    va_client = utils.get_boto3_client('verifiedaccess', region_name=region)
    groups = []

    try:
        # List all groups
        paginator = va_client.get_paginator('describe_verified_access_groups')

        for page in paginator.paginate():
            for group in page.get('VerifiedAccessGroups', []):
                group_id = group.get('VerifiedAccessGroupId', 'N/A')
                utils.log_info(f"Processing group: {group_id}")

                # Get policy for this group
                policy_enabled = 'No'
                policy_document = 'None'
                try:
                    policy_response = va_client.get_verified_access_group_policy(
                        VerifiedAccessGroupId=group_id
                    )
                    policy_enabled = 'Yes' if policy_response.get('PolicyEnabled', False) else 'No'
                    policy_document = policy_response.get('PolicyDocument', 'None')
                    # Truncate long policies for display
                    if len(policy_document) > 500:
                        policy_document = policy_document[:500] + '... (truncated)'
                except Exception as e:
                    utils.log_warning(f"Could not get policy for group {group_id}: {e}")

                group_info = {
                    'Region': region,
                    'Group ID': group_id,
                    'Group ARN': group.get('VerifiedAccessGroupArn', 'N/A'),
                    'Instance ID': group.get('VerifiedAccessInstanceId', 'N/A'),
                    'Description': group.get('Description', 'N/A'),
                    'Policy Enabled': policy_enabled,
                    'Policy Document (Preview)': policy_document,
                    'Owner': group.get('Owner', 'N/A'),
                    'Creation Time': group.get('CreationTime', 'N/A'),
                    'Last Updated Time': group.get('LastUpdatedTime', 'N/A'),
                    'Deletion Time': group.get('DeletionTime', 'N/A'),
                    'Tags': format_tags(group.get('Tags', []))
                }

                groups.append(group_info)

        if groups:
            utils.log_success(f"Found {len(groups)} Verified Access groups in {region}")

    except Exception as e:
        utils.log_warning(f"No groups found in {region} or service not available: {e}")

    return groups

@utils.aws_error_handler("Collecting Verified Access Endpoints", default_return=[])
def collect_verified_access_endpoints(region: str) -> List[Dict[str, Any]]:
    """Collect Verified Access Endpoints in a region."""
    utils.log_info(f"Collecting Verified Access Endpoints in {region}...")

    va_client = utils.get_boto3_client('verifiedaccess', region_name=region)
    endpoints = []

    try:
        # List all endpoints
        paginator = va_client.get_paginator('describe_verified_access_endpoints')

        for page in paginator.paginate():
            for endpoint in page.get('VerifiedAccessEndpoints', []):
                endpoint_id = endpoint.get('VerifiedAccessEndpointId', 'N/A')
                utils.log_info(f"Processing endpoint: {endpoint_id}")

                # Extract endpoint configuration
                endpoint_type = endpoint.get('EndpointType', 'N/A')
                attachment_type = endpoint.get('AttachmentType', 'N/A')
                endpoint_domain = endpoint.get('EndpointDomain', 'N/A')
                application_domain = endpoint.get('ApplicationDomain', 'N/A')
                status = endpoint.get('Status', {}).get('Code', 'Unknown')

                # Load balancer options
                lb_options = endpoint.get('LoadBalancerOptions', {})
                load_balancer_arn = lb_options.get('LoadBalancerArn', 'N/A')
                lb_protocol = lb_options.get('Protocol', 'N/A')
                lb_port = lb_options.get('Port', 'N/A')

                # Network interface options
                ni_options = endpoint.get('NetworkInterfaceOptions', {})
                network_interface_id = ni_options.get('NetworkInterfaceId', 'N/A')
                ni_protocol = ni_options.get('Protocol', 'N/A')
                ni_port = ni_options.get('Port', 'N/A')

                # Get policy for this endpoint
                policy_enabled = 'No'
                policy_document = 'None'
                try:
                    policy_response = va_client.get_verified_access_endpoint_policy(
                        VerifiedAccessEndpointId=endpoint_id
                    )
                    policy_enabled = 'Yes' if policy_response.get('PolicyEnabled', False) else 'No'
                    policy_document = policy_response.get('PolicyDocument', 'None')
                    # Truncate long policies for display
                    if len(policy_document) > 500:
                        policy_document = policy_document[:500] + '... (truncated)'
                except Exception as e:
                    utils.log_warning(f"Could not get policy for endpoint {endpoint_id}: {e}")

                endpoint_info = {
                    'Region': region,
                    'Endpoint ID': endpoint_id,
                    'Endpoint ARN': endpoint.get('VerifiedAccessEndpointArn', 'N/A'),
                    'Instance ID': endpoint.get('VerifiedAccessInstanceId', 'N/A'),
                    'Group ID': endpoint.get('VerifiedAccessGroupId', 'N/A'),
                    'Endpoint Type': endpoint_type,
                    'Attachment Type': attachment_type,
                    'Endpoint Domain': endpoint_domain,
                    'Application Domain': application_domain,
                    'Status': status,
                    'Load Balancer ARN': load_balancer_arn if endpoint_type == 'load-balancer' else 'N/A',
                    'LB Protocol/Port': f"{lb_protocol}:{lb_port}" if endpoint_type == 'load-balancer' else 'N/A',
                    'Network Interface ID': network_interface_id if endpoint_type == 'network-interface' else 'N/A',
                    'NI Protocol/Port': f"{ni_protocol}:{ni_port}" if endpoint_type == 'network-interface' else 'N/A',
                    'Policy Enabled': policy_enabled,
                    'Policy Document (Preview)': policy_document,
                    'Description': endpoint.get('Description', 'N/A'),
                    'Creation Time': endpoint.get('CreationTime', 'N/A'),
                    'Last Updated Time': endpoint.get('LastUpdatedTime', 'N/A'),
                    'Deletion Time': endpoint.get('DeletionTime', 'N/A'),
                    'Tags': format_tags(endpoint.get('Tags', []))
                }

                endpoints.append(endpoint_info)

        if endpoints:
            utils.log_success(f"Found {len(endpoints)} Verified Access endpoints in {region}")

    except Exception as e:
        utils.log_warning(f"No endpoints found in {region} or service not available: {e}")

    return endpoints

@utils.aws_error_handler("Collecting Access Logs Configuration", default_return=[])
def collect_access_logs_config(region: str, instances: List[Dict]) -> List[Dict[str, Any]]:
    """Collect Access Logs configuration for Verified Access instances."""
    utils.log_info(f"Collecting Access Logs configurations in {region}...")

    va_client = utils.get_boto3_client('verifiedaccess', region_name=region)
    logs_configs = []

    for instance in instances:
        instance_id = instance.get('Instance ID', 'N/A')

        try:
            # Get logging configuration for each instance
            response = va_client.describe_verified_access_instance_logging_configurations(
                VerifiedAccessInstanceIds=[instance_id]
            )

            for config in response.get('LoggingConfigurations', []):
                access_logs = config.get('AccessLogs', {})

                # CloudWatch Logs
                cloudwatch = access_logs.get('CloudWatchLogs', {})
                cloudwatch_enabled = cloudwatch.get('Enabled', False)
                cloudwatch_log_group = cloudwatch.get('LogGroup', 'N/A')

                # Kinesis Data Firehose
                kinesis = access_logs.get('KinesisDataFirehose', {})
                kinesis_enabled = kinesis.get('Enabled', False)
                kinesis_delivery_stream = kinesis.get('DeliveryStream', 'N/A')

                # S3
                s3 = access_logs.get('S3', {})
                s3_enabled = s3.get('Enabled', False)
                s3_bucket_name = s3.get('BucketName', 'N/A')
                s3_prefix = s3.get('Prefix', 'N/A')

                log_version = access_logs.get('LogVersion', 'N/A')
                include_trust_context = access_logs.get('IncludeTrustContext', False)

                logs_config = {
                    'Region': region,
                    'Instance ID': instance_id,
                    'CloudWatch Logs Enabled': 'Yes' if cloudwatch_enabled else 'No',
                    'CloudWatch Log Group': cloudwatch_log_group if cloudwatch_enabled else 'N/A',
                    'Kinesis Enabled': 'Yes' if kinesis_enabled else 'No',
                    'Kinesis Delivery Stream': kinesis_delivery_stream if kinesis_enabled else 'N/A',
                    'S3 Enabled': 'Yes' if s3_enabled else 'No',
                    'S3 Bucket': s3_bucket_name if s3_enabled else 'N/A',
                    'S3 Prefix': s3_prefix if s3_enabled else 'N/A',
                    'Log Version': log_version,
                    'Include Trust Context': 'Yes' if include_trust_context else 'No'
                }

                logs_configs.append(logs_config)

        except Exception as e:
            utils.log_warning(f"Could not get logging config for instance {instance_id}: {e}")

    if logs_configs:
        utils.log_success(f"Found {len(logs_configs)} logging configurations in {region}")

    return logs_configs

def create_summary(instances: List[Dict], trust_providers: List[Dict], groups: List[Dict],
                  endpoints: List[Dict], logs_configs: List[Dict]) -> Dict[str, Any]:
    """Create summary statistics for Verified Access."""
    summary = {
        'Category': [
            'Verified Access Instances',
            '',
            'Trust Providers',
            'Trust Providers - User Type',
            'Trust Providers - Device Type',
            'Trust Providers - Jamf',
            'Trust Providers - CrowdStrike',
            'Trust Providers - JumpCloud',
            '',
            'Verified Access Groups',
            'Groups - With Policy Enabled',
            '',
            'Verified Access Endpoints',
            'Endpoints - Active',
            'Endpoints - Load Balancer Type',
            'Endpoints - Network Interface Type',
            'Endpoints - With Policy Enabled',
            '',
            'Access Logging',
            'CloudWatch Logs Enabled',
            'Kinesis Data Firehose Enabled',
            'S3 Logging Enabled',
            '',
            'Configuration Status'
        ],
        'Count': [
            len(instances),
            '',
            len(trust_providers),
            len([tp for tp in trust_providers if tp.get('Trust Provider Type') == 'user']),
            len([tp for tp in trust_providers if tp.get('Trust Provider Type') == 'device']),
            len([tp for tp in trust_providers if tp.get('Device Trust Provider Type') == 'jamf']),
            len([tp for tp in trust_providers if tp.get('Device Trust Provider Type') == 'crowdstrike']),
            len([tp for tp in trust_providers if tp.get('Device Trust Provider Type') == 'jumpcloud']),
            '',
            len(groups),
            len([g for g in groups if g.get('Policy Enabled') == 'Yes']),
            '',
            len(endpoints),
            len([e for e in endpoints if e.get('Status') == 'active']),
            len([e for e in endpoints if e.get('Endpoint Type') == 'load-balancer']),
            len([e for e in endpoints if e.get('Endpoint Type') == 'network-interface']),
            len([e for e in endpoints if e.get('Policy Enabled') == 'Yes']),
            '',
            len(logs_configs),
            len([lc for lc in logs_configs if lc.get('CloudWatch Logs Enabled') == 'Yes']),
            len([lc for lc in logs_configs if lc.get('Kinesis Enabled') == 'Yes']),
            len([lc for lc in logs_configs if lc.get('S3 Enabled') == 'Yes']),
            '',
            'Configured' if (instances or trust_providers or groups or endpoints) else 'Not Configured'
        ]
    }

    return summary

def export_to_excel(all_data: Dict[str, List[Dict]], account_id: str, account_name: str) -> str:
    """Export Verified Access data to Excel with multiple sheets."""
    try:
        import pandas as pd

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(account_name, "verifiedaccess", "comprehensive", current_date)

        # Prepare data frames
        data_frames = {}

        # Summary sheet
        summary_data = create_summary(
            all_data['instances'],
            all_data['trust_providers'],
            all_data['groups'],
            all_data['endpoints'],
            all_data['logs_configs']
        )
        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Instances sheet
        if all_data['instances']:
            instances_df = pd.DataFrame(all_data['instances'])
            instances_df = utils.prepare_dataframe_for_export(instances_df)
            data_frames['Instances'] = instances_df
        else:
            data_frames['Instances'] = pd.DataFrame({
                'Status': ['No Verified Access instances configured'],
                'Note': ['AWS Verified Access may not be in use in this account']
            })

        # Trust Providers sheet
        if all_data['trust_providers']:
            trust_providers_df = pd.DataFrame(all_data['trust_providers'])
            trust_providers_df = utils.prepare_dataframe_for_export(trust_providers_df)
            data_frames['Trust Providers'] = trust_providers_df
        else:
            data_frames['Trust Providers'] = pd.DataFrame({
                'Status': ['No trust providers configured'],
                'Note': ['Trust providers are required for Verified Access']
            })

        # Groups sheet
        if all_data['groups']:
            groups_df = pd.DataFrame(all_data['groups'])
            groups_df = utils.prepare_dataframe_for_export(groups_df)
            data_frames['Groups'] = groups_df
        else:
            data_frames['Groups'] = pd.DataFrame({
                'Status': ['No Verified Access groups configured'],
                'Note': ['Groups organize endpoints and apply policies']
            })

        # Endpoints sheet
        if all_data['endpoints']:
            endpoints_df = pd.DataFrame(all_data['endpoints'])
            endpoints_df = utils.prepare_dataframe_for_export(endpoints_df)
            data_frames['Endpoints'] = endpoints_df
        else:
            data_frames['Endpoints'] = pd.DataFrame({
                'Status': ['No Verified Access endpoints configured'],
                'Note': ['Endpoints represent protected applications']
            })

        # Access Logs sheet
        if all_data['logs_configs']:
            logs_df = pd.DataFrame(all_data['logs_configs'])
            logs_df = utils.prepare_dataframe_for_export(logs_df)
            data_frames['Access Logs'] = logs_df
        else:
            data_frames['Access Logs'] = pd.DataFrame({
                'Status': ['No access logging configured'],
                'Note': ['Access logs can be sent to CloudWatch, Kinesis, or S3']
            })

        # Save using utils function
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS Verified Access data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            total_resources = (len(all_data['instances']) + len(all_data['trust_providers']) +
                             len(all_data['groups']) + len(all_data['endpoints']))
            utils.log_info(f"Export contains {total_resources} total resources across all regions")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """Main function to orchestrate Verified Access data collection."""
    try:
        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Print title and get account info
        account_id, account_name = utils.print_script_banner("AWS VERIFIED ACCESS COMPREHENSIVE EXPORT")

        # Validate AWS credentials
        is_valid, validated_account_id, error_message = utils.validate_aws_credentials()
        if not is_valid:
            utils.log_error(f"AWS credentials validation failed: {error_message}")
            print("\nPlease configure your credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return

        utils.log_success("AWS credentials validated")

        # Get regions to scan
        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        utils.log_info("Starting AWS Verified Access data collection...")
        print("====================================================================")
        print("\nNOTE: AWS Verified Access provides secure access to applications")
        print("without a VPN using zero-trust principles. If not configured, this")
        print("export will create a report indicating the service is not in use.")
        print("====================================================================\n")

        # Collect data across all regions using concurrent scanning
        print("\n=== COLLECTING VERIFIED ACCESS RESOURCES ===")

        # Collect instances, trust providers, groups, and endpoints concurrently
        print("Collecting Verified Access Instances...")
        instances_results = utils.scan_regions_concurrent(regions, collect_verified_access_instances)
        all_instances = [inst for result in instances_results for inst in result]
        utils.log_success(f"Total instances collected: {len(all_instances)}")

        print("Collecting Trust Providers...")
        tp_results = utils.scan_regions_concurrent(regions, collect_trust_providers)
        all_trust_providers = [tp for result in tp_results for tp in result]
        utils.log_success(f"Total trust providers collected: {len(all_trust_providers)}")

        print("Collecting Verified Access Groups...")
        groups_results = utils.scan_regions_concurrent(regions, collect_verified_access_groups)
        all_groups = [grp for result in groups_results for grp in result]
        utils.log_success(f"Total groups collected: {len(all_groups)}")

        print("Collecting Verified Access Endpoints...")
        endpoints_results = utils.scan_regions_concurrent(regions, collect_verified_access_endpoints)
        all_endpoints = [ep for result in endpoints_results for ep in result]
        utils.log_success(f"Total endpoints collected: {len(all_endpoints)}")

        # Collect access logs configurations (depends on instances per region)
        print("Collecting Access Logs Configurations...")
        all_logs_configs = []
        for region in regions:
            region_instances = [inst for inst in all_instances if inst['Region'] == region]
            if region_instances:
                logs_configs = collect_access_logs_config(region, region_instances)
                all_logs_configs.extend(logs_configs)
        utils.log_success(f"Total access logs configurations collected: {len(all_logs_configs)}")

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Prepare all data for export
        all_data = {
            'instances': all_instances,
            'trust_providers': all_trust_providers,
            'groups': all_groups,
            'endpoints': all_endpoints,
            'logs_configs': all_logs_configs
        }

        # Export even if empty (with helpful messaging)
        filename = export_to_excel(all_data, account_id, account_name)

        if filename:
            total_resources = (len(all_instances) + len(all_trust_providers) +
                             len(all_groups) + len(all_endpoints))

            if total_resources == 0:
                utils.log_info("AWS Verified Access is not configured in scanned regions")
                utils.log_info("The export file contains informational placeholders")
            else:
                utils.log_info(f"Total instances: {len(all_instances)}")
                utils.log_info(f"Total trust providers: {len(all_trust_providers)}")
                utils.log_info(f"Total groups: {len(all_groups)}")
                utils.log_info(f"Total endpoints: {len(all_endpoints)}")
                utils.log_info(f"Regions scanned: {', '.join(regions)}")

            print("\nScript execution completed successfully.")
        else:
            utils.log_error("Export failed. Please check the logs.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
