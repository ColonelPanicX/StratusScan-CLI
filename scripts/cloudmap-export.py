#!/usr/bin/env python3
"""
AWS Cloud Map (Service Discovery) Export Script for StratusScan

Exports comprehensive AWS Cloud Map information including:
- Namespaces (HTTP, private DNS, public DNS)
- Services and their discovery configurations
- Service instances with attributes and health status
- Operations history

Output: Multi-worksheet Excel file with Cloud Map resources
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
def _scan_namespaces_region(region: str) -> List[Dict[str, Any]]:
    """Scan Cloud Map namespaces in a single region."""
    regional_namespaces = []
    sd_client = utils.get_boto3_client('servicediscovery', region_name=region)

    try:
        paginator = sd_client.get_paginator('list_namespaces')
        for page in paginator.paginate():
            namespaces = page.get('Namespaces', [])

            for namespace_summary in namespaces:
                namespace_id = namespace_summary.get('Id', 'N/A')
                namespace_name = namespace_summary.get('Name', 'N/A')
                namespace_type = namespace_summary.get('Type', 'N/A')

                try:
                    # Get detailed namespace information
                    namespace_response = sd_client.get_namespace(
                        Id=namespace_id
                    )
                    namespace_details = namespace_response.get('Namespace', {})

                    description = namespace_details.get('Description', 'N/A')
                    service_count = namespace_details.get('ServiceCount', 0)
                    arn = namespace_details.get('Arn', 'N/A')
                    create_date = namespace_details.get('CreateDate', 'N/A')
                    if create_date != 'N/A':
                        create_date = create_date.strftime('%Y-%m-%d %H:%M:%S')

                    # Properties specific to namespace type
                    properties = namespace_details.get('Properties', {})
                    dns_properties = properties.get('DnsProperties', {})
                    http_properties = properties.get('HttpProperties', {})

                    hosted_zone_id = dns_properties.get('HostedZoneId', 'N/A')
                    http_name = http_properties.get('HttpName', 'N/A')

                    regional_namespaces.append({
                        'Region': region,
                        'Namespace ID': namespace_id,
                        'Namespace Name': namespace_name,
                        'Type': namespace_type,
                        'Description': description,
                        'Service Count': service_count,
                        'Hosted Zone ID': hosted_zone_id,
                        'HTTP Name': http_name,
                        'Created': create_date,
                        'ARN': arn
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for namespace {namespace_id} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing namespaces in {region}: {str(e)}")

    return regional_namespaces


@utils.aws_error_handler("Collecting Cloud Map namespaces", default_return=[])
def collect_namespaces(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Cloud Map namespace information from AWS regions."""
    print("\n=== COLLECTING CLOUD MAP NAMESPACES ===")
    results = utils.scan_regions_concurrent(regions, _scan_namespaces_region)
    all_namespaces = [namespace for result in results for namespace in result]
    utils.log_success(f"Total namespaces collected: {len(all_namespaces)}")
    return all_namespaces


def _scan_services_region(region: str) -> List[Dict[str, Any]]:
    """Scan Cloud Map services in a single region."""
    regional_services = []
    sd_client = utils.get_boto3_client('servicediscovery', region_name=region)

    try:
        paginator = sd_client.get_paginator('list_services')
        for page in paginator.paginate():
            services = page.get('Services', [])

            for service_summary in services:
                service_id = service_summary.get('Id', 'N/A')
                service_name = service_summary.get('Name', 'N/A')

                try:
                    # Get detailed service information
                    service_response = sd_client.get_service(
                        Id=service_id
                    )
                    service_details = service_response.get('Service', {})

                    namespace_id = service_details.get('NamespaceId', 'N/A')
                    description = service_details.get('Description', 'N/A')
                    instance_count = service_details.get('InstanceCount', 0)
                    arn = service_details.get('Arn', 'N/A')
                    create_date = service_details.get('CreateDate', 'N/A')
                    if create_date != 'N/A':
                        create_date = create_date.strftime('%Y-%m-%d %H:%M:%S')

                    # DNS configuration
                    dns_config = service_details.get('DnsConfig', {})
                    routing_policy = dns_config.get('RoutingPolicy', 'N/A')
                    dns_records = dns_config.get('DnsRecords', [])
                    dns_records_str = 'N/A'
                    if dns_records:
                        dns_records_str = ', '.join([f"{r.get('Type', 'N/A')}:{r.get('TTL', 'N/A')}" for r in dns_records])

                    # Health check configuration
                    health_check_config = service_details.get('HealthCheckConfig', {})
                    health_check_type = health_check_config.get('Type', 'N/A')
                    resource_path = health_check_config.get('ResourcePath', 'N/A')
                    failure_threshold = health_check_config.get('FailureThreshold', 'N/A')

                    # Health check custom config
                    health_check_custom_config = service_details.get('HealthCheckCustomConfig', {})
                    failure_threshold_custom = health_check_custom_config.get('FailureThreshold', 'N/A')

                    regional_services.append({
                        'Region': region,
                        'Service ID': service_id,
                        'Service Name': service_name,
                        'Namespace ID': namespace_id,
                        'Description': description,
                        'Instance Count': instance_count,
                        'Routing Policy': routing_policy,
                        'DNS Records': dns_records_str,
                        'Health Check Type': health_check_type,
                        'Health Check Path': resource_path,
                        'Health Check Failure Threshold': failure_threshold if failure_threshold != 'N/A' else failure_threshold_custom,
                        'Created': create_date,
                        'ARN': arn
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for service {service_id} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing services in {region}: {str(e)}")

    return regional_services


@utils.aws_error_handler("Collecting Cloud Map services", default_return=[])
def collect_services(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Cloud Map service information from AWS regions."""
    print("\n=== COLLECTING CLOUD MAP SERVICES ===")
    results = utils.scan_regions_concurrent(regions, _scan_services_region)
    all_services = [service for result in results for service in result]
    utils.log_success(f"Total services collected: {len(all_services)}")
    return all_services


def _scan_service_instances_region(region: str) -> List[Dict[str, Any]]:
    """Scan service instances in a single region."""
    regional_instances = []
    sd_client = utils.get_boto3_client('servicediscovery', region_name=region)

    try:
        # Get all services first
        services_paginator = sd_client.get_paginator('list_services')
        for services_page in services_paginator.paginate():
            services = services_page.get('Services', [])

            for service in services:
                service_id = service.get('Id', 'N/A')
                service_name = service.get('Name', 'N/A')

                try:
                    # List instances for this service
                    instances_paginator = sd_client.get_paginator('list_instances')
                    for instances_page in instances_paginator.paginate(ServiceId=service_id):
                        instances = instances_page.get('Instances', [])

                        for instance in instances:
                            instance_id = instance.get('Id', 'N/A')

                            # Attributes
                            attributes = instance.get('Attributes', {})
                            attributes_str = json.dumps(attributes) if attributes else 'None'

                            regional_instances.append({
                                'Region': region,
                                'Service ID': service_id,
                                'Service Name': service_name,
                                'Instance ID': instance_id,
                                'Attributes': attributes_str
                            })

                except Exception as e:
                    utils.log_warning(f"Could not list instances for service {service_id} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing service instances in {region}: {str(e)}")

    return regional_instances


@utils.aws_error_handler("Collecting service instances", default_return=[])
def collect_service_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect service instance information from AWS regions."""
    print("\n=== COLLECTING SERVICE INSTANCES ===")
    results = utils.scan_regions_concurrent(regions, _scan_service_instances_region)
    all_instances = [instance for result in results for instance in result]
    utils.log_success(f"Total service instances collected: {len(all_instances)}")
    return all_instances


def generate_summary(namespaces: List[Dict[str, Any]],
                     services: List[Dict[str, Any]],
                     instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Cloud Map resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Namespaces summary
    total_namespaces = len(namespaces)
    http_namespaces = sum(1 for n in namespaces if n.get('Type', '') == 'HTTP')
    dns_private_namespaces = sum(1 for n in namespaces if n.get('Type', '') == 'DNS_PRIVATE')
    dns_public_namespaces = sum(1 for n in namespaces if n.get('Type', '') == 'DNS_PUBLIC')

    summary.append({
        'Metric': 'Total Namespaces',
        'Count': total_namespaces,
        'Details': f'HTTP: {http_namespaces}, Private DNS: {dns_private_namespaces}, Public DNS: {dns_public_namespaces}'
    })

    # Services summary
    total_services = len(services)
    multicast_services = sum(1 for s in services if s.get('Routing Policy', '') == 'MULTIVALUE')
    weighted_services = sum(1 for s in services if s.get('Routing Policy', '') == 'WEIGHTED')
    services_with_health_checks = sum(1 for s in services if s.get('Health Check Type', 'N/A') != 'N/A')

    summary.append({
        'Metric': 'Total Services',
        'Count': total_services,
        'Details': f'Multivalue: {multicast_services}, Weighted: {weighted_services}'
    })

    summary.append({
        'Metric': 'Services with Health Checks',
        'Count': services_with_health_checks,
        'Details': 'Services configured with health checking'
    })

    # Instances summary
    summary.append({
        'Metric': 'Total Service Instances',
        'Count': len(instances),
        'Details': 'Registered service instances'
    })

    # Regional distribution
    if namespaces:
        df = pd.DataFrame(namespaces)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Namespaces in {region}',
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
    print("AWS Cloud Map (Service Discovery) Export Tool")
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
    print("\nCollecting Cloud Map data...")

    namespaces = collect_namespaces(regions)
    services = collect_services(regions)
    instances = collect_service_instances(regions)
    summary = generate_summary(namespaces, services, instances)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if namespaces:
        df_namespaces = pd.DataFrame(namespaces)
        df_namespaces = utils.prepare_dataframe_for_export(df_namespaces)
        dataframes['Namespaces'] = df_namespaces

    if services:
        df_services = pd.DataFrame(services)
        df_services = utils.prepare_dataframe_for_export(df_services)
        dataframes['Services'] = df_services

    if instances:
        df_instances = pd.DataFrame(instances)
        df_instances = utils.prepare_dataframe_for_export(df_instances)
        dataframes['Service Instances'] = df_instances

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'cloudmap', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Namespaces': len(namespaces),
            'Services': len(services),
            'Service Instances': len(instances)
        })
    else:
        utils.log_warning("No Cloud Map data found to export")

    utils.log_success("Cloud Map export completed successfully")


if __name__ == "__main__":
    main()
