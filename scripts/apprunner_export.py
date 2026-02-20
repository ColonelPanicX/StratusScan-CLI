#!/usr/bin/env python3
"""
AWS App Runner Export Script for StratusScan

Exports comprehensive AWS App Runner service information including web applications,
API services, auto-scaling configurations, and custom domains.

Features:
- App Runner Services: Container and source code based applications
- Auto Scaling Configurations: CPU and memory-based scaling rules
- VPC Connectors: Private VPC connectivity configurations
- Custom Domains: Domain associations and SSL certificates
- Summary: Service counts, status distribution, and metrics

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


def _scan_apprunner_services_region(region: str) -> List[Dict[str, Any]]:
    """Scan App Runner services in a single region."""
    regional_services = []

    try:
        apprunner_client = utils.get_boto3_client('apprunner', region_name=region)
        paginator = apprunner_client.get_paginator('list_services')
        for page in paginator.paginate():
            service_summaries = page.get('ServiceSummaryList', [])

            for service_summary in service_summaries:
                service_arn = service_summary.get('ServiceArn', 'N/A')
                service_name = service_summary.get('ServiceName', 'N/A')
                service_id = service_summary.get('ServiceId', 'N/A')
                service_url = service_summary.get('ServiceUrl', 'N/A')
                status = service_summary.get('Status', 'N/A')

                # Get detailed service information
                try:
                    service_response = apprunner_client.describe_service(ServiceArn=service_arn)
                    service = service_response.get('Service', {})

                    # Source configuration
                    source_config = service.get('SourceConfiguration', {})

                    # Image repository or code repository
                    image_repo = source_config.get('ImageRepository', {})
                    code_repo = source_config.get('CodeRepository', {})

                    if image_repo:
                        source_type = 'Container Image'
                        image_identifier = image_repo.get('ImageIdentifier', 'N/A')
                        image_repo_type = image_repo.get('ImageRepositoryType', 'N/A')
                        source_details = f"{image_repo_type}: {image_identifier}"
                    elif code_repo:
                        source_type = 'Source Code'
                        repo_url = code_repo.get('RepositoryUrl', 'N/A')
                        source_code_version = code_repo.get('SourceCodeVersion', {})
                        branch = source_code_version.get('Value', 'N/A')
                        source_details = f"Branch: {branch}"
                    else:
                        source_type = 'Unknown'
                        source_details = 'N/A'

                    # Auto deployment
                    auto_deploy_enabled = source_config.get('AutoDeploymentsEnabled', False)

                    # Instance configuration
                    instance_config = service.get('InstanceConfiguration', {})
                    cpu = instance_config.get('Cpu', 'N/A')
                    memory = instance_config.get('Memory', 'N/A')
                    instance_role_arn = instance_config.get('InstanceRoleArn', 'N/A')

                    # Extract role name
                    instance_role = 'N/A'
                    if instance_role_arn != 'N/A' and '/' in instance_role_arn:
                        instance_role = instance_role_arn.split('/')[-1]

                    # Health check configuration
                    health_check_config = service.get('HealthCheckConfiguration', {})
                    health_check_protocol = health_check_config.get('Protocol', 'N/A')
                    health_check_path = health_check_config.get('Path', 'N/A')
                    health_check_interval = health_check_config.get('Interval', 'N/A')
                    health_check_timeout = health_check_config.get('Timeout', 'N/A')

                    # Auto scaling configuration ARN
                    auto_scaling_config_arn = service.get('AutoScalingConfigurationSummary', {}).get('AutoScalingConfigurationArn', 'N/A')
                    auto_scaling_config_name = service.get('AutoScalingConfigurationSummary', {}).get('AutoScalingConfigurationName', 'N/A')

                    # Network configuration
                    network_config = service.get('NetworkConfiguration', {})
                    egress_config = network_config.get('EgressConfiguration', {})
                    egress_type = egress_config.get('EgressType', 'DEFAULT')  # DEFAULT or VPC
                    vpc_connector_arn = egress_config.get('VpcConnectorArn', 'N/A') if egress_type == 'VPC' else 'N/A'

                    # Encryption configuration
                    encryption_config = service.get('EncryptionConfiguration', {})
                    kms_key = encryption_config.get('KmsKey', 'AWS Managed')

                    # Created and updated timestamps
                    created_at = service.get('CreatedAt')
                    if created_at:
                        created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        created_at_str = 'N/A'

                    updated_at = service.get('UpdatedAt')
                    if updated_at:
                        updated_at_str = updated_at.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        updated_at_str = 'N/A'

                    regional_services.append({
                        'Region': region,
                        'Service Name': service_name,
                        'Service ID': service_id,
                        'Status': status,
                        'Service URL': service_url,
                        'Source Type': source_type,
                        'Source Details': source_details,
                        'Auto Deploy': 'Enabled' if auto_deploy_enabled else 'Disabled',
                        'CPU': cpu,
                        'Memory': memory,
                        'Instance Role': instance_role,
                        'Health Check Protocol': health_check_protocol,
                        'Health Check Path': health_check_path,
                        'Health Check Interval (s)': health_check_interval,
                        'Health Check Timeout (s)': health_check_timeout,
                        'Auto Scaling Config': auto_scaling_config_name,
                        'Egress Type': egress_type,
                        'VPC Connector': vpc_connector_arn if egress_type == 'VPC' else 'N/A',
                        'KMS Key': kms_key,
                        'Created': created_at_str,
                        'Updated': updated_at_str,
                        'Service ARN': service_arn,
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for service {service_name}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_error(f"Error collecting App Runner services in {region}", e)

    return regional_services


@utils.aws_error_handler("Collecting App Runner services", default_return=[])
def collect_apprunner_services(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect App Runner service information from AWS regions."""
    print("\n=== COLLECTING APP RUNNER SERVICES ===")
    results = utils.scan_regions_concurrent(regions, _scan_apprunner_services_region)
    all_services = [svc for result in results for svc in result]
    utils.log_success(f"Total App Runner services collected: {len(all_services)}")
    return all_services


def _scan_auto_scaling_configs_region(region: str) -> List[Dict[str, Any]]:
    """Scan App Runner auto scaling configs in a single region."""
    regional_configs = []

    try:
        apprunner_client = utils.get_boto3_client('apprunner', region_name=region)
        paginator = apprunner_client.get_paginator('list_auto_scaling_configurations')
        for page in paginator.paginate():
            config_summaries = page.get('AutoScalingConfigurationSummaryList', [])

            for config_summary in config_summaries:
                config_arn = config_summary.get('AutoScalingConfigurationArn', 'N/A')
                config_name = config_summary.get('AutoScalingConfigurationName', 'N/A')
                config_revision = config_summary.get('AutoScalingConfigurationRevision', 'N/A')

                # Get detailed configuration
                try:
                    config_response = apprunner_client.describe_auto_scaling_configuration(
                        AutoScalingConfigurationArn=config_arn
                    )
                    config = config_response.get('AutoScalingConfiguration', {})

                    max_concurrency = config.get('MaxConcurrency', 'N/A')
                    min_size = config.get('MinSize', 'N/A')
                    max_size = config.get('MaxSize', 'N/A')
                    status = config.get('Status', 'N/A')

                    # Creation timestamp
                    created_at = config.get('CreatedAt')
                    if created_at:
                        created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        created_at_str = 'N/A'

                    regional_configs.append({
                        'Region': region,
                        'Config Name': config_name,
                        'Revision': config_revision,
                        'Status': status,
                        'Max Concurrency': max_concurrency,
                        'Min Size': min_size,
                        'Max Size': max_size,
                        'Created': created_at_str,
                        'Config ARN': config_arn,
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for auto scaling config {config_name}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_error(f"Error collecting App Runner auto scaling configs in {region}", e)

    return regional_configs


@utils.aws_error_handler("Collecting App Runner auto scaling configs", default_return=[])
def collect_auto_scaling_configs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect App Runner auto scaling configuration information from AWS regions."""
    print("\n=== COLLECTING APP RUNNER AUTO SCALING CONFIGS ===")
    results = utils.scan_regions_concurrent(regions, _scan_auto_scaling_configs_region)
    all_configs = [cfg for result in results for cfg in result]
    utils.log_success(f"Total App Runner auto scaling configs collected: {len(all_configs)}")
    return all_configs


def _scan_vpc_connectors_region(region: str) -> List[Dict[str, Any]]:
    """Scan App Runner VPC connectors in a single region."""
    regional_connectors = []

    try:
        apprunner_client = utils.get_boto3_client('apprunner', region_name=region)
        paginator = apprunner_client.get_paginator('list_vpc_connectors')
        for page in paginator.paginate():
            connector_summaries = page.get('VpcConnectors', [])

            for connector_summary in connector_summaries:
                connector_arn = connector_summary.get('VpcConnectorArn', 'N/A')
                connector_name = connector_summary.get('VpcConnectorName', 'N/A')
                status = connector_summary.get('Status', 'N/A')

                # Get detailed connector information
                try:
                    connector_response = apprunner_client.describe_vpc_connector(
                        VpcConnectorArn=connector_arn
                    )
                    connector = connector_response.get('VpcConnector', {})

                    vpc_connector_revision = connector.get('VpcConnectorRevision', 'N/A')
                    subnets = connector.get('Subnets', [])
                    subnets_str = ', '.join(subnets) if subnets else 'N/A'

                    security_groups = connector.get('SecurityGroups', [])
                    security_groups_str = ', '.join(security_groups) if security_groups else 'N/A'

                    # Creation timestamp
                    created_at = connector.get('CreatedAt')
                    if created_at:
                        created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        created_at_str = 'N/A'

                    regional_connectors.append({
                        'Region': region,
                        'Connector Name': connector_name,
                        'Revision': vpc_connector_revision,
                        'Status': status,
                        'Subnets': subnets_str,
                        'Security Groups': security_groups_str,
                        'Created': created_at_str,
                        'Connector ARN': connector_arn,
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for VPC connector {connector_name}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_error(f"Error collecting App Runner VPC connectors in {region}", e)

    return regional_connectors


@utils.aws_error_handler("Collecting App Runner VPC connectors", default_return=[])
def collect_vpc_connectors(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect App Runner VPC connector information from AWS regions."""
    print("\n=== COLLECTING APP RUNNER VPC CONNECTORS ===")
    results = utils.scan_regions_concurrent(regions, _scan_vpc_connectors_region)
    all_connectors = [conn for result in results for conn in result]
    utils.log_success(f"Total App Runner VPC connectors collected: {len(all_connectors)}")
    return all_connectors


@utils.aws_error_handler("Collecting App Runner custom domains", default_return=[])
def collect_custom_domains(regions: List[str], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect App Runner custom domain associations from AWS regions."""
    all_domains = []

    for region in regions:
        utils.log_info(f"Scanning App Runner custom domains in {region}...")
        apprunner_client = utils.get_boto3_client('apprunner', region_name=region)

        # Get custom domains for each service
        region_services = [s for s in services if s['Region'] == region]

        for service in region_services:
            service_arn = service['Service ARN']
            service_name = service['Service Name']

            try:
                paginator = apprunner_client.get_paginator('list_custom_domains')
                for page in paginator.paginate(ServiceArn=service_arn):
                    custom_domains = page.get('CustomDomains', [])

                    for domain in custom_domains:
                        domain_name = domain.get('DomainName', 'N/A')
                        enable_www_subdomain = domain.get('EnableWWWSubdomain', False)
                        status = domain.get('Status', 'N/A')

                        # Certificate validation records
                        cert_validation_records = domain.get('CertificateValidationRecords', [])
                        cert_records_str = 'N/A'
                        if cert_validation_records:
                            records = [f"{r.get('Name', '')}: {r.get('Value', '')}" for r in cert_validation_records]
                            cert_records_str = ' | '.join(records[:2])  # First 2 records
                            if len(cert_validation_records) > 2:
                                cert_records_str += f" (+{len(cert_validation_records) - 2} more)"

                        all_domains.append({
                            'Region': region,
                            'Service Name': service_name,
                            'Domain Name': domain_name,
                            'WWW Subdomain': 'Enabled' if enable_www_subdomain else 'Disabled',
                            'Status': status,
                            'Certificate Validation': cert_records_str,
                        })

            except Exception as e:
                utils.log_warning(f"Could not get custom domains for service {service_name}: {str(e)}")
                continue

        utils.log_success(f"Collected {len([d for d in all_domains if d['Region'] == region])} App Runner custom domains from {region}")

    return all_domains


def generate_summary(services: List[Dict[str, Any]],
                     auto_scaling_configs: List[Dict[str, Any]],
                     vpc_connectors: List[Dict[str, Any]],
                     custom_domains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for App Runner resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total App Runner Services',
        'Count': len(services),
        'Details': f"{len([s for s in services if s['Status'] == 'RUNNING'])} running"
    })

    summary.append({
        'Metric': 'Total Auto Scaling Configs',
        'Count': len(auto_scaling_configs),
        'Details': f"{len(auto_scaling_configs)} scaling configurations"
    })

    summary.append({
        'Metric': 'Total VPC Connectors',
        'Count': len(vpc_connectors),
        'Details': f"{len(vpc_connectors)} VPC connectors for private networking"
    })

    summary.append({
        'Metric': 'Total Custom Domains',
        'Count': len(custom_domains),
        'Details': f"{len(custom_domains)} custom domain associations"
    })

    # Source types
    if services:
        source_types = {}
        for service in services:
            source_type = service['Source Type']
            source_types[source_type] = source_types.get(source_type, 0) + 1

        type_details = ', '.join([f"{stype}: {count}" for stype, count in sorted(source_types.items())])
        summary.append({
            'Metric': 'Services by Source Type',
            'Count': len(source_types),
            'Details': type_details
        })

    # Auto deployment
    if services:
        auto_deploy_enabled = len([s for s in services if s['Auto Deploy'] == 'Enabled'])
        summary.append({
            'Metric': 'Auto Deployment Enabled',
            'Count': auto_deploy_enabled,
            'Details': f"{auto_deploy_enabled}/{len(services)} services with auto deployment"
        })

    # VPC connectivity
    if services:
        vpc_connected = len([s for s in services if s['Egress Type'] == 'VPC'])
        summary.append({
            'Metric': 'VPC Connected Services',
            'Count': vpc_connected,
            'Details': f"{vpc_connected}/{len(services)} services connected to VPC"
        })

    # Services by region
    if services:
        regions = {}
        for service in services:
            region = service['Region']
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'Services by Region',
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
    regions = utils.prompt_region_selection()
    # Collect data
    print("\n=== Collecting App Runner Data ===")
    services = collect_apprunner_services(regions)
    auto_scaling_configs = collect_auto_scaling_configs(regions)
    vpc_connectors = collect_vpc_connectors(regions)
    custom_domains = collect_custom_domains(regions, services)

    # Generate summary
    summary = generate_summary(services, auto_scaling_configs, vpc_connectors, custom_domains)

    # Convert to DataFrames
    services_df = pd.DataFrame(services) if services else pd.DataFrame()
    auto_scaling_df = pd.DataFrame(auto_scaling_configs) if auto_scaling_configs else pd.DataFrame()
    vpc_connectors_df = pd.DataFrame(vpc_connectors) if vpc_connectors else pd.DataFrame()
    custom_domains_df = pd.DataFrame(custom_domains) if custom_domains else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not services_df.empty:
        services_df = utils.prepare_dataframe_for_export(services_df)
    if not auto_scaling_df.empty:
        auto_scaling_df = utils.prepare_dataframe_for_export(auto_scaling_df)
    if not vpc_connectors_df.empty:
        vpc_connectors_df = utils.prepare_dataframe_for_export(vpc_connectors_df)
    if not custom_domains_df.empty:
        custom_domains_df = utils.prepare_dataframe_for_export(custom_domains_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'apprunner', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'App Runner Services': services_df,
        'Auto Scaling Configs': auto_scaling_df,
        'VPC Connectors': vpc_connectors_df,
        'Custom Domains': custom_domains_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(services) + len(auto_scaling_configs) + len(vpc_connectors) + len(custom_domains),
            details={
                'Services': len(services),
                'Auto Scaling Configs': len(auto_scaling_configs),
                'VPC Connectors': len(vpc_connectors),
                'Custom Domains': len(custom_domains)
            }
        )

    utils.log_script_end(script_name)


if __name__ == "__main__":
    main()
