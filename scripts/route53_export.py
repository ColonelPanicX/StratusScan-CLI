#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Route 53 DNS Service Export Tool
Date: NOV-11-2025

Description:
This script exports comprehensive Route 53 DNS service information from AWS into an Excel file
with multiple worksheets. The output includes hosted zones, DNS records, health checks, resolver
endpoints, resolver rules, and query logging configurations.

Features:
- Hosted zones (public and private) with DNSSEC status
- DNS records with routing policies and health checks
- Health checks with endpoint monitoring details
- Resolver endpoints (inbound/outbound) and VPC associations
- Resolver rules for DNS forwarding
- Query logging configurations
- Comprehensive summary sheet

Notes:
- Route 53 is a global service (uses us-east-1 endpoint)
- Route 53 Resolver is regional and requires multi-region scanning
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


@utils.aws_error_handler("Collecting Route 53 hosted zones", default_return=[])
def collect_hosted_zones() -> List[Dict[str, Any]]:
    """
    Collect Route 53 hosted zone information.

    Returns:
        list: List of dictionaries with hosted zone details
    """
    print("\n=== COLLECTING HOSTED ZONES ===")
    utils.log_info("Route 53 is a global service - collecting from us-east-1")

    zones = []
    # Route53 is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    route53 = utils.get_boto3_client('route53', region_name=home_region)

    # Use paginator to handle large numbers of zones
    paginator = route53.get_paginator('list_hosted_zones')

    total_count = 0
    for page in paginator.paginate():
        zone_list = page.get('HostedZones', [])
        total_count += len(zone_list)

        for zone in zone_list:
            zone_id = zone.get('Id', '').split('/')[-1]  # Extract ID from ARN
            zone_name = zone.get('Name', '')

            print(f"  Processing hosted zone: {zone_name} ({zone_id})")

            try:
                # Get detailed zone information
                zone_detail = route53.get_hosted_zone(Id=zone_id)
                zone_info = zone_detail.get('HostedZone', {})
                zone_config = zone_info.get('Config', {})

                # Basic information
                is_private = zone_config.get('PrivateZone', False)
                zone_type = 'Private' if is_private else 'Public'
                comment = zone_config.get('Comment', 'N/A')

                # VPC associations (for private zones)
                vpcs = zone_detail.get('VPCs', [])
                vpc_list = []
                for vpc in vpcs:
                    vpc_id = vpc.get('VPCId', '')
                    vpc_region = vpc.get('VPCRegion', '')
                    vpc_list.append(f"{vpc_id} ({vpc_region})")
                vpc_associations = ', '.join(vpc_list) if vpc_list else 'N/A'

                # Resource record set count
                record_count = zone_info.get('ResourceRecordSetCount', 0)

                # Get DNSSEC status
                dnssec_status = 'N/A'
                try:
                    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
                    dnssec_status = dnssec.get('Status', {}).get('ServeSignature', 'DISABLED')
                except Exception:
                    # DNSSEC not configured
                    dnssec_status = 'NOT_CONFIGURED'

                # Get query logging config
                query_logging = 'Disabled'
                try:
                    query_configs = route53.list_query_logging_configs(HostedZoneId=zone_id)
                    configs = query_configs.get('QueryLoggingConfigs', [])
                    if configs:
                        query_logging = f"Enabled ({len(configs)} configs)"
                except Exception:
                    pass

                # Tags
                try:
                    tags_response = route53.list_tags_for_resource(
                        ResourceType='hostedzone',
                        ResourceId=zone_id
                    )
                    tags_list = tags_response.get('ResourceTagSet', {}).get('Tags', [])
                    tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags_list]) if tags_list else 'N/A'
                except Exception:
                    tags = 'N/A'

                zones.append({
                    'Zone ID': zone_id,
                    'Zone Name': zone_name,
                    'Type': zone_type,
                    'Record Count': record_count,
                    'VPC Associations': vpc_associations,
                    'DNSSEC Status': dnssec_status,
                    'Query Logging': query_logging,
                    'Comment': comment,
                    'Tags': tags
                })

            except Exception as e:
                utils.log_error(f"Error getting details for zone {zone_id}", e)
                zones.append({
                    'Zone ID': zone_id,
                    'Zone Name': zone_name,
                    'Error': f'Could not retrieve full details: {str(e)}'
                })

    print(f"\nTotal hosted zones found: {total_count}")
    utils.log_success(f"Total Route 53 hosted zones collected: {total_count}")

    return zones


@utils.aws_error_handler("Collecting DNS records", default_return=[])
def collect_dns_records() -> List[Dict[str, Any]]:
    """
    Collect DNS record information from all hosted zones.

    Returns:
        list: List of dictionaries with DNS record details
    """
    print("\n=== COLLECTING DNS RECORDS ===")

    records = []
    route53 = utils.get_boto3_client('route53', region_name=home_region)

    # Get all hosted zones
    paginator = route53.get_paginator('list_hosted_zones')

    for page in paginator.paginate():
        zone_list = page.get('HostedZones', [])

        for zone in zone_list:
            zone_id = zone.get('Id', '').split('/')[-1]
            zone_name = zone.get('Name', '')

            print(f"  Processing records for zone: {zone_name}")

            try:
                # Use paginator for large record sets
                record_paginator = route53.get_paginator('list_resource_record_sets')

                for record_page in record_paginator.paginate(HostedZoneId=zone_id):
                    record_sets = record_page.get('ResourceRecordSets', [])

                    for record_set in record_sets:
                        record_name = record_set.get('Name', '')
                        record_type = record_set.get('Type', '')
                        ttl = record_set.get('TTL', 'N/A')

                        # Get record values
                        resource_records = record_set.get('ResourceRecords', [])
                        values = [r.get('Value', '') for r in resource_records]

                        # Alias target
                        alias_target = record_set.get('AliasTarget', {})
                        if alias_target:
                            alias_dns_name = alias_target.get('DNSName', '')
                            alias_zone_id = alias_target.get('HostedZoneId', '')
                            alias_evaluate_health = alias_target.get('EvaluateTargetHealth', False)
                            values.append(f"ALIAS: {alias_dns_name} (Zone: {alias_zone_id}, EvaluateHealth: {alias_evaluate_health})")

                        record_values = ', '.join(values) if values else 'N/A'

                        # Routing policy
                        set_identifier = record_set.get('SetIdentifier', '')
                        weight = record_set.get('Weight', '')
                        region = record_set.get('Region', '')
                        failover = record_set.get('Failover', '')
                        multi_value_answer = record_set.get('MultiValueAnswer', False)
                        geo_location = record_set.get('GeoLocation', {})

                        # Determine routing policy
                        if weight != '':
                            routing_policy = f"Weighted (Weight: {weight})"
                        elif region:
                            routing_policy = f"Latency ({region})"
                        elif failover:
                            routing_policy = f"Failover ({failover})"
                        elif geo_location:
                            continent = geo_location.get('ContinentCode', '')
                            country = geo_location.get('CountryCode', '')
                            subdivision = geo_location.get('SubdivisionCode', '')
                            geo_str = continent or country or subdivision or 'Geolocation'
                            routing_policy = f"Geolocation ({geo_str})"
                        elif multi_value_answer:
                            routing_policy = "Multivalue Answer"
                        else:
                            routing_policy = "Simple"

                        # Health check
                        health_check_id = record_set.get('HealthCheckId', 'N/A')

                        records.append({
                            'Zone Name': zone_name,
                            'Record Name': record_name,
                            'Type': record_type,
                            'Routing Policy': routing_policy,
                            'TTL': ttl,
                            'Values/Alias Target': record_values,
                            'Health Check ID': health_check_id,
                            'Set Identifier': set_identifier if set_identifier else 'N/A'
                        })

            except Exception as e:
                utils.log_error(f"Error collecting records for zone {zone_id}", e)

    utils.log_success(f"Total DNS records collected: {len(records)}")
    return records


@utils.aws_error_handler("Collecting Route 53 health checks", default_return=[])
def collect_health_checks() -> List[Dict[str, Any]]:
    """
    Collect Route 53 health check information.

    Returns:
        list: List of dictionaries with health check details
    """
    print("\n=== COLLECTING HEALTH CHECKS ===")

    health_checks = []
    route53 = utils.get_boto3_client('route53', region_name=home_region)

    # Use paginator
    paginator = route53.get_paginator('list_health_checks')

    for page in paginator.paginate():
        hc_list = page.get('HealthChecks', [])

        for hc in hc_list:
            hc_id = hc.get('Id', '')
            hc_config = hc.get('HealthCheckConfig', {})

            print(f"  Processing health check: {hc_id}")

            # Health check type
            hc_type = hc_config.get('Type', '')

            # Endpoint details
            ip_address = hc_config.get('IPAddress', 'N/A')
            port = hc_config.get('Port', 'N/A')
            resource_path = hc_config.get('ResourcePath', 'N/A')
            fully_qualified_domain_name = hc_config.get('FullyQualifiedDomainName', 'N/A')

            # For calculated health checks
            child_health_checks = hc_config.get('ChildHealthChecks', [])
            if child_health_checks:
                endpoint = f"Calculated ({len(child_health_checks)} children)"
            elif ip_address != 'N/A':
                endpoint = ip_address
            elif fully_qualified_domain_name != 'N/A':
                endpoint = fully_qualified_domain_name
            else:
                endpoint = 'N/A'

            # Request interval and failure threshold
            request_interval = hc_config.get('RequestInterval', 30)
            failure_threshold = hc_config.get('FailureThreshold', 3)

            # Get health check status
            try:
                status_response = route53.get_health_check_status(HealthCheckId=hc_id)
                checkers = status_response.get('HealthCheckObservations', [])
                if checkers:
                    # Check if all checkers report success
                    all_healthy = all(c.get('StatusReport', {}).get('Status', '') == 'Success' for c in checkers)
                    status = 'Healthy' if all_healthy else 'Unhealthy'
                else:
                    status = 'Unknown'
            except Exception:
                status = 'Unknown'

            # CloudWatch alarm
            alarm_name = hc_config.get('AlarmIdentifier', {}).get('Name', 'N/A')

            # Tags
            try:
                tags_response = route53.list_tags_for_resource(
                    ResourceType='healthcheck',
                    ResourceId=hc_id
                )
                tags_list = tags_response.get('ResourceTagSet', {}).get('Tags', [])
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags_list]) if tags_list else 'N/A'
            except Exception:
                tags = 'N/A'

            health_checks.append({
                'Health Check ID': hc_id,
                'Type': hc_type,
                'Endpoint': endpoint,
                'Port': port,
                'Resource Path': resource_path,
                'Request Interval (s)': request_interval,
                'Failure Threshold': failure_threshold,
                'Status': status,
                'Alarm Name': alarm_name,
                'Tags': tags
            })

    utils.log_success(f"Total health checks collected: {len(health_checks)}")
    return health_checks


@utils.aws_error_handler("Collecting Route 53 Resolver endpoints", default_return=[])
def collect_resolver_endpoints(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Route 53 Resolver endpoint information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with resolver endpoint details
    """
    print("\n=== COLLECTING RESOLVER ENDPOINTS ===")
    utils.log_info("Route 53 Resolver is regional - scanning selected regions")

    endpoints = []

    for region in regions:
        print(f"\n  Scanning region: {region}")

        try:
            resolver = utils.get_boto3_client('route53resolver', region_name=region)

            # Use paginator
            paginator = resolver.get_paginator('list_resolver_endpoints')

            for page in paginator.paginate():
                endpoint_list = page.get('ResolverEndpoints', [])

                for endpoint in endpoint_list:
                    endpoint_id = endpoint.get('Id', '')
                    name = endpoint.get('Name', 'N/A')
                    direction = endpoint.get('Direction', '')
                    status = endpoint.get('Status', '')

                    print(f"    Processing endpoint: {name} ({endpoint_id})")

                    # IP addresses
                    ip_address_count = endpoint.get('IpAddressCount', 0)

                    # Get IP address details
                    try:
                        ip_response = resolver.list_resolver_endpoint_ip_addresses(
                            ResolverEndpointId=endpoint_id
                        )
                        ip_addresses = ip_response.get('IpAddresses', [])
                        ip_list = [f"{ip.get('Ip', '')} ({ip.get('SubnetId', '')})" for ip in ip_addresses]
                        ip_details = ', '.join(ip_list) if ip_list else 'N/A'
                    except Exception:
                        ip_details = 'N/A'

                    # VPC and security groups
                    vpc_id = endpoint.get('HostVPCId', 'N/A')
                    security_group_ids = endpoint.get('SecurityGroupIds', [])
                    security_groups = ', '.join(security_group_ids) if security_group_ids else 'N/A'

                    endpoints.append({
                        'Region': region,
                        'Endpoint ID': endpoint_id,
                        'Name': name,
                        'Direction': direction,
                        'Status': status,
                        'IP Address Count': ip_address_count,
                        'IP Addresses': ip_details,
                        'VPC ID': vpc_id,
                        'Security Group IDs': security_groups
                    })

        except Exception as e:
            utils.log_error(f"Error collecting resolver endpoints in {region}", e)

    utils.log_success(f"Total resolver endpoints collected: {len(endpoints)}")
    return endpoints


@utils.aws_error_handler("Collecting Route 53 Resolver rules", default_return=[])
def collect_resolver_rules(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Route 53 Resolver rule information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with resolver rule details
    """
    print("\n=== COLLECTING RESOLVER RULES ===")

    rules = []

    for region in regions:
        print(f"\n  Scanning region: {region}")

        try:
            resolver = utils.get_boto3_client('route53resolver', region_name=region)

            # Use paginator
            paginator = resolver.get_paginator('list_resolver_rules')

            for page in paginator.paginate():
                rule_list = page.get('ResolverRules', [])

                for rule in rule_list:
                    rule_id = rule.get('Id', '')
                    name = rule.get('Name', 'N/A')
                    rule_type = rule.get('RuleType', '')
                    domain_name = rule.get('DomainName', '')
                    status = rule.get('Status', '')

                    print(f"    Processing rule: {name} ({domain_name})")

                    # Target IPs (for FORWARD rules)
                    target_ips = rule.get('TargetIps', [])
                    if target_ips:
                        target_list = [f"{t.get('Ip', '')}:{t.get('Port', 53)}" for t in target_ips]
                        targets = ', '.join(target_list)
                    else:
                        targets = 'N/A'

                    # Resolver endpoint ID
                    resolver_endpoint_id = rule.get('ResolverEndpointId', 'N/A')

                    # Get VPC associations
                    try:
                        assoc_response = resolver.list_resolver_rule_associations(
                            Filters=[{'Name': 'ResolverRuleId', 'Values': [rule_id]}]
                        )
                        associations = assoc_response.get('ResolverRuleAssociations', [])
                        vpc_ids = [assoc.get('VPCId', '') for assoc in associations]
                        associated_vpcs = ', '.join(vpc_ids) if vpc_ids else 'N/A'
                    except Exception:
                        associated_vpcs = 'N/A'

                    rules.append({
                        'Region': region,
                        'Rule ID': rule_id,
                        'Name': name,
                        'Type': rule_type,
                        'Domain Name': domain_name,
                        'Status': status,
                        'Target IPs': targets,
                        'Resolver Endpoint ID': resolver_endpoint_id,
                        'Associated VPCs': associated_vpcs
                    })

        except Exception as e:
            utils.log_error(f"Error collecting resolver rules in {region}", e)

    utils.log_success(f"Total resolver rules collected: {len(rules)}")
    return rules


@utils.aws_error_handler("Collecting query logging configs", default_return=[])
def collect_query_logging_configs() -> List[Dict[str, Any]]:
    """
    Collect Route 53 query logging configuration information.

    Returns:
        list: List of dictionaries with query logging config details
    """
    print("\n=== COLLECTING QUERY LOGGING CONFIGS ===")

    configs = []
    route53 = utils.get_boto3_client('route53', region_name=home_region)

    # Use paginator
    paginator = route53.get_paginator('list_query_logging_configs')

    for page in paginator.paginate():
        config_list = page.get('QueryLoggingConfigs', [])

        for config in config_list:
            config_id = config.get('Id', '')
            hosted_zone_id = config.get('HostedZoneId', '').split('/')[-1]
            destination_arn = config.get('CloudWatchLogsLogGroupArn', '')

            print(f"  Processing query logging config: {config_id}")

            # Parse destination type from ARN
            if 'logs' in destination_arn:
                destination_type = 'CloudWatch Logs'
            elif 's3' in destination_arn:
                destination_type = 'S3'
            elif 'firehose' in destination_arn:
                destination_type = 'Kinesis Firehose'
            else:
                destination_type = 'Unknown'

            # Get zone name
            try:
                zone = route53.get_hosted_zone(Id=hosted_zone_id)
                zone_name = zone.get('HostedZone', {}).get('Name', hosted_zone_id)
            except Exception:
                zone_name = hosted_zone_id

            configs.append({
                'Config ID': config_id,
                'Hosted Zone ID': hosted_zone_id,
                'Zone Name': zone_name,
                'Destination Type': destination_type,
                'Destination ARN': destination_arn
            })

    utils.log_success(f"Total query logging configs collected: {len(configs)}")
    return configs


def generate_summary(zones: List[Dict], records: List[Dict], health_checks: List[Dict],
                     endpoints: List[Dict], rules: List[Dict], query_configs: List[Dict]) -> List[Dict[str, Any]]:
    """
    Generate summary statistics for Route 53 resources.

    Args:
        zones: List of hosted zones
        records: List of DNS records
        health_checks: List of health checks
        endpoints: List of resolver endpoints
        rules: List of resolver rules
        query_configs: List of query logging configs

    Returns:
        list: List of dictionaries with summary data
    """
    print("\n=== GENERATING SUMMARY ===")

    summary = []

    # Hosted zones summary
    public_zones = sum(1 for z in zones if z.get('Type') == 'Public')
    private_zones = sum(1 for z in zones if z.get('Type') == 'Private')

    summary.append({
        'Category': 'Hosted Zones',
        'Subcategory': 'Public Zones',
        'Count': public_zones
    })
    summary.append({
        'Category': 'Hosted Zones',
        'Subcategory': 'Private Zones',
        'Count': private_zones
    })
    summary.append({
        'Category': 'Hosted Zones',
        'Subcategory': 'Total Zones',
        'Count': len(zones)
    })

    # DNS records by type
    if records:
        import pandas as pd
        records_df = pd.DataFrame(records)
        record_types = records_df['Type'].value_counts().to_dict()

        for record_type, count in sorted(record_types.items()):
            summary.append({
                'Category': 'DNS Records',
                'Subcategory': f'{record_type} Records',
                'Count': count
            })

        summary.append({
            'Category': 'DNS Records',
            'Subcategory': 'Total Records',
            'Count': len(records)
        })

    # Health checks by status
    if health_checks:
        import pandas as pd
        hc_df = pd.DataFrame(health_checks)
        hc_statuses = hc_df['Status'].value_counts().to_dict()

        for status, count in sorted(hc_statuses.items()):
            summary.append({
                'Category': 'Health Checks',
                'Subcategory': f'{status} Health Checks',
                'Count': count
            })

        summary.append({
            'Category': 'Health Checks',
            'Subcategory': 'Total Health Checks',
            'Count': len(health_checks)
        })

    # Resolver endpoints
    summary.append({
        'Category': 'Resolver',
        'Subcategory': 'Resolver Endpoints',
        'Count': len(endpoints)
    })

    # Resolver rules
    summary.append({
        'Category': 'Resolver',
        'Subcategory': 'Resolver Rules',
        'Count': len(rules)
    })

    # Query logging configs
    summary.append({
        'Category': 'Logging',
        'Subcategory': 'Query Logging Configs',
        'Count': len(query_configs)
    })

    utils.log_success("Summary generated successfully")
    return summary


def export_route53_data(account_id: str, account_name: str, regions: List[str]):
    """
    Export Route 53 DNS service information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
        regions: List of AWS regions to scan for Resolver resources
    """
    print("\n" + "=" * 60)
    print("Starting Route 53 export process...")
    print("=" * 60)

    utils.log_info("Beginning Route 53 data collection")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect hosted zones
    zones = collect_hosted_zones()
    if zones:
        data_frames['Hosted Zones'] = pd.DataFrame(zones)

    # STEP 2: Collect DNS records
    records = collect_dns_records()
    if records:
        data_frames['DNS Records'] = pd.DataFrame(records)

    # STEP 3: Collect health checks
    health_checks = collect_health_checks()
    if health_checks:
        data_frames['Health Checks'] = pd.DataFrame(health_checks)

    # STEP 4: Collect resolver endpoints (regional)
    endpoints = collect_resolver_endpoints(regions)
    if endpoints:
        data_frames['Resolver Endpoints'] = pd.DataFrame(endpoints)

    # STEP 5: Collect resolver rules (regional)
    rules = collect_resolver_rules(regions)
    if rules:
        data_frames['Resolver Rules'] = pd.DataFrame(rules)

    # STEP 6: Collect query logging configs
    query_configs = collect_query_logging_configs()
    if query_configs:
        data_frames['Query Logging Configs'] = pd.DataFrame(query_configs)

    # STEP 7: Generate summary
    summary = generate_summary(zones, records, health_checks, endpoints, rules, query_configs)
    if summary:
        data_frames['Summary'] = pd.DataFrame(summary)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Route 53 data was collected. Nothing to export.")
        print("\nNo Route 53 resources found in this account.")
        return

    # STEP 8: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 9: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'route53',
        'dns',
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Route 53 data exported successfully!")
            utils.log_info(f"File location: {output_path}")

            # Summary of exported data
            print("\n" + "=" * 60)
            print("EXPORT SUMMARY")
            print("=" * 60)
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    # Initialize logging
    utils.setup_logging("route53-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("route53-export.py", "AWS Route 53 DNS Service Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS ROUTE 53 DNS SERVICE EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Prompt for regions (for Resolver resources)
        print("\nRoute 53 is a global service, but Resolver is regional.")

        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        # Export Route 53 data
        export_route53_data(account_id, account_name, regions)

        print("\nRoute 53 export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("route53-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
