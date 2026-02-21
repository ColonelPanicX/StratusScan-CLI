#!/usr/bin/env python3
"""
OpenSearch Service Export Script for StratusScan

Exports comprehensive AWS OpenSearch Service (successor to Elasticsearch) domain information
including cluster configurations, access policies, encryption, VPC settings, and snapshots.

Features:
- OpenSearch Domains: Version, instance types, storage, encryption
- VPC Configuration: Subnets, security groups, endpoints
- Access Policies: Domain access control and fine-grained access control
- Encryption Settings: At-rest, in-transit, node-to-node encryption
- Snapshot Configuration: Automated snapshots to S3
- Summary: Domain counts, versions, and key metrics

Output: Excel file with 3 worksheets
"""

import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
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
    utils.log_error("pandas library is required but not installed")
    utils.log_error("Install with: pip install pandas")
    sys.exit(1)


def scan_opensearch_domains_in_region(region: str) -> List[Dict[str, Any]]:
    """Scan OpenSearch domains in a single AWS region."""
    region_domains = []

    try:
        opensearch_client = utils.get_boto3_client('opensearch', region_name=region)

        # List all domain names
        try:
            response = opensearch_client.list_domain_names()
            domain_names = [domain['DomainName'] for domain in response.get('DomainNames', [])]
        except Exception as e:
            utils.log_warning(f"Could not list domains in {region}: {str(e)}")
            return region_domains

        if not domain_names:
            utils.log_info(f"No OpenSearch domains found in {region}")
            return region_domains

        # Describe each domain
        for domain_name in domain_names:
            try:
                domain_response = opensearch_client.describe_domain(DomainName=domain_name)
                domain = domain_response.get('DomainStatus', {})

                domain_id = domain.get('DomainId', 'N/A')
                arn = domain.get('ARN', 'N/A')

                # Engine version
                engine_version = domain.get('EngineVersion', 'N/A')

                # Cluster configuration
                cluster_config = domain.get('ClusterConfig', {})
                instance_type = cluster_config.get('InstanceType', 'N/A')
                instance_count = cluster_config.get('InstanceCount', 0)
                dedicated_master_enabled = cluster_config.get('DedicatedMasterEnabled', False)
                dedicated_master_type = cluster_config.get('DedicatedMasterType', 'N/A') if dedicated_master_enabled else 'N/A'
                dedicated_master_count = cluster_config.get('DedicatedMasterCount', 0) if dedicated_master_enabled else 0
                zone_awareness_enabled = cluster_config.get('ZoneAwarenessEnabled', False)
                warm_enabled = cluster_config.get('WarmEnabled', False)
                warm_type = cluster_config.get('WarmType', 'N/A') if warm_enabled else 'N/A'
                warm_count = cluster_config.get('WarmCount', 0) if warm_enabled else 0

                # EBS storage
                ebs_options = domain.get('EBSOptions', {})
                ebs_enabled = ebs_options.get('EBSEnabled', False)
                volume_type = ebs_options.get('VolumeType', 'N/A') if ebs_enabled else 'N/A'
                volume_size = ebs_options.get('VolumeSize', 0) if ebs_enabled else 0
                iops = ebs_options.get('Iops', 0) if ebs_enabled else 0

                # VPC configuration
                vpc_options = domain.get('VPCOptions', {})
                vpc_id = vpc_options.get('VPCId', 'N/A')
                subnet_ids = vpc_options.get('SubnetIds', [])
                subnet_ids_str = ', '.join(subnet_ids) if subnet_ids else 'N/A'
                security_group_ids = vpc_options.get('SecurityGroupIds', [])
                security_groups_str = ', '.join(security_group_ids) if security_group_ids else 'N/A'
                availability_zones = vpc_options.get('AvailabilityZones', [])
                az_str = ', '.join(availability_zones) if availability_zones else 'N/A'

                # Endpoints
                endpoint = domain.get('Endpoint', 'N/A')
                endpoints = domain.get('Endpoints', {})
                vpc_endpoint = endpoints.get('vpc', 'N/A') if endpoints else 'N/A'

                # Encryption settings
                encryption_at_rest = domain.get('EncryptionAtRestOptions', {})
                encryption_enabled = encryption_at_rest.get('Enabled', False)
                kms_key_id = encryption_at_rest.get('KmsKeyId', 'N/A') if encryption_enabled else 'N/A'
                if kms_key_id != 'N/A' and '/' in kms_key_id:
                    kms_key_id = kms_key_id.split('/')[-1]  # Extract key ID from ARN

                # Node-to-node encryption
                node_to_node_encryption = domain.get('NodeToNodeEncryptionOptions', {})
                node_encryption_enabled = node_to_node_encryption.get('Enabled', False)

                # Domain endpoint encryption (in-transit)
                domain_endpoint_options = domain.get('DomainEndpointOptions', {})
                enforce_https = domain_endpoint_options.get('EnforceHTTPS', False)
                tls_security_policy = domain_endpoint_options.get('TLSSecurityPolicy', 'N/A')

                # Advanced security options (fine-grained access control)
                advanced_security_options = domain.get('AdvancedSecurityOptions', {})
                fine_grained_access_enabled = advanced_security_options.get('Enabled', False)
                internal_user_database_enabled = advanced_security_options.get('InternalUserDatabaseEnabled', False)

                # Cognito options
                cognito_options = domain.get('CognitoOptions', {})
                cognito_enabled = cognito_options.get('Enabled', False)
                user_pool_id = cognito_options.get('UserPoolId', 'N/A') if cognito_enabled else 'N/A'

                # Snapshot configuration
                snapshot_options = domain.get('SnapshotOptions', {})
                automated_snapshot_start_hour = snapshot_options.get('AutomatedSnapshotStartHour', 'N/A')

                # Domain status
                processing = domain.get('Processing', False)
                created = domain.get('Created', False)
                deleted = domain.get('Deleted', False)

                # Auto-Tune options
                auto_tune_options = domain.get('AutoTuneOptions', {})
                auto_tune_state = auto_tune_options.get('State', 'N/A')

                # Access policies
                access_policies = domain.get('AccessPolicies', 'N/A')
                if access_policies != 'N/A':
                    try:
                        policy_json = json.loads(access_policies)
                        # Check if policy allows public access
                        statements = policy_json.get('Statement', [])
                        public_access = 'No'
                        for statement in statements:
                            principal = statement.get('Principal', {})
                            if principal == '*' or principal.get('AWS') == '*':
                                public_access = 'Yes - Review Policy'
                                break
                    except Exception:
                        public_access = 'Unknown'
                else:
                    public_access = 'N/A'

                # Domain creation time
                created_time = domain.get('Created')
                if created and created_time:
                    created_time_str = 'Yes'
                else:
                    created_time_str = 'Unknown'

                region_domains.append({
                    'Region': region,
                    'Domain Name': domain_name,
                    'Domain ID': domain_id,
                    'Engine Version': engine_version,
                    'Status': 'Processing' if processing else ('Deleted' if deleted else 'Active'),
                    'Endpoint': endpoint if endpoint != 'N/A' else vpc_endpoint,
                    'Instance Type': instance_type,
                    'Instance Count': instance_count,
                    'Dedicated Master': 'Yes' if dedicated_master_enabled else 'No',
                    'Master Type': dedicated_master_type,
                    'Master Count': dedicated_master_count,
                    'Zone Awareness': 'Enabled' if zone_awareness_enabled else 'Disabled',
                    'Warm Storage': 'Enabled' if warm_enabled else 'Disabled',
                    'Warm Type': warm_type,
                    'Warm Count': warm_count,
                    'EBS Enabled': 'Yes' if ebs_enabled else 'No',
                    'Volume Type': volume_type,
                    'Volume Size (GB)': volume_size,
                    'IOPS': iops if iops > 0 else 'N/A',
                    'VPC ID': vpc_id,
                    'Subnets': subnet_ids_str,
                    'Security Groups': security_groups_str,
                    'Availability Zones': az_str,
                    'Encryption at Rest': 'Yes' if encryption_enabled else 'No',
                    'KMS Key ID': kms_key_id,
                    'Node-to-Node Encryption': 'Yes' if node_encryption_enabled else 'No',
                    'Enforce HTTPS': 'Yes' if enforce_https else 'No',
                    'TLS Policy': tls_security_policy,
                    'Fine-Grained Access Control': 'Enabled' if fine_grained_access_enabled else 'Disabled',
                    'Internal User DB': 'Yes' if internal_user_database_enabled else 'No',
                    'Cognito Auth': 'Enabled' if cognito_enabled else 'Disabled',
                    'Cognito User Pool': user_pool_id,
                    'Snapshot Start Hour': automated_snapshot_start_hour,
                    'Auto-Tune': auto_tune_state,
                    'Public Access': public_access,
                    'Created': created_time_str,
                    'ARN': arn,
                })

            except Exception as e:
                utils.log_error(f"Error describing domain {domain_name} in {region}: {str(e)}")
                continue

    except Exception as e:
        utils.log_error(f"Error scanning OpenSearch domains in {region}", e)

    utils.log_info(f"Found {len(region_domains)} OpenSearch domains in {region}")
    return region_domains


@utils.aws_error_handler("Collecting OpenSearch domains", default_return=[])
def collect_opensearch_domains(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect OpenSearch Service domain information from AWS regions."""
    utils.log_info("Using concurrent region scanning for improved performance")

    all_domains = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_opensearch_domains_in_region,
        resource_type="OpenSearch domains"
    )

    return all_domains


def scan_opensearch_tags_in_region(region: str) -> List[Dict[str, Any]]:
    """Scan OpenSearch domain tags in a single AWS region."""
    region_tags = []

    try:
        opensearch_client = utils.get_boto3_client('opensearch', region_name=region)

        # List all domain names
        try:
            response = opensearch_client.list_domain_names()
            domain_names = [domain['DomainName'] for domain in response.get('DomainNames', [])]
        except Exception as e:
            utils.log_warning(f"Could not list domains in {region}: {str(e)}")
            return region_tags

        if not domain_names:
            return region_tags

        # Get tags for each domain
        for domain_name in domain_names:
            try:
                # Get domain ARN first
                domain_response = opensearch_client.describe_domain(DomainName=domain_name)
                domain_arn = domain_response.get('DomainStatus', {}).get('ARN', '')

                if not domain_arn:
                    continue

                # List tags for this domain
                tags_response = opensearch_client.list_tags(ARN=domain_arn)
                tags = tags_response.get('TagList', [])

                for tag in tags:
                    tag_key = tag.get('Key', 'N/A')
                    tag_value = tag.get('Value', 'N/A')

                    region_tags.append({
                        'Region': region,
                        'Domain Name': domain_name,
                        'Tag Key': tag_key,
                        'Tag Value': tag_value,
                    })

            except Exception as e:
                utils.log_warning(f"Could not retrieve tags for domain {domain_name}: {str(e)}")
                continue

    except Exception as e:
        utils.log_error(f"Error scanning OpenSearch domain tags in {region}", e)

    utils.log_info(f"Found {len(region_tags)} OpenSearch domain tags in {region}")
    return region_tags


@utils.aws_error_handler("Collecting OpenSearch domain tags", default_return=[])
def collect_opensearch_tags(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect OpenSearch Service domain tags from AWS regions."""
    utils.log_info("Using concurrent region scanning for improved performance")

    all_tags = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_opensearch_tags_in_region,
        resource_type="OpenSearch domain tags"
    )

    return all_tags


def generate_summary(domains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for OpenSearch domains."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total OpenSearch Domains',
        'Count': len(domains),
        'Details': f"{len([d for d in domains if d['Status'] == 'Active'])} active"
    })

    # Domains by region
    if domains:
        regions = {}
        for domain in domains:
            region = domain['Region']
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'Domains by Region',
            'Count': len(regions),
            'Details': region_details
        })

    # OpenSearch versions
    if domains:
        versions = {}
        for domain in domains:
            version = domain['Engine Version']
            versions[version] = versions.get(version, 0) + 1

        version_details = ', '.join([f"{ver}: {count}" for ver, count in sorted(versions.items())])
        summary.append({
            'Metric': 'Engine Versions',
            'Count': len(versions),
            'Details': version_details
        })

    # Encryption statistics
    encrypted_at_rest = len([d for d in domains if d['Encryption at Rest'] == 'Yes'])
    summary.append({
        'Metric': 'Encryption at Rest',
        'Count': encrypted_at_rest,
        'Details': f"{encrypted_at_rest}/{len(domains)} domains encrypted" if domains else "N/A"
    })

    node_encryption = len([d for d in domains if d['Node-to-Node Encryption'] == 'Yes'])
    summary.append({
        'Metric': 'Node-to-Node Encryption',
        'Count': node_encryption,
        'Details': f"{node_encryption}/{len(domains)} domains with node encryption" if domains else "N/A"
    })

    enforce_https = len([d for d in domains if d['Enforce HTTPS'] == 'Yes'])
    summary.append({
        'Metric': 'HTTPS Enforcement',
        'Count': enforce_https,
        'Details': f"{enforce_https}/{len(domains)} domains enforce HTTPS" if domains else "N/A"
    })

    # VPC deployment
    vpc_domains = len([d for d in domains if d['VPC ID'] != 'N/A'])
    summary.append({
        'Metric': 'VPC Deployment',
        'Count': vpc_domains,
        'Details': f"{vpc_domains}/{len(domains)} domains in VPC" if domains else "N/A"
    })

    # Fine-grained access control
    fine_grained = len([d for d in domains if d['Fine-Grained Access Control'] == 'Enabled'])
    summary.append({
        'Metric': 'Fine-Grained Access Control',
        'Count': fine_grained,
        'Details': f"{fine_grained}/{len(domains)} domains with fine-grained access" if domains else "N/A"
    })

    # Dedicated masters
    dedicated_masters = len([d for d in domains if d['Dedicated Master'] == 'Yes'])
    summary.append({
        'Metric': 'Dedicated Master Nodes',
        'Count': dedicated_masters,
        'Details': f"{dedicated_masters}/{len(domains)} domains with dedicated masters" if domains else "N/A"
    })

    # Zone awareness
    zone_aware = len([d for d in domains if d['Zone Awareness'] == 'Enabled'])
    summary.append({
        'Metric': 'Multi-AZ (Zone Awareness)',
        'Count': zone_aware,
        'Details': f"{zone_aware}/{len(domains)} domains multi-AZ" if domains else "N/A"
    })

    # Warm storage
    warm_storage = len([d for d in domains if d['Warm Storage'] == 'Enabled'])
    summary.append({
        'Metric': 'UltraWarm Storage',
        'Count': warm_storage,
        'Details': f"{warm_storage}/{len(domains)} domains with UltraWarm" if domains else "N/A"
    })

    # Public access warning
    public_access = len([d for d in domains if 'Yes' in d['Public Access']])
    if public_access > 0:
        summary.append({
            'Metric': '⚠️ Public Access Detected',
            'Count': public_access,
            'Details': f"{public_access} domains may have public access - review policies"
        })

    # Total storage
    if domains:
        total_storage_gb = sum(d['Volume Size (GB)'] for d in domains if isinstance(d['Volume Size (GB)'], (int, float)))
        summary.append({
            'Metric': 'Total EBS Storage',
            'Count': total_storage_gb,
            'Details': f"{total_storage_gb} GB across all domains"
        })

    # Instance types distribution
    if domains:
        instance_types = {}
        for domain in domains:
            instance_type = domain['Instance Type']
            instance_types[instance_type] = instance_types.get(instance_type, 0) + 1

        top_types = sorted(instance_types.items(), key=lambda x: x[1], reverse=True)[:3]
        type_details = ', '.join([f"{itype}: {count}" for itype, count in top_types])
        summary.append({
            'Metric': 'Top Instance Types',
            'Count': len(instance_types),
            'Details': type_details
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
    utils.log_info(f"Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\n=== Collecting OpenSearch Data ===")
    domains = collect_opensearch_domains(regions)
    tags = collect_opensearch_tags(regions)

    # Generate summary
    summary = generate_summary(domains)

    # Convert to DataFrames
    domains_df = pd.DataFrame(domains) if domains else pd.DataFrame()
    tags_df = pd.DataFrame(tags) if tags else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not domains_df.empty:
        domains_df = utils.prepare_dataframe_for_export(domains_df)
    if not tags_df.empty:
        tags_df = utils.prepare_dataframe_for_export(tags_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'opensearch', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'OpenSearch Domains': domains_df,
        'Domain Tags': tags_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(domains) + len(tags),
            details={
                'Domains': len(domains),
                'Tags': len(tags)
            }
        )

    utils.log_script_end(script_name)


if __name__ == "__main__":
    main()
