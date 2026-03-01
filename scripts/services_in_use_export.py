#!/usr/bin/env python3
"""
AWS Services In Use Discovery Script for StratusScan

Discovers all AWS services currently in use by checking for actual resources
across your AWS environment. Provides categorized, detailed inventory with
resource counts and regional distribution.

Features:
- Leverages all 105+ StratusScan export scripts for accurate detection
- Categorized output (Compute, Storage, Network, Security, etc.)
- Resource counts (e.g., "15 EC2 instances" not just "EC2: Yes")
- Regional distribution for each service
- Fast concurrent scanning
- Human-readable categorized output

Output: Multi-worksheet Excel file with services categorized by type
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

# Setup logging
logger = utils.setup_logging('services-in-use-export')

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)
# Service detection configuration - maps to your export scripts
SERVICE_CHECKS = {
    'Compute Resources': {
        'Amazon EC2': {
            'client': 'ec2',
            'check': lambda c, r: sum(
                len(inst)
                for page in c.get_paginator('describe_instances').paginate(
                    Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
                )
                for inst in [res['Instances'] for res in page['Reservations']]
            ),
            'detail': lambda c, r: {
                state: sum(
                    1 for page in c.get_paginator('describe_instances').paginate(
                        Filters=[{'Name': 'instance-state-name', 'Values': [state]}]
                    )
                    for res in page['Reservations']
                    for _ in res['Instances']
                )
                for state in ['running', 'stopped']
            },
            'unit': 'instances',
            'regional': True
        },
        'Amazon RDS': {
            'client': 'rds',
            'check': lambda c, r: sum(
                len(page['DBInstances'])
                for page in c.get_paginator('describe_db_instances').paginate()
            ),
            'detail': lambda c, r: {
                status: count
                for status, count in {
                    s: sum(
                        1 for page in c.get_paginator('describe_db_instances').paginate()
                        for db in page['DBInstances']
                        if db['DBInstanceStatus'] == s
                    )
                    for s in ['available', 'stopped']
                }.items()
                if count > 0
            },
            'unit': 'databases',
            'regional': True
        },
        'AWS Lambda': {
            'client': 'lambda',
            'check': lambda c, r: sum(
                len(page['Functions'])
                for page in c.get_paginator('list_functions').paginate()
            ),
            'detail': lambda c, r: {
                rt: count
                for rt, count in {
                    'Python': sum(
                        1 for page in c.get_paginator('list_functions').paginate()
                        for fn in page['Functions']
                        if fn.get('Runtime', '').startswith('python')
                    ),
                    'Node.js': sum(
                        1 for page in c.get_paginator('list_functions').paginate()
                        for fn in page['Functions']
                        if fn.get('Runtime', '').startswith('nodejs')
                    ),
                    'Java': sum(
                        1 for page in c.get_paginator('list_functions').paginate()
                        for fn in page['Functions']
                        if fn.get('Runtime', '').startswith('java')
                    ),
                    'Go': sum(
                        1 for page in c.get_paginator('list_functions').paginate()
                        for fn in page['Functions']
                        if fn.get('Runtime', '').startswith('go')
                    ),
                    'Other': sum(
                        1 for page in c.get_paginator('list_functions').paginate()
                        for fn in page['Functions']
                        if not any(
                            fn.get('Runtime', '').startswith(p)
                            for p in ('python', 'nodejs', 'java', 'go')
                        )
                    ),
                }.items()
                if count > 0
            },
            'unit': 'functions',
            'regional': True
        },
        'Amazon ECS': {
            'client': 'ecs',
            'check': lambda c, r: len([cl for cl in c.list_clusters()['clusterArns'] if cl]),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon EKS': {
            'client': 'eks',
            'check': lambda c, r: len(c.list_clusters()['clusters']),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon Lightsail': {
            'client': 'lightsail',
            'check': lambda c, r: len(c.get_instances()['instances']),
            'unit': 'instances',
            'regional': True
        },
        'AWS Batch': {
            'client': 'batch',
            'check': lambda c, r: len(c.describe_compute_environments()['computeEnvironments']),
            'unit': 'compute environments',
            'regional': True
        },
    },
    'Storage Resources': {
        'Amazon S3': {
            'client': 's3',
            'check': lambda c, r: len(c.list_buckets()['Buckets']),
            'unit': 'buckets',
            'regional': False
        },
        'Amazon EBS': {
            'client': 'ec2',
            'check': lambda c, r: len(c.describe_volumes()['Volumes']),
            'detail': lambda c, r: {
                'in-use': sum(
                    1 for page in c.get_paginator('describe_volumes').paginate(
                        Filters=[{'Name': 'status', 'Values': ['in-use']}]
                    )
                    for _ in page['Volumes']
                ),
                'available': sum(
                    1 for page in c.get_paginator('describe_volumes').paginate(
                        Filters=[{'Name': 'status', 'Values': ['available']}]
                    )
                    for _ in page['Volumes']
                ),
            },
            'unit': 'volumes',
            'regional': True
        },
        'Amazon EFS': {
            'client': 'efs',
            'check': lambda c, r: len(c.describe_file_systems()['FileSystems']),
            'unit': 'file systems',
            'regional': True
        },
        'Amazon FSx': {
            'client': 'fsx',
            'check': lambda c, r: len(c.describe_file_systems()['FileSystems']),
            'unit': 'file systems',
            'regional': True
        },
        'AWS Backup': {
            'client': 'backup',
            'check': lambda c, r: len(c.list_backup_vaults()['BackupVaultList']),
            'unit': 'vaults',
            'regional': True
        },
        'Amazon Glacier': {
            'client': 'glacier',
            'check': lambda c, r: len(c.list_vaults()['VaultList']),
            'unit': 'vaults',
            'regional': True
        },
        'AWS Storage Gateway': {
            'client': 'storagegateway',
            'check': lambda c, r: len(c.list_gateways()['Gateways']),
            'unit': 'gateways',
            'regional': True
        },
    },
    'Network Resources': {
        'Amazon VPC': {
            'client': 'ec2',
            'check': lambda c, r: len([vpc for vpc in c.describe_vpcs()['Vpcs'] if not vpc.get('IsDefault', False)]),
            'unit': 'VPCs',
            'regional': True
        },
        'Elastic Load Balancing': {
            'client': 'elbv2',
            'check': lambda c, r: len(c.describe_load_balancers()['LoadBalancers']),
            'detail': lambda c, r: {
                lb_type: count
                for lb_type, count in {
                    t: sum(
                        1 for page in c.get_paginator('describe_load_balancers').paginate()
                        for lb in page['LoadBalancers']
                        if lb['Type'] == t
                    )
                    for t in ['application', 'network', 'gateway']
                }.items()
                if count > 0
            },
            'unit': 'load balancers',
            'regional': True
        },
        'Amazon CloudFront': {
            'client': 'cloudfront',
            'check': lambda c, r: len(c.list_distributions().get('DistributionList', {}).get('Items', [])),
            'unit': 'distributions',
            'regional': False
        },
        'Amazon Route 53': {
            'client': 'route53',
            'check': lambda c, r: len(c.list_hosted_zones()['HostedZones']),
            'unit': 'hosted zones',
            'regional': False
        },
        'AWS Direct Connect': {
            'client': 'directconnect',
            'check': lambda c, r: len(c.describe_connections()['connections']),
            'unit': 'connections',
            'regional': True
        },
        'AWS VPN': {
            'client': 'ec2',
            'check': lambda c, r: len(c.describe_vpn_connections()['VpnConnections']),
            'unit': 'VPN connections',
            'regional': True
        },
        'AWS Transit Gateway': {
            'client': 'ec2',
            'check': lambda c, r: len(c.describe_transit_gateways()['TransitGateways']),
            'unit': 'transit gateways',
            'regional': True
        },
        'AWS Global Accelerator': {
            'client': 'globalaccelerator',
            'check': lambda c, r: len(c.list_accelerators()['Accelerators']),
            'unit': 'accelerators',
            'regional': False
        },
        'AWS Network Firewall': {
            'client': 'network-firewall',
            'check': lambda c, r: len(c.list_firewalls()['Firewalls']),
            'unit': 'firewalls',
            'regional': True
        },
    },
    'Database Resources': {
        'Amazon DynamoDB': {
            'client': 'dynamodb',
            'check': lambda c, r: len(c.list_tables()['TableNames']),
            'unit': 'tables',
            'regional': True
        },
        'Amazon ElastiCache': {
            'client': 'elasticache',
            'check': lambda c, r: len(c.describe_cache_clusters()['CacheClusters']),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon Redshift': {
            'client': 'redshift',
            'check': lambda c, r: len(c.describe_clusters()['Clusters']),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon DocumentDB': {
            'client': 'docdb',
            'check': lambda c, r: len(c.describe_db_clusters()['DBClusters']),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon Neptune': {
            'client': 'neptune',
            'check': lambda c, r: len(c.describe_db_clusters()['DBClusters']),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon Timestream': {
            'client': 'timestream-write',
            # list_databases avoids the hanging DescribeEndpoints call.
            # Endpoint-discovery errors are caught by _is_not_in_use_error.
            'check': lambda c, r: len(
                c.list_databases(MaxResults=10).get('Databases', [])
            ),
            'unit': 'databases',
            'regional': True
        },
    },
    'Security & Identity': {
        'AWS IAM': {
            'client': 'iam',
            'check': lambda c, r: len(c.list_users()['Users']),
            'detail': lambda c, r: {
                'roles': sum(len(page['Roles']) for page in c.get_paginator('list_roles').paginate()),
                'groups': sum(len(page['Groups']) for page in c.get_paginator('list_groups').paginate()),
            },
            'unit': 'users',
            'regional': False
        },
        'AWS IAM Identity Center': {
            'client': 'sso-admin',
            'check': lambda c, r: len(c.list_instances()['Instances']),
            'unit': 'instances',
            'regional': False
        },
        'AWS Security Hub': {
            'client': 'securityhub',
            'check': lambda c, r: 1 if c.describe_hub() else 0,
            'unit': 'enabled',
            'regional': True
        },
        'Amazon GuardDuty': {
            'client': 'guardduty',
            'check': lambda c, r: len(c.list_detectors()['DetectorIds']),
            'unit': 'detectors',
            'regional': True
        },
        'AWS WAF': {
            'client': 'wafv2',
            'check': lambda c, r: len(c.list_web_acls(Scope='REGIONAL')['WebACLs']),
            'unit': 'web ACLs',
            'regional': True
        },
        'AWS KMS': {
            'client': 'kms',
            'check': lambda c, r: len([k for k in c.list_keys()['Keys']]),
            'unit': 'keys',
            'regional': True
        },
        'AWS Secrets Manager': {
            'client': 'secretsmanager',
            'check': lambda c, r: len(c.list_secrets().get('SecretList', [])),
            'unit': 'secrets',
            'regional': True
        },
        'Amazon Cognito': {
            'client': 'cognito-idp',
            'check': lambda c, r: len(c.list_user_pools(MaxResults=60)['UserPools']),
            'unit': 'user pools',
            'regional': True
        },
        'AWS Certificate Manager': {
            'client': 'acm',
            'check': lambda c, r: len(c.list_certificates()['CertificateSummaryList']),
            'unit': 'certificates',
            'regional': True
        },
        'Amazon Macie': {
            'client': 'macie2',
            'check': lambda c, r: 1 if c.get_macie_session()['status'] == 'ENABLED' else 0,
            'unit': 'enabled',
            'regional': True
        },
    },
    'Management & Governance': {
        'AWS CloudTrail': {
            'client': 'cloudtrail',
            'check': lambda c, r: len(c.describe_trails()['trailList']),
            'unit': 'trails',
            'regional': True
        },
        'AWS Config': {
            'client': 'config',
            'check': lambda c, r: len(c.describe_configuration_recorders()['ConfigurationRecorders']),
            'unit': 'recorders',
            'regional': True
        },
        'AWS CloudFormation': {
            'client': 'cloudformation',
            'check': lambda c, r: len([s for s in c.list_stacks()['StackSummaries'] if s['StackStatus'] != 'DELETE_COMPLETE']),
            'unit': 'stacks',
            'regional': True
        },
        'AWS Systems Manager': {
            'client': 'ssm',
            'check': lambda c, r: len(c.describe_instance_information()['InstanceInformationList']),
            'unit': 'managed instances',
            'regional': True
        },
        'AWS Organizations': {
            'client': 'organizations',
            'check': lambda c, r: len(c.list_accounts()['Accounts']),
            'unit': 'accounts',
            'regional': False
        },
        'AWS Control Tower': {
            'client': 'controltower',
            'check': lambda c, r: len(c.list_enabled_controls()['enabledControls']),
            'unit': 'controls',
            'regional': False
        },
        'AWS Service Catalog': {
            'client': 'servicecatalog',
            'check': lambda c, r: len(c.list_portfolios()['PortfolioDetails']),
            'unit': 'portfolios',
            'regional': True
        },
    },
    'Analytics & Data': {
        'Amazon Athena': {
            'client': 'athena',
            'check': lambda c, r: len(c.list_work_groups()['WorkGroups']),
            'unit': 'workgroups',
            'regional': True
        },
        'AWS Glue': {
            'client': 'glue',
            'check': lambda c, r: len(c.get_databases()['DatabaseList']),
            'unit': 'databases',
            'regional': True
        },
        'Amazon EMR': {
            'client': 'emr',
            'check': lambda c, r: len(c.list_clusters()['Clusters']),
            'unit': 'clusters',
            'regional': True
        },
        'Amazon Kinesis': {
            'client': 'kinesis',
            'check': lambda c, r: len(c.list_streams()['StreamNames']),
            'unit': 'streams',
            'regional': True
        },
        'Amazon OpenSearch': {
            'client': 'opensearch',
            'check': lambda c, r: len(c.list_domain_names()['DomainNames']),
            'unit': 'domains',
            'regional': True
        },
        'AWS Lake Formation': {
            'client': 'lakeformation',
            'check': lambda c, r: len(c.list_resources()['ResourceInfoList']),
            'unit': 'resources',
            'regional': True
        },
    },
    'Integration & Messaging': {
        'Amazon SNS': {
            'client': 'sns',
            'check': lambda c, r: len(c.list_topics()['Topics']),
            'unit': 'topics',
            'regional': True
        },
        'Amazon SQS': {
            'client': 'sqs',
            'check': lambda c, r: len(c.list_queues().get('QueueUrls', [])),
            'unit': 'queues',
            'regional': True
        },
        'Amazon EventBridge': {
            'client': 'events',
            'check': lambda c, r: len(c.list_event_buses()['EventBuses']),
            'unit': 'event buses',
            'regional': True
        },
        'AWS Step Functions': {
            'client': 'stepfunctions',
            'check': lambda c, r: len(c.list_state_machines()['stateMachines']),
            'unit': 'state machines',
            'regional': True
        },
        'Amazon API Gateway': {
            'client': 'apigateway',
            'check': lambda c, r: len(c.get_rest_apis()['items']),
            'unit': 'APIs',
            'regional': True
        },
        'Amazon AppSync': {
            'client': 'appsync',
            'check': lambda c, r: len(c.list_graphql_apis()['graphqlApis']),
            'unit': 'GraphQL APIs',
            'regional': True
        },
    },
    'Monitoring & Logging': {
        'Amazon CloudWatch': {
            'client': 'cloudwatch',
            # list_metrics returns thousands of entries and is very slow.
            # Count alarms instead — fast, meaningful, and paginator-safe.
            'check': lambda c, r: sum(
                len(page['MetricAlarms'])
                for page in c.get_paginator('describe_alarms').paginate()
            ),
            'unit': 'alarms',
            'regional': True
        },
        'AWS X-Ray': {
            'client': 'xray',
            'check': lambda c, r: len(c.get_sampling_rules()['SamplingRuleRecords']),
            'unit': 'sampling rules',
            'regional': True
        },
        'Amazon CloudWatch Logs': {
            'client': 'logs',
            'check': lambda c, r: len(c.describe_log_groups()['logGroups']),
            'unit': 'log groups',
            'regional': True
        },
    },
    'AI & Machine Learning': {
        'Amazon SageMaker': {
            'client': 'sagemaker',
            'check': lambda c, r: len(c.list_notebook_instances()['NotebookInstances']),
            'unit': 'notebook instances',
            'regional': True
        },
        'Amazon Bedrock': {
            'client': 'bedrock',
            'check': lambda c, r: len(c.list_custom_models()['modelSummaries']),
            'unit': 'custom models',
            'regional': True
        },
        'Amazon Comprehend': {
            'client': 'comprehend',
            'check': lambda c, r: len(c.list_endpoints()['EndpointPropertiesList']),
            'unit': 'endpoints',
            'regional': True
        },
        'Amazon Rekognition': {
            'client': 'rekognition',
            'check': lambda c, r: len(c.list_collections()['CollectionIds']),
            'unit': 'collections',
            'regional': True
        },
    },
    'Application Services': {
        'AWS App Runner': {
            'client': 'apprunner',
            'check': lambda c, r: len(c.list_services()['ServiceSummaryList']),
            'unit': 'services',
            'regional': True
        },
        'Amazon Connect': {
            'client': 'connect',
            'check': lambda c, r: len(c.list_instances()['InstanceSummaryList']),
            'unit': 'instances',
            'regional': True
        },
        'AWS Amplify': {
            'client': 'amplify',
            'check': lambda c, r: len(c.list_apps()['apps']),
            'unit': 'apps',
            'regional': True
        },
    },
}


# Flat map from service name → config dict for O(1) lookup in _enrich_with_detail.
_SERVICE_CONFIG_FLAT: Dict[str, dict] = {
    service_name: config
    for category_services in SERVICE_CHECKS.values()
    for service_name, config in category_services.items()
}


# Error message fragments that indicate a service is simply not in use or not
# available in this region — expected states, not genuine unexpected errors.
_NOT_IN_USE_FRAGMENTS = (
    "could not connect to the endpoint url",      # endpoint absent in this region
    "unknownoperationexception",                  # service/op not in this region
    "unknown operation",                          # Bedrock, others: region gap
    "unsupported_operation",                      # Comprehend: region gap
    "this operation is not supported in this region",
    "not subscribed to",                          # Security Hub: not enabled
    "not enabled",                                # Macie, others: not enabled
    "must create a landing zone",                 # Control Tower: not deployed
    "endpoint discovery failed",                  # Timestream: endpoint issue
)


def _is_not_in_use_error(exc: Exception) -> bool:
    """
    Return True when an exception indicates a service is not in use or not
    available in this region — not a genuine unexpected error.
    """
    msg = str(exc).lower()
    if any(frag in msg for frag in _NOT_IN_USE_FRAGMENTS):
        return True
    # Timestream: "Only existing ... customers can access the service"
    if "only existing" in msg and "customers" in msg:
        return True
    return False


def check_service_in_region(service_name: str, config: dict, region: str) -> Tuple[str, Any, str, Any]:
    """
    Check if a service has resources in a specific region.

    Returns:
        Tuple of (service_name, count, region, error_msg)
        count is None on a genuine unexpected failure; error_msg is None on
        success or on a recognized "not in use / not available" condition.
    """
    try:
        client = utils.get_boto3_client(config['client'], region_name=region)
        count = config['check'](client, region)
        return (service_name, count, region, None)
    except Exception as e:
        if _is_not_in_use_error(e):
            utils.log_debug(f"Service not available/not in use: {service_name} in {region}")
            return (service_name, 0, region, None)
        utils.log_warning(f"Service check failed for {service_name} in {region}: {e}")
        return (service_name, None, region, str(e))


def _enrich_with_detail(
    services: Dict[str, Dict[str, Any]],
    regions: List[str],
    errors: Dict[str, List[str]],
) -> None:
    """
    Second pass (Deep Scan only): add asset breakdown to detected services.

    Runs only for services that were found in the count pass and have a
    'detail' lambda defined. Failures are logged at DEBUG and skipped —
    they never break the scan.
    """
    for service_name, data in services.items():
        config = _SERVICE_CONFIG_FLAT.get(service_name)
        if config is None or 'detail' not in config:
            continue

        aggregated: Dict[str, int] = {}
        check_regions = list(data['regions'].keys()) if data['regional'] else regions[:1]

        for region in check_regions:
            try:
                client = utils.get_boto3_client(config['client'], region_name=region)
                result = config['detail'](client, region)
                for k, v in result.items():
                    aggregated[k] = aggregated.get(k, 0) + v
            except Exception as e:
                utils.log_debug(f"Detail check skipped for {service_name} in {region}: {e}")

        if aggregated:
            data['detail'] = aggregated


def discover_services(
    regions: List[str],
    mode: str = 'quick',
    errors_out=None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[str]]]:
    """
    Discover all services in use across regions using concurrent scanning.

    Args:
        regions: List of AWS region names to scan.
        mode: Scan mode — 'quick' (counts only) or 'deep' (counts + detail breakdown).
        errors_out: Optional dict to update with errors (for backward-compat callers).
                    If provided, it is updated in-place with the same data as the
                    returned errors dict.

    Returns:
        Tuple of (services, errors) where services maps service names to their
        details and errors maps service names to lists of regional error strings.
    """
    utils.log_info("Starting concurrent service discovery across all categories...")

    all_services = {}
    errors: Dict[str, List[str]] = {}
    total_services = sum(len(services) for services in SERVICE_CHECKS.values())
    completed = 0

    for category, services in SERVICE_CHECKS.items():
        utils.log_info(f"\n{'='*60}")
        utils.log_info(f"Scanning {category}...")
        utils.log_info(f"{'='*60}")

        for service_name, config in services.items():
            completed += 1
            progress = (completed / total_services) * 100

            # Check if regional or global service
            check_regions = regions if config['regional'] else [regions[0]]

            # Use concurrent scanning for regional services
            if len(check_regions) > 1:
                utils.log_info(f"[{progress:5.1f}%] Checking {service_name} across {len(check_regions)} regions...")

                regional_counts = {}
                total_count = 0

                concurrent_config = utils.config_value('advanced_settings.concurrent_scanning', default={})
                max_workers = concurrent_config.get('max_workers', 3)
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(check_service_in_region, service_name, config, region): region
                        for region in check_regions
                    }

                    for future in as_completed(futures):
                        try:
                            svc_name, count, region, err_msg = future.result(timeout=30)
                        except Exception:
                            region = futures[future]
                            errors.setdefault(service_name, []).append(f"{region}: check timed out")
                            continue
                        if count is not None and count > 0:
                            regional_counts[region] = count
                            total_count += count
                        elif count is None:
                            errors.setdefault(service_name, []).append(f"{region}: {err_msg}")

                if total_count > 0:
                    all_services[service_name] = {
                        'category': category,
                        'count': total_count,
                        'unit': config['unit'],
                        'regions': regional_counts,
                        'regional': True
                    }
                    utils.log_success(f"  ✓ {service_name}: {total_count} {config['unit']} across {len(regional_counts)} region(s)")
            else:
                # Global service - single check
                utils.log_info(f"[{progress:5.1f}%] Checking {service_name} (global service)...")
                _, count, _, err_msg = check_service_in_region(service_name, config, check_regions[0])

                if count is not None and count > 0:
                    all_services[service_name] = {
                        'category': category,
                        'count': count,
                        'unit': config['unit'],
                        'regions': {},
                        'regional': False
                    }
                    utils.log_success(f"  ✓ {service_name}: {count} {config['unit']}")
                elif count is None:
                    errors.setdefault(service_name, []).append(f"{check_regions[0]}: {err_msg}")

            # Brief pause between services to avoid blasting all regions simultaneously
            time.sleep(0.1)

    if mode == 'deep':
        utils.log_info("Deep Scan: collecting asset detail...")
        _enrich_with_detail(all_services, regions, errors)

    if errors_out is not None:
        errors_out.update(errors)

    return all_services, errors


def generate_summary(services: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics."""
    summary = []

    # Overall stats
    total_services = len(services)
    total_resources = sum(s['count'] for s in services.values())

    summary.append({
        'Metric': 'Total Services In Use',
        'Value': total_services,
        'Details': f'{total_resources:,} total resources across all services'
    })

    # By category
    category_counts = {}
    for service_data in services.values():
        category = service_data['category']
        category_counts[category] = category_counts.get(category, 0) + 1

    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        category_services = [s for s, d in services.items() if d['category'] == category]
        resource_count = sum(services[s]['count'] for s in category_services)

        summary.append({
            'Metric': category,
            'Value': count,
            'Details': f'{resource_count:,} resources'
        })

    return summary


def create_detailed_export(services: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    """Create detailed services DataFrame."""
    rows = []

    for service_name, data in sorted(services.items()):
        regional_dist = 'Global' if not data['regional'] else ', '.join([
            f"{region}: {count}" for region, count in sorted(data['regions'].items())
        ])

        rows.append({
            'Category': data['category'],
            'Service Name': service_name,
            'Resource Count': data['count'],
            'Unit': data['unit'],
            'Type': 'Global' if not data['regional'] else 'Regional',
            'Regional Distribution': regional_dist if data['regional'] else 'N/A'
        })

    return pd.DataFrame(rows)


def create_category_sheets(services: Dict[str, Dict[str, Any]]) -> Dict[str, pd.DataFrame]:
    """Create separate sheets for each category."""
    sheets = {}

    for category in sorted(set(s['category'] for s in services.values())):
        category_services = {
            name: data for name, data in services.items()
            if data['category'] == category
        }

        rows = []
        for service_name, data in sorted(category_services.items()):
            regional_dist = 'Global' if not data['regional'] else ', '.join([
                f"{region}: {count}" for region, count in sorted(data['regions'].items())
            ])

            rows.append({
                'Service Name': service_name,
                'Resource Count': data['count'],
                'Unit': data['unit'],
                'Regional Distribution': regional_dist if data['regional'] else 'N/A'
            })

        if rows:
            sheets[category] = pd.DataFrame(rows)

    return sheets


def create_recommendations_sheet(services: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    """
    Generate Smart Scan recommendations based on discovered services.

    Args:
        services: Dictionary of discovered services

    Returns:
        DataFrame with recommended export scripts
    """
    try:
        from smart_scan import analyze_services, map_services_to_scripts
        from smart_scan.mapping import ALWAYS_RUN_SCRIPTS, get_category_for_script

        # Extract just service names
        service_names = set(services.keys())

        # Map services to scripts
        service_script_mapping = map_services_to_scripts(service_names)

        # Build recommendations list
        recommendations = []

        # Add always-run scripts (security/compliance baseline)
        for script in sorted(ALWAYS_RUN_SCRIPTS):
            category = get_category_for_script(script)
            recommendations.append({
                'Script Name': script,
                'Category': category,
                'Priority': 'Always Run',
                'Reason': 'Security & compliance baseline - recommended for all accounts'
            })

        # Add service-based recommendations
        for service_name, scripts in sorted(service_script_mapping.items()):
            for script in sorted(scripts):
                # Skip if already added as always-run
                if script in ALWAYS_RUN_SCRIPTS:
                    continue

                category = get_category_for_script(script)
                resource_info = services.get(service_name, {})
                count = resource_info.get('count', 0)
                unit = resource_info.get('unit', 'resources')

                recommendations.append({
                    'Script Name': script,
                    'Category': category,
                    'Priority': 'Service-Based',
                    'Reason': f'{service_name} detected ({count} {unit})'
                })

        if recommendations:
            df = pd.DataFrame(recommendations)
            # Sort by priority (Always Run first) then by category
            df['_sort_priority'] = df['Priority'].map({'Always Run': 0, 'Service-Based': 1})
            df = df.sort_values(['_sort_priority', 'Category', 'Script Name'])
            df = df.drop('_sort_priority', axis=1)
            return df
        else:
            # Return empty DataFrame with proper structure
            return pd.DataFrame(columns=['Script Name', 'Category', 'Priority', 'Reason'])

    except ImportError:
        # Smart Scan not available - return empty DataFrame with note
        utils.log_warning("Smart Scan module not available - skipping recommendations")
        return pd.DataFrame([{
            'Script Name': 'N/A',
            'Category': 'N/A',
            'Priority': 'N/A',
            'Reason': 'Smart Scan module not installed'
        }])
    except Exception as e:
        utils.log_warning(f"Error generating recommendations: {e}")
        return pd.DataFrame([{
            'Script Name': 'Error',
            'Category': 'N/A',
            'Priority': 'N/A',
            'Reason': f'Error: {str(e)}'
        }])


def main():
    """Main execution function."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='AWS Services In Use Discovery with Smart Scan Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (default)
  python3 services-in-use-export.py

  # Auto-launch Smart Scan with interactive selection
  python3 services-in-use-export.py --smart-scan

  # Skip Smart Scan prompt entirely
  python3 services-in-use-export.py --no-smart-scan

  # Run Quick Scan (all recommended scripts) automatically
  python3 services-in-use-export.py --smart-scan --quick-scan
        """
    )

    parser.add_argument(
        '--smart-scan',
        action='store_true',
        help='Automatically launch Smart Scan after service discovery'
    )

    parser.add_argument(
        '--no-smart-scan',
        action='store_true',
        help='Skip Smart Scan prompt (discovery only)'
    )

    parser.add_argument(
        '--quick-scan',
        action='store_true',
        help='Run Quick Scan (all recommended scripts) without interactive selection'
    )

    args = parser.parse_args()

    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    account_id, account_name = utils.print_script_banner("AWS SERVICES IN USE DISCOVERY EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()

    # Prompt for scan mode (skipped in auto-run — defaults to quick)
    if utils.is_auto_run():
        scan_mode = 'quick'
    else:
        print("\n  Scan Mode:")
        print("  [1] Quick Scan  — service presence and resource counts")
        print("  [2] Deep Scan   — counts + asset breakdown (slower)")
        mode_choice = input("  Enter choice [1]: ").strip() or "1"
        scan_mode = 'deep' if mode_choice == '2' else 'quick'

    # Discover services
    print(f"\nScanning {len(regions)} region(s) for services in use ({scan_mode} mode)...")
    services, errors = discover_services(regions, mode=scan_mode)

    if not services:
        utils.log_warning("No services with resources found")
        return

    utils.log_success(f"\nDiscovered {len(services)} services in use!")

    if errors:
        print(f"\n  Note: {len(errors)} service(s) had check failures (see log):")
        for svc in sorted(errors):
            utils.log_warning(f"  {svc}: {'; '.join(errors[svc])}")

    # Generate summary and export
    utils.log_info("Generating reports...")

    summary = generate_summary(services)
    df_summary = pd.DataFrame(summary)
    df_summary = utils.prepare_dataframe_for_export(df_summary)

    df_details = create_detailed_export(services)
    df_details = utils.prepare_dataframe_for_export(df_details)

    category_sheets = create_category_sheets(services)

    # Generate Smart Scan recommendations
    utils.log_info("Generating Smart Scan script recommendations...")
    df_recommendations = create_recommendations_sheet(services)
    df_recommendations = utils.prepare_dataframe_for_export(df_recommendations)

    # Combine all sheets
    dataframes = {
        'Summary': df_summary,
        'Recommended Scripts': df_recommendations,  # Add recommendations as 2nd sheet
        'All Services': df_details,
    }

    # Add category sheets
    for category, df in category_sheets.items():
        df = utils.prepare_dataframe_for_export(df)
        # Shorten sheet names to fit Excel's 31-char limit
        sheet_name = category.replace(' Resources', '').replace('&', 'and')[:31]
        dataframes[sheet_name] = df

    # Export to Excel
    region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
    filename = utils.create_export_filename(account_name, 'services-in-use', region_suffix)

    utils.log_info(f"Exporting to {filename}...")
    utils.save_multiple_dataframes_to_excel(dataframes, filename)

    # Log summary
    utils.log_export_summary(
        'Services In Use',
        len(services),
        filename
    )

    # Print summary to console
    print("\n" + "="*60)
    print("SERVICES IN USE SUMMARY")
    print("="*60)
    for item in summary[:6]:  # Show first 6 items
        print(f"{item['Metric']:.<40} {item['Value']}")
        if item.get('Details'):
            print(f"  └─ {item['Details']}")

    # Show recommendations summary
    recommendation_count = len(df_recommendations)
    if recommendation_count > 0:
        print()
        print("="*60)
        print("SMART SCAN RECOMMENDATIONS")
        print("="*60)
        print(f"✓ {recommendation_count} export scripts recommended")
        print(f"  └─ See 'Recommended Scripts' worksheet in Excel export")
        print()
        always_run = len([r for r in df_recommendations.to_dict('records') if r.get('Priority') == 'Always Run'])
        service_based = recommendation_count - always_run
        if always_run > 0:
            print(f"  • {always_run} Always-Run scripts (security baseline)")
        if service_based > 0:
            print(f"  • {service_based} Service-Based scripts (for discovered services)")

    utils.log_success("Services discovery completed successfully")


if __name__ == "__main__":
    main()
