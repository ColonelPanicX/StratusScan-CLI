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

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)


def check_dependencies():
    """Check if required dependencies are installed."""
    utils.log_info("Checking dependencies...")

    missing = []

    try:
        import pandas
        utils.log_info("✓ pandas is installed")
    except ImportError:
        missing.append("pandas")

    try:
        import openpyxl
        utils.log_info("✓ openpyxl is installed")
    except ImportError:
        missing.append("openpyxl")

    try:
        import boto3
        utils.log_info("✓ boto3 is installed")
    except ImportError:
        missing.append("boto3")

    if missing:
        utils.log_error(f"Missing dependencies: {', '.join(missing)}")
        utils.log_error("Please install using: pip install " + " ".join(missing))
        sys.exit(1)

    utils.log_success("All dependencies are installed")


# Service detection configuration - maps to your export scripts
SERVICE_CHECKS = {
    'Compute Resources': {
        'Amazon EC2': {
            'client': 'ec2',
            'check': lambda c, r: len(c.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])['Reservations']),
            'unit': 'instances',
            'regional': True
        },
        'Amazon RDS': {
            'client': 'rds',
            'check': lambda c, r: len(c.describe_db_instances()['DBInstances']),
            'unit': 'databases',
            'regional': True
        },
        'AWS Lambda': {
            'client': 'lambda',
            'check': lambda c, r: len(c.list_functions()['Functions']),
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
            'check': lambda c, r: len(c.list_databases()['Databases']),
            'unit': 'databases',
            'regional': True
        },
    },
    'Security & Identity': {
        'AWS IAM': {
            'client': 'iam',
            'check': lambda c, r: len(c.list_users()['Users']),
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
            'check': lambda c, r: len(c.list_metrics()['Metrics']),
            'unit': 'metrics',
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


def check_service_in_region(service_name: str, config: dict, region: str) -> Tuple[str, int, str]:
    """
    Check if a service has resources in a specific region.

    Returns:
        Tuple of (service_name, count, region)
    """
    try:
        client = utils.get_boto3_client(config['client'], region_name=region)
        count = config['check'](client, region)
        return (service_name, count, region)
    except Exception as e:
        # Service not available in region or no access
        return (service_name, 0, region)


def discover_services(regions: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Discover all services in use across regions using concurrent scanning.

    Returns:
        Dictionary of services with their details
    """
    utils.log_info("Starting concurrent service discovery across all categories...")

    all_services = {}
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

                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = {
                        executor.submit(check_service_in_region, service_name, config, region): region
                        for region in check_regions
                    }

                    for future in as_completed(futures):
                        svc_name, count, region = future.result()
                        if count > 0:
                            regional_counts[region] = count
                            total_count += count

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
                _, count, _ = check_service_in_region(service_name, config, check_regions[0])

                if count > 0:
                    all_services[service_name] = {
                        'category': category,
                        'count': count,
                        'unit': config['unit'],
                        'regions': {},
                        'regional': False
                    }
                    utils.log_success(f"  ✓ {service_name}: {count} {config['unit']}")

    return all_services


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

    print("\n" + "="*60)
    print("AWS Services In Use Discovery Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Get regions to scan
    print("\nThis script will check for resources across all AWS services.")
    print("Choose regions to scan (more regions = more comprehensive but slower):")
    print("1. Default regions (us-east-1, us-west-2, us-west-1, eu-west-1)")
    print("2. All regions")
    print("3. Specific region")

    choice = input("\nEnter your choice (1-3): ").strip()

    if choice == '1':
        regions = utils.get_default_regions()
        utils.log_info(f"Selected default regions: {', '.join(regions)}")
    elif choice == '2':
        regions = utils.get_aws_regions()
        utils.log_info(f"Selected all regions: {len(regions)} regions")
    elif choice == '3':
        region = input("Enter AWS region (e.g., us-east-1): ").strip()
        if not utils.validate_aws_region(region):
            utils.log_error(f"Invalid region: {region}")
            return
        regions = [region]
    else:
        utils.log_error("Invalid choice")
        return

    # Discover services
    print(f"\nScanning {len(regions)} region(s) for services in use...")
    services = discover_services(regions)

    if not services:
        utils.log_warning("No services with resources found")
        return

    utils.log_success(f"\nDiscovered {len(services)} services in use!")

    # Generate summary and export
    utils.log_info("Generating reports...")

    summary = generate_summary(services)
    df_summary = pd.DataFrame(summary)
    df_summary = utils.prepare_dataframe_for_export(df_summary)

    df_details = create_detailed_export(services)
    df_details = utils.prepare_dataframe_for_export(df_details)

    category_sheets = create_category_sheets(services)

    # Combine all sheets
    dataframes = {
        'Summary': df_summary,
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

    utils.log_success("Services discovery completed successfully")

    # Smart Scan integration - prompt user to run recommended scripts
    # Skip if --no-smart-scan flag provided
    if args.no_smart_scan:
        utils.log_info("Smart Scan skipped (--no-smart-scan flag)")
        return

    try:
        from smart_scan import (
            analyze_services,
            interactive_select,
            execute_scripts,
            QUESTIONARY_AVAILABLE,
        )

        print("\n" + "="*60)
        print("SMART SCAN - Intelligent Script Recommendations")
        print("="*60)
        print()
        print("Smart Scan can analyze your discovered services and recommend")
        print("relevant export scripts to run for comprehensive AWS auditing.")
        print()

        # Determine if we should launch Smart Scan
        if args.smart_scan:
            # Auto-launch via CLI flag
            launch_smart_scan = 'y'
            utils.log_info("Auto-launching Smart Scan (--smart-scan flag)")
        else:
            # Interactive prompt
            launch_smart_scan = input("Launch Smart Scan analyzer? (y/n): ").strip().lower()

        if launch_smart_scan == 'y':
            utils.log_info("Launching Smart Scan analyzer...")

            # Analyze the services export we just created
            recommendations = analyze_services(filename, include_always_run=True)

            if not recommendations or not recommendations.get("all_scripts"):
                utils.log_warning("No script recommendations generated")
            else:
                # Show quick stats
                stats = recommendations.get("coverage_stats", {})
                print()
                print(f"✓ Found {stats.get('services_with_scripts', 0)} services with export scripts")
                print(f"✓ {stats.get('total_scripts_recommended', 0)} scripts recommended")
                print()

                # Determine selection method
                if args.quick_scan:
                    # Quick Scan mode - run all recommended scripts
                    utils.log_info("Quick Scan mode - running all recommended scripts")
                    selected_scripts = recommendations.get("all_scripts", set())
                elif QUESTIONARY_AVAILABLE:
                    # Interactive selection if questionary available
                    utils.log_info("Starting interactive script selection...")
                    selected_scripts = interactive_select(recommendations)
                else:
                    # Fallback - no questionary, run all scripts
                    utils.log_warning("Questionary not installed - defaulting to Quick Scan")
                    selected_scripts = recommendations.get("all_scripts", set())

                if selected_scripts:
                        print()
                        print(f"Executing {len(selected_scripts)} selected scripts...")
                        print()

                        # Execute the selected scripts
                        summary = execute_scripts(selected_scripts, show_progress=True, save_log=True)

                        # Show final summary
                        print()
                        print("="*60)
                        print("SMART SCAN COMPLETE")
                        print("="*60)
                        print(f"Total Scripts: {summary['total']}")
                        print(f"Successful: {summary['successful']}")
                        print(f"Failed: {summary['failed']}")
                        print(f"Success Rate: {summary['success_rate']:.1f}%")
                        print("="*60)
                        print()

                        utils.log_success("Smart Scan batch execution completed")
                else:
                    utils.log_info("Smart Scan cancelled by user")

        else:
            utils.log_info("Smart Scan skipped")

    except ImportError:
        # Smart Scan not available - silently continue
        pass
    except Exception as e:
        # Don't fail the entire script if Smart Scan has issues
        utils.log_warning(f"Smart Scan encountered an error (continuing): {e}")


if __name__ == "__main__":
    main()
