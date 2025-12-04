#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: StratusScan Configuration Tool
Version: v1.0.0
Date: AUG-26-2025

Description:
Interactive configuration tool for setting up the StratusScan AWS environment.
This script allows users to configure account mappings, default regions, and other
AWS-specific settings in the config.json file.

Features:
- Interactive account ID and name mapping setup
- AWS region selection (all commercial regions)
- Validates AWS account ID format (12 digits)
- Creates or updates config.json file
- Preserves existing configuration while adding new entries
- Dependency validation and automatic installation
- Command-line options for dependency checking only

Usage:
- python configure.py          (full configuration)
- python configure.py --deps   (dependency check only)
- python configure.py --perms  (AWS permissions check only)
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def detect_aws_partition():
    """
    Detect the AWS partition (commercial vs govcloud) from caller identity.

    Returns:
        tuple: (partition, default_region) - e.g., ('aws', 'us-east-1') or ('aws-us-gov', 'us-gov-west-1')
    """
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        arn = identity.get('Arn', '')

        if 'aws-us-gov' in arn:
            return 'aws-us-gov', 'us-gov-west-1'
        else:
            return 'aws', 'us-east-1'
    except:
        # Default to commercial if detection fails
        return 'aws', 'us-east-1'

def print_header():
    """Print the configuration tool header."""
    partition, _ = detect_aws_partition()
    env_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

    print("=" * 70)
    print("            STRATUSSCAN CONFIGURATION TOOL")
    print("=" * 70)
    print("Version: v1.0.0                             Date: AUG-26-2025")
    print(f"Environment: {env_name}")
    print("=" * 70)
    print()

def validate_account_id(account_id):
    """
    Validate that the account ID is a 12-digit number.

    Args:
        account_id (str): The account ID to validate

    Returns:
        bool: True if valid, False otherwise
    """
    # Remove any whitespace
    account_id = account_id.strip()

    # Check if it's exactly 12 digits
    pattern = re.compile(r'^\d{12}$')
    return bool(pattern.match(account_id))

def get_aws_region_choice():
    """
    Get the user's choice for the default AWS region.
    Automatically detects partition (Commercial vs GovCloud) and shows appropriate regions.

    Returns:
        str: The selected AWS region
    """
    # Detect the partition
    partition, default_region = detect_aws_partition()
    is_govcloud = partition == 'aws-us-gov'

    print("\nAWS Region Selection:")

    if is_govcloud:
        print("Please select the default AWS GovCloud region:")
        print("1. us-gov-west-1 (AWS GovCloud US-West)")
        print("2. us-gov-east-1 (AWS GovCloud US-East)")

        region_map = {
            "1": "us-gov-west-1",
            "2": "us-gov-east-1"
        }
        max_choice = 2
    else:
        print("Please select the default AWS Commercial region:")
        print("1. us-east-1 (US East - N. Virginia)")
        print("2. us-east-2 (US East - Ohio)")
        print("3. us-west-1 (US West - N. California)")
        print("4. us-west-2 (US West - Oregon)")
        print("5. eu-west-1 (Europe - Ireland)")
        print("6. eu-central-1 (Europe - Frankfurt)")
        print("7. ap-southeast-1 (Asia Pacific - Singapore)")
        print("8. ap-northeast-1 (Asia Pacific - Tokyo)")

        region_map = {
            "1": "us-east-1",
            "2": "us-east-2",
            "3": "us-west-1",
            "4": "us-west-2",
            "5": "eu-west-1",
            "6": "eu-central-1",
            "7": "ap-southeast-1",
            "8": "ap-northeast-1"
        }
        max_choice = 8

    while True:
        try:
            choice = input(f"\nEnter your choice (1-{max_choice}): ").strip()

            if choice in region_map:
                return region_map[choice]
            else:
                print(f"Invalid choice. Please enter 1-{max_choice}.")
        except KeyboardInterrupt:
            print("\n\nConfiguration cancelled by user.")
            sys.exit(0)

def load_existing_config(config_path):
    """
    Load existing configuration file if it exists.

    Args:
        config_path (Path): Path to the config file

    Returns:
        dict: Existing configuration or default structure
    """
    if config_path.exists():
        try:
            with open(config_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not read existing config file: {e}")
            print("Creating new configuration...")

    # Return default AWS configuration structure
    return {
        "__comment": "StratusScan Configuration - Customize this file for your environment",
        "account_mappings": {},
        "organization_name": "YOUR-ORGANIZATION",
        "default_regions": ["us-east-1", "us-west-2"],
        "resource_preferences": {
            "ec2": {
                "default_filter": "all",
                "include_stopped": True,
                "default_region": "us-east-1"
            },
            "vpc": {
                "default_export_type": "all",
                "default_region": "us-east-1"
            },
            "s3": {
                "default_region": "us-east-1"
            },
            "ebs": {
                "default_region": "us-east-1"
            },
            "rds": {
                "default_region": "us-east-1"
            },
            "ecs": {
                "default_region": "us-east-1"
            },
            "elb": {
                "default_region": "us-east-1"
            },
            "compute_optimizer": {
                "enabled": True,
                "default_region": "us-east-1"
            }
        },
        "aws_commercial": {
            "partition": "aws",
            "valid_regions": [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
                "ap-northeast-2", "ap-south-1", "sa-east-1", "ca-central-1"
            ],
            "notes": [
                "This configuration is optimized for AWS Commercial",
                "All standard AWS services are available"
            ]
        }
    }

def get_account_mappings():
    """
    Interactively collect account ID and name mappings from the user.

    Returns:
        dict: Dictionary of account ID to name mappings
    """
    mappings = {}

    print("\n" + "=" * 50)
    print("ACCOUNT MAPPING CONFIGURATION")
    print("=" * 50)
    print("Enter your AWS account ID and corresponding friendly name.")
    print("You can add multiple accounts. Press Enter without input when done.")
    print()

    while True:
        print(f"\nAccount #{len(mappings) + 1}:")

        # Get Account ID
        while True:
            account_id = input("Enter AWS Account ID (12 digits) or press Enter to finish: ").strip()

            # If empty, user is done
            if not account_id:
                if len(mappings) == 0:
                    print("Warning: No account mappings configured. You can add them later by running this script again.")
                return mappings

            # Validate account ID format
            if validate_account_id(account_id):
                # Check if account ID already exists
                if account_id in mappings:
                    overwrite = input(f"Account ID {account_id} already exists. Overwrite? (y/n): ").lower().strip()
                    if overwrite != 'y':
                        continue
                break
            else:
                print("Invalid account ID. Must be exactly 12 digits (e.g., 123456789012)")

        # Get Account Name
        while True:
            account_name = input(f"Enter friendly name for account {account_id}: ").strip()
            if account_name:
                break
            print("Account name cannot be empty.")

        # Store the mapping
        mappings[account_id] = account_name
        print(f"Added: {account_id} -> {account_name}")

        # Ask if user wants to add more
        more = input("\nWould you like to add another account? (y/n): ").lower().strip()
        if more != 'y':
            break

    return mappings

def get_organization_name(current_org="YOUR-ORGANIZATION"):
    """
    Get the organization/company name from the user.

    Args:
        current_org (str): Current organization/company name in config

    Returns:
        str: Organization/company name
    """
    print(f"\nCurrent organization/company name: {current_org}")
    org = input("Enter your organization/company name (or press Enter to keep current): ").strip()

    if org:
        return org
    return current_org

def update_resource_preferences(config, default_region):
    """
    Update resource preferences with the selected default region.

    Args:
        config (dict): Configuration dictionary
        default_region (str): Selected default region
    """
    if "resource_preferences" in config:
        for service, prefs in config["resource_preferences"].items():
            if isinstance(prefs, dict) and "default_region" in prefs:
                prefs["default_region"] = default_region

def save_configuration(config, config_path):
    """
    Save the configuration to the JSON file.

    Args:
        config (dict): Configuration dictionary
        config_path (Path): Path to save the config file
    """
    try:
        # Create backup if file exists
        if config_path.exists():
            backup_path = config_path.with_suffix('.json.backup')
            config_path.rename(backup_path)
            print(f"Backup created: {backup_path}")

        # Save new configuration
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"\nConfiguration saved successfully to: {config_path}")
        return True

    except Exception as e:
        print(f"Error saving configuration: {e}")
        return False

def display_summary(config):
    """
    Display a summary of the current configuration.

    Args:
        config (dict): Configuration dictionary
    """
    print("\n" + "=" * 50)
    print("CONFIGURATION SUMMARY")
    print("=" * 50)

    # Organization/company name
    print(f"Organization/Company Name: {config.get('organization_name', 'Not set')}")

    # Default regions
    default_regions = config.get('default_regions', [])
    print(f"Default Regions: {', '.join(default_regions)}")

    # Account mappings
    mappings = config.get('account_mappings', {})
    print(f"\nAccount Mappings ({len(mappings)} configured):")
    if mappings:
        for account_id, name in mappings.items():
            print(f"  {account_id} -> {name}")
    else:
        print("  None configured")

    # Resource preferences (show EC2 default region as example)
    ec2_region = config.get('resource_preferences', {}).get('ec2', {}).get('default_region', 'Not set')
    print(f"\nDefault Resource Region: {ec2_region}")

    print("=" * 50)

def check_dependencies():
    """
    Check if required StratusScan dependencies are installed.

    Returns:
        tuple: (bool, list) - (all_dependencies_satisfied, missing_packages)
    """
    required_packages = [
        {'name': 'boto3', 'import_name': 'boto3', 'description': 'AWS SDK for Python'},
        {'name': 'pandas', 'import_name': 'pandas', 'description': 'Data manipulation and analysis library'},
        {'name': 'openpyxl', 'import_name': 'openpyxl', 'description': 'Excel file reading/writing library'}
    ]

    missing_packages = []
    installed_packages = []

    print("\n" + "=" * 50)
    print("DEPENDENCY CHECK")
    print("=" * 50)
    print("Checking required StratusScan dependencies...")

    for package in required_packages:
        try:
            __import__(package['import_name'])
            print(f"[OK] {package['name']} - {package['description']}")
            installed_packages.append(package)
        except ImportError:
            print(f"[MISSING] {package['name']} - {package['description']}")
            missing_packages.append(package)

    print(f"\nSummary: {len(installed_packages)}/{len(required_packages)} dependencies satisfied")

    if missing_packages:
        print(f"\nMissing packages: {', '.join([p['name'] for p in missing_packages])}")
        return False, missing_packages
    else:
        print("\n[SUCCESS] All dependencies are installed and ready!")
        return True, []

def install_dependencies(missing_packages):
    """
    Install missing dependencies with user confirmation.

    Args:
        missing_packages (list): List of package dictionaries to install

    Returns:
        bool: True if installation was successful, False otherwise
    """
    if not missing_packages:
        return True

    print("\n" + "=" * 50)
    print("DEPENDENCY INSTALLATION")
    print("=" * 50)

    print("The following packages need to be installed:")
    for package in missing_packages:
        print(f"  - {package['name']} - {package['description']}")

    confirm = input(f"\nWould you like to install these {len(missing_packages)} packages now? (y/n): ").lower().strip()

    if confirm != 'y':
        print("Dependency installation skipped.")
        print("Note: StratusScan may not work properly without these dependencies.")
        return False

    print(f"\nInstalling packages using pip...")

    all_successful = True

    for package in missing_packages:
        print(f"\n[INSTALLING] {package['name']}...")
        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package['name']
            ], capture_output=True, text=True, check=True)

            print(f"[SUCCESS] {package['name']} installed successfully")

            # Verify the installation
            try:
                __import__(package['import_name'])
                print(f"[VERIFIED] {package['name']} import verification successful")
            except ImportError:
                print(f"[WARNING] {package['name']} installed but import verification failed")
                all_successful = False

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install {package['name']}")
            print(f"Error: {e.stderr.strip()}")
            all_successful = False
        except Exception as e:
            print(f"[ERROR] Unexpected error installing {package['name']}: {e}")
            all_successful = False

    if all_successful:
        print(f"\n[SUCCESS] All dependencies installed successfully!")
        print("StratusScan is now ready to use.")
    else:
        print(f"\n[WARNING] Some dependencies failed to install.")
        print("You may need to install them manually or check your Python environment.")

    return all_successful

def dependency_management_menu():
    """
    Interactive menu for dependency management.

    Returns:
        bool: True if dependencies are satisfied, False otherwise
    """
    while True:
        # Check current dependency status
        deps_satisfied, missing_packages = check_dependencies()

        if deps_satisfied:
            print(f"\n[SUCCESS] All dependencies are satisfied!")
            return True

        print(f"\n[OPTIONS] Dependency Management Options:")
        print("1. Install missing dependencies automatically")
        print("2. Show installation commands for manual installation")
        print("3. Continue without installing dependencies")
        print("4. Check dependencies again")

        choice = input("\nSelect an option (1-4): ").strip()

        if choice == '1':
            success = install_dependencies(missing_packages)
            if success:
                return True
            else:
                print("\nSome dependencies failed to install. You can:")
                print("- Try option 2 for manual installation commands")
                print("- Continue with option 3 (not recommended)")
                continue

        elif choice == '2':
            print(f"\n[MANUAL] Installation Commands:")
            print("Run the following commands in your terminal:")
            print(f"")
            for package in missing_packages:
                print(f"pip install {package['name']}")
            print(f"\nAlternatively, install all at once:")
            print(f"pip install {' '.join([p['name'] for p in missing_packages])}")
            print(f"\nAfter manual installation, choose option 4 to check again.")
            continue

        elif choice == '3':
            print(f"\n[WARNING] Continuing without all dependencies installed.")
            print("Note: StratusScan scripts may fail to run properly.")
            return False

        elif choice == '4':
            print(f"\nRechecking dependencies...")
            continue

        else:
            print("Invalid choice. Please select 1-4.")
            continue

def get_aws_managed_policy_recommendations():
    """
    Get comprehensive AWS managed policy recommendations for StratusScan.

    Returns:
        dict: Dictionary of service categories and their recommended managed policies
    """
    return {
        'core_permissions': {
            'policies': ['ReadOnlyAccess'],
            'description': 'Comprehensive read-only access to most AWS services',
            'priority': 'HIGH',
            'reason': 'Provides broad read access needed for resource scanning'
        },
        'alternative_minimal': {
            'policies': [
                'AmazonEC2ReadOnlyAccess',
                'AmazonS3ReadOnlyAccess',
                'AmazonRDSReadOnlyAccess',
                'AmazonVPCReadOnlyAccess',
                'IAMReadOnlyAccess',
                'AWSCloudTrailReadOnlyAccess',
                'CloudWatchReadOnlyAccess'
            ],
            'description': 'Minimal set of service-specific read-only policies',
            'priority': 'MEDIUM',
            'reason': 'More granular control but requires multiple policy attachments'
        },
        'cost_management': {
            'policies': ['AWSBillingReadOnlyAccess'],
            'description': 'Access to Cost Explorer for service usage analysis',
            'priority': 'MEDIUM',
            'reason': 'Required for services-in-use detection via cost data'
        },
        'identity_center': {
            'policies': ['AWSSSOReadOnly'],
            'description': 'Read access to AWS IAM Identity Center (SSO)',
            'priority': 'LOW',
            'reason': 'Only needed if using Identity Center export scripts'
        },
        'security_services': {
            'policies': ['SecurityAudit'],
            'description': 'Read access to security-related configurations',
            'priority': 'MEDIUM',
            'reason': 'Provides access to security services like GuardDuty, Security Hub'
        }
    }

def test_aws_permissions():
    """
    Test current AWS permissions by attempting key API calls.
    Automatically detects partition and uses appropriate region.

    Returns:
        dict: Dictionary of permission test results
    """
    # Detect partition and get appropriate region
    partition, test_region = detect_aws_partition()
    is_govcloud = partition == 'aws-us-gov'

    permission_tests = {
        'sts:GetCallerIdentity': {
            'test_function': lambda: boto3.client('sts').get_caller_identity(),
            'required': True,
            'service': 'AWS Security Token Service',
            'description': 'Basic AWS authentication verification'
        },
        'ec2:DescribeInstances': {
            'test_function': lambda: boto3.client('ec2', region_name=test_region).describe_instances(MaxResults=5),
            'required': True,
            'service': 'Amazon EC2',
            'description': 'List EC2 instances for compute resource scanning'
        },
        's3:ListBuckets': {
            'test_function': lambda: boto3.client('s3').list_buckets(),
            'required': True,
            'service': 'Amazon S3',
            'description': 'List S3 buckets for storage resource scanning'
        },
        'iam:ListUsers': {
            'test_function': lambda: boto3.client('iam').list_users(MaxItems=5),
            'required': True,
            'service': 'AWS Identity and Access Management',
            'description': 'List IAM users for identity management scanning'
        },
        'rds:DescribeDBInstances': {
            'test_function': lambda: boto3.client('rds', region_name=test_region).describe_db_instances(),
            'required': True,
            'service': 'Amazon RDS',
            'description': 'List RDS instances for database resource scanning'
        },
        'ec2:DescribeVpcs': {
            'test_function': lambda: boto3.client('ec2', region_name=test_region).describe_vpcs(),
            'required': True,
            'service': 'Amazon VPC',
            'description': 'List VPCs for network resource scanning'
        },
        'cloudtrail:LookupEvents': {
            'test_function': lambda: boto3.client('cloudtrail', region_name=test_region).lookup_events(MaxResults=1),
            'required': False,
            'service': 'AWS CloudTrail',
            'description': 'Access event history for service usage analysis'
        },
        'sso-admin:ListInstances': {
            'test_function': lambda: boto3.client('sso-admin', region_name=test_region).list_instances(),
            'required': False,
            'service': 'AWS IAM Identity Center',
            'description': 'List Identity Center instances for SSO analysis'
        },
        'identitystore:ListUsers': {
            'test_function': lambda: boto3.client('identitystore', region_name=test_region).list_users(
                IdentityStoreId='d-example123456'  # This will likely fail but tests the permission
            ),
            'required': False,
            'service': 'AWS Identity Store',
            'description': 'Access Identity Store for user/group analysis'
        }
    }

    # Cost Explorer is NOT available in GovCloud - skip this test
    if not is_govcloud:
        permission_tests['ce:GetDimensionValues'] = {
            'test_function': lambda: boto3.client('ce', region_name=test_region).get_dimension_values(
                TimePeriod={'Start': '2024-01-01', 'End': '2024-01-02'},
                Dimension='SERVICE'
            ),
            'required': False,
            'service': 'AWS Cost Explorer',
            'description': 'Access cost data for comprehensive service discovery'
        }

    results = {}

    for permission, config in permission_tests.items():
        try:
            config['test_function']()
            results[permission] = {
                'status': 'ALLOWED',
                'error': None,
                'required': config['required'],
                'service': config['service'],
                'description': config['description']
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            results[permission] = {
                'status': 'DENIED',
                'error': error_code,
                'required': config['required'],
                'service': config['service'],
                'description': config['description']
            }
        except Exception as e:
            results[permission] = {
                'status': 'ERROR',
                'error': str(e),
                'required': config['required'],
                'service': config['service'],
                'description': config['description']
            }

    return results

def check_aws_permissions():
    """
    Check AWS permissions and provide recommendations.

    Returns:
        tuple: (bool, dict) - (has_required_permissions, detailed_results)
    """
    print("\n" + "=" * 50)
    print("AWS PERMISSIONS CHECK")
    print("=" * 50)
    print("Testing AWS permissions for StratusScan operations...")

    try:
        # Test basic AWS connectivity first
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        user_arn = identity.get('Arn', 'Unknown')
        account_id = identity.get('Account', 'Unknown')

        # Detect partition
        partition, test_region = detect_aws_partition()
        partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

        print(f"\nAWS Identity: {user_arn}")
        print(f"Account ID: {account_id}")
        print(f"User ID: {identity.get('UserId', 'Unknown')}")
        print(f"Partition: {partition_name}")
        print(f"Test Region: {test_region}")

    except NoCredentialsError:
        print("\n[ERROR] No AWS credentials found!")
        print("Please configure your AWS credentials before running StratusScan.")
        return False, {'error': 'No AWS credentials configured'}
    except Exception as e:
        print(f"\n[ERROR] AWS authentication failed: {e}")
        return False, {'error': f'AWS authentication failed: {e}'}

    # Test individual permissions
    print(f"\nTesting individual permissions...")
    permission_results = test_aws_permissions()

    # Analyze results
    required_passed = 0
    required_failed = 0
    optional_passed = 0
    optional_failed = 0

    print(f"\nPermission Test Results:")
    print("-" * 50)

    for permission, result in permission_results.items():
        status_icon = "[OK]" if result['status'] == 'ALLOWED' else "[DENIED]"
        priority = "REQUIRED" if result['required'] else "OPTIONAL"

        print(f"{status_icon} {permission} ({priority})")
        print(f"    Service: {result['service']}")
        print(f"    Purpose: {result['description']}")

        if result['status'] != 'ALLOWED':
            print(f"    Error: {result['error']}")

        # Count results
        if result['required']:
            if result['status'] == 'ALLOWED':
                required_passed += 1
            else:
                required_failed += 1
        else:
            if result['status'] == 'ALLOWED':
                optional_passed += 1
            else:
                optional_failed += 1

        print()

    # Summary
    total_required = required_passed + required_failed
    total_optional = optional_passed + optional_failed

    print("=" * 50)
    print("PERMISSIONS SUMMARY")
    print("=" * 50)
    print(f"Required permissions: {required_passed}/{total_required} passed")
    print(f"Optional permissions: {optional_passed}/{total_optional} passed")

    has_required_permissions = required_failed == 0

    if has_required_permissions:
        print("\n[SUCCESS] All required permissions are available!")
        if optional_failed > 0:
            print(f"[INFO] {optional_failed} optional permissions are missing.")
            print("Some advanced features may not be available.")
    else:
        print(f"\n[WARNING] {required_failed} required permissions are missing!")
        print("StratusScan scripts may fail without these permissions.")

    return has_required_permissions, {
        'required_passed': required_passed,
        'required_failed': required_failed,
        'optional_passed': optional_passed,
        'optional_failed': optional_failed,
        'detailed_results': permission_results
    }

def show_policy_recommendations(permission_results):
    """
    Show comprehensive policy recommendations including custom StratusScan policies.

    Args:
        permission_results (dict): Results from permission testing
    """
    print("\n" + "=" * 70)
    print("IAM POLICY RECOMMENDATIONS")
    print("=" * 70)

    # Get the path to policy files
    script_dir = Path(__file__).parent.absolute()
    required_policy_path = script_dir / "policies" / "stratusscan-required-permissions.json"
    optional_policy_path = script_dir / "policies" / "stratusscan-optional-permissions.json"
    policies_readme_path = script_dir / "policies" / "README.md"

    # Check if user has required permissions
    has_required = permission_results.get('required_failed', 0) == 0
    has_all_optional = permission_results.get('optional_failed', 0) == 0

    if has_required and has_all_optional:
        print("[SUCCESS] You have all required AND optional permissions!")
        print("StratusScan is fully configured and ready to use.\n")
        print("You can run the full suite of export scripts without restrictions.")
        return

    if has_required:
        print("[SUCCESS] You have all required permissions for basic StratusScan functionality!")
        print("\nBasic features available:")
        print("  - EC2, RDS, Lambda, ECS, EKS (Compute resources)")
        print("  - S3, EBS, EFS, FSx (Storage resources)")
        print("  - VPC, Load Balancers, Route 53 (Network resources)")
        print("  - IAM, KMS, Secrets Manager (Security and identity)")
        print("  - CloudWatch, CloudTrail, Config (Monitoring and compliance)")

        if permission_results.get('optional_failed', 0) > 0:
            print("\n[OPTIONAL] Some advanced features are unavailable:")
            failed_optional = [p for p, r in permission_results.get('detailed_results', {}).items()
                             if not r['required'] and r['status'] != 'ALLOWED']

            if any('securityhub' in p.lower() for p in failed_optional):
                print("  - Security Hub findings and compliance reports")
            if any('ce:' in p or 'cost' in p.lower() for p in failed_optional):
                print("  - Cost Explorer and Cost Optimization Hub")
            if any('support' in p.lower() for p in failed_optional):
                print("  - Trusted Advisor recommendations (requires Business/Enterprise Support)")
            if any('sso' in p.lower() or 'identity' in p.lower() for p in failed_optional):
                print("  - IAM Identity Center (SSO) users and groups")

            print(f"\nTo enable these features:")
            print(f"1. Review and copy policy from: {optional_policy_path}")
            print(f"2. Create a custom IAM policy named 'StratusScanOptionalPermissions'")
            print(f"3. Attach it to your IAM user or role")
            print(f"\nFor detailed instructions, see: {policies_readme_path}")
    else:
        print("[REQUIRED] You are missing required permissions to run StratusScan.\n")

        # Show which required permissions are missing
        failed_required = [p for p, r in permission_results.get('detailed_results', {}).items()
                          if r['required'] and r['status'] != 'ALLOWED']

        if failed_required:
            print("Missing required permissions:")
            for perm in failed_required[:5]:  # Show first 5
                print(f"  - {perm}")
            if len(failed_required) > 5:
                print(f"  ... and {len(failed_required) - 5} more")

        print("\n" + "=" * 70)
        print("RECOMMENDED SOLUTION: Use StratusScan Custom Policies")
        print("=" * 70)
        print("\nWe provide ready-to-use IAM policy JSON files optimized for StratusScan:")
        print("")
        print("Option 1: CUSTOM POLICIES (Recommended - Least Privilege)")
        print("-" * 70)
        print(f"Required Policy: {required_policy_path}")
        print("  - Covers 100+ export scripts across 80+ AWS services")
        print("  - Read-only permissions only (Get*, Describe*, List*)")
        print("  - ~250 specific actions for precise access control")
        print("")
        print(f"Optional Policy: {optional_policy_path}")
        print("  - Advanced features: Security Hub, Cost Optimization, Trusted Advisor")
        print("  - IAM Identity Center (SSO), Compute Optimizer, Health Dashboard")
        print("  - ~60 additional actions for optional functionality")
        print("")
        print("How to apply custom policies:")
        print("  1. Open the policy file and copy the JSON content")
        print("  2. Go to IAM Console > Policies > Create policy")
        print("  3. Paste JSON, name it 'StratusScanRequiredPermissions'")
        print("  4. Attach policy to your IAM user or role")
        print(f"  5. See detailed instructions: {policies_readme_path}")

        print("\n" + "-" * 70)
        print("Option 2: AWS MANAGED POLICIES (Simpler but broader permissions)")
        print("-" * 70)

        policy_recommendations = get_aws_managed_policy_recommendations()

        print("\nPrimary managed policy (covers most needs):")
        for policy in policy_recommendations['core_permissions']['policies']:
            print(f"  - {policy}")
        print(f"    {policy_recommendations['core_permissions']['description']}")

        print("\nAlternative managed policies (more granular):")
        for policy in policy_recommendations['alternative_minimal']['policies']:
            print(f"  - {policy}")
        print(f"    {policy_recommendations['alternative_minimal']['description']}")

        print("\nAdditional managed policies for optional features:")
        for category in ['cost_management', 'security_services', 'identity_center']:
            info = policy_recommendations[category]
            for policy in info['policies']:
                print(f"  - {policy}")
            print(f"    {info['description']}")

    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)

    if has_required:
        print("1. (Optional) Review optional permissions policy")
        print(f"   Location: {optional_policy_path}")
        print("2. Create and attach the optional policy if needed")
        print("3. Re-run permission check: python configure.py --perms")
    else:
        print("1. Review the required permissions policy")
        print(f"   Location: {required_policy_path}")
        print("2. Create a custom IAM policy with the JSON content")
        print("3. Attach the policy to your IAM user or role")
        print("4. Re-run permission check: python configure.py --perms")
        print("")
        print("OR use AWS managed policies (ReadOnlyAccess, SecurityAudit, etc.)")

    print("\nFor complete documentation and troubleshooting:")
    print(f"  {policies_readme_path}")
    print("=" * 70)

def permissions_management_menu():
    """
    Interactive menu for AWS permissions management.

    Returns:
        bool: True if permissions are adequate, False otherwise
    """
    while True:
        # Check current permission status
        has_required, results = check_aws_permissions()

        print(f"\n[OPTIONS] Permissions Management Options:")
        print("1. Show policy recommendations and next steps")
        print("2. View StratusScan policy file locations")
        print("3. Re-test permissions (after applying policies)")
        print("4. Show detailed permission test results")
        print("5. Continue with current permissions")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == '1':
            show_policy_recommendations(results)
            continue

        elif choice == '2':
            # Show policy file locations
            script_dir = Path(__file__).parent.absolute()
            print("\n" + "=" * 70)
            print("STRATUSSCAN POLICY FILES")
            print("=" * 70)
            print("\nRequired Permissions Policy (Core Functionality):")
            print(f"  {script_dir / 'policies' / 'stratusscan-required-permissions.json'}")
            print("  Covers: EC2, S3, RDS, VPC, IAM, Lambda, and 70+ other services")
            print("  Actions: ~250 read-only permissions")
            print("")
            print("Optional Permissions Policy (Advanced Features):")
            print(f"  {script_dir / 'policies' / 'stratusscan-optional-permissions.json'}")
            print("  Covers: Security Hub, Cost Optimization, Trusted Advisor, Identity Center")
            print("  Actions: ~60 read-only permissions")
            print("")
            print("Complete Documentation:")
            print(f"  {script_dir / 'policies' / 'README.md'}")
            print("  Includes: Usage instructions, troubleshooting, GovCloud considerations")
            print("=" * 70)
            continue

        elif choice == '3':
            print(f"\nRe-testing permissions...")
            continue

        elif choice == '4':
            # Show detailed results
            detailed = results.get('detailed_results', {})
            print(f"\n[DETAILS] Complete Permission Test Results:")
            print("-" * 70)

            for permission, result in detailed.items():
                print(f"Permission: {permission}")
                print(f"  Status: {result['status']}")
                print(f"  Required: {'Yes' if result['required'] else 'No'}")
                print(f"  Service: {result['service']}")
                print(f"  Description: {result['description']}")
                if result['error']:
                    print(f"  Error: {result['error']}")
                print()
            continue

        elif choice == '5':
            if not has_required:
                print(f"\n[WARNING] Continuing without all required permissions!")
                print("StratusScan scripts may encounter errors or produce incomplete results.")
                confirm = input("Are you sure you want to continue? (y/n): ").lower().strip()
                if confirm != 'y':
                    continue
            return has_required

        else:
            print("Invalid choice. Please select 1-5.")
            continue

def main():
    """Main function to run the configuration tool."""
    try:
        # Print header
        print_header()

        # Check and manage dependencies
        print("Checking StratusScan dependencies before configuration...")
        dependency_management_menu()

        # Check and manage AWS permissions
        print("\nChecking AWS permissions for StratusScan operations...")
        permissions_management_menu()

        # Get the config file path (same directory as this script)
        script_dir = Path(__file__).parent.absolute()
        config_path = script_dir / "config.json"

        print(f"\nConfiguration file: {config_path}")

        # Load existing configuration
        config = load_existing_config(config_path)

        # Show current configuration if it exists
        if config_path.exists():
            print("\nCurrent configuration loaded:")
            display_summary(config)

            modify = input("\nWould you like to modify the configuration? (y/n): ").lower().strip()
            if modify != 'y':
                print("Configuration unchanged. Exiting...")
                return

        # Get organization name
        current_org = config.get('organization_name', 'YOUR-ORGANIZATION')
        organization_name = get_organization_name(current_org)
        config['organization_name'] = organization_name

        # Get default AWS region
        print(f"\nCurrent default regions: {', '.join(config.get('default_regions', []))}")
        change_region = input("Would you like to change the primary default region? (y/n): ").lower().strip()

        if change_region == 'y':
            default_region = get_aws_region_choice()
            # Update all default regions to prioritize the selected one
            # Set secondary region based on partition
            if default_region.startswith('us-gov-'):
                # GovCloud: Choose the other GovCloud region
                secondary_region = "us-gov-east-1" if default_region == "us-gov-west-1" else "us-gov-west-1"
            else:
                # Commercial: Use traditional defaults
                secondary_region = "us-west-2" if default_region == "us-east-1" else "us-east-1"
            config['default_regions'] = [default_region, secondary_region]
            # Update resource preferences
            update_resource_preferences(config, default_region)
            print(f"Default region updated to: {default_region}")

        # Get account mappings
        print(f"\nCurrent account mappings: {len(config.get('account_mappings', {}))}")
        modify_accounts = input("Would you like to add/modify account mappings? (y/n): ").lower().strip()

        if modify_accounts == 'y':
            new_mappings = get_account_mappings()
            # Merge with existing mappings
            existing_mappings = config.get('account_mappings', {})
            existing_mappings.update(new_mappings)
            config['account_mappings'] = existing_mappings

        # Display final configuration summary
        display_summary(config)

        # Confirm save
        save_confirm = input("\nSave this configuration? (y/n): ").lower().strip()

        if save_confirm == 'y':
            if save_configuration(config, config_path):
                print("\n✅ Configuration completed successfully!")
                print(f"You can now use StratusScan with your configured settings.")
                print(f"Run 'python stratusscan.py' to start the main menu.")
            else:
                print("\n❌ Configuration save failed.")
                sys.exit(1)
        else:
            print("\nConfiguration not saved. Exiting...")

    except KeyboardInterrupt:
        print("\n\nConfiguration cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for command-line arguments
    if len(sys.argv) > 1:
        if '--deps' in sys.argv or '--dependencies' in sys.argv:
            # Run dependency check only
            print_header()
            print("Running dependency check only...\n")
            dependency_management_menu()
            print("\nDependency check complete.")
            sys.exit(0)
        elif '--perms' in sys.argv or '--permissions' in sys.argv:
            # Run permissions check only
            print_header()
            print("Running AWS permissions check only...\n")
            permissions_management_menu()
            print("\nPermissions check complete.")
            sys.exit(0)
        elif '--help' in sys.argv or '-h' in sys.argv:
            print("StratusScan Configuration Tool")
            print("\nUsage:")
            print("  python configure.py           # Full configuration")
            print("  python configure.py --deps    # Dependency check only")
            print("  python configure.py --perms   # Permissions check only")
            print("  python configure.py --help    # Show this help")
            sys.exit(0)
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Use --help for usage information.")
            sys.exit(1)

    # Run full configuration
    main()