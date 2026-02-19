#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: StratusScan Configuration Tool
Version: v0.1.0
Date: DEC-24-2024

Description:
Interactive configuration tool for setting up the StratusScan AWS environment.
This script provides a menu-driven dashboard for managing AWS-specific settings,
account mappings, dependencies, and permissions.

Features:
- Menu-driven dashboard (non-linear navigation)
- Background dependency and permissions checks
- Quick edit mode via CLI arguments
- Visual status indicators
- Configuration validation and backup
- Partition-aware (Commercial vs GovCloud)
- Smart defaults and auto-detection

Usage:
- python configure.py                              (interactive dashboard)
- python configure.py --deps                       (dependency check only)
- python configure.py --perms                      (permissions check only)
- python configure.py --org "Company Name"         (quick org name update)
- python configure.py --account ID NAME            (quick account mapping)
- python configure.py --region REGION              (quick region update)
- python configure.py --validate                   (full validation check)
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, Optional, List

# Try to import boto3, but don't fail if it's missing (will be caught later)
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    # Define placeholder exception classes
    class ClientError(Exception):
        pass
    class NoCredentialsError(Exception):
        pass

# ============================================================================
# GLOBAL STATE (for background checks)
# ============================================================================

_dependency_status = None  # Will be populated by background check
_permission_status = None  # Will be populated by background check
_aws_identity = None       # Current AWS identity info
_config_modified = False   # Track if config has unsaved changes

# ============================================================================
# AWS PARTITION & IDENTITY DETECTION
# ============================================================================

def detect_aws_partition() -> Tuple[str, str]:
    """
    Detect the AWS partition (commercial vs govcloud) from caller identity.

    Returns:
        tuple: (partition, default_region) - e.g., ('aws', 'us-east-1') or ('aws-us-gov', 'us-gov-west-1')
    """
    if not BOTO3_AVAILABLE:
        return 'aws', 'us-east-1'

    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        arn = identity.get('Arn', '')

        if 'aws-us-gov' in arn:
            return 'aws-us-gov', 'us-gov-west-1'
        else:
            return 'aws', 'us-east-1'
    except Exception:
        # Default to commercial if detection fails (e.g., no credentials configured)
        return 'aws', 'us-east-1'

def get_aws_identity() -> Optional[Dict]:
    """
    Get current AWS identity information.

    Returns:
        dict: Identity info or None if credentials unavailable
    """
    global _aws_identity

    if _aws_identity is not None:
        return _aws_identity

    if not BOTO3_AVAILABLE:
        return None

    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        partition, default_region = detect_aws_partition()

        _aws_identity = {
            'arn': identity.get('Arn', 'Unknown'),
            'account_id': identity.get('Account', 'Unknown'),
            'user_id': identity.get('UserId', 'Unknown'),
            'partition': partition,
            'partition_name': "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial",
            'default_region': default_region
        }
        return _aws_identity
    except Exception:
        return None

# ============================================================================
# VISUAL HELPERS
# ============================================================================

def print_box(title: str, width: int = 70):
    """Print a box with title."""
    print("╔" + "═" * (width - 2) + "╗")
    padding = (width - len(title) - 2) // 2
    print("║" + " " * padding + title + " " * (width - len(title) - padding - 2) + "║")
    print("╚" + "═" * (width - 2) + "╝")

def print_section(title: str, width: int = 70):
    """Print a section header."""
    print("\n" + "─" * width)
    print(title)
    print("─" * width)

def print_status_line(label: str, status: str, width: int = 70):
    """Print a status line with alignment."""
    label_part = f"║ {label}: "
    status_part = f"{status} ║"
    padding = width - len(label_part) - len(status_part)
    print(label_part + " " * padding + status_part)

def get_status_icon(status: str) -> str:
    """Get status icon based on status string."""
    if status == "ok":
        return "✅"
    elif status == "warning":
        return "⚠️ "
    elif status == "error":
        return "❌"
    elif status == "unknown":
        return "❓"
    else:
        return "  "

# ============================================================================
# BACKGROUND CHECKS
# ============================================================================

def check_dependencies_silent() -> Dict:
    """
    Check dependencies without user interaction.

    Returns:
        dict: Dependency status information
    """
    required_packages = [
        {'name': 'boto3', 'import_name': 'boto3', 'description': 'AWS SDK for Python'},
        {'name': 'pandas', 'import_name': 'pandas', 'description': 'Data manipulation and analysis library'},
        {'name': 'openpyxl', 'import_name': 'openpyxl', 'description': 'Excel file reading/writing library'}
    ]

    missing_packages = []
    installed_packages = []

    for package in required_packages:
        try:
            __import__(package['import_name'])
            installed_packages.append(package)
        except ImportError:
            missing_packages.append(package)

    return {
        'all_satisfied': len(missing_packages) == 0,
        'installed_count': len(installed_packages),
        'total_count': len(required_packages),
        'missing_packages': missing_packages,
        'installed_packages': installed_packages
    }

def check_permissions_silent() -> Dict:
    """
    Check AWS permissions without user interaction.

    Returns:
        dict: Permission status information
    """
    identity = get_aws_identity()
    if not identity:
        return {
            'has_credentials': False,
            'has_required': False,
            'required_passed': 0,
            'required_failed': 0,
            'optional_passed': 0,
            'optional_failed': 0,
            'error': 'No AWS credentials configured'
        }

    partition = identity['partition']
    test_region = identity['default_region']
    is_govcloud = partition == 'aws-us-gov'

    # Simplified permission tests (subset for speed)
    permission_tests = {
        'sts:GetCallerIdentity': {
            'test_function': lambda: boto3.client('sts').get_caller_identity(),
            'required': True
        },
        'ec2:DescribeInstances': {
            'test_function': lambda: boto3.client('ec2', region_name=test_region).describe_instances(MaxResults=5),
            'required': True
        },
        's3:ListBuckets': {
            'test_function': lambda: boto3.client('s3').list_buckets(),
            'required': True
        },
        'iam:ListUsers': {
            'test_function': lambda: boto3.client('iam').list_users(MaxItems=5),
            'required': True
        }
    }

    required_passed = 0
    required_failed = 0
    optional_passed = 0
    optional_failed = 0

    for permission, config in permission_tests.items():
        try:
            config['test_function']()
            if config['required']:
                required_passed += 1
            else:
                optional_passed += 1
        except Exception:
            if config['required']:
                required_failed += 1
            else:
                optional_failed += 1

    return {
        'has_credentials': True,
        'has_required': required_failed == 0,
        'required_passed': required_passed,
        'required_failed': required_failed,
        'optional_passed': optional_passed,
        'optional_failed': optional_failed
    }

def run_background_checks():
    """Run background checks for dependencies and permissions."""
    global _dependency_status, _permission_status

    # Check dependencies
    _dependency_status = check_dependencies_silent()

    # Check permissions
    _permission_status = check_permissions_silent()

# ============================================================================
# CONFIGURATION FILE MANAGEMENT
# ============================================================================

def get_config_path() -> Path:
    """Get the path to config.json file."""
    script_dir = Path(__file__).parent.absolute()
    return script_dir / "config.json"

def load_existing_config(config_path: Path) -> Dict:
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

def save_configuration(config: Dict, config_path: Path) -> bool:
    """
    Save the configuration to the JSON file.

    Args:
        config (dict): Configuration dictionary
        config_path (Path): Path to save the config file

    Returns:
        bool: True if successful, False otherwise
    """
    global _config_modified

    try:
        # Create backup if file exists
        if config_path.exists():
            backup_path = config_path.with_suffix('.json.backup')
            config_path.rename(backup_path)
            print(f"\n✅ Backup created: {backup_path}")

        # Save new configuration
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuration saved successfully to: {config_path}")
        _config_modified = False
        return True

    except Exception as e:
        print(f"❌ Error saving configuration: {e}")
        return False

def get_config_status(config: Dict, config_path: Path) -> str:
    """
    Get configuration status string.

    Args:
        config (dict): Configuration dictionary
        config_path (Path): Path to config file

    Returns:
        str: Status string
    """
    if not config_path.exists():
        return "❌ Not configured"

    if _config_modified:
        return "⚠️  Modified (unsaved)"

    # Check if essential fields are set
    if config.get('organization_name') == 'YOUR-ORGANIZATION':
        return "⚠️  Needs setup"

    if not config.get('account_mappings'):
        return "⚠️  No accounts"

    # Get last modified time
    try:
        mtime = config_path.stat().st_mtime
        mod_date = datetime.fromtimestamp(mtime).strftime("%b %d")
        return f"✅ OK (Updated {mod_date})"
    except OSError:
        return "✅ OK"

# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def validate_account_id(account_id: str) -> bool:
    """
    Validate that the account ID is a 12-digit number.

    Args:
        account_id (str): The account ID to validate

    Returns:
        bool: True if valid, False otherwise
    """
    account_id = account_id.strip()
    pattern = re.compile(r'^\d{12}$')
    return bool(pattern.match(account_id))

# ============================================================================
# MAIN MENU & DASHBOARD
# ============================================================================

def print_dashboard(config: Dict, config_path: Path):
    """
    Print the main dashboard.

    Args:
        config (dict): Configuration dictionary
        config_path (Path): Path to config file
    """
    identity = get_aws_identity()

    # Header
    print("\n")
    print_box("STRATUSSCAN CONFIGURATION TOOL v0.1.0", 70)

    # Status box
    print("╔" + "═" * 68 + "╗")

    if identity:
        print_status_line("Environment", identity['partition_name'], 70)
        print_status_line("Account", f"{identity['account_id']}", 70)
    else:
        print_status_line("AWS Credentials", "❌ Not configured", 70)

    config_status = get_config_status(config, config_path)
    print_status_line("Configuration", config_status, 70)

    print("╚" + "═" * 68 + "╝")

    # Main menu
    print("\n" + "═" * 70)
    print("MAIN MENU")
    print("═" * 70)

    # Configuration options
    print("\nConfiguration:")
    print("  [1] View Current Configuration")
    print("  [2] Edit Organization Settings")
    print("  [3] Manage Account Mappings")
    print("  [4] Configure Default Regions")
    print("  [5] Advanced Settings (Resource Preferences)")

    # System checks
    print("\nSystem Checks:")

    # Dependencies status
    if _dependency_status:
        if _dependency_status['all_satisfied']:
            dep_status = f"✅ All OK ({_dependency_status['installed_count']}/{_dependency_status['total_count']})"
        else:
            missing_count = len(_dependency_status['missing_packages'])
            dep_status = f"❌ {missing_count} missing"
    else:
        dep_status = "❓ Not checked"
    print(f"  [6] Check Dependencies                     {dep_status}")

    # Permissions status
    if _permission_status:
        if not _permission_status['has_credentials']:
            perm_status = "❌ No credentials"
        elif _permission_status['has_required']:
            optional_failed = _permission_status.get('optional_failed', 0)
            if optional_failed > 0:
                perm_status = f"⚠️  {optional_failed} optional missing"
            else:
                perm_status = "✅ All OK"
        else:
            required_failed = _permission_status['required_failed']
            perm_status = f"❌ {required_failed} required missing"
    else:
        perm_status = "❓ Not checked"
    print(f"  [7] Check AWS Permissions                  {perm_status}")

    # Actions
    print("\nActions:")
    print("  [8] Save & Exit")
    print("  [9] Exit Without Saving" + (" (Unsaved changes!)" if _config_modified else ""))
    print("  [0] Refresh Status")

    print("\n" + "═" * 70)

def main_menu_loop(config: Dict, config_path: Path):
    """
    Main menu loop.

    Args:
        config (dict): Configuration dictionary
        config_path (Path): Path to config file
    """
    while True:
        print_dashboard(config, config_path)

        choice = input("\nSelect option (0-9): ").strip()

        if choice == '1':
            view_configuration(config)
        elif choice == '2':
            edit_organization_settings(config)
        elif choice == '3':
            manage_account_mappings(config)
        elif choice == '4':
            configure_default_regions(config)
        elif choice == '5':
            advanced_settings(config)
        elif choice == '6':
            dependency_management_menu()
        elif choice == '7':
            permissions_management_menu()
        elif choice == '8':
            # Save & Exit
            if _config_modified:
                print("\n" + "═" * 70)
                print("SAVE CONFIGURATION")
                print("═" * 70)
                display_summary(config)
                confirm = input("\nSave this configuration? (y/n): ").lower().strip()
                if confirm == 'y':
                    if save_configuration(config, config_path):
                        print("\n✅ Configuration saved successfully!")
                        print("You can now use StratusScan with your configured settings.")
                        print("Run 'python stratusscan.py' to start the main menu.")
                        return
                    else:
                        print("\n❌ Configuration save failed.")
                        input("\nPress Enter to return to menu...")
                        continue
                else:
                    input("\nPress Enter to return to menu...")
                    continue
            else:
                print("\n✅ No unsaved changes. Exiting...")
                return
        elif choice == '9':
            # Exit without saving
            if _config_modified:
                print("\n⚠️  WARNING: You have unsaved changes!")
                confirm = input("Exit without saving? (y/n): ").lower().strip()
                if confirm == 'y':
                    print("\n❌ Configuration not saved. Exiting...")
                    return
                else:
                    continue
            else:
                print("\n✅ Exiting...")
                return
        elif choice == '0':
            # Refresh status
            print("\n🔄 Refreshing status...")
            run_background_checks()
            continue
        else:
            print("\n❌ Invalid choice. Please select 0-9.")
            input("Press Enter to continue...")

# ============================================================================
# CONFIGURATION VIEWERS & EDITORS
# ============================================================================

def view_configuration(config: Dict):
    """View current configuration."""
    print("\n" + "═" * 70)
    print("CURRENT CONFIGURATION")
    print("═" * 70)
    display_summary(config)
    input("\nPress Enter to return to menu...")

def display_summary(config: Dict):
    """
    Display a summary of the current configuration.

    Args:
        config (dict): Configuration dictionary
    """
    # Organization/company name
    print(f"\nOrganization/Company Name: {config.get('organization_name', 'Not set')}")

    # Default regions
    default_regions = config.get('default_regions', [])
    print(f"Default Regions: {', '.join(default_regions)}")

    # Account mappings
    mappings = config.get('account_mappings', {})
    print(f"\nAccount Mappings ({len(mappings)} configured):")
    if mappings:
        for account_id, name in sorted(mappings.items()):
            print(f"  {account_id} → {name}")
    else:
        print("  None configured")

    # Resource preferences (show EC2 default region as example)
    ec2_region = config.get('resource_preferences', {}).get('ec2', {}).get('default_region', 'Not set')
    print(f"\nDefault Resource Region: {ec2_region}")

def edit_organization_settings(config: Dict):
    """Edit organization settings."""
    global _config_modified

    print_section("EDIT ORGANIZATION SETTINGS")

    current_org = config.get('organization_name', 'YOUR-ORGANIZATION')
    print(f"\nCurrent organization/company name: {current_org}")

    new_org = input("Enter new organization/company name (or press Enter to keep current): ").strip()

    if new_org and new_org != current_org:
        config['organization_name'] = new_org
        _config_modified = True
        print(f"\n✅ Organization name updated to: {new_org}")
    else:
        print("\n✅ Organization name unchanged")

    input("\nPress Enter to return to menu...")

def manage_account_mappings(config: Dict):
    """Manage account mappings."""
    global _config_modified

    while True:
        print_section("MANAGE ACCOUNT MAPPINGS")

        mappings = config.get('account_mappings', {})

        print(f"\nCurrent Account Mappings ({len(mappings)}):")
        if mappings:
            for idx, (account_id, name) in enumerate(sorted(mappings.items()), 1):
                print(f"  {idx}. {account_id} → {name}")
        else:
            print("  None configured")

        print("\nOptions:")
        print("  [A] Add new account")
        print("  [E] Edit existing account")
        print("  [D] Delete account")
        print("  [B] Back to main menu")

        choice = input("\nSelect option (A/E/D/B): ").strip().upper()

        if choice == 'A':
            # Add new account
            while True:
                account_id = input("\nEnter AWS Account ID (12 digits): ").strip()
                if not account_id:
                    break
                if validate_account_id(account_id):
                    if account_id in mappings:
                        overwrite = input(f"Account {account_id} already exists. Overwrite? (y/n): ").lower().strip()
                        if overwrite != 'y':
                            continue
                    break
                else:
                    print("❌ Invalid account ID. Must be exactly 12 digits (e.g., 123456789012)")

            if account_id:
                account_name = input(f"Enter friendly name for account {account_id}: ").strip()
                if account_name:
                    mappings[account_id] = account_name
                    config['account_mappings'] = mappings
                    _config_modified = True
                    print(f"\n✅ Added: {account_id} → {account_name}")
                else:
                    print("\n❌ Account name cannot be empty")

        elif choice == 'E':
            # Edit existing account
            if not mappings:
                print("\n❌ No accounts to edit")
                input("Press Enter to continue...")
                continue

            account_id = input("\nEnter Account ID to edit: ").strip()
            if account_id in mappings:
                print(f"Current name: {mappings[account_id]}")
                new_name = input("Enter new friendly name: ").strip()
                if new_name:
                    mappings[account_id] = new_name
                    config['account_mappings'] = mappings
                    _config_modified = True
                    print(f"\n✅ Updated: {account_id} → {new_name}")
            else:
                print(f"\n❌ Account {account_id} not found")

        elif choice == 'D':
            # Delete account
            if not mappings:
                print("\n❌ No accounts to delete")
                input("Press Enter to continue...")
                continue

            account_id = input("\nEnter Account ID to delete: ").strip()
            if account_id in mappings:
                confirm = input(f"Delete {account_id} ({mappings[account_id]})? (y/n): ").lower().strip()
                if confirm == 'y':
                    del mappings[account_id]
                    config['account_mappings'] = mappings
                    _config_modified = True
                    print(f"\n✅ Deleted: {account_id}")
            else:
                print(f"\n❌ Account {account_id} not found")

        elif choice == 'B':
            # Back to main menu
            return

        else:
            print("\n❌ Invalid choice. Please select A/E/D/B.")

def configure_default_regions(config: Dict):
    """Configure default regions."""
    global _config_modified

    print_section("CONFIGURE DEFAULT REGIONS")

    identity = get_aws_identity()
    if identity:
        partition = identity['partition']
        is_govcloud = partition == 'aws-us-gov'
    else:
        is_govcloud = False

    current_regions = config.get('default_regions', [])
    print(f"\nCurrent default regions: {', '.join(current_regions)}")

    print("\nSelect primary default region:")

    if is_govcloud:
        print("1. us-gov-west-1 (AWS GovCloud US-West)")
        print("2. us-gov-east-1 (AWS GovCloud US-East)")

        region_map = {
            "1": "us-gov-west-1",
            "2": "us-gov-east-1"
        }
        max_choice = 2
    else:
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
        choice = input(f"\nEnter choice (1-{max_choice}, or 0 to cancel): ").strip()

        if choice == '0':
            print("\n✅ Region configuration cancelled")
            input("Press Enter to return to menu...")
            return

        if choice in region_map:
            default_region = region_map[choice]

            # Set secondary region based on partition
            if default_region.startswith('us-gov-'):
                secondary_region = "us-gov-east-1" if default_region == "us-gov-west-1" else "us-gov-west-1"
            else:
                secondary_region = "us-west-2" if default_region == "us-east-1" else "us-east-1"

            # Count how many per-service regions will be rewritten
            services_to_update = [
                svc for svc, prefs in config.get("resource_preferences", {}).items()
                if isinstance(prefs, dict) and "default_region" in prefs
            ]

            # Summarise the impact and require confirmation before bulk rewrite
            print(f"\nThis will update default_regions to [{default_region}, {secondary_region}]")
            if services_to_update:
                print(f"and rewrite default_region for {len(services_to_update)} service(s) in resource_preferences:")
                for svc in services_to_update:
                    print(f"  - {svc}")
            confirm = input("\nApply these changes? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Cancelled — no changes made.")
                break

            config['default_regions'] = [default_region, secondary_region]

            # Update resource preferences
            if "resource_preferences" in config:
                for service, prefs in config["resource_preferences"].items():
                    if isinstance(prefs, dict) and "default_region" in prefs:
                        prefs["default_region"] = default_region

            _config_modified = True
            print(f"\n✅ Default regions updated: {default_region}, {secondary_region}")
            break
        else:
            print(f"❌ Invalid choice. Please enter 1-{max_choice}.")

    input("\nPress Enter to return to menu...")

def advanced_settings(config: Dict):
    """Advanced settings editor."""
    print_section("ADVANCED SETTINGS")
    print("\n⚠️  Advanced settings are configured in resource_preferences.")
    print("These are typically set automatically based on your default region.")
    print("\nTo manually edit advanced settings, directly edit config.json")
    print("and refer to the StratusScan documentation.")
    input("\nPress Enter to return to menu...")

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

def dependency_management_menu():
    """Interactive menu for dependency management."""
    while True:
        print_section("DEPENDENCY CHECK")

        # Refresh dependency status
        global _dependency_status
        _dependency_status = check_dependencies_silent()

        print(f"\nChecking required StratusScan dependencies...")

        for package in _dependency_status['installed_packages']:
            print(f"  ✅ {package['name']} - {package['description']}")

        for package in _dependency_status['missing_packages']:
            print(f"  ❌ {package['name']} - {package['description']}")

        print(f"\nSummary: {_dependency_status['installed_count']}/{_dependency_status['total_count']} dependencies satisfied")

        if _dependency_status['all_satisfied']:
            print("\n✅ All dependencies are installed and ready!")
            input("\nPress Enter to return to menu...")
            return

        print("\nOptions:")
        print("  [1] Install missing dependencies automatically")
        print("  [2] Show installation commands for manual installation")
        print("  [3] Re-check dependencies")
        print("  [4] Back to main menu")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == '1':
            install_dependencies(_dependency_status['missing_packages'])
            _dependency_status = check_dependencies_silent()
        elif choice == '2':
            print("\n" + "═" * 70)
            print("MANUAL INSTALLATION COMMANDS")
            print("═" * 70)
            print("\nRun the following commands in your terminal:\n")
            for package in _dependency_status['missing_packages']:
                print(f"pip install {package['name']}")
            print(f"\nAlternatively, install all at once:")
            print(f"pip install {' '.join([p['name'] for p in _dependency_status['missing_packages']])}")
            input("\nPress Enter to continue...")
        elif choice == '3':
            print("\n🔄 Re-checking dependencies...")
            continue
        elif choice == '4':
            return
        else:
            print("\n❌ Invalid choice. Please select 1-4.")
            input("Press Enter to continue...")

def install_dependencies(missing_packages: List[Dict]) -> bool:
    """
    Install missing dependencies with user confirmation.

    Args:
        missing_packages (list): List of package dictionaries to install

    Returns:
        bool: True if installation was successful, False otherwise
    """
    if not missing_packages:
        return True

    print("\n" + "═" * 70)
    print("DEPENDENCY INSTALLATION")
    print("═" * 70)

    print("\nThe following packages will be installed:")
    for package in missing_packages:
        print(f"  - {package['name']} - {package['description']}")

    confirm = input(f"\nInstall these {len(missing_packages)} packages now? (y/n): ").lower().strip()

    if confirm != 'y':
        print("\n❌ Installation cancelled.")
        input("Press Enter to continue...")
        return False

    print(f"\n🔧 Installing packages using pip...")

    all_successful = True

    for package in missing_packages:
        print(f"\n[INSTALLING] {package['name']}...")
        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package['name']
            ], capture_output=True, text=True, check=True)

            print(f"  ✅ {package['name']} installed successfully")

            # Verify the installation
            try:
                __import__(package['import_name'])
                print(f"  ✅ {package['name']} import verification successful")
            except ImportError:
                print(f"  ⚠️  {package['name']} installed but import verification failed")
                all_successful = False

        except subprocess.CalledProcessError as e:
            print(f"  ❌ Failed to install {package['name']}")
            print(f"  Error: {e.stderr.strip()}")
            all_successful = False
        except Exception as e:
            print(f"  ❌ Unexpected error installing {package['name']}: {e}")
            all_successful = False

    if all_successful:
        print(f"\n✅ All dependencies installed successfully!")
    else:
        print(f"\n⚠️  Some dependencies failed to install.")
        print("You may need to install them manually or check your Python environment.")

    input("\nPress Enter to continue...")
    return all_successful

# ============================================================================
# PERMISSIONS MANAGEMENT
# ============================================================================

def permissions_management_menu():
    """Interactive menu for AWS permissions management."""
    while True:
        print_section("AWS PERMISSIONS CHECK")

        # Refresh permission status
        global _permission_status
        _permission_status = check_permissions_silent()

        identity = get_aws_identity()

        if not identity:
            print("\n❌ No AWS credentials found!")
            print("Please configure your AWS credentials before running StratusScan.")
            print("\nOptions:")
            print("  [1] Show credential configuration help")
            print("  [2] Back to main menu")

            choice = input("\nSelect option (1-2): ").strip()
            if choice == '1':
                print("\n" + "═" * 70)
                print("AWS CREDENTIALS SETUP")
                print("═" * 70)
                print("\nTo configure AWS credentials, use one of these methods:")
                print("\n1. AWS CLI (Recommended):")
                print("   aws configure")
                print("\n2. Environment Variables:")
                print("   export AWS_ACCESS_KEY_ID=your_access_key")
                print("   export AWS_SECRET_ACCESS_KEY=your_secret_key")
                print("\n3. IAM Role (for EC2 instances)")
                print("   Attach an IAM role to your EC2 instance")
                input("\nPress Enter to continue...")
            else:
                return
            continue

        print(f"\nAWS Identity: {identity['arn']}")
        print(f"Account ID: {identity['account_id']}")
        print(f"Partition: {identity['partition_name']}")

        print(f"\nPermission Status:")
        print(f"  Required permissions: {_permission_status['required_passed']}/{_permission_status['required_passed'] + _permission_status['required_failed']} passed")
        print(f"  Optional permissions: {_permission_status['optional_passed']}/{_permission_status['optional_passed'] + _permission_status['optional_failed']} passed")

        if _permission_status['has_required']:
            print("\n✅ All required permissions are available!")
            if _permission_status['optional_failed'] > 0:
                print(f"⚠️  {_permission_status['optional_failed']} optional permissions are missing.")
                print("Some advanced features may not be available.")
        else:
            print(f"\n❌ {_permission_status['required_failed']} required permissions are missing!")
            print("StratusScan scripts may fail without these permissions.")

        print("\nOptions:")
        print("  [1] Show policy recommendations")
        print("  [2] View policy file locations")
        print("  [3] Run full permission test (detailed)")
        print("  [4] Re-test permissions")
        print("  [5] Back to main menu")

        choice = input("\nSelect option (1-5): ").strip()

        if choice == '1':
            show_policy_recommendations_brief()
        elif choice == '2':
            show_policy_file_locations()
        elif choice == '3':
            run_full_permission_test()
        elif choice == '4':
            print("\n🔄 Re-testing permissions...")
            continue
        elif choice == '5':
            return
        else:
            print("\n❌ Invalid choice. Please select 1-5.")
            input("Press Enter to continue...")

def show_policy_recommendations_brief():
    """Show brief policy recommendations."""
    script_dir = Path(__file__).parent.absolute()
    required_policy_path = script_dir / "policies" / "stratusscan-required-permissions.json"
    optional_policy_path = script_dir / "policies" / "stratusscan-optional-permissions.json"

    print("\n" + "═" * 70)
    print("IAM POLICY RECOMMENDATIONS")
    print("═" * 70)

    print("\nOption 1: CUSTOM POLICIES (Recommended - Least Privilege)")
    print("─" * 70)
    print(f"Required Policy: {required_policy_path}")
    print("  - Covers 100+ export scripts across 80+ AWS services")
    print("  - Read-only permissions only (Get*, Describe*, List*)")
    print("  - ~250 specific actions for precise access control")
    print("")
    print(f"Optional Policy: {optional_policy_path}")
    print("  - Advanced features: Security Hub, Cost Optimization, Trusted Advisor")
    print("  - ~60 additional actions for optional functionality")

    print("\n" + "─" * 70)
    print("Option 2: AWS MANAGED POLICIES (Simpler but broader)")
    print("─" * 70)
    print("  - ReadOnlyAccess (covers most needs)")
    print("  - SecurityAudit (for security services)")
    print("  - AWSBillingReadOnlyAccess (for cost data)")

    print("\nFor detailed instructions, see:")
    print(f"  {script_dir / 'policies' / 'README.md'}")

    input("\nPress Enter to continue...")

def show_policy_file_locations():
    """Show policy file locations."""
    script_dir = Path(__file__).parent.absolute()

    print("\n" + "═" * 70)
    print("STRATUSSCAN POLICY FILES")
    print("═" * 70)
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

    input("\nPress Enter to continue...")

def run_full_permission_test():
    """Run full permission test with detailed results."""
    print("\n" + "═" * 70)
    print("FULL PERMISSION TEST")
    print("═" * 70)
    print("\n⚠️  This will test multiple AWS API calls and may take a moment...")
    print("This is the same detailed test from the old version.")
    print("\nFor now, use the quick test in the main dashboard.")
    print("Full detailed testing will be added in a future update.")
    input("\nPress Enter to continue...")

# ============================================================================
# QUICK EDIT CLI FUNCTIONS
# ============================================================================

def quick_edit_org(org_name: str) -> bool:
    """
    Quick edit organization name via CLI.

    Args:
        org_name (str): New organization name

    Returns:
        bool: True if successful
    """
    config_path = get_config_path()
    config = load_existing_config(config_path)
    config['organization_name'] = org_name

    if save_configuration(config, config_path):
        print(f"\n✅ Organization name updated to: {org_name}")
        return True
    else:
        print(f"\n❌ Failed to update organization name")
        return False

def quick_edit_account(account_id: str, account_name: str) -> bool:
    """
    Quick add/edit account mapping via CLI.

    Args:
        account_id (str): AWS account ID
        account_name (str): Friendly name

    Returns:
        bool: True if successful
    """
    if not validate_account_id(account_id):
        print(f"\n❌ Invalid account ID: {account_id}")
        print("Account ID must be exactly 12 digits (e.g., 123456789012)")
        return False

    config_path = get_config_path()
    config = load_existing_config(config_path)

    if 'account_mappings' not in config:
        config['account_mappings'] = {}

    config['account_mappings'][account_id] = account_name

    if save_configuration(config, config_path):
        print(f"\n✅ Account mapping added: {account_id} → {account_name}")
        return True
    else:
        print(f"\n❌ Failed to add account mapping")
        return False

def quick_edit_region(region: str) -> bool:
    """
    Quick edit default region via CLI.

    Args:
        region (str): AWS region code

    Returns:
        bool: True if successful
    """
    config_path = get_config_path()
    config = load_existing_config(config_path)

    # Determine secondary region based on partition
    if region.startswith('us-gov-'):
        secondary_region = "us-gov-east-1" if region == "us-gov-west-1" else "us-gov-west-1"
    else:
        secondary_region = "us-west-2" if region == "us-east-1" else "us-east-1"

    config['default_regions'] = [region, secondary_region]

    # Update resource preferences
    if "resource_preferences" in config:
        for service, prefs in config["resource_preferences"].items():
            if isinstance(prefs, dict) and "default_region" in prefs:
                prefs["default_region"] = region

    if save_configuration(config, config_path):
        print(f"\n✅ Default regions updated: {region}, {secondary_region}")
        return True
    else:
        print(f"\n❌ Failed to update default regions")
        return False

def validate_only() -> bool:
    """
    Run validation checks only (deps + perms + config).

    Returns:
        bool: True if all checks pass
    """
    print_box("STRATUSSCAN VALIDATION CHECK", 70)

    # Check dependencies
    print("\n" + "═" * 70)
    print("1. DEPENDENCY CHECK")
    print("═" * 70)
    dep_status = check_dependencies_silent()

    for package in dep_status['installed_packages']:
        print(f"  ✅ {package['name']}")

    for package in dep_status['missing_packages']:
        print(f"  ❌ {package['name']}")

    print(f"\nSummary: {dep_status['installed_count']}/{dep_status['total_count']} dependencies satisfied")

    # Check permissions
    print("\n" + "═" * 70)
    print("2. AWS PERMISSIONS CHECK")
    print("═" * 70)
    perm_status = check_permissions_silent()

    identity = get_aws_identity()
    if identity:
        print(f"\nAWS Identity: {identity['arn']}")
        print(f"Account ID: {identity['account_id']}")
        print(f"Partition: {identity['partition_name']}")
        print(f"\nRequired permissions: {perm_status['required_passed']}/{perm_status['required_passed'] + perm_status['required_failed']} passed")
        print(f"Optional permissions: {perm_status['optional_passed']}/{perm_status['optional_passed'] + perm_status['optional_failed']} passed")
    else:
        print("\n❌ No AWS credentials found")

    # Check configuration
    print("\n" + "═" * 70)
    print("3. CONFIGURATION CHECK")
    print("═" * 70)
    config_path = get_config_path()

    if config_path.exists():
        config = load_existing_config(config_path)
        print(f"\n✅ Configuration file exists: {config_path}")
        print(f"Organization: {config.get('organization_name', 'Not set')}")
        print(f"Account mappings: {len(config.get('account_mappings', {}))} configured")
        print(f"Default regions: {', '.join(config.get('default_regions', []))}")
    else:
        print(f"\n❌ Configuration file not found: {config_path}")

    # Overall status
    print("\n" + "═" * 70)
    print("OVERALL STATUS")
    print("═" * 70)

    all_ok = (
        dep_status['all_satisfied'] and
        (perm_status['has_required'] if identity else False) and
        config_path.exists()
    )

    if all_ok:
        print("\n✅ All checks passed! StratusScan is ready to use.")
        return True
    else:
        print("\n⚠️  Some checks failed. Review the output above for details.")
        if not dep_status['all_satisfied']:
            print("  - Install missing dependencies: python configure.py --deps")
        if not (perm_status['has_required'] if identity else False):
            print("  - Fix AWS permissions: python configure.py --perms")
        if not config_path.exists():
            print("  - Run configuration: python configure.py")
        return False

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main function to run the configuration tool."""
    try:
        # Run background checks
        run_background_checks()

        # Load configuration
        config_path = get_config_path()
        config = load_existing_config(config_path)

        # Start main menu loop
        main_menu_loop(config, config_path)

    except KeyboardInterrupt:
        print("\n\n❌ Configuration cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for command-line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ['--deps', '--dependencies']:
            # Run dependency check only
            print_box("STRATUSSCAN DEPENDENCY CHECK", 70)
            dependency_management_menu()
            sys.exit(0)

        elif arg in ['--perms', '--permissions']:
            # Run permissions check only
            print_box("STRATUSSCAN PERMISSIONS CHECK", 70)
            run_background_checks()
            permissions_management_menu()
            sys.exit(0)

        elif arg == '--org' and len(sys.argv) == 3:
            # Quick edit organization name
            success = quick_edit_org(sys.argv[2])
            sys.exit(0 if success else 1)

        elif arg == '--account' and len(sys.argv) == 4:
            # Quick add account mapping
            success = quick_edit_account(sys.argv[2], sys.argv[3])
            sys.exit(0 if success else 1)

        elif arg == '--region' and len(sys.argv) == 3:
            # Quick edit default region
            success = quick_edit_region(sys.argv[2])
            sys.exit(0 if success else 1)

        elif arg == '--validate':
            # Full validation check
            success = validate_only()
            sys.exit(0 if success else 1)

        elif arg in ['--help', '-h']:
            print("StratusScan Configuration Tool v0.1.0")
            print("\nUsage:")
            print("  python configure.py                              # Interactive dashboard")
            print("  python configure.py --deps                       # Dependency check only")
            print("  python configure.py --perms                      # Permissions check only")
            print("  python configure.py --org \"Company Name\"         # Quick org name update")
            print("  python configure.py --account ID NAME            # Quick account mapping")
            print("  python configure.py --region REGION              # Quick region update")
            print("  python configure.py --validate                   # Full validation check")
            print("  python configure.py --help                       # Show this help")
            print("\nExamples:")
            print("  python configure.py --org \"ACME Corporation\"")
            print("  python configure.py --account 123456789012 Production")
            print("  python configure.py --region us-east-1")
            sys.exit(0)

        else:
            print(f"❌ Unknown argument: {arg}")
            print("Use --help for usage information.")
            sys.exit(1)

    # Run full interactive configuration
    main()
