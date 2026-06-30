#!/usr/bin/env python3
# StratusScan.py - Main menu script for AWS resource export tools

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: StratusScan - AWS Resource Exporter Main Menu
Version: v0.1.0
Date: DEC-04-2025

Description:
This script provides a centralized interface for executing various AWS resource
export tools within the StratusScan package. It allows users to select which resource
type to export (EC2 instances, VPC resources, etc.) and calls the appropriate script
to perform the selected operation.

Features:
- Multi-partition support (AWS Commercial & GovCloud)
- Automatic partition detection from credentials
- Zero-configuration cross-environment compatibility
- 109 comprehensive export scripts covering 105+ AWS services
- Trusted Advisor enabled (Commercial) with GovCloud service awareness
- Partition-aware region selection and ARN building
- All AWS services and regions available in respective partitions

Deployment Structure:
- The main menu script should be located in the root directory of the StratusScan package
- Individual export scripts should be located in the 'scripts' subdirectory
- Exported files will be saved to the 'output' subdirectory
- Account mappings and configuration are stored in config.json
"""

import argparse
import contextlib
import datetime
import logging
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

# Add the current directory to the path to ensure we can import utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the utility module
try:
    import utils
except ImportError:
    print("ERROR: Could not import the utils module. Make sure utils.py is in the same directory as this script.")
    sys.exit(1)

# Initialize logging for main menu
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("main-menu", log_to_file=True)
utils.log_script_start("stratusscan.py", "AWS Resource Scanner Main Menu")
utils.log_system_info()

# ---------------------------------------------------------------------------
# Navigation signals — imported from utils so all modules share one hierarchy
# ---------------------------------------------------------------------------

from utils import BackSignal, ExitToMainSignal, QuitSignal


def prompt_with_navigation(prompt_text: str) -> str:
    """
    Wrap input() and raise navigation signals for b, x, and q.

    Args:
        prompt_text: The prompt string to display.

    Returns:
        The raw user input string for all other input.

    Raises:
        BackSignal: user entered 'b'.
        ExitToMainSignal: user entered 'x'.
        QuitSignal: user entered 'q'.
    """
    value = input(prompt_text).strip()
    lower = value.lower()
    if lower == 'b':
        raise BackSignal
    if lower == 'x':
        raise ExitToMainSignal
    if lower == 'q':
        raise QuitSignal
    return value


def _confirm(message: str) -> bool:
    """
    Prompt for y/n confirmation, supporting b/x/q navigation signals.

    Args:
        message: The confirmation question to display.

    Returns:
        True if the user answered 'y', False for any other non-navigation input.

    Raises:
        BackSignal, ExitToMainSignal, QuitSignal: propagated from
            prompt_with_navigation().
    """
    response = prompt_with_navigation(f"{message} (y/n): ")
    return response.lower() == 'y'


def clear_screen():
    """
    Clear the terminal screen using ANSI escape codes (avoids os.system shell call).
    Works on Windows 10+, Linux, and macOS terminals.
    """
    print('\033[2J\033[H', end='', flush=True)

# ---------------------------------------------------------------------------
# Visual helpers — mirrors the pattern established in configure.py
# ---------------------------------------------------------------------------

def print_box(title: str, width: int = 70):
    """Print a centred title inside a box."""
    print("╔" + "═" * (width - 2) + "╗")
    padding = (width - len(title) - 2) // 2
    print("║" + " " * padding + title + " " * (width - len(title) - padding - 2) + "║")
    print("╚" + "═" * (width - 2) + "╝")

def print_section(title: str, width: int = 70):
    """Print a section divider with an ALL-CAPS label."""
    print("\n" + "═" * width)
    print(title)
    print("═" * width)

def print_status_line(label: str, status: str, width: int = 70):
    """Print a status line with the right ║ anchored at exact column via ANSI CHA."""
    content = f"║ {label}: {status}"
    # \033[{n}G (Cursor Horizontal Absolute) jumps to column n (1-indexed).
    # This anchors ║ at exactly column `width` regardless of how the terminal
    # renders wide or emoji characters — no glyph-width guesswork needed.
    print(f"{content}\033[{width}G║")

# Cache AWS identity so the STS call is only made once per session
_identity_cache: tuple = ()

def print_header():
    """
    Print the styled status panel. AWS identity is fetched once and cached.

    Returns:
        tuple: (account_id, account_name)
    """
    global _identity_cache

    if not _identity_cache:
        try:
            sts = utils.get_boto3_client('sts')
            identity = sts.get_caller_identity()
            account_id = identity["Account"]
            account_name = utils.get_account_name(account_id, default=account_id)
            partition = utils.detect_partition()
            environment = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
            _identity_cache = (account_id, account_name, environment)
        except Exception:
            _identity_cache = ("UNKNOWN", "UNKNOWN-ACCOUNT", "Unknown")

    account_id, account_name, environment = _identity_cache

    print_box("STRATUSSCAN", 70)
    print("╔" + "═" * 68 + "╗")
    print_status_line("Environment", environment, 70)
    print_status_line("Account", f"{account_id}  ({account_name})", 70)

    config_path = Path(__file__).parent / "config.json"
    config_status = "✅ Loaded" if config_path.exists() else "⚠️  Not configured — run [0] Configure StratusScan"
    print_status_line("Configuration", config_status, 70)
    print("╚" + "═" * 68 + "╝")

    return account_id, account_name

def check_dependency(dependency):
    """
    Check if a Python dependency is installed.

    Args:
        dependency: Name of the Python package to check

    Returns:
        bool: True if installed, False otherwise
    """
    try:
        __import__(dependency)
        return True
    except ImportError:
        return False

def install_dependency(dependency):
    """
    Install a Python dependency after user confirmation.

    Args:
        dependency: Name of the Python package to install

    Returns:
        bool: True if installed successfully, False otherwise
    """
    print(f"\nPackage '{dependency}' is required but not installed.")
    response = input(f"Would you like to install {dependency}? (y/n): ").lower()

    if response == 'y':
        try:
            import subprocess
            print(f"Installing {dependency}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dependency])
            print(f"[SUCCESS] Successfully installed {dependency}")
            return True
        except Exception as e:
            print(f"Error installing {dependency}: {e}")
            return False
    else:
        print(f"Cannot proceed without {dependency}.")
        return False

def check_dependencies():
    """
    Check required dependencies. Silent when all satisfied; prompts to install if missing.

    Returns:
        bool: True if all dependencies are satisfied, False otherwise
    """
    required_packages = ['boto3', 'pandas', 'openpyxl']
    for package in required_packages:
        if not check_dependency(package):
            print(f"  ❌ Missing: {package}")
            if not install_dependency(package):
                return False
    return True

def ensure_directory_structure():
    """
    Ensure the required directory structure exists.
    Creates the scripts and output directories if they don't exist.

    Returns:
        tuple: (scripts_dir, output_dir) - Paths to the scripts and output directories
    """
    # Get the base directory (where this script is located)
    base_dir = Path(__file__).parent.absolute()

    # Create scripts directory if it doesn't exist
    scripts_dir = base_dir / "scripts"
    if not scripts_dir.exists():
        print(f"Creating scripts directory: {scripts_dir}")
        scripts_dir.mkdir(exist_ok=True)

    # Create output directory if it doesn't exist
    output_dir = base_dir / "output"
    if not output_dir.exists():
        print(f"Creating output directory: {output_dir}")
        output_dir.mkdir(exist_ok=True)

    # Check if config.json exists, create default if it doesn't
    config_path = base_dir / "config.json"

    if not config_path.exists():
        print("No configuration file found. The config.json file should exist.")
        print("Please ensure config.json is present in the StratusScan directory.")
        print("You may want to edit this file to add your account mappings.")

    return scripts_dir, output_dir

def execute_script(script_path):
    """
    Execute the selected export script.

    Args:
        script_path (Path): Path to the script to execute

    Returns:
        bool: True if the script executed successfully, False otherwise
    """
    start_time = datetime.datetime.now()
    script_name = script_path.name

    try:
        # Log script execution start
        utils.log_section(f"EXECUTING SCRIPT: {script_name}")
        utils.log_info(f"Script path: {script_path}")
        utils.log_info(f"Execution start time: {start_time}")

        # Clear the screen before executing the script
        clear_screen()

        print(f"Executing: {script_path.name}")
        print("─" * 70)

        # Execute the script as a subprocess
        result = subprocess.run([sys.executable, str(script_path)],
                              check=True,
                              timeout=1800)  # 30-minute timeout, consistent with smart_scan/executor.py

        if result.returncode == 0:
            print("\nScript execution completed successfully.")
            utils.log_success(f"Script executed successfully: {script_name}")
            return True
        else:
            print(f"\nScript execution failed with return code: {result.returncode}")
            utils.log_error(f"Script execution failed: {script_name} (return code: {result.returncode})")
            return False

    except subprocess.CalledProcessError as e:
        if e.returncode == 10:
            raise BackSignal
        if e.returncode == 11:
            raise ExitToMainSignal
        print(f"Error executing script: {e}")
        utils.log_error(f"Script execution error: {script_name}", e)
        return False
    except Exception as e:
        print(f"Unexpected error during script execution: {e}")
        utils.log_error(f"Unexpected error executing script: {script_name}", e)
        return False
    finally:
        # Log execution completion
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        utils.log_info(f"Script execution completed: {script_name}")
        utils.log_info(f"Execution duration: {duration}")

def create_output_archive(account_name):
    """
    Create a zip archive of the output directory.

    Args:
        account_name: The AWS account name to use in the filename

    Returns:
        bool: True if archive was created successfully, False otherwise
    """
    try:
        # Clear the screen
        clear_screen()

        print_section("CREATING OUTPUT ARCHIVE")

        # Get the output directory path
        output_dir = Path(__file__).parent / "output"

        # Check if output directory exists and has files
        if not output_dir.exists():
            print(f"Output directory not found: {output_dir}")
            return False

        files = list(output_dir.glob("*.*"))
        if not files:
            print("No files found in the output directory to archive.")
            return False

        print(f"Found {len(files)} files to archive.")

        # Create filename with current date
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        zip_filename = f"{account_name}-export-{current_date}.zip"
        zip_path = Path(__file__).parent / zip_filename

        # Create the zip file
        print(f"Creating archive: {zip_filename}")
        print("Please wait...")

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files:
                # Archive file with relative path inside the zip
                zipf.write(file, arcname=file.name)
                print(f"  Added: {file.name}")

        print("\nArchive creation completed successfully!")
        print(f"Archive saved to: {zip_path}")

        return True

    except Exception as e:
        print(f"Error creating archive: {e}")
        return False

def get_menu_structure():
    """
    Create a hierarchical menu structure with main categories and submenus.
    Simplified 10-option main menu for better usability.
    Updated for multi-partition support - includes all available services for
    both AWS Commercial and GovCloud environments.

    Returns:
        dict: Dictionary with main menu options and their corresponding submenus
    """
    scripts_dir, _ = ensure_directory_structure()

    # Define the simplified menu structure with consolidated categories
    menu_structure = {
        "0": {
            "name": "Configure StratusScan",
            "file": Path(__file__).parent / "configure.py",
            "description": "Interactive configuration tool for account mappings and AWS settings"
        },
        "O": {
            "name": "Org Scan — Run exporter across all accounts",
            "description": "Iterate all configured cross-account roles and run one exporter per account",
            "action": "org_scan"
        },
        "1": {
            "name": "Service Discovery",
            "file": Path(__file__).parent / "smart_scan.py",
            "description": "Discover all AWS services in use; optionally launch Smart Scan to auto-run recommended exporters"
        },
        "2": {
            "name": "Infrastructure (Compute, Storage, Network, Database)",
            "submenu": {
                "1": {
                    "name": "Compute Resources",
                    "submenu": {
                        "1": {"name": "EC2", "file": scripts_dir / "ec2_export.py", "description": "Export EC2 instance data"},
                        "2": {"name": "EKS", "file": scripts_dir / "eks_export.py", "description": "Export EKS cluster information"},
                        "3": {"name": "ECS", "file": scripts_dir / "ecs_export.py", "description": "Export ECS cluster and service information"},
                        "4": {"name": "Auto Scaling Groups", "file": scripts_dir / "autoscaling_export.py", "description": "Export Auto Scaling Group configurations"},
                        "5": {"name": "Lambda Functions", "file": scripts_dir / "lambda_export.py", "description": "Export Lambda function configurations"},
                        "6": {"name": "ECR", "file": scripts_dir / "ecr_export.py", "description": "Export ECR repositories and images"},
                        "7": {"name": "AMI", "file": scripts_dir / "ami_export.py", "description": "Export account-owned AMIs"},
                        "8": {"name": "EC2 Image Builder", "file": scripts_dir / "image_builder_export.py", "description": "Export Image Builder pipelines"},
                        "9": {"name": "EC2 Capacity Reservations", "file": scripts_dir / "ec2_capacity_reservations_export.py", "description": "Export EC2 Capacity Reservations"},
                        "10": {"name": "EC2 Dedicated Hosts", "file": scripts_dir / "ec2_dedicated_hosts_export.py", "description": "Export EC2 Dedicated Hosts"},
                        "11": {"name": "All Compute Resources", "file": scripts_dir / "compute_resources.py", "description": "Export all compute resources in one report"},
                    }
                },
                "2": {
                    "name": "Storage Resources",
                    "submenu": {
                        "1": {"name": "EBS Volumes", "file": scripts_dir / "ebs_volumes_export.py", "description": "Export EBS volume information"},
                        "2": {"name": "EBS Snapshots", "file": scripts_dir / "ebs_snapshots_export.py", "description": "Export EBS snapshot information"},
                        "3": {"name": "S3", "file": scripts_dir / "s3_export.py", "description": "Export S3 bucket information"},
                        "4": {"name": "EFS", "file": scripts_dir / "efs_export.py", "description": "Export EFS file systems"},
                        "5": {"name": "FSx", "file": scripts_dir / "fsx_export.py", "description": "Export FSx file systems"},
                        "6": {"name": "AWS Backup", "file": scripts_dir / "backup_export.py", "description": "Export AWS Backup vaults and plans"},
                        "7": {"name": "S3 Access Points", "file": scripts_dir / "s3_accesspoints_export.py", "description": "Export S3 Access Points"},
                        "8": {"name": "DataSync", "file": scripts_dir / "datasync_export.py", "description": "Export DataSync tasks and locations"},
                        "9": {"name": "Transfer Family", "file": scripts_dir / "transfer_family_export.py", "description": "Export Transfer Family servers"},
                        "10": {"name": "Storage Gateway", "file": scripts_dir / "storagegateway_export.py", "description": "Export Storage Gateway"},
                        "11": {"name": "Glacier Vaults", "file": scripts_dir / "glacier_export.py", "description": "Export Glacier vaults"},
                        "12": {"name": "All Storage Resources", "file": scripts_dir / "storage_resources.py", "description": "Export all storage resources in one report"},
                    }
                },
                "3": {
                    "name": "Network Resources",
                    "submenu": {
                        "1": {"name": "VPC/Subnet", "file": scripts_dir / "vpc_data_export.py", "description": "Export VPC and subnet information"},
                        "2": {"name": "ELB", "file": scripts_dir / "elb_export.py", "description": "Export load balancer information"},
                        "3": {"name": "Network ACLs", "file": scripts_dir / "nacl_export.py", "description": "Export Network ACL information"},
                        "4": {"name": "Security Groups", "file": scripts_dir / "security_groups_export.py", "description": "Export security group rules"},
                        "5": {"name": "Route Tables", "file": scripts_dir / "route_tables_export.py", "description": "Export route table information"},
                        "6": {"name": "CloudFront", "file": scripts_dir / "cloudfront_export.py", "description": "Export CloudFront distributions"},
                        "7": {"name": "Route 53", "file": scripts_dir / "route53_export.py", "description": "Export Route 53 hosted zones and records"},
                        "8": {"name": "VPN", "file": scripts_dir / "vpn_export.py", "description": "Export VPN connections"},
                        "9": {"name": "Direct Connect", "file": scripts_dir / "directconnect_export.py", "description": "Export Direct Connect connections"},
                        "10": {"name": "Global Accelerator", "file": scripts_dir / "globalaccelerator_export.py", "description": "Export Global Accelerator"},
                        "11": {"name": "Transit Gateway", "file": scripts_dir / "transit_gateway_export.py", "description": "Export Transit Gateway configurations"},
                        "12": {"name": "Network Firewall", "file": scripts_dir / "network_firewall_export.py", "description": "Export Network Firewall"},
                        "13": {"name": "Network Manager", "file": scripts_dir / "network_manager_export.py", "description": "Export Network Manager topology"},
                        "14": {"name": "All Network Resources", "file": scripts_dir / "network_resources.py", "description": "Export network resources (select regions during run)"},
                    }
                },
                "4": {
                    "name": "Database Resources",
                    "submenu": {
                        "1": {"name": "RDS", "file": scripts_dir / "rds_export.py", "description": "Export RDS instance information"},
                        "2": {"name": "DynamoDB", "file": scripts_dir / "dynamodb_export.py", "description": "Export DynamoDB tables and GSIs"},
                        "3": {"name": "ElastiCache", "file": scripts_dir / "elasticache_export.py", "description": "Export ElastiCache clusters"},
                        "4": {"name": "DocumentDB", "file": scripts_dir / "documentdb_export.py", "description": "Export DocumentDB clusters"},
                        "5": {"name": "Neptune", "file": scripts_dir / "neptune_export.py", "description": "Export Neptune graph databases"},
                        "6": {"name": "All Database Resources", "file": scripts_dir / "database_resources.py", "description": "Export all database resources (multi-select, zip output)"},
                    }
                },
            }
        },
        "3": {
            "name": "Security & Compliance",
            "submenu": {
                "1": {
                    "name": "Security Monitoring",
                    "submenu": {
                        "1": {"name": "Security Hub", "file": scripts_dir / "security_hub_export.py", "description": "Export Security Hub findings"},
                        "2": {"name": "GuardDuty", "file": scripts_dir / "guardduty_export.py", "description": "Export GuardDuty findings"},
                        "3": {"name": "Detective", "file": scripts_dir / "detective_export.py", "description": "Export Detective behavior graphs"},
                        "4": {"name": "Macie", "file": scripts_dir / "macie_export.py", "description": "Export Macie data security findings"},
                        "5": {"name": "AWS WAF", "file": scripts_dir / "waf_export.py", "description": "Export WAF web ACLs and rules"},
                        "6": {"name": "Shield Advanced", "file": scripts_dir / "shield_export.py", "description": "Export Shield DDoS protection"},
                        "7": {"name": "IAM Access Analyzer", "file": scripts_dir / "access_analyzer_export.py", "description": "Export Access Analyzer findings"},
                    }
                },
                "2": {
                    "name": "Identity, Certs & Config",
                    "submenu": {
                        "1": {"name": "KMS", "file": scripts_dir / "kms_export.py", "description": "Export KMS keys and encryption configs"},
                        "2": {"name": "ACM", "file": scripts_dir / "acm_export.py", "description": "Export ACM SSL/TLS certificates"},
                        "3": {"name": "ACM Private CA", "file": scripts_dir / "acm_privateca_export.py", "description": "Export ACM Private CAs"},
                        "4": {"name": "Secrets Manager", "file": scripts_dir / "secrets_manager_export.py", "description": "Export Secrets Manager metadata"},
                        "5": {"name": "Cognito", "file": scripts_dir / "cognito_export.py", "description": "Export Cognito user pools"},
                        "6": {"name": "Verified Access", "file": scripts_dir / "verifiedaccess_export.py", "description": "Export Verified Access zero-trust"},
                        "7": {"name": "Verified Permissions", "file": scripts_dir / "verifiedpermissions_export.py", "description": "Export Verified Permissions Cedar policies"},
                        "8": {"name": "IAM Roles Anywhere", "file": scripts_dir / "iam_rolesanywhere_export.py", "description": "Export IAM Roles Anywhere"},
                        "9": {"name": "IAM Identity Providers", "file": scripts_dir / "iam_identity_providers_export.py", "description": "Export IAM SAML/OIDC providers"},
                        "10": {"name": "CloudTrail", "file": scripts_dir / "cloudtrail_export.py", "description": "Export CloudTrail trails"},
                        "11": {"name": "AWS Config", "file": scripts_dir / "config_export.py", "description": "Export Config rules and compliance"},
                    }
                },
                "3": {"name": "All Security & Compliance", "file": scripts_dir / "security_compliance_resources.py", "description": "Export all security & compliance resources in one report"},
            }
        },
        "4": {
            "name": "Identity & Access Management",
            "submenu": {
                "1": {
                    "name": "IAM",
                    "file": scripts_dir / "iam_export.py",
                    "description": "Export IAM users, roles, and policies"
                },
                "2": {
                    "name": "IAM Identity Center",
                    "file": scripts_dir / "iam_identity_center_export.py",
                    "description": "Export IAM Identity Center users, groups, and permission sets"
                },
                "3": {"name": "All IAM Resources", "file": scripts_dir / "iam_resources.py", "description": "Export all IAM resources in one report"},
            }
        },
        "5": {
            "name": "Cost Management & Optimization",
            "submenu": {
                "1": {"name": "Billing Export", "file": scripts_dir / "billing_export.py", "description": "Export AWS billing and cost data"},
                "2": {"name": "Cost Optimization Hub", "file": scripts_dir / "cost_optimization_hub_export.py", "description": "Export Cost Optimization Hub recommendations"},
                "3": {"name": "Trusted Advisor", "file": scripts_dir / "trusted_advisor_cost_optimization_export.py", "description": "Export Trusted Advisor cost recommendations"},
                "4": {"name": "Compute Optimizer", "file": scripts_dir / "compute_optimizer_export.py", "description": "Export Compute Optimizer recommendations"},
                "5": {"name": "Savings Plans", "file": scripts_dir / "savings_plans_export.py", "description": "Export Savings Plans commitments"},
                "6": {"name": "AWS Budgets", "file": scripts_dir / "budgets_export.py", "description": "Export AWS Budgets and alerts"},
                "7": {"name": "Reserved Instances", "file": scripts_dir / "reserved_instances_export.py", "description": "Export Reserved Instances"},
                "8": {"name": "Cost Categories", "file": scripts_dir / "cost_categories_export.py", "description": "Export Cost Categories"},
                "9": {"name": "Cost Anomaly Detection", "file": scripts_dir / "cost_anomaly_detection_export.py", "description": "Export Cost Anomaly Detection"},
                "10": {"name": "All Cost Management", "file": scripts_dir / "cost_resources.py", "description": "Export all cost management resources in one report"},
            }
        },
        "6": {
            "name": "Application Services",
            "submenu": {
                "1": {"name": "Step Functions", "file": scripts_dir / "stepfunctions_export.py", "description": "Export Step Functions state machines"},
                "2": {"name": "App Runner", "file": scripts_dir / "apprunner_export.py", "description": "Export App Runner services"},
                "3": {"name": "Elastic Beanstalk", "file": scripts_dir / "elasticbeanstalk_export.py", "description": "Export Elastic Beanstalk applications"},
                "4": {"name": "AppSync", "file": scripts_dir / "appsync_export.py", "description": "Export AppSync GraphQL APIs"},
                "5": {"name": "AWS Connect", "file": scripts_dir / "connect_export.py", "description": "Export Connect contact center"},
                "6": {"name": "API Gateway", "file": scripts_dir / "api_gateway_export.py", "description": "Export API Gateway REST/HTTP APIs"},
                "7": {"name": "EventBridge", "file": scripts_dir / "eventbridge_export.py", "description": "Export EventBridge event buses"},
                "8": {"name": "SQS/SNS", "file": scripts_dir / "sqs_sns_export.py", "description": "Export SQS queues and SNS topics"},
                "9": {"name": "Cloud Map", "file": scripts_dir / "cloudmap_export.py", "description": "Export Cloud Map service discovery"},
                "10": {"name": "SES", "file": scripts_dir / "ses_export.py", "description": "Export SES email identities"},
                "11": {"name": "SES & Pinpoint", "file": scripts_dir / "ses_pinpoint_export.py", "description": "Export SES and Pinpoint combined"},
                "12": {"name": "All Application Services", "file": scripts_dir / "application_resources.py", "description": "Export all application services resources in one report"},
            }
        },
        "7": {
            "name": "Data & Analytics",
            "submenu": {
                "1": {"name": "OpenSearch Service", "file": scripts_dir / "opensearch_export.py", "description": "Export OpenSearch domains"},
                "2": {"name": "Redshift", "file": scripts_dir / "redshift_export.py", "description": "Export Redshift data warehouse clusters"},
                "3": {"name": "Glue & Athena", "file": scripts_dir / "glue_athena_export.py", "description": "Export Glue databases and Athena workgroups"},
                "4": {"name": "Lake Formation", "file": scripts_dir / "lakeformation_export.py", "description": "Export Lake Formation resources"},
                "5": {"name": "SageMaker", "file": scripts_dir / "sagemaker_export.py", "description": "Export SageMaker ML resources"},
                "6": {"name": "Bedrock", "file": scripts_dir / "bedrock_export.py", "description": "Export Bedrock generative AI"},
                "7": {"name": "Comprehend", "file": scripts_dir / "comprehend_export.py", "description": "Export Comprehend NLP resources"},
                "8": {"name": "Rekognition", "file": scripts_dir / "rekognition_export.py", "description": "Export Rekognition computer vision"},
                "9": {"name": "CloudWatch", "file": scripts_dir / "cloudwatch_export.py", "description": "Export CloudWatch alarms and logs"},
                "10": {"name": "X-Ray", "file": scripts_dir / "xray_export.py", "description": "Export X-Ray distributed tracing"},
                "11": {"name": "All Data & Analytics", "file": scripts_dir / "analytics_resources.py", "description": "Export all data & analytics resources in one report"},
            }
        },
        "8": {
            "name": "DevOps Services",
            "submenu": {
                "1": {"name": "CodeBuild", "file": scripts_dir / "codebuild_export.py", "description": "Export CodeBuild projects"},
                "2": {"name": "CodePipeline", "file": scripts_dir / "codepipeline_export.py", "description": "Export CodePipeline pipelines"},
                "3": {"name": "CodeCommit", "file": scripts_dir / "codecommit_export.py", "description": "Export CodeCommit repositories"},
                "4": {"name": "CodeDeploy", "file": scripts_dir / "codedeploy_export.py", "description": "Export CodeDeploy applications"},
                "5": {"name": "All DevOps Services", "file": scripts_dir / "devops_resources.py", "description": "Export all DevOps services resources in one report"},
            }
        },
        "9": {
            "name": "Management & Governance",
            "submenu": {
                "1": {"name": "CloudFormation", "file": scripts_dir / "cloudformation_export.py", "description": "Export CloudFormation stacks"},
                "2": {"name": "Service Catalog", "file": scripts_dir / "service_catalog_export.py", "description": "Export Service Catalog portfolios"},
                "3": {"name": "AWS Health", "file": scripts_dir / "health_export.py", "description": "Export AWS Health events"},
                "4": {"name": "License Manager", "file": scripts_dir / "license_manager_export.py", "description": "Export License Manager configurations"},
                "5": {"name": "AWS Marketplace", "file": scripts_dir / "marketplace_export.py", "description": "Export AWS Marketplace configuration"},
                "6": {"name": "AWS Control Tower", "file": scripts_dir / "controltower_export.py", "description": "Export Control Tower landing zone"},
                "7": {"name": "Systems Manager Fleet", "file": scripts_dir / "ssm_fleet_export.py", "description": "Export SSM managed instances"},
                "8": {"name": "All Management & Governance", "file": scripts_dir / "governance_resources.py", "description": "Export all management & governance resources in one report"},
            }
        },
        "10": {
            "name": "Output Management",
            "file": scripts_dir / "output_archive.py",
            "description": "Create a zip archive of all exported files"
        },
    }

    # Verify the script files exist (only for actual scripts)
    for _main_option, main_info in menu_structure.items():
        if "submenu" in main_info:
            # Check first level submenus
            for _sub_option, sub_info in main_info["submenu"].items():
                if "submenu" in sub_info:
                    # Check nested submenus
                    for _nested_option, nested_info in sub_info["submenu"].items():
                        if nested_info.get("file") and not nested_info["file"].exists():
                            print(f"Warning: Script file {nested_info['file']} not found!")
                elif sub_info.get("file") and not sub_info["file"].exists():
                    print(f"Warning: Script file {sub_info['file']} not found!")
        elif main_info.get("file") and main_info["file"] is not None and not main_info["file"].exists():
            print(f"Warning: Script file {main_info['file']} not found!")

    return menu_structure

def display_main_menu():
    """
    Clear screen, print status panel, and display the main menu.

    Returns:
        tuple: (menu_structure, account_name)
    """
    clear_screen()
    _, account_name = print_header()
    menu_structure = get_menu_structure()

    print_section("MAIN MENU")
    for option, info in menu_structure.items():
        print(f"  [{option:>2}] {info['name']}")

    print("\n" + "─" * 70)
    print("  o = org scan  |  h = scan history  |  q = quit")
    print("─" * 70)

    return menu_structure, account_name

def display_submenu(submenu, category_name):
    """
    Display a submenu for a specific category.

    Args:
        submenu (dict): The submenu options
        category_name (str): The name of the category

    Returns:
        dict: The submenu structure
    """
    clear_screen()
    print_section(category_name.upper())

    for option, info in submenu.items():
        print(f"  [{option:>2}] {info['name']}")

    print("\n" + "─" * 70)
    print("  b = back  |  x = main menu  |  q = quit")
    print("─" * 70)

    return submenu


def handle_submenu(category_option, account_name):
    """
    Handle submenu navigation and script execution.

    BackSignal raised at the selection prompt causes this function to return
    (go back one level). ExitToMainSignal and QuitSignal propagate to the caller.

    Args:
        category_option (dict): The selected main menu option containing a submenu.
        account_name (str): The AWS account name for archive creation.

    Raises:
        ExitToMainSignal: propagated when the user enters 'x' or selects
            'Return to Main Menu'.
        QuitSignal: propagated when the user enters 'q'.
    """
    while True:
        submenu = display_submenu(category_option["submenu"], category_option["name"])

        print("\nSelect an option:")
        try:
            user_choice = prompt_with_navigation("> ")
        except BackSignal:
            return  # Go back to parent menu
        # ExitToMainSignal and QuitSignal propagate to the caller

        if user_choice not in submenu:
            print("Invalid selection. Please try again.")
            continue

        selected_option = submenu[user_choice]
        submenu_path = f"{category_option.get('name', 'Unknown')}.{user_choice}"
        utils.log_menu_selection(submenu_path, selected_option['name'])

        # Legacy "Return to" entries remain functional
        if selected_option["name"] == "Return to Main Menu":
            utils.log_info(f"User selected: {selected_option['name']}")
            raise ExitToMainSignal
        if selected_option["name"] == "Return to Previous Menu":
            utils.log_info(f"User selected: {selected_option['name']}")
            return

        # Nested submenu
        if "submenu" in selected_option:
            with contextlib.suppress(BackSignal):
                # ExitToMainSignal and QuitSignal propagate
                handle_submenu(selected_option, account_name)
            continue

        # Special action (e.g. Create Output Archive)
        if selected_option.get("action") == "create_archive":
            print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")
            with contextlib.suppress(BackSignal):
                # ExitToMainSignal and QuitSignal propagate
                if _confirm("Do you want to continue?"):
                    create_output_archive(account_name)
                    if not _confirm("Would you like to perform another action from this menu?"):
                        return
            continue

        # Regular script execution
        print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")
        try:
            confirmed = _confirm("Do you want to continue?")
        except BackSignal:
            continue  # Cancel confirmation, stay in submenu
        # ExitToMainSignal and QuitSignal propagate

        if confirmed:
            if selected_option["file"]:
                try:
                    execute_script(selected_option["file"])
                except BackSignal:
                    continue  # Script returned 'b' — stay in this submenu
            with contextlib.suppress(BackSignal):
                # ExitToMainSignal and QuitSignal propagate
                if not _confirm("Would you like to run another tool from this menu?"):
                    return

def _collect_scripts(menu_structure: dict) -> list:
    """
    Recursively walk the menu structure and collect all leaf script entries.

    Returns a flat list of dicts with keys 'name' and 'file', where 'file'
    is a Path to an exporter script.  Entries with no 'file' key or with
    file=None are skipped (e.g. the Configure and Org Scan top-level entries).

    Args:
        menu_structure: A menu dict (any level — top or submenu).

    Returns:
        list[dict]: Sorted list of {"name": str, "file": Path} entries.
    """
    results: list = []
    for info in menu_structure.values():
        if "submenu" in info:
            results.extend(_collect_scripts(info["submenu"]))
        elif info.get("file") is not None:
            results.append({"name": info["name"], "file": info["file"]})
    return results


def run_org_scan() -> None:
    """
    Run a single exporter script across all configured cross-account roles.

    Flow:
      1. Load cross-account roles from config.
      2. Display configured accounts.
      3. Let the user pick an exporter from a flat numbered list.
      4. Confirm, then iterate accounts — launching each exporter with
         STRATUSSCAN_ROLE_ARN and STRATUSSCAN_AUTO_RUN set in the child env.
      5. Print a pass/fail summary.

    Raises:
        BackSignal: propagated from the script-selection prompt so the caller
            can suppress it and return to the main menu.
    """
    cross_account_roles: dict = utils.get_cross_account_roles()

    if not cross_account_roles:
        print("\nNo cross-account roles configured.")
        print("Run [0] Configure StratusScan → Config Wizard → Step 5 to add roles.")
        input("\nPress Enter to return to menu...")
        return

    # Display configured accounts
    SEP = "─" * 70
    print(f"\nCONFIGURED ACCOUNTS ({len(cross_account_roles)})")
    print(SEP)
    print(f"  {'Account ID':<20} {'Name':<24} Role ARN (truncated)")
    print(SEP)
    for acct_id, role_arn in cross_account_roles.items():
        acct_name = utils.get_account_name(acct_id)
        truncated = role_arn[:47] + "..." if len(role_arn) > 50 else role_arn
        print(f"  {acct_id:<20} {acct_name:<24} {truncated}")
    print(SEP)

    # Build flat exporter list from the full menu structure
    menu_structure = get_menu_structure()
    scripts: list = _collect_scripts(menu_structure)

    if not scripts:
        print("\nNo exporter scripts found.")
        input("\nPress Enter to return to menu...")
        return

    # Script selection loop
    selected_script: dict | None = None
    while selected_script is None:
        print("\nSELECT EXPORTER")
        print(SEP)
        for idx, entry in enumerate(scripts, start=1):
            print(f"  [{idx:>3}] {entry['name']}")
        print(SEP)

        raw = prompt_with_navigation("Select exporter to run across all accounts (b=back): ")
        # prompt_with_navigation raises BackSignal for 'b' — let it propagate

        if not raw.isdigit():
            print("Invalid selection. Please enter a number.")
            continue
        choice = int(raw)
        if not (1 <= choice <= len(scripts)):
            print(f"Invalid selection. Enter a number between 1 and {len(scripts)}.")
            continue
        selected_script = scripts[choice - 1]

    # Confirm
    n_accounts = len(cross_account_roles)
    answer = input(
        f"\nRun [{selected_script['name']}] across {n_accounts} account(s)? (y/n): "
    ).strip().lower()
    if answer != "y":
        return

    script_file: Path = selected_script["file"]

    # Build planned list for session tracking
    planned = [
        {
            "key": acct_id,
            "script": script_file.name,
            "account_id": acct_id,
            "account_name": utils.get_account_name(acct_id),
        }
        for acct_id in cross_account_roles
    ]

    # Check for an interrupted session for the same script; offer resume
    skip_accounts: set = set()
    interrupted_sessions = [
        s for s in utils.get_interrupted_sessions()
        if any(p.get("script") == script_file.name for p in s.get("planned", []))
    ]
    if interrupted_sessions:
        prev = interrupted_sessions[0]
        n_done = len(prev.get("results", []))
        n_total = len(prev.get("planned", []))
        resume_ans = input(
            f"  Resume interrupted session ({n_done}/{n_total} accounts completed)? (y/n): "
        ).strip().lower()
        if resume_ans == "y":
            session = prev
            utils.resume_scan_session(session)
            skip_accounts = {
                r["key"] for r in session.get("results", []) if r.get("status") == "success"
            }
        else:
            label = f"{selected_script['name']} ({script_file.name}) — {n_accounts} accounts"
            session = utils.start_scan_session("org-scan", label, planned)
    else:
        label = f"{selected_script['name']} ({script_file.name}) — {n_accounts} accounts"
        session = utils.start_scan_session("org-scan", label, planned)

    # Execute across all accounts
    results: list = []
    for acct_id, role_arn in cross_account_roles.items():
        acct_name = utils.get_account_name(acct_id)

        if acct_id in skip_accounts:
            print(f"  ⏭  Skipping {acct_name} ({acct_id}) — already completed")
            continue

        print(f"\nScanning account: {acct_name} ({acct_id})...")

        child_env = os.environ.copy()
        child_env["STRATUSSCAN_ROLE_ARN"] = role_arn
        child_env["STRATUSSCAN_AUTO_RUN"] = "1"

        exit_code: int = 0
        start_time = time.monotonic()
        try:
            result = subprocess.run(
                [sys.executable, str(script_file)],
                env=child_env,
                timeout=1800,
            )
            exit_code = result.returncode
        except subprocess.CalledProcessError as exc:
            utils.log_error("Org scan: account %s exporter failed: %s", acct_id, exc)
            exit_code = exc.returncode if exc.returncode is not None else 1
        except subprocess.TimeoutExpired:
            utils.log_error("Org scan: account %s exporter timed out (30 min)", acct_id)
            exit_code = -1
        except Exception as exc:  # noqa: BLE001
            utils.log_error("Org scan: account %s unexpected error: %s", acct_id, exc)
            exit_code = -1

        duration_s = time.monotonic() - start_time
        status_str = "success" if exit_code == 0 else "failed"
        utils.record_scan_result(
            session,
            acct_id,
            status_str,
            exit_code,
            duration_s,
            script=script_file.name,
            account_id=acct_id,
            account_name=acct_name,
        )
        results.append({"acct_id": acct_id, "acct_name": acct_name, "exit_code": exit_code})

    utils.complete_scan_session(session)

    # Summary
    print("\nORG SCAN COMPLETE")
    print(SEP)
    for r in results:
        icon = "✅" if r["exit_code"] == 0 else "❌"
        status = "success" if r["exit_code"] == 0 else f"failed (exit code {r['exit_code']})"
        print(f"  {icon}  {r['acct_name']} ({r['acct_id']}) — {status}")
    print(SEP)
    input("\nPress Enter to return to menu...")


def _show_session_detail(session: dict) -> None:
    """Display per-item status for a single scan session."""
    results_map = {r["key"]: r for r in session.get("results", [])}
    planned = session.get("planned", [])
    SEP = "─" * 70

    print(f"\n{session.get('label', 'Session')} — {session.get('started_at', '')[:16]}")
    print(SEP)

    for item in planned:
        key = item["key"]
        if key in results_map:
            r = results_map[key]
            icon = "✅" if r["status"] == "success" else "❌"
            label = item.get("account_name") or item.get("script") or key
            print(f"  {icon} {label} ({key}) — {r['duration_s']}s")
        else:
            label = item.get("account_name") or item.get("script") or key
            print(f"  ⏳ {label} ({key}) — not run")

    print(SEP)
    input("\nPress Enter to return...")


def show_scan_history() -> None:
    """Display recent scan sessions and allow drilling into details."""
    sessions = utils.load_scan_sessions(10)
    SEP = "─" * 70
    print(f"\nSCAN HISTORY (last {len(sessions)} sessions)")
    print(SEP)

    if not sessions:
        print("  No scan sessions found.")
        input("\nPress Enter to return...")
        return

    for idx, s in enumerate(sessions, 1):
        n_done = len(s.get("results", []))
        n_total = len(s.get("planned", []))
        status = s.get("status", "?")
        icon = "✅" if status == "completed" else ("⚠ " if status == "running" else "?")
        ts = s.get("started_at", "")[:16].replace("T", " ")
        print(f"  [{idx}] {icon} {s.get('label', s.get('scan_type'))} — {n_done}/{n_total} | {ts}")

    print(SEP)
    print("  [#] View session details    [B] Back")
    choice = input("\nSelect: ").strip().upper()
    if choice == "B" or not choice:
        return
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(sessions):
            _show_session_detail(sessions[idx])


def _resume_org_scan_from_session(session: dict) -> None:
    """Execute remaining org-scan accounts from an interrupted session."""
    planned = session.get("planned", [])
    if not planned:
        print("\n  ❌ Session has no planned entries — cannot resume.")
        input("  Press Enter to return to menu...")
        return

    script_name = planned[0].get("script", "")
    script_file = Path(__file__).parent / "scripts" / script_name
    if not script_file.exists():
        print(f"\n  ❌ Script {script_name} not found on disk — cannot resume.")
        input("  Press Enter to return to menu...")
        return

    cross_account_roles = utils.get_cross_account_roles()
    if not cross_account_roles:
        print("\n  ❌ No cross-account roles configured.")
        input("  Press Enter to return to menu...")
        return

    done_keys = {r["key"] for r in session.get("results", []) if r.get("status") == "success"}
    remaining = {acct: role for acct, role in cross_account_roles.items() if acct not in done_keys}

    SEP = "─" * 70
    n_done = len(done_keys)
    n_remaining = len(remaining)
    print(f"\n  Script:   {script_name}")
    print(f"  Done:     {n_done} account(s)")
    print(f"  Pending:  {n_remaining} account(s)")
    print(f"  {SEP}")

    if not remaining:
        print("\n  ✅ All accounts already completed. Marking session done.")
        utils.complete_scan_session(session)
        input("  Press Enter to return to menu...")
        return

    confirm = input(f"\n  Run {script_name} across {n_remaining} remaining account(s)? (y/n): ").strip().lower()
    if confirm != "y":
        return

    utils.resume_scan_session(session)
    results: list = []

    for acct_id, role_arn in remaining.items():
        acct_name = utils.get_account_name(acct_id)
        print(f"\n  Scanning: {acct_name} ({acct_id})...")
        child_env = os.environ.copy()
        child_env["STRATUSSCAN_ROLE_ARN"] = role_arn
        child_env["STRATUSSCAN_AUTO_RUN"] = "1"
        start_t = time.monotonic()
        exit_code = 0
        try:
            proc = subprocess.run([sys.executable, str(script_file)], env=child_env, timeout=1800)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            utils.log_error("Resume org-scan: %s timed out", acct_id)
            exit_code = -1
        except Exception as exc:  # noqa: BLE001
            utils.log_error("Resume org-scan: %s error: %s", acct_id, exc)
            exit_code = -1
        duration_s = time.monotonic() - start_t
        status_str = "success" if exit_code == 0 else "failed"
        utils.record_scan_result(session, acct_id, status_str, exit_code, duration_s,
                                 script=script_name, account_id=acct_id, account_name=acct_name)
        results.append({"acct_id": acct_id, "acct_name": acct_name, "exit_code": exit_code})

    utils.complete_scan_session(session)
    print("\n  RESUME COMPLETE")
    print(f"  {SEP}")
    for r in results:
        icon = "✅" if r["exit_code"] == 0 else "❌"
        status = "success" if r["exit_code"] == 0 else f"failed ({r['exit_code']})"
        print(f"  {icon}  {r['acct_name']} ({r['acct_id']}) — {status}")
    print(f"  {SEP}")
    input("\n  Press Enter to return to menu...")


def _startup_interrupted_check() -> None:
    """
    If an interrupted scan session exists, surface it immediately at startup
    with a Y/N resume prompt — before the main menu renders.
    """
    interrupted = utils.get_interrupted_sessions()
    if not interrupted:
        return

    session = interrupted[0]
    scan_type = session.get("scan_type", "")
    label = session.get("label", scan_type)
    n_done = len(session.get("results", []))
    n_total = len(session.get("planned", []))
    ts = session.get("started_at", "")[:16].replace("T", " ")

    SEP = "─" * 60
    print()
    print(f"  {SEP}")
    print("  ⚠  INTERRUPTED SCAN DETECTED")
    print(f"  {SEP}")
    print(f"  {label}")
    print(f"  Started: {ts}  |  Completed: {n_done}/{n_total}")
    print(f"  {SEP}")
    print("  [Y] Resume now")
    print("  [N] Skip — go to main menu")
    print("  [H] View scan history")
    print(f"  {SEP}")

    choice = input("\n  Choice [Y/N/H]: ").strip().upper() or "N"

    if choice == "H":
        show_scan_history()
        return

    if choice != "Y":
        return

    if scan_type == "org-scan":
        _resume_org_scan_from_session(session)
    elif scan_type == "smart-scan":
        session_path = session.get("_path", "")
        smart_scan_path = Path(__file__).parent / "smart_scan.py"
        child_env = os.environ.copy()
        child_env["STRATUSSCAN_RESUME_SESSION_PATH"] = session_path
        subprocess.run([sys.executable, str(smart_scan_path)], env=child_env)
        input("\n  Press Enter to return to menu...")
    else:
        print(f"\n  ❌ Unknown scan type '{scan_type}' — use [H] Scan History to view details.")
        input("  Press Enter to return to menu...")


def navigate_menus():
    """
    Display the main menu and handle user navigation through nested menus.
    """
    try:
        if not check_dependencies():
            print("Required dependencies are missing. Please install them to continue.")
            sys.exit(1)

        ensure_directory_structure()
        _startup_interrupted_check()

        while True:
            menu_structure, account_name = display_main_menu()

            if not menu_structure:
                print("\nNo scripts found in the mapping. Please ensure script files exist in the scripts directory.")
                sys.exit(1)

            print("\nSelect an option:")
            try:
                user_choice = prompt_with_navigation("> ")
            except QuitSignal:
                clear_screen()
                print("Exiting StratusScan. Thank you for using the tool.")
                return
            except (BackSignal, ExitToMainSignal):
                continue  # Already at main menu — just redisplay

            # Scan history (special key — not in menu_structure dict)
            if user_choice.upper() == "H":
                show_scan_history()
                continue

            if user_choice not in menu_structure:
                print("Invalid selection. Please try again.")
                continue

            selected_option = menu_structure[user_choice]
            utils.log_menu_selection(user_choice, selected_option['name'])

            # Org scan
            if selected_option.get("action") == "org_scan":
                with contextlib.suppress(BackSignal, ExitToMainSignal):
                    run_org_scan()
                continue

            # Direct script (e.g. Configure StratusScan, Service Discovery)
            if "file" in selected_option and "submenu" not in selected_option:
                print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")

                try:
                    confirmed = _confirm("Do you want to continue?")
                except (BackSignal, ExitToMainSignal):
                    continue  # Return to main menu
                # QuitSignal propagates to outer except

                if confirmed:
                    utils.log_info(f"User confirmed execution of: {selected_option['name']}")
                    if selected_option["name"] == "Create Output Archive":
                        create_output_archive(account_name)
                    elif selected_option["name"] == "Configure StratusScan":
                        if selected_option["file"]:
                            try:
                                success = execute_script(selected_option["file"])
                            except (BackSignal, ExitToMainSignal):
                                continue
                            if success:
                                print("\nConfiguration completed successfully!")
                                print("You may need to restart StratusScan for changes to take effect.")
                            else:
                                print("\nConfiguration may not have completed successfully.")
                    elif selected_option.get("file"):
                        try:
                            execute_script(selected_option["file"])
                        except (BackSignal, ExitToMainSignal):
                            continue  # Script returned 'b' or 'x' — redisplay main menu

            # Submenu
            elif "submenu" in selected_option:
                with contextlib.suppress(ExitToMainSignal, BackSignal):
                    # QuitSignal propagates to outer except
                    handle_submenu(selected_option, account_name)

    except QuitSignal:
        clear_screen()
        print("Exiting StratusScan. Thank you for using the tool.")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stratusscan",
        description="StratusScanCLI-AWS — export AWS resource inventories to Excel",
        add_help=True,
    )
    parser.add_argument(
        "--version", action="version", version=f"StratusScanCLI-AWS {utils.get_version()}"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate credentials and config, show what would run, then exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable debug-level console output",
    )
    return parser


def _run_dry_run() -> None:
    """Validate credentials and config, print a summary, then exit 0."""
    print("\nStratusScanCLI-AWS — dry run")
    print("=" * 60)

    ok, account_id, account_name = utils.validate_aws_credentials()
    if not ok:
        print("  [✗] AWS credentials: not found or invalid")
        print("\nDry run failed. Configure credentials before running.")
        sys.exit(1)

    print("  [✓] AWS credentials: valid")
    print(f"  [✓] Account: {account_name} ({account_id})")

    partition = utils.detect_partition()
    print(f"  [✓] Partition: {partition}")

    config, _ = utils.get_config()
    print("  [✓] Config: loaded")

    # Count available scripts
    scripts_dir = Path(__file__).parent / "scripts"
    script_count = len(list(scripts_dir.glob("*_export.py")))
    print(f"  [✓] Export scripts available: {script_count}")

    print("=" * 60)
    print("Dry run complete. No exports were run.")
    sys.exit(0)


def main():
    """
    Main function to display the menu and handle script execution.
    """
    parser = _build_parser()
    # parse_known_args so unrecognised flags don't abort interactive mode
    args, _ = parser.parse_known_args()

    if args.verbose:
        # Lower the console handler to DEBUG so all log output reaches stdout
        for handler in logging.getLogger("stratusscan").handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                handler.setLevel(logging.DEBUG)
        utils.log_debug("Verbose mode enabled")

    if args.dry_run:
        _run_dry_run()
        return  # sys.exit(0) called inside, but be explicit

    try:
        utils.log_section("STARTING MAIN MENU NAVIGATION")
        navigate_menus()
    except KeyboardInterrupt:
        utils.log_info("User cancelled operation with Ctrl+C")
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error in main function: {e}")
        utils.log_error("Error in main function", e)
        sys.exit(1)
    finally:
        utils.log_script_end("stratusscan.py", SCRIPT_START_TIME)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        utils.log_error("Fatal error in main execution", e)
        sys.exit(1)
