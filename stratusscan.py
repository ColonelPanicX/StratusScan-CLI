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

import contextlib
import datetime
import os
import subprocess
import sys
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
# Navigation signals — raised by prompt_with_navigation() for b / x / q input
# ---------------------------------------------------------------------------

class BackSignal(BaseException):
    """Raised when the user enters 'b' to return to the parent menu."""


class ExitToMainSignal(BaseException):
    """Raised when the user enters 'x' to exit directly to the main menu."""


class QuitSignal(BaseException):
    """Raised when the user enters 'q' to quit StratusScan."""


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

def _visual_len(s: str) -> int:
    """Return terminal column width of s, counting emoji/wide chars as 2 columns."""
    count = 0
    for ch in s:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F or cp == 0x200D:
            continue
        if cp >= 0x2600 and not (0x2500 <= cp <= 0x257F):
            count += 2
        else:
            count += 1
    return count

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
    """Print a right-aligned status line inside box walls."""
    label_part = f"║ {label}: "
    status_part = f"{status} ║"
    padding = width - len(label_part) - _visual_len(status_part)
    if padding < 0:
        padding = 0
    print(label_part + " " * padding + status_part)

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
        print(f"No configuration file found. The config.json file should exist.")
        print(f"Please ensure config.json is present in the StratusScan directory.")
        print(f"You may want to edit this file to add your account mappings.")
    
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
        "1": {
            "name": "Service Discovery + Smart Scan",
            "file": scripts_dir / "services_in_use_export.py",
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
            }
        },
        "8": {
            "name": "DevOps Services",
            "submenu": {
                "1": {"name": "CodeBuild", "file": scripts_dir / "codebuild_export.py", "description": "Export CodeBuild projects"},
                "2": {"name": "CodePipeline", "file": scripts_dir / "codepipeline_export.py", "description": "Export CodePipeline pipelines"},
                "3": {"name": "CodeCommit", "file": scripts_dir / "codecommit_export.py", "description": "Export CodeCommit repositories"},
                "4": {"name": "CodeDeploy", "file": scripts_dir / "codedeploy_export.py", "description": "Export CodeDeploy applications"},
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
            }
        },
        "10": {
            "name": "Output Management",
            "file": scripts_dir / "output_archive.py",
            "description": "Create a zip archive of all exported files"
        },
    }

    # Verify the script files exist (only for actual scripts)
    for main_option, main_info in menu_structure.items():
        if "submenu" in main_info:
            # Check first level submenus
            for sub_option, sub_info in main_info["submenu"].items():
                if "submenu" in sub_info:
                    # Check nested submenus
                    for nested_option, nested_info in sub_info["submenu"].items():
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
    print("  q = quit")
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

def navigate_menus():
    """
    Display the main menu and handle user navigation through nested menus.
    """
    try:
        if not check_dependencies():
            print("Required dependencies are missing. Please install them to continue.")
            sys.exit(1)

        ensure_directory_structure()

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

            if user_choice not in menu_structure:
                print("Invalid selection. Please try again.")
                continue

            selected_option = menu_structure[user_choice]
            utils.log_menu_selection(user_choice, selected_option['name'])

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

def main():
    """
    Main function to display the menu and handle script execution.
    """
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
        # Log script completion
        utils.log_script_end("stratusscan.py", SCRIPT_START_TIME)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        utils.log_error("Fatal error in main execution", e)
        sys.exit(1)