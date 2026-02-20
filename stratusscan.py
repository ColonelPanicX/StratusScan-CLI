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

import os
import sys
import subprocess
import zipfile
import datetime
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

def clear_screen():
    """
    Clear the terminal screen using ANSI escape codes (avoids os.system shell call).
    Works on Windows 10+, Linux, and macOS terminals.
    """
    print('\033[2J\033[H', end='', flush=True)

def print_header():
    """
    Print the main menu header with version information.
    
    Returns:
        tuple: (account_id, account_name) - The AWS account information
    """
    clear_screen()
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("                         STRATUSSCAN                                ")
    print("                   AWS RESOURCE EXPORTER MENU                      ")
    print("====================================================================")
    print(f"Version: {utils.get_version()}                                Date: FEB-17-2026")
    print("Multi-Partition: Commercial & GovCloud Support")
    print("====================================================================")

    # Get the current AWS account ID and map to account name
    try:
        # Create a boto3 STS client
        sts = utils.get_boto3_client('sts')
        account_id = sts.get_caller_identity()["Account"]
        account_name = utils.get_account_name(account_id, default=account_id)

        # Detect partition and display environment
        try:
            caller_arn = sts.get_caller_identity()["Arn"]
            partition = utils.detect_partition()
            if partition == 'aws-us-gov':
                environment = "AWS GovCloud (US)"
            elif partition == 'aws':
                environment = "AWS Commercial"
            else:
                environment = f"AWS ({partition})"
            print(f"Environment: {environment}")
        except Exception:
            print("Environment: AWS Commercial (default)")

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print(f"Error getting account information: {e}")
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"

    print("====================================================================")
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
    Check and install common required dependencies.
    
    Returns:
        bool: True if all dependencies are satisfied, False otherwise
    """
    print("Checking required dependencies...")
    required_packages = ['boto3', 'pandas', 'openpyxl']
    
    for package in required_packages:
        if check_dependency(package):
            print(f"[OK] {package} is already installed")
        else:
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

        print(f"Executing: {script_path}")
        print("=" * 60)

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
        
        print("====================================================================")
        print("CREATING OUTPUT ARCHIVE")
        print("====================================================================")
        
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
                        "2": {"name": "RDS", "file": scripts_dir / "rds_export.py", "description": "Export RDS instance information"},
                        "3": {"name": "EKS", "file": scripts_dir / "eks_export.py", "description": "Export EKS cluster information"},
                        "4": {"name": "ECS", "file": scripts_dir / "ecs_export.py", "description": "Export ECS cluster and service information"},
                        "5": {"name": "Auto Scaling Groups", "file": scripts_dir / "autoscaling_export.py", "description": "Export Auto Scaling Group configurations"},
                        "6": {"name": "Lambda Functions", "file": scripts_dir / "lambda_export.py", "description": "Export Lambda function configurations"},
                        "7": {"name": "ECR", "file": scripts_dir / "ecr_export.py", "description": "Export ECR repositories and images"},
                        "8": {"name": "AMI", "file": scripts_dir / "ami_export.py", "description": "Export account-owned AMIs"},
                        "9": {"name": "EC2 Image Builder", "file": scripts_dir / "image_builder_export.py", "description": "Export Image Builder pipelines"},
                        "10": {"name": "EC2 Capacity Reservations", "file": scripts_dir / "ec2_capacity_reservations_export.py", "description": "Export EC2 Capacity Reservations"},
                        "11": {"name": "EC2 Dedicated Hosts", "file": scripts_dir / "ec2_dedicated_hosts_export.py", "description": "Export EC2 Dedicated Hosts"},
                        "12": {"name": "All Compute Resources", "file": scripts_dir / "compute_resources.py", "description": "Export all compute resources in one report"},
                        "13": {"name": "Return to Previous Menu", "file": None, "description": "Return to Infrastructure menu"}
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
                        "13": {"name": "Return to Previous Menu", "file": None, "description": "Return to Infrastructure menu"}
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
                        "15": {"name": "Return to Previous Menu", "file": None, "description": "Return to Infrastructure menu"}
                    }
                },
                "4": {
                    "name": "Database Resources",
                    "submenu": {
                        "1": {"name": "DynamoDB", "file": scripts_dir / "dynamodb_export.py", "description": "Export DynamoDB tables and GSIs"},
                        "2": {"name": "ElastiCache", "file": scripts_dir / "elasticache_export.py", "description": "Export ElastiCache clusters"},
                        "3": {"name": "DocumentDB", "file": scripts_dir / "documentdb_export.py", "description": "Export DocumentDB clusters"},
                        "4": {"name": "Neptune", "file": scripts_dir / "neptune_export.py", "description": "Export Neptune graph databases"},
                        "5": {"name": "Return to Previous Menu", "file": None, "description": "Return to Infrastructure menu"}
                    }
                },
                "5": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
            }
        },
        "3": {
            "name": "Security & Compliance",
            "submenu": {
                "1": {"name": "Security Hub", "file": scripts_dir / "security_hub_export.py", "description": "Export Security Hub findings"},
                "2": {"name": "GuardDuty", "file": scripts_dir / "guardduty_export.py", "description": "Export GuardDuty findings"},
                "3": {"name": "AWS WAF", "file": scripts_dir / "waf_export.py", "description": "Export WAF web ACLs and rules"},
                "4": {"name": "CloudTrail", "file": scripts_dir / "cloudtrail_export.py", "description": "Export CloudTrail trails"},
                "5": {"name": "AWS Config", "file": scripts_dir / "config_export.py", "description": "Export Config rules and compliance"},
                "6": {"name": "KMS", "file": scripts_dir / "kms_export.py", "description": "Export KMS keys and encryption configs"},
                "7": {"name": "Secrets Manager", "file": scripts_dir / "secrets_manager_export.py", "description": "Export Secrets Manager metadata"},
                "8": {"name": "ACM", "file": scripts_dir / "acm_export.py", "description": "Export ACM SSL/TLS certificates"},
                "9": {"name": "IAM Access Analyzer", "file": scripts_dir / "access_analyzer_export.py", "description": "Export Access Analyzer findings"},
                "10": {"name": "Detective", "file": scripts_dir / "detective_export.py", "description": "Export Detective behavior graphs"},
                "11": {"name": "Shield Advanced", "file": scripts_dir / "shield_export.py", "description": "Export Shield DDoS protection"},
                "12": {"name": "IAM Roles Anywhere", "file": scripts_dir / "iam_rolesanywhere_export.py", "description": "Export IAM Roles Anywhere"},
                "13": {"name": "Verified Access", "file": scripts_dir / "verifiedaccess_export.py", "description": "Export Verified Access zero-trust"},
                "14": {"name": "Macie", "file": scripts_dir / "macie_export.py", "description": "Export Macie data security findings"},
                "15": {"name": "Cognito", "file": scripts_dir / "cognito_export.py", "description": "Export Cognito user pools"},
                "16": {"name": "ACM Private CA", "file": scripts_dir / "acm_privateca_export.py", "description": "Export ACM Private CAs"},
                "17": {"name": "IAM Identity Providers", "file": scripts_dir / "iam_identity_providers_export.py", "description": "Export IAM SAML/OIDC providers"},
                "18": {"name": "Verified Permissions", "file": scripts_dir / "verifiedpermissions_export.py", "description": "Export Verified Permissions Cedar policies"},
                "19": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
            }
        },
        "4": {
            "name": "Identity & Access Management",
            "submenu": {
                "1": {
                    "name": "IAM",
                    "description": "Traditional IAM resources (users, roles, policies)",
                    "submenu": {
                        "1": {"name": "IAM Users", "file": scripts_dir / "iam_export.py", "description": "Export IAM user information"},
                        "2": {"name": "IAM Roles", "file": scripts_dir / "iam_roles_export.py", "description": "Export IAM role information"},
                        "3": {"name": "IAM Policies", "file": scripts_dir / "iam_policies_export.py", "description": "Export IAM policy information"},
                        "4": {"name": "All IAM Resources", "file": scripts_dir / "iam_comprehensive_export.py", "description": "Export all IAM resources in one report"},
                        "5": {"name": "Return to Previous Menu", "file": None, "description": "Return to IAM menu"}
                    }
                },
                "2": {"name": "AWS Organizations", "file": scripts_dir / "organizations_export.py", "description": "Export AWS Organizations structure"},
                "3": {
                    "name": "IAM Identity Center",
                    "description": "IAM Identity Center (formerly AWS SSO) resources",
                    "submenu": {
                        "1": {"name": "IAM Identity Center", "file": scripts_dir / "iam_identity_center_export.py", "description": "Export users, groups, and permission sets"},
                        "2": {"name": "Groups", "file": scripts_dir / "iam_identity_center_groups_export.py", "description": "Export Identity Center groups"},
                        "3": {"name": "Permission Sets", "file": scripts_dir / "iam_identity_center_permission_sets_export.py", "description": "Export permission sets"},
                        "4": {"name": "Comprehensive", "file": scripts_dir / "iam_identity_center_comprehensive_export.py", "description": "Export all Identity Center data"},
                        "5": {"name": "Return to Previous Menu", "file": None, "description": "Return to IAM menu"}
                    }
                },
                "4": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
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
                "10": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
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
                "12": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
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
                "11": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
            }
        },
        "8": {
            "name": "Developer Tools",
            "submenu": {
                "1": {"name": "CodeBuild", "file": scripts_dir / "codebuild_export.py", "description": "Export CodeBuild projects"},
                "2": {"name": "CodePipeline", "file": scripts_dir / "codepipeline_export.py", "description": "Export CodePipeline pipelines"},
                "3": {"name": "CodeCommit", "file": scripts_dir / "codecommit_export.py", "description": "Export CodeCommit repositories"},
                "4": {"name": "CodeDeploy", "file": scripts_dir / "codedeploy_export.py", "description": "Export CodeDeploy applications"},
                "5": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
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
                "8": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
            }
        },
        "10": {
            "name": "Output Management",
            "submenu": {
                "1": {"name": "Create Output Archive", "file": None, "description": "Create a zip archive of all exported files", "action": "create_archive"},
                "2": {"name": "Return to Main Menu", "file": None, "description": "Return to the main menu"}
            }
        }
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
    Display the main menu with categories.
    
    Returns:
        tuple: (menu_structure, exit_option) - The menu structure and exit option
    """
    # Get the menu structure
    menu_structure = get_menu_structure()
    
    # Display the main menu options
    print("\nMAIN MENU:")
    print("====================================================================")
    
    for option, info in menu_structure.items():
        print(f"{option}. {info['name']}")
    
    # Add exit option
    print("x. Exit")

    return menu_structure, 'x'

def display_submenu(submenu, category_name):
    """
    Display a submenu for a specific category.

    Args:
        submenu (dict): The submenu options
        category_name (str): The name of the category

    Returns:
        dict: The submenu structure
    """
    # Clear the screen
    clear_screen()

    print(f"====================================================================")
    print(f"                  {category_name.upper()}")
    print(f"====================================================================")

    # Display the submenu options
    print("\nSelect an option:")
    for option, info in submenu.items():
        # Handle items with or without descriptions
        if 'description' in info:
            print(f"{option}. {info['name']} - {info['description']}")
        else:
            print(f"{option}. {info['name']}")

    return submenu


def handle_submenu(category_option, account_name):
    """
    Handle the submenu navigation and script execution.
    
    Args:
        category_option (dict): The selected main menu option with submenu
        account_name (str): The AWS account name for archive creation
    """
    while True:
        # Display submenu for this category
        submenu = display_submenu(category_option["submenu"], category_option["name"])
        
        # Get user choice
        print("\nSelect an option:")
        user_choice = input("> ")
        
        # Handle return to main menu
        if user_choice in submenu:
            selected_option = submenu[user_choice]

            # Log submenu selection
            submenu_path = f"{category_option.get('name', 'Unknown')}.{user_choice}"
            utils.log_menu_selection(submenu_path, selected_option['name'])

            # Check if this is the "Return to Main Menu" or "Return to Previous Menu" option
            if selected_option["name"] in ["Return to Main Menu", "Return to Previous Menu"]:
                utils.log_info(f"User selected: {selected_option['name']}")
                return

            # Check if this option has its own submenu (nested submenu)
            if "submenu" in selected_option:
                handle_submenu(selected_option, account_name)
                continue

            # Check if this is a special action (like Create Output Archive)
            if selected_option.get("action") == "create_archive":
                print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")

                # Confirm execution
                if utils.prompt_for_confirmation("Do you want to continue?"):
                    create_output_archive(account_name)
                    # Ask if user wants to perform another action from this submenu
                    if not utils.prompt_for_confirmation("Would you like to perform another action from this menu?"):
                        return  # Return to main menu
                continue

            # Handle regular script execution
            print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")

            # Confirm execution
            if utils.prompt_for_confirmation("Do you want to continue?"):
                # Execute the script
                if selected_option["file"]:
                    success = execute_script(selected_option["file"])

                    # Ask if user wants to run another tool from this submenu
                    if not utils.prompt_for_confirmation("Would you like to run another tool from this menu?"):
                        return  # Return to main menu
                
            # If user didn't confirm, stay in the submenu
        
        else:
            print("Invalid selection. Please try again.")

def navigate_menus():
    """
    Display the main menu and handle user navigation through nested menus.
    """
    try:
        # Print header and get account information
        account_id, account_name = print_header()
        
        # Check dependencies
        if not check_dependencies():
            print("Required dependencies are missing. Please install them to continue.")
            sys.exit(1)
        
        # Ensure directory structure
        ensure_directory_structure()
        
        # Main menu loop
        while True:
            # Get menu structure
            menu_structure, exit_option = display_main_menu()
            
            if not menu_structure:
                print("\nNo scripts found in the mapping. Please ensure script files exist in the scripts directory.")
                sys.exit(1)
            
            print("\nSelect an option:")
            user_choice = input("> ")
            
            # Exit option
            if user_choice.lower() == exit_option.lower():
                clear_screen()
                print("Exiting StratusScan. Thank you for using the tool.")
                break
            
            # Main menu option
            elif user_choice in menu_structure:
                selected_option = menu_structure[user_choice]

                # Log menu selection
                utils.log_menu_selection(user_choice, selected_option['name'])

                # If it's a direct script (like Create Output Archive or Configure StratusScan)
                if "file" in selected_option and "submenu" not in selected_option:
                    print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")

                    # Confirm execution
                    if utils.prompt_for_confirmation("Do you want to continue?"):
                        utils.log_info(f"User confirmed execution of: {selected_option['name']}")
                        # Handle special case for creating output archive
                        if selected_option["name"] == "Create Output Archive":
                            create_output_archive(account_name)
                        # Handle Configure StratusScan
                        elif selected_option["name"] == "Configure StratusScan":
                            if selected_option["file"]:
                                success = execute_script(selected_option["file"])
                                if success:
                                    print("\nConfiguration completed successfully!")
                                    print("You may need to restart StratusScan for changes to take effect.")
                                else:
                                    print("\nConfiguration may not have completed successfully.")
                        # Handle other direct scripts
                        elif selected_option.get("file"):
                            execute_script(selected_option["file"])
                
                # If it's a submenu
                elif "submenu" in selected_option:
                    # Display the submenu and handle selection
                    handle_submenu(selected_option, account_name)
            
            else:
                print("Invalid selection. Please try again.")
    
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