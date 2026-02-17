"""
Service-to-Script Mapping Database

Maps AWS service names from services-in-use export to their corresponding
StratusScan export scripts. Includes service aliases and categorization.
"""

import logging
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Special category: Always recommended for security/compliance audits
ALWAYS_RUN_SCRIPTS = [
    "iam-comprehensive-export.py",
    "cloudtrail-export.py",
    "config-export.py",
    "guardduty-export.py",
    "security-groups-export.py",
    "nacl-export.py",
    "services-in-use-export.py",
    "trusted-advisor-cost-optimization-export.py",
    "budgets-export.py",
]

# Service name aliases and variations
# Maps common service name variations to canonical names
SERVICE_ALIASES: Dict[str, str] = {
    # EC2 and Compute
    "ec2": "Amazon Elastic Compute Cloud",
    "amazon ec2": "Amazon Elastic Compute Cloud",
    "elastic compute cloud": "Amazon Elastic Compute Cloud",
    "lambda": "AWS Lambda",
    "eks": "Amazon Elastic Kubernetes Service",
    "Amazon EKS": "Amazon Elastic Kubernetes Service",
    "kubernetes": "Amazon Elastic Kubernetes Service",
    "ecs": "Amazon Elastic Container Service",
    "Amazon ECS": "Amazon Elastic Container Service",
    "fargate": "AWS Fargate",
    "batch": "AWS Batch",
    "lightsail": "Amazon Lightsail",
    "app runner": "AWS App Runner",
    "apprunner": "AWS App Runner",

    # Storage
    "s3": "Amazon Simple Storage Service",
    "amazon s3": "Amazon Simple Storage Service",
    "simple storage service": "Amazon Simple Storage Service",
    "ebs": "Amazon Elastic Block Store",
    "elastic block store": "Amazon Elastic Block Store",
    "efs": "Amazon Elastic File System",
    "elastic file system": "Amazon Elastic File System",
    "fsx": "Amazon FSx",
    "glacier": "Amazon S3 Glacier",
    "s3 glacier": "Amazon S3 Glacier",
    "storage gateway": "AWS Storage Gateway",
    "backup": "AWS Backup",

    # Database
    "rds": "Amazon Relational Database Service",
    "relational database service": "Amazon Relational Database Service",
    "dynamodb": "Amazon DynamoDB",
    "elasticache": "Amazon ElastiCache",
    "redshift": "Amazon Redshift",
    "neptune": "Amazon Neptune",
    "documentdb": "Amazon DocumentDB",
    "aurora": "Amazon Aurora",
    "keyspaces": "Amazon Keyspaces",
    "timestream": "Amazon Timestream",
    "memorydb": "Amazon MemoryDB for Redis",

    # Networking
    "vpc": "Amazon Virtual Private Cloud",
    "virtual private cloud": "Amazon Virtual Private Cloud",
    "cloudfront": "Amazon CloudFront",
    "route 53": "Amazon Route 53",
    "route53": "Amazon Route 53",
    "elb": "Elastic Load Balancing",
    "elastic load balancing": "Elastic Load Balancing",
    "alb": "Elastic Load Balancing",
    "nlb": "Elastic Load Balancing",
    "direct connect": "AWS Direct Connect",
    "directconnect": "AWS Direct Connect",
    "vpn": "AWS Virtual Private Network",
    "transit gateway": "AWS Transit Gateway",
    "global accelerator": "AWS Global Accelerator",
    "api gateway": "Amazon API Gateway",
    "apigateway": "Amazon API Gateway",

    # Security & Identity
    "iam": "AWS Identity and Access Management",
    "identity and access management": "AWS Identity and Access Management",
    "cognito": "Amazon Cognito",
    "secrets manager": "AWS Secrets Manager",
    "secretsmanager": "AWS Secrets Manager",
    "kms": "AWS Key Management Service",
    "key management service": "AWS Key Management Service",
    "acm": "AWS Certificate Manager",
    "certificate manager": "AWS Certificate Manager",
    "guardduty": "Amazon GuardDuty",
    "macie": "Amazon Macie",
    "security hub": "AWS Security Hub",
    "securityhub": "AWS Security Hub",
    "waf": "AWS WAF",
    "shield": "AWS Shield",
    "firewall manager": "AWS Firewall Manager",
    "network firewall": "AWS Network Firewall",
    "detective": "Amazon Detective",
    "access analyzer": "AWS IAM Access Analyzer",

    # Management & Governance
    "cloudwatch": "Amazon CloudWatch",
    "cloudtrail": "AWS CloudTrail",
    "config": "AWS Config",
    "systems manager": "AWS Systems Manager",
    "ssm": "AWS Systems Manager",
    "organizations": "AWS Organizations",
    "control tower": "AWS Control Tower",
    "service catalog": "AWS Service Catalog",
    "trusted advisor": "AWS Trusted Advisor",
    "cost explorer": "AWS Cost Explorer",

    # Application Integration
    "sns": "Amazon Simple Notification Service",
    "simple notification service": "Amazon Simple Notification Service",
    "sqs": "Amazon Simple Queue Service",
    "simple queue service": "Amazon Simple Queue Service",
    "eventbridge": "Amazon EventBridge",
    "step functions": "AWS Step Functions",
    "stepfunctions": "AWS Step Functions",
    "appflow": "Amazon AppFlow",

    # Analytics
    "athena": "Amazon Athena",
    "glue": "AWS Glue",
    "emr": "Amazon EMR",
    "kinesis": "Amazon Kinesis",
    "quicksight": "Amazon QuickSight",
    "opensearch": "Amazon OpenSearch Service",
    "elasticsearch": "Amazon OpenSearch Service",

    # Developer Tools
    "codecommit": "AWS CodeCommit",
    "codebuild": "AWS CodeBuild",
    "codedeploy": "AWS CodeDeploy",
    "codepipeline": "AWS CodePipeline",
    "codeartifact": "AWS CodeArtifact",
    "cloud9": "AWS Cloud9",

    # Machine Learning
    "sagemaker": "Amazon SageMaker",
    "bedrock": "Amazon Bedrock",
    "comprehend": "Amazon Comprehend",
    "rekognition": "Amazon Rekognition",
    "textract": "Amazon Textract",

    # Containers
    "ecr": "Amazon Elastic Container Registry",
    "elastic container registry": "Amazon Elastic Container Registry",
    "elastic container service": "Amazon Elastic Container Service",
    "elastic kubernetes service": "Amazon Elastic Kubernetes Service",
}

# Primary mapping: Service name → list of export scripts
# Only references scripts that exist on disk. Entries for services whose
# scripts have not yet been created are omitted until those scripts are added.
SERVICE_SCRIPT_MAP: Dict[str, List[str]] = {
    # Compute Services
    "Amazon Elastic Compute Cloud": [
        "ec2-export.py",
        "ami-export.py",
        "autoscaling-export.py",
        "ebs-volumes-export.py",
        "ebs-snapshots-export.py",
        "ec2-capacity-reservations-export.py",
        "ec2-dedicated-hosts-export.py",
        "compute-resources.py",
    ],
    "AWS Lambda": ["lambda-export.py"],
    "Amazon Elastic Kubernetes Service": ["eks-export.py"],
    "Amazon Elastic Container Service": ["ecs-export.py"],
    "Amazon Elastic Container Registry": ["ecr-export.py"],
    "AWS Fargate": ["ecs-export.py"],  # Fargate is ECS launch type
    "Amazon EC2 Auto Scaling": ["autoscaling-export.py"],
    "AWS Elastic Beanstalk": ["elasticbeanstalk-export.py"],
    "AWS App Runner": ["apprunner-export.py"],

    # Storage Services
    "Amazon Simple Storage Service": [
        "s3-export.py",
        "s3-accesspoints-export.py",
        "storage-resources.py",
    ],
    "Amazon Elastic Block Store": [
        "ebs-volumes-export.py",
        "ebs-snapshots-export.py",
    ],
    "Amazon Elastic File System": ["efs-export.py"],
    "Amazon FSx": ["fsx-export.py"],
    "Amazon S3 Glacier": ["glacier-export.py"],
    "AWS Storage Gateway": ["storagegateway-export.py"],
    "AWS Backup": ["backup-export.py"],
    "AWS DataSync": ["datasync-export.py"],
    "AWS Transfer Family": ["transfer-family-export.py"],

    # Database Services
    "Amazon Relational Database Service": ["rds-export.py"],
    "Amazon Aurora": ["rds-export.py"],  # Aurora is part of RDS
    "Amazon DynamoDB": ["dynamodb-export.py"],
    "Amazon ElastiCache": ["elasticache-export.py"],
    "Amazon Redshift": ["redshift-export.py"],
    "Amazon Neptune": ["neptune-export.py"],
    "Amazon DocumentDB": ["documentdb-export.py"],

    # Networking & Content Delivery
    "Amazon Virtual Private Cloud": [
        "vpc-data-export.py",
        "security-groups-export.py",
        "nacl-export.py",
        "route-tables-export.py",
        "network-resources.py",
    ],
    "Amazon CloudFront": ["cloudfront-export.py"],
    "Amazon Route 53": ["route53-export.py"],
    "Elastic Load Balancing": ["elb-export.py"],
    "AWS Direct Connect": ["directconnect-export.py"],
    "AWS Virtual Private Network": ["vpn-export.py"],
    "AWS Transit Gateway": ["transit-gateway-export.py"],
    "AWS Global Accelerator": ["globalaccelerator-export.py"],
    "Amazon API Gateway": ["api-gateway-export.py"],
    "AWS Cloud Map": ["cloudmap-export.py"],
    "AWS PrivateLink": ["network-resources.py"],
    "AWS Client VPN": ["vpn-export.py"],
    "AWS Verified Access": ["verifiedaccess-export.py"],
    "AWS Network Manager": ["network-manager-export.py"],

    # Security, Identity & Compliance
    "AWS Identity and Access Management": [
        "iam-export.py",
        "iam-comprehensive-export.py",
        "iam-roles-export.py",
        "iam-policies-export.py",
        "iam-identity-providers-export.py",
        "iam-rolesanywhere-export.py",
    ],
    "AWS IAM Identity Center": [
        "iam-identity-center-comprehensive-export.py",
        "iam-identity-center-permission-sets-export.py",
        "iam-identity-center-groups-export.py",
        "iam-identity-center-export.py",
    ],
    "Amazon Cognito": ["cognito-export.py"],
    "AWS Secrets Manager": ["secrets-manager-export.py"],
    "AWS Key Management Service": ["kms-export.py"],
    "AWS Certificate Manager": ["acm-export.py"],
    "AWS Certificate Manager Private Certificate Authority": ["acm-privateca-export.py"],
    "Amazon GuardDuty": ["guardduty-export.py"],
    "Amazon Macie": ["macie-export.py"],
    "AWS Security Hub": ["security-hub-export.py"],
    "AWS WAF": ["waf-export.py"],
    "AWS Shield": ["shield-export.py"],
    "AWS Network Firewall": ["network-firewall-export.py"],
    "Amazon Detective": ["detective-export.py"],
    "AWS IAM Access Analyzer": ["access-analyzer-export.py"],
    "Amazon Verified Permissions": ["verifiedpermissions-export.py"],

    # Management & Governance
    "Amazon CloudWatch": ["cloudwatch-export.py"],
    "AWS CloudTrail": ["cloudtrail-export.py"],
    "AWS Config": ["config-export.py"],
    "AWS Systems Manager": ["ssm-fleet-export.py"],
    "AWS Organizations": ["organizations-export.py"],
    "AWS Control Tower": ["controltower-export.py"],
    "AWS Service Catalog": ["service-catalog-export.py"],
    "AWS Trusted Advisor": ["trusted-advisor-cost-optimization-export.py"],
    "AWS Budgets": ["budgets-export.py"],
    "AWS License Manager": ["license-manager-export.py"],
    "AWS Health": ["health-export.py"],
    "AWS CloudFormation": ["cloudformation-export.py"],
    "AWS Compute Optimizer": ["compute-optimizer-export.py"],
    "AWS Cost Anomaly Detection": ["cost-anomaly-detection-export.py"],
    "AWS Cost Categories": ["cost-categories-export.py"],
    "Cost Optimization Hub": ["cost-optimization-hub-export.py"],
    "Savings Plans": ["savings-plans-export.py"],
    "AWS Marketplace": ["marketplace-export.py"],
    "Amazon EC2 Image Builder": ["image-builder-export.py"],

    # Cost & Billing
    "AWS Billing": ["billing-export.py"],
    "AWS Reserved Instances": ["reserved-instances-export.py"],
    "AWS Services In Use": ["services-in-use-export.py"],

    # Application Integration
    "Amazon Simple Notification Service": ["sqs-sns-export.py"],
    "Amazon Simple Queue Service": ["sqs-sns-export.py"],
    "Amazon EventBridge": ["eventbridge-export.py"],
    "AWS Step Functions": ["stepfunctions-export.py"],

    # Analytics
    "Amazon Athena": ["glue-athena-export.py"],
    "AWS Glue": ["glue-athena-export.py"],
    "Amazon OpenSearch Service": ["opensearch-export.py"],
    "AWS Lake Formation": ["lakeformation-export.py"],

    # Developer Tools
    "AWS CodeCommit": ["codecommit-export.py"],
    "AWS CodeBuild": ["codebuild-export.py"],
    "AWS CodeDeploy": ["codedeploy-export.py"],
    "AWS CodePipeline": ["codepipeline-export.py"],
    "AWS X-Ray": ["xray-export.py"],

    # Machine Learning
    "Amazon SageMaker": ["sagemaker-export.py"],
    "Amazon Bedrock": ["bedrock-export.py"],
    "Amazon Comprehend": ["comprehend-export.py"],
    "Amazon Rekognition": ["rekognition-export.py"],

    # Customer Engagement
    "Amazon Connect": ["connect-export.py"],
    "Amazon Simple Email Service": ["ses-export.py", "ses-pinpoint-export.py"],
    "Amazon Pinpoint": ["ses-pinpoint-export.py"],

    # Front-End Web & Mobile
    "AWS AppSync": ["appsync-export.py"],
}

# Script categories for organization
SCRIPT_CATEGORIES: Dict[str, List[str]] = {
    "Security & Compliance": [
        "iam-comprehensive-export.py",
        "guardduty-export.py",
        "security-hub-export.py",
        "cloudtrail-export.py",
        "config-export.py",
        "macie-export.py",
        "access-analyzer-export.py",
        "detective-export.py",
        "waf-export.py",
        "network-firewall-export.py",
        "shield-export.py",
        "security-groups-export.py",
        "nacl-export.py",
        "verifiedpermissions-export.py",
        "verifiedaccess-export.py",
        "iam-identity-center-export.py",
    ],
    "Compute": [
        "ec2-export.py",
        "lambda-export.py",
        "eks-export.py",
        "ecs-export.py",
        "autoscaling-export.py",
        "elasticbeanstalk-export.py",
        "apprunner-export.py",
        "compute-resources.py",
        "ec2-capacity-reservations-export.py",
        "ec2-dedicated-hosts-export.py",
    ],
    "Storage": [
        "s3-export.py",
        "ebs-volumes-export.py",
        "ebs-snapshots-export.py",
        "efs-export.py",
        "fsx-export.py",
        "glacier-export.py",
        "storagegateway-export.py",
        "backup-export.py",
        "datasync-export.py",
        "storage-resources.py",
    ],
    "Database": [
        "rds-export.py",
        "dynamodb-export.py",
        "elasticache-export.py",
        "redshift-export.py",
        "neptune-export.py",
        "documentdb-export.py",
    ],
    "Networking": [
        "vpc-data-export.py",
        "elb-export.py",
        "cloudfront-export.py",
        "route53-export.py",
        "directconnect-export.py",
        "vpn-export.py",
        "transit-gateway-export.py",
        "api-gateway-export.py",
        "route-tables-export.py",
        "globalaccelerator-export.py",
        "network-resources.py",
        "network-manager-export.py",
    ],
    "Cost Management": [
        "budgets-export.py",
        "trusted-advisor-cost-optimization-export.py",
        "cost-anomaly-detection-export.py",
        "cost-categories-export.py",
        "cost-optimization-hub-export.py",
        "savings-plans-export.py",
        "billing-export.py",
        "reserved-instances-export.py",
    ],
    "Management & Monitoring": [
        "cloudwatch-export.py",
        "ssm-fleet-export.py",
        "organizations-export.py",
        "controltower-export.py",
        "service-catalog-export.py",
        "cloudformation-export.py",
        "compute-optimizer-export.py",
        "services-in-use-export.py",
        "health-export.py",
        "license-manager-export.py",
        "marketplace-export.py",
    ],
    "Analytics": [
        "glue-athena-export.py",
        "opensearch-export.py",
        "lakeformation-export.py",
    ],
    "Machine Learning": [
        "sagemaker-export.py",
        "bedrock-export.py",
        "comprehend-export.py",
        "rekognition-export.py",
    ],
    "Developer Tools": [
        "codecommit-export.py",
        "codebuild-export.py",
        "codedeploy-export.py",
        "codepipeline-export.py",
        "xray-export.py",
    ],
    "Application Integration": [
        "sqs-sns-export.py",
        "eventbridge-export.py",
        "stepfunctions-export.py",
    ],
    "Business Applications": [
        "ses-export.py",
        "ses-pinpoint-export.py",
        "connect-export.py",
    ],
}


def get_all_scripts() -> Set[str]:
    """Get a set of all unique script names from the mapping."""
    scripts = set()
    for script_list in SERVICE_SCRIPT_MAP.values():
        scripts.update(script_list)
    return scripts


def get_canonical_service_name(service_name: str) -> str:
    """
    Convert a service name to its canonical form.

    Args:
        service_name: Service name (may be an alias or variation)

    Returns:
        Canonical service name, or original if no alias found
    """
    # Try exact match first
    if service_name in SERVICE_SCRIPT_MAP:
        return service_name

    # Try case-insensitive lookup in aliases
    normalized = service_name.lower().strip()
    if normalized in SERVICE_ALIASES:
        return SERVICE_ALIASES[normalized]

    # Return original if no match
    return service_name


def get_scripts_for_service(service_name: str) -> List[str]:
    """
    Get export scripts for a given service name.

    Args:
        service_name: AWS service name (canonical or alias)

    Returns:
        List of export script filenames, empty list if service not found
    """
    canonical = get_canonical_service_name(service_name)
    return SERVICE_SCRIPT_MAP.get(canonical, [])


def get_category_for_script(script_name: str) -> str:
    """
    Get the category for a given script.

    Args:
        script_name: Export script filename

    Returns:
        Category name, or "Other" if not categorized
    """
    for category, scripts in SCRIPT_CATEGORIES.items():
        if script_name in scripts:
            return category
    return "Other"


def validate_script_mappings(scripts_dir: Path = None) -> Dict[str, List[str]]:
    """
    Validate that all scripts referenced in SERVICE_SCRIPT_MAP exist on disk.

    Logs a warning for each script referenced in the map that cannot be found
    in the scripts directory. This function is safe to call at import time.

    Args:
        scripts_dir: Path to the scripts directory. If None, resolves relative
                     to this file's grandparent (i.e., stratusscan-cli/scripts/).

    Returns:
        Dict with keys 'missing' and 'found', each containing a list of
        script filenames.
    """
    if scripts_dir is None:
        # mapping.py lives at scripts/smart_scan/mapping.py
        # so the scripts dir is two levels up from this file
        scripts_dir = Path(__file__).parent.parent

    result: Dict[str, List[str]] = {"missing": [], "found": []}

    for script in get_all_scripts():
        script_path = scripts_dir / script
        if script_path.exists():
            result["found"].append(script)
        else:
            result["missing"].append(script)
            logger.warning(
                "SERVICE_SCRIPT_MAP references script that does not exist on disk: %s "
                "(expected at %s)",
                script,
                script_path,
            )

    if result["missing"]:
        logger.warning(
            "validate_script_mappings: %d script(s) missing from disk out of %d mapped. "
            "These entries will not produce results during smart scan.",
            len(result["missing"]),
            len(result["found"]) + len(result["missing"]),
        )
    else:
        logger.debug(
            "validate_script_mappings: all %d mapped scripts found on disk.",
            len(result["found"]),
        )

    return result


# Run validation at import time so stale mappings surface immediately in logs.
# This is a non-fatal check — warnings are emitted but execution continues.
_validation_result = validate_script_mappings()
