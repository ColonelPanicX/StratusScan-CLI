#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Compute Optimizer Recommendations Export
Version: v1.0.0
Date: MAR-05-2025

Description:
This script exports AWS Compute Optimizer recommendations for EC2 instances, 
Auto Scaling groups, EBS volumes, Lambda functions, and ECS services on Fargate.
The data is exported to an Excel file with separate tabs for each recommendation type.
"""

import os
import sys
import boto3
import datetime
import json
import pandas as pd
from botocore.exceptions import ClientError
from pathlib import Path

# Add path to import utils module
try:
    # Try to import directly (if utils.py is in Python path)
    import utils
except ImportError:
    # If import fails, try to find the module relative to this script
    script_dir = Path(__file__).parent.absolute()
    
    # Check if we're in the scripts directory
    if script_dir.name.lower() == 'scripts':
        # Add the parent directory (StratusScan root) to the path
        sys.path.append(str(script_dir.parent))
    else:
        # Add the current directory to the path
        sys.path.append(str(script_dir))
    
    # Try import again
    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

def check_dependencies():
    """
    Check if required dependencies are installed and offer to install them if missing.
    """
    required_packages = ['pandas', 'openpyxl', 'boto3']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} is already installed")
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\nPackages required but not installed: {', '.join(missing_packages)}")
        response = input("Would you like to install these packages now? (y/n): ").lower()
        
        if response == 'y':
            import subprocess
            for package in missing_packages:
                print(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    print(f"✓ Successfully installed {package}")
                except Exception as e:
                    print(f"Error installing {package}: {e}")
                    print("Please install it manually with: pip install " + package)
                    return False
            return True
        else:
            print("Cannot proceed without required dependencies.")
            return False
    
    return True

def print_title():
    """
    Print the script title banner and get account info.
    
    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                              ")
    print("====================================================================")
    print("AWS COMPUTE OPTIMIZER RECOMMENDATIONS EXPORT TOOL")
    print("====================================================================")
    print("Version: v1.0.0                                Date: MAR-05-2025")
    print("====================================================================")
    
    # Get the current AWS account ID
    try:
        # Create a new STS client to get the current account ID
        sts_client = utils.get_boto3_client('sts')
        # Get account ID from caller identity
        account_id = sts_client.get_caller_identity()['Account']
        # Map the account ID to an account name using utils module
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print(f"Could not determine account information: {e}")
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"
    
    print("====================================================================")
    return account_id, account_name

@utils.aws_error_handler("Getting available regions", default_return=[
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ca-central-1', 'eu-west-1', 'eu-west-2', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-south-1'
])
def get_all_regions():
    """
    Get a list of all available AWS regions.

    Returns:
        list: List of region names
    """
    ec2_client = utils.get_boto3_client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions

@utils.aws_error_handler("Checking Compute Optimizer availability", default_return=False)
def check_compute_optimizer_availability(region):
    """
    Check if Compute Optimizer is available and has recommendations in the specified region.

    Args:
        region (str): AWS region name

    Returns:
        bool: True if Compute Optimizer is available, False otherwise
    """
    compute_optimizer = utils.get_boto3_client('compute-optimizer', region_name=region)
    enrollment = compute_optimizer.get_enrollment_status()
    status = enrollment.get('status', 'NOT_ENROLLED')

    if status == 'ACTIVE':
        print(f"Compute Optimizer is enrolled and active in {region}")
        return True
    else:
        print(f"Compute Optimizer is not active in {region} (Status: {status})")
        return False

@utils.aws_error_handler("Fetching EC2 instance recommendations", default_return=[])
def get_ec2_recommendations(region):
    """
    Get EC2 instance recommendations from Compute Optimizer.

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries containing EC2 recommendations
    """
    utils.log_info(f"Fetching EC2 instance recommendations for region {region}")
    recommendations = []

    compute_optimizer = utils.get_boto3_client('compute-optimizer', region_name=region)

    # Use pagination to handle large number of recommendations
    paginator = compute_optimizer.get_paginator('get_ec2_instance_recommendations')

    for page in paginator.paginate():
        for recommendation in page.get('instanceRecommendations', []):
            current_instance = recommendation.get('currentInstanceType', 'Unknown')
            instance_id = recommendation.get('instanceArn', 'Unknown').split('/')[-1]

            # Process recommendation options
            rec_options = recommendation.get('recommendationOptions', [])
            if rec_options:
                top_recommendation = rec_options[0]
                recommended_type = top_recommendation.get('instanceType', 'Unknown')
                savings_opportunity = top_recommendation.get('savingsOpportunity', {})
                savings_percentage = savings_opportunity.get('savingsPercentage', 0) * 100
                estimated_monthly_savings = savings_opportunity.get('estimatedMonthlySavings', {}).get('value', 0)
                performance_risk = top_recommendation.get('performanceRisk', 'Unknown')
            else:
                recommended_type = 'No recommendation'
                savings_percentage = 0
                estimated_monthly_savings = 0
                performance_risk = 'Unknown'

            # Get utilization metrics
            metrics = recommendation.get('utilizationMetrics', [])
            cpu_utilization = next((m.get('value') for m in metrics if m.get('name') == 'CPU'), 0)
            memory_utilization = next((m.get('value') for m in metrics if m.get('name') == 'MEMORY'), 0)

            # Create recommendation entry
            rec_entry = {
                'Region': region,
                'Instance ID': instance_id,
                'Current Instance Type': current_instance,
                'Recommended Instance Type': recommended_type,
                'Finding': recommendation.get('finding', 'Unknown'),
                'Performance Risk': performance_risk,
                'CPU Utilization (%)': cpu_utilization,
                'Memory Utilization (%)': memory_utilization,
                'Savings Percentage (%)': round(savings_percentage, 2),
                'Estimated Monthly Savings ($)': round(estimated_monthly_savings, 2),
                'Reason': recommendation.get('findingReasonCodes', ['Unknown'])[0] if recommendation.get('findingReasonCodes') else 'Unknown'
            }

            recommendations.append(rec_entry)

    utils.log_success(f"Found {len(recommendations)} EC2 instance recommendations in {region}")
    return recommendations

@utils.aws_error_handler("Fetching Auto Scaling Group recommendations", default_return=[])
def get_asg_recommendations(region):
    """
    Get Auto Scaling Group recommendations from Compute Optimizer.

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries containing ASG recommendations
    """
    utils.log_info(f"Fetching Auto Scaling Group recommendations for region {region}")
    recommendations = []

    compute_optimizer = utils.get_boto3_client('compute-optimizer', region_name=region)

    # Use pagination to handle large number of recommendations
    paginator = compute_optimizer.get_paginator('get_auto_scaling_group_recommendations')

    for page in paginator.paginate():
        for recommendation in page.get('autoScalingGroupRecommendations', []):
            asg_name = recommendation.get('autoScalingGroupName', 'Unknown')
            current_instances = recommendation.get('currentInstanceType', ['Unknown'])

            # Process recommendation options
            rec_options = recommendation.get('recommendationOptions', [])
            if rec_options:
                top_recommendation = rec_options[0]
                recommended_types = top_recommendation.get('instanceType', ['Unknown'])
                savings_opportunity = top_recommendation.get('savingsOpportunity', {})
                savings_percentage = savings_opportunity.get('savingsPercentage', 0) * 100
                estimated_monthly_savings = savings_opportunity.get('estimatedMonthlySavings', {}).get('value', 0)
                projected_utilization = top_recommendation.get('projectedUtilizationMetrics', [])
            else:
                recommended_types = ['No recommendation']
                savings_percentage = 0
                estimated_monthly_savings = 0
                projected_utilization = []

            # Get current configuration
            current_config = recommendation.get('currentConfiguration', {})
            min_size = current_config.get('desiredCapacity', 'Unknown')
            max_size = current_config.get('maxSize', 'Unknown')

            # Create recommendation entry
            rec_entry = {
                'Region': region,
                'Auto Scaling Group Name': asg_name,
                'Current Instance Types': ', '.join(current_instances),
                'Recommended Instance Types': ', '.join(recommended_types),
                'Desired Capacity': min_size,
                'Max Size': max_size,
                'Finding': recommendation.get('finding', 'Unknown'),
                'Savings Percentage (%)': round(savings_percentage, 2),
                'Estimated Monthly Savings ($)': round(estimated_monthly_savings, 2),
                'Reason': recommendation.get('findingReasonCodes', ['Unknown'])[0] if recommendation.get('findingReasonCodes') else 'Unknown'
            }

            recommendations.append(rec_entry)

    utils.log_success(f"Found {len(recommendations)} Auto Scaling Group recommendations in {region}")
    return recommendations

@utils.aws_error_handler("Fetching EBS volume recommendations", default_return=[])
def get_ebs_recommendations(region):
    """
    Get EBS volume recommendations from Compute Optimizer.

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries containing EBS recommendations
    """
    utils.log_info(f"Fetching EBS volume recommendations for region {region}")
    recommendations = []

    compute_optimizer = utils.get_boto3_client('compute-optimizer', region_name=region)

    # Use pagination to handle large number of recommendations
    paginator = compute_optimizer.get_paginator('get_ebs_volume_recommendations')

    for page in paginator.paginate():
        for recommendation in page.get('volumeRecommendations', []):
            volume_arn = recommendation.get('volumeArn', 'Unknown')
            volume_id = volume_arn.split('/')[-1]
            current_config = recommendation.get('currentConfiguration', {})
            current_volume_type = current_config.get('volumeType', 'Unknown')
            current_volume_size = current_config.get('volumeSize', 0)
            current_volume_iops = current_config.get('volumeBaselineIOPS', 0)

            # Process recommendation options
            rec_options = recommendation.get('volumeRecommendationOptions', [])
            if rec_options:
                top_recommendation = rec_options[0]
                recommended_config = top_recommendation.get('configuration', {})
                recommended_type = recommended_config.get('volumeType', 'Unknown')
                recommended_size = recommended_config.get('volumeSize', 0)
                recommended_iops = recommended_config.get('volumeBaselineIOPS', 0)
                savings_opportunity = top_recommendation.get('savingsOpportunity', {})
                savings_percentage = savings_opportunity.get('savingsPercentage', 0) * 100
                estimated_monthly_savings = savings_opportunity.get('estimatedMonthlySavings', {}).get('value', 0)
            else:
                recommended_type = 'No recommendation'
                recommended_size = current_volume_size
                recommended_iops = current_volume_iops
                savings_percentage = 0
                estimated_monthly_savings = 0

            # Get utilization metrics
            if 'utilizationMetrics' in recommendation:
                metrics = recommendation.get('utilizationMetrics', [])
                read_ops_per_second = next((m.get('value') for m in metrics if m.get('name') == 'VolumeReadOpsPerSecond'), 0)
                write_ops_per_second = next((m.get('value') for m in metrics if m.get('name') == 'VolumeWriteOpsPerSecond'), 0)
            else:
                read_ops_per_second = 0
                write_ops_per_second = 0

            # Create recommendation entry
            rec_entry = {
                'Region': region,
                'Volume ID': volume_id,
                'Current Volume Type': current_volume_type,
                'Current Size (GB)': current_volume_size,
                'Current IOPS': current_volume_iops,
                'Recommended Volume Type': recommended_type,
                'Recommended Size (GB)': recommended_size,
                'Recommended IOPS': recommended_iops,
                'Read Ops/Sec': read_ops_per_second,
                'Write Ops/Sec': write_ops_per_second,
                'Finding': recommendation.get('finding', 'Unknown'),
                'Savings Percentage (%)': round(savings_percentage, 2),
                'Estimated Monthly Savings ($)': round(estimated_monthly_savings, 2),
                'Reason': recommendation.get('findingReasonCodes', ['Unknown'])[0] if recommendation.get('findingReasonCodes') else 'Unknown'
            }

            recommendations.append(rec_entry)

    utils.log_success(f"Found {len(recommendations)} EBS volume recommendations in {region}")
    return recommendations

@utils.aws_error_handler("Fetching Lambda function recommendations", default_return=[])
def get_lambda_recommendations(region):
    """
    Get Lambda function recommendations from Compute Optimizer.

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries containing Lambda recommendations
    """
    utils.log_info(f"Fetching Lambda function recommendations for region {region}")
    recommendations = []

    compute_optimizer = utils.get_boto3_client('compute-optimizer', region_name=region)

    # Use pagination to handle large number of recommendations
    paginator = compute_optimizer.get_paginator('get_lambda_function_recommendations')

    for page in paginator.paginate():
        for recommendation in page.get('lambdaFunctionRecommendations', []):
            function_arn = recommendation.get('functionArn', 'Unknown')
            function_name = function_arn.split(':')[-1]

            # Get current configuration
            current_config = recommendation.get('currentConfiguration', {})
            current_memory = current_config.get('memorySize', 0)

            # Process recommendation options
            rec_options = recommendation.get('functionRecommendationOptions', [])
            if rec_options:
                top_recommendation = rec_options[0]
                recommended_config = top_recommendation.get('configuration', {})
                recommended_memory = recommended_config.get('memorySize', 0)
                savings_opportunity = top_recommendation.get('savingsOpportunity', {})
                savings_percentage = savings_opportunity.get('savingsPercentage', 0) * 100
                estimated_monthly_savings = savings_opportunity.get('estimatedMonthlySavings', {}).get('value', 0)
            else:
                recommended_memory = current_memory
                savings_percentage = 0
                estimated_monthly_savings = 0

            # Get utilization metrics
            metrics = recommendation.get('utilizationMetrics', [])
            memory_utilization = next((m.get('value') for m in metrics if m.get('name') == 'Memory'), 0)

            # Create recommendation entry
            rec_entry = {
                'Region': region,
                'Function Name': function_name,
                'Current Memory (MB)': current_memory,
                'Recommended Memory (MB)': recommended_memory,
                'Memory Utilization (%)': memory_utilization,
                'Finding': recommendation.get('finding', 'Unknown'),
                'Savings Percentage (%)': round(savings_percentage, 2),
                'Estimated Monthly Savings ($)': round(estimated_monthly_savings, 2),
                'Last Invocation Time': recommendation.get('lastRefreshTimestamp', 'Unknown')
            }

            recommendations.append(rec_entry)

    utils.log_success(f"Found {len(recommendations)} Lambda function recommendations in {region}")
    return recommendations

@utils.aws_error_handler("Fetching ECS service recommendations", default_return=[])
def get_ecs_recommendations(region):
    """
    Get ECS service recommendations from Compute Optimizer.

    Args:
        region (str): AWS region name

    Returns:
        list: List of dictionaries containing ECS recommendations
    """
    utils.log_info(f"Fetching ECS service recommendations for region {region}")
    recommendations = []

    compute_optimizer = utils.get_boto3_client('compute-optimizer', region_name=region)

    # Use pagination to handle large number of recommendations
    paginator = compute_optimizer.get_paginator('get_ecs_service_recommendations')

    for page in paginator.paginate():
        for recommendation in page.get('ecsServiceRecommendations', []):
            service_arn = recommendation.get('serviceArn', 'Unknown')
            service_name = service_arn.split('/')[-1]
            cluster_name = service_arn.split('/')[-2]

            # Get current configuration
            current_config = recommendation.get('currentServiceConfiguration', {})
            current_cpu = current_config.get('cpu', 'Unknown')
            current_memory = current_config.get('memory', 'Unknown')

            # Process recommendation options
            rec_options = recommendation.get('serviceRecommendationOptions', [])
            if rec_options:
                top_recommendation = rec_options[0]
                recommended_config = top_recommendation.get('serviceConfiguration', {})
                recommended_cpu = recommended_config.get('cpu', 'Unknown')
                recommended_memory = recommended_config.get('memory', 'Unknown')
                savings_opportunity = top_recommendation.get('savingsOpportunity', {})
                savings_percentage = savings_opportunity.get('savingsPercentage', 0) * 100
                estimated_monthly_savings = savings_opportunity.get('estimatedMonthlySavings', {}).get('value', 0)
            else:
                recommended_cpu = current_cpu
                recommended_memory = current_memory
                savings_percentage = 0
                estimated_monthly_savings = 0

            # Get utilization metrics
            metrics = recommendation.get('utilizationMetrics', [])
            cpu_utilization = next((m.get('value') for m in metrics if m.get('name') == 'CPU'), 0)
            memory_utilization = next((m.get('value') for m in metrics if m.get('name') == 'MEMORY'), 0)

            # Create recommendation entry
            rec_entry = {
                'Region': region,
                'Cluster Name': cluster_name,
                'Service Name': service_name,
                'Current CPU': current_cpu,
                'Current Memory': current_memory,
                'Recommended CPU': recommended_cpu,
                'Recommended Memory': recommended_memory,
                'CPU Utilization (%)': cpu_utilization,
                'Memory Utilization (%)': memory_utilization,
                'Finding': recommendation.get('finding', 'Unknown'),
                'Savings Percentage (%)': round(savings_percentage, 2),
                'Estimated Monthly Savings ($)': round(estimated_monthly_savings, 2),
                'Reason': recommendation.get('findingReasonCodes', ['Unknown'])[0] if recommendation.get('findingReasonCodes') else 'Unknown'
            }

            recommendations.append(rec_entry)

    utils.log_success(f"Found {len(recommendations)} ECS service recommendations in {region}")
    return recommendations

def export_recommendations_to_excel(all_recommendations, account_name):
    """
    Export recommendations to an Excel file with separate tabs for each resource type.
    
    Args:
        all_recommendations (dict): Dictionary containing recommendations for each resource type
        account_name (str): AWS account name for file naming
        
    Returns:
        str: Path to the created Excel file
    """
    # Create DataFrames for each resource type
    dfs = {}
    
    # Check if there are any recommendations for each resource type
    if all_recommendations.get('EC2'):
        dfs['EC2 Instances'] = pd.DataFrame(all_recommendations['EC2'])
    
    if all_recommendations.get('ASG'):
        dfs['Auto Scaling Groups'] = pd.DataFrame(all_recommendations['ASG'])
    
    if all_recommendations.get('EBS'):
        dfs['EBS Volumes'] = pd.DataFrame(all_recommendations['EBS'])
    
    if all_recommendations.get('Lambda'):
        dfs['Lambda Functions'] = pd.DataFrame(all_recommendations['Lambda'])
    
    if all_recommendations.get('ECS'):
        dfs['ECS Services'] = pd.DataFrame(all_recommendations['ECS'])
    
    # If no recommendations found for any resource type
    if not dfs:
        print("No recommendations found for any resource type.")
        return None
    
    # Generate filename with current date
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    
    # Use utils module to generate filename
    filename = utils.create_export_filename(
        account_name, 
        "compute-optimizer", 
        "", 
        current_date
    )
    
    # Use utils module to save multiple DataFrames to Excel
    output_path = utils.save_multiple_dataframes_to_excel(dfs, filename)
    
    if output_path:
        print(f"\nRecommendations exported successfully to: {output_path}")
        return output_path
    else:
        print("Error exporting recommendations to Excel.")
        return None

def get_recommendations_for_all_regions():
    """
    Get Compute Optimizer recommendations for all supported regions.
    
    Returns:
        dict: Dictionary containing recommendations for each resource type
    """
    # Dictionary to store recommendations for each resource type
    all_recommendations = {
        'EC2': [],
        'ASG': [],
        'EBS': [],
        'Lambda': [],
        'ECS': []
    }
    
    # Get all available regions
    regions = get_all_regions()
    print(f"Found {len(regions)} AWS regions.")
    
    # For each region, check if Compute Optimizer is available and get recommendations
    for region in regions:
        print(f"\nChecking Compute Optimizer availability in region: {region}")
        
        if check_compute_optimizer_availability(region):
            # Get recommendations for each resource type
            ec2_recommendations = get_ec2_recommendations(region)
            all_recommendations['EC2'].extend(ec2_recommendations)
            
            asg_recommendations = get_asg_recommendations(region)
            all_recommendations['ASG'].extend(asg_recommendations)
            
            ebs_recommendations = get_ebs_recommendations(region)
            all_recommendations['EBS'].extend(ebs_recommendations)
            
            lambda_recommendations = get_lambda_recommendations(region)
            all_recommendations['Lambda'].extend(lambda_recommendations)
            
            ecs_recommendations = get_ecs_recommendations(region)
            all_recommendations['ECS'].extend(ecs_recommendations)
    
    # Print summary
    print("\n=== RECOMMENDATIONS SUMMARY ===")
    print(f"EC2 Instance recommendations: {len(all_recommendations['EC2'])}")
    print(f"Auto Scaling Group recommendations: {len(all_recommendations['ASG'])}")
    print(f"EBS Volume recommendations: {len(all_recommendations['EBS'])}")
    print(f"Lambda Function recommendations: {len(all_recommendations['Lambda'])}")
    print(f"ECS Service recommendations: {len(all_recommendations['ECS'])}")
    
    return all_recommendations

def main():
    """
    Main function to run the script.
    """
    try:
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)

        # Print title and get account info
        account_id, account_name = print_title()

        # Validate AWS credentials
        try:
            # Test AWS credentials
            sts = utils.get_boto3_client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")

        except Exception as e:
            utils.log_error("AWS credentials not found or invalid. Please configure your credentials.")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return

        # Check if Compute Optimizer is enabled
        print("\n" + "="*70)
        print("IMPORTANT: AWS Compute Optimizer must be opted-in to get recommendations.")
        print("Visit the AWS Compute Optimizer console to enable it if not already enabled.")
        print("="*70)

        confirm = input("\nHave you enabled Compute Optimizer? (y/n): ").lower()
        if confirm != 'y':
            print("Please enable Compute Optimizer first, then run this script again.")
            return

        # Get recommendations for all regions
        print("\nGetting AWS Compute Optimizer recommendations...")
        utils.log_info("Starting Compute Optimizer recommendations collection")
        all_recommendations = get_recommendations_for_all_regions()

        # Export recommendations to Excel
        print("\nExporting recommendations to Excel...")
        output_path = export_recommendations_to_excel(all_recommendations, account_name)

        if output_path:
            print("\nExport completed successfully!")
            print(f"Recommendations exported to: {output_path}")
            utils.log_success(f"Compute Optimizer recommendations exported to: {output_path}")
        else:
            print("\nNo recommendations were exported. Please check if Compute Optimizer is enabled for your account.")
            utils.log_warning("No Compute Optimizer recommendations found")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An error occurred during script execution", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
