#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Auto Scaling Groups Export Tool
Version: v0.1.0
Date: NOV-15-2025

Description:
This script exports AWS Auto Scaling Group information from all regions into an Excel file with
multiple worksheets. The output includes Auto Scaling Group configurations, instances,
launch configurations/templates, scaling policies, and scheduled actions.

Features:
- Auto Scaling Group overview with desired/min/max capacity
- Instance information with health status and lifecycle state
- Launch Configurations and Launch Templates
- Scaling policies (target tracking, step scaling, simple scaling)
- Scheduled actions
- Lifecycle hooks
- Tags and metadata

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()

    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))

    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

# Initialize logging
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("autoscaling-export")
utils.log_script_start("autoscaling-export.py", "AWS Auto Scaling Groups Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("          AWS AUTO SCALING GROUPS EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-09-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get the current AWS account ID
    try:
        sts_client = utils.get_boto3_client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print("Could not determine account information.")
        utils.log_error("Error getting account information", e)
        account_id = "unknown"
        account_name = "unknown"

    print("====================================================================")
    return account_id, account_name


def get_aws_regions():
    """Get a list of available AWS regions for the current partition."""
    try:
        # Get partition-aware regions
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


@utils.aws_error_handler("Collecting Auto Scaling Groups", default_return=[])
def collect_autoscaling_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Auto Scaling Group information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with Auto Scaling Group information
    """
    all_asgs = []

    for region in regions:
        if not utils.validate_aws_region(region):
            utils.log_error(f"Skipping invalid AWS region: {region}")
            continue

        print(f"\nProcessing region: {region}")

        try:
            asg_client = utils.get_boto3_client('autoscaling', region_name=region)

            # Get Auto Scaling Groups
            paginator = asg_client.get_paginator('describe_auto_scaling_groups')
            asg_count = 0

            for page in paginator.paginate():
                asgs = page.get('AutoScalingGroups', [])
                asg_count += len(asgs)

                for asg in asgs:
                    asg_name = asg.get('AutoScalingGroupName', '')
                    print(f"  Processing ASG: {asg_name}")

                    # Basic information
                    asg_arn = asg.get('AutoScalingGroupARN', '')
                    min_size = asg.get('MinSize', 0)
                    max_size = asg.get('MaxSize', 0)
                    desired_capacity = asg.get('DesiredCapacity', 0)
                    default_cooldown = asg.get('DefaultCooldown', 0)
                    health_check_type = asg.get('HealthCheckType', 'N/A')
                    health_check_grace_period = asg.get('HealthCheckGracePeriod', 0)

                    # Launch configuration or template
                    launch_config_name = asg.get('LaunchConfigurationName', 'N/A')
                    launch_template = asg.get('LaunchTemplate', {})
                    mixed_instances_policy = asg.get('MixedInstancesPolicy', {})

                    if launch_template:
                        launch_source = f"LT: {launch_template.get('LaunchTemplateName', '')} ({launch_template.get('Version', '')})"
                    elif mixed_instances_policy:
                        lt_spec = mixed_instances_policy.get('LaunchTemplate', {}).get('LaunchTemplateSpecification', {})
                        launch_source = f"Mixed: {lt_spec.get('LaunchTemplateName', '')} ({lt_spec.get('Version', '')})"
                    else:
                        launch_source = f"LC: {launch_config_name}"

                    # VPC and subnets
                    vpc_zone_identifier = asg.get('VPCZoneIdentifier', '')
                    subnet_ids = vpc_zone_identifier.split(',') if vpc_zone_identifier else []
                    subnet_count = len(subnet_ids)
                    availability_zones = asg.get('AvailabilityZones', [])
                    az_list = ', '.join(availability_zones) if availability_zones else 'N/A'

                    # Load balancers
                    load_balancer_names = asg.get('LoadBalancerNames', [])
                    target_group_arns = asg.get('TargetGroupARNs', [])
                    lb_count = len(load_balancer_names) + len(target_group_arns)

                    # Instance information
                    instances = asg.get('Instances', [])
                    instance_count = len(instances)
                    healthy_count = sum(1 for i in instances if i.get('HealthStatus') == 'Healthy')
                    unhealthy_count = instance_count - healthy_count

                    # Service-linked role
                    service_linked_role_arn = asg.get('ServiceLinkedRoleARN', 'N/A')

                    # New instances protected from scale in
                    new_instances_protected = asg.get('NewInstancesProtectedFromScaleIn', False)

                    # Capacity rebalance
                    capacity_rebalance = asg.get('CapacityRebalance', False)

                    # Creation time
                    created_time = asg.get('CreatedTime', '')
                    if created_time:
                        created_time = created_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_time, datetime.datetime) else str(created_time)

                    # Tags
                    tags = asg.get('Tags', [])
                    tag_dict = {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
                    tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                    all_asgs.append({
                        'Region': region,
                        'ASG Name': asg_name,
                        'Min Size': min_size,
                        'Max Size': max_size,
                        'Desired Capacity': desired_capacity,
                        'Current Instances': instance_count,
                        'Healthy Instances': healthy_count,
                        'Unhealthy Instances': unhealthy_count,
                        'Launch Source': launch_source,
                        'Availability Zones': az_list,
                        'Subnet Count': subnet_count,
                        'Load Balancer Count': lb_count,
                        'Health Check Type': health_check_type,
                        'Health Check Grace Period (s)': health_check_grace_period,
                        'Default Cooldown (s)': default_cooldown,
                        'New Instance Protection': new_instances_protected,
                        'Capacity Rebalance': capacity_rebalance,
                        'Service Linked Role': service_linked_role_arn,
                        'Created Time': created_time,
                        'Tags': tags_str,
                        'ASG ARN': asg_arn
                    })

            print(f"  Found {asg_count} Auto Scaling Groups")

        except Exception as e:
            utils.log_error(f"Error processing region {region} for Auto Scaling Groups", e)

    return all_asgs


@utils.aws_error_handler("Collecting ASG instances", default_return=[])
def collect_asg_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect instance information from Auto Scaling Groups.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with instance information
    """
    all_instances = []

    for region in regions:
        if not utils.validate_aws_region(region):
            continue

        print(f"\nProcessing region: {region}")

        try:
            asg_client = utils.get_boto3_client('autoscaling', region_name=region)
            paginator = asg_client.get_paginator('describe_auto_scaling_groups')

            for page in paginator.paginate():
                asgs = page.get('AutoScalingGroups', [])

                for asg in asgs:
                    asg_name = asg.get('AutoScalingGroupName', '')
                    instances = asg.get('Instances', [])

                    for instance in instances:
                        instance_id = instance.get('InstanceId', '')
                        az = instance.get('AvailabilityZone', '')
                        lifecycle_state = instance.get('LifecycleState', '')
                        health_status = instance.get('HealthStatus', '')
                        launch_config_name = instance.get('LaunchConfigurationName', 'N/A')
                        launch_template = instance.get('LaunchTemplate', {})

                        if launch_template:
                            launch_source = f"LT: {launch_template.get('LaunchTemplateName', '')} ({launch_template.get('Version', '')})"
                        else:
                            launch_source = f"LC: {launch_config_name}"

                        protected_from_scale_in = instance.get('ProtectedFromScaleIn', False)

                        all_instances.append({
                            'Region': region,
                            'ASG Name': asg_name,
                            'Instance ID': instance_id,
                            'Availability Zone': az,
                            'Lifecycle State': lifecycle_state,
                            'Health Status': health_status,
                            'Launch Source': launch_source,
                            'Protected from Scale In': protected_from_scale_in
                        })

        except Exception as e:
            utils.log_error(f"Error collecting instances in region {region}", e)

    return all_instances


@utils.aws_error_handler("Collecting scaling policies", default_return=[])
def collect_scaling_policies(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect scaling policy information from Auto Scaling Groups.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with scaling policy information
    """
    all_policies = []

    for region in regions:
        if not utils.validate_aws_region(region):
            continue

        print(f"\nProcessing region: {region}")

        try:
            asg_client = utils.get_boto3_client('autoscaling', region_name=region)
            paginator = asg_client.get_paginator('describe_policies')

            for page in paginator.paginate():
                policies = page.get('ScalingPolicies', [])

                for policy in policies:
                    policy_name = policy.get('PolicyName', '')
                    asg_name = policy.get('AutoScalingGroupName', '')
                    policy_type = policy.get('PolicyType', '')
                    adjustment_type = policy.get('AdjustmentType', 'N/A')
                    scaling_adjustment = policy.get('ScalingAdjustment', 'N/A')
                    cooldown = policy.get('Cooldown', 'N/A')
                    metric_aggregation_type = policy.get('MetricAggregationType', 'N/A')

                    # Target tracking configuration
                    target_tracking_config = policy.get('TargetTrackingConfiguration', {})
                    if target_tracking_config:
                        target_value = target_tracking_config.get('TargetValue', 'N/A')
                        predefined_metric = target_tracking_config.get('PredefinedMetricSpecification', {})
                        custom_metric = target_tracking_config.get('CustomizedMetricSpecification', {})

                        if predefined_metric:
                            metric_type = predefined_metric.get('PredefinedMetricType', 'N/A')
                            policy_detail = f"Target: {target_value}, Metric: {metric_type}"
                        elif custom_metric:
                            metric_name = custom_metric.get('MetricName', 'N/A')
                            namespace = custom_metric.get('Namespace', 'N/A')
                            policy_detail = f"Target: {target_value}, Custom: {namespace}/{metric_name}"
                        else:
                            policy_detail = f"Target: {target_value}"
                    else:
                        policy_detail = f"Adjustment: {scaling_adjustment}, Type: {adjustment_type}"

                    # Enabled status
                    enabled = policy.get('Enabled', True)

                    all_policies.append({
                        'Region': region,
                        'ASG Name': asg_name,
                        'Policy Name': policy_name,
                        'Policy Type': policy_type,
                        'Policy Detail': policy_detail,
                        'Metric Aggregation': metric_aggregation_type,
                        'Cooldown (s)': cooldown,
                        'Enabled': enabled
                    })

        except Exception as e:
            utils.log_error(f"Error collecting scaling policies in region {region}", e)

    return all_policies


def export_autoscaling_data(account_id: str, account_name: str):
    """
    Export Auto Scaling Group information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition and set partition-aware example regions
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = get_aws_regions()
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        # Default regions
        regions = default_regions
        region_text = f"default AWS regions ({len(regions)} regions)"
        region_suffix = ""
    elif selection_int == 2:
        # All regions
        regions = all_available_regions
        region_text = f"all AWS regions ({len(regions)} regions)"
        region_suffix = ""
    else:  # selection_int == 3
        # Specific region - show numbered list
        print()
        print("=" * 68)
        print("AVAILABLE REGIONS")
        print("=" * 68)
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx}. {region}")
        print()

        while True:
            try:
                region_choice = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_choice) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_text = f"AWS region {selected_region}"
                    region_suffix = f"-{selected_region}"
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print("Please enter a valid number.")

    print(f"\nStarting Auto Scaling export process for {region_text}...")
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Auto Scaling Groups (Phase 4B: concurrent)
    print("\n=== COLLECTING AUTO SCALING GROUPS ===")
    asg_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: collect_autoscaling_groups([r]),
        show_progress=True
    )
    asgs = []
    for result in asg_results:
        asgs.extend(result)
    utils.log_success(f"Total Auto Scaling Groups collected: {len(asgs)}")
    if asgs:
        data_frames['Auto Scaling Groups'] = pd.DataFrame(asgs)

    # STEP 2: Collect instances (Phase 4B: concurrent)
    print("\n=== COLLECTING AUTO SCALING GROUP INSTANCES ===")
    instance_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: collect_asg_instances([r]),
        show_progress=True
    )
    instances = []
    for result in instance_results:
        instances.extend(result)
    utils.log_success(f"Total ASG instances collected: {len(instances)}")
    if instances:
        data_frames['Instances'] = pd.DataFrame(instances)

    # STEP 3: Collect scaling policies (Phase 4B: concurrent)
    print("\n=== COLLECTING SCALING POLICIES ===")
    policy_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: collect_scaling_policies([r]),
        show_progress=True
    )
    policies = []
    for result in policy_results:
        policies.extend(result)
    utils.log_success(f"Total scaling policies collected: {len(policies)}")
    if policies:
        data_frames['Scaling Policies'] = pd.DataFrame(policies)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Auto Scaling Group data was collected. Nothing to export.")
        print("\nNo Auto Scaling Groups found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'autoscaling',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Auto Scaling data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    """Main function to execute the script."""
    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Export Auto Scaling data
        export_autoscaling_data(account_id, account_name)

        print("\nAuto Scaling export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("autoscaling-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
