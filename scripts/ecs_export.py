#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS ECS Resource Export Script
Date: NOV-16-2025

Description:
This script exports AWS ECS (Elastic Container Service) resources including clusters,
services, tasks, and container details across all regions. The data is exported to
an Excel spreadsheet with detailed information about ECS deployments.

Features:
- Comprehensive ECS resource collection (clusters, services, tasks, containers)
- Multi-region scanning with automatic region detection
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
- Export to Excel with detailed container and networking information

Exported information includes: Cluster Name, Service Name, Task Definition, Task Family,
Task Revision, Task Status, Launch Type, Desired Task Count, Running Task Count,
CPU Allocation, Memory Allocation, Container Name, Image Used, Port Mappings,
ELB Target Group, Network Mode, Subnet IDs, Security Groups, IAM Role, and Creation Date.
"""

import datetime
import sys
from pathlib import Path
from typing import Any

from botocore.exceptions import EndpointConnectionError

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
args = utils.parse_script_args("Export ECS clusters, services, and tasks to Excel")
@utils.aws_error_handler("Getting account information", default_return=("UNKNOWN", "UNKNOWN-ACCOUNT"))
def get_account_info():
    """
    Get the current AWS account ID and name.

    Returns:
        tuple: account_id, account_name
    """
    # Create a STS client
    sts_client = utils.get_boto3_client('sts')

    # Get the account ID
    account_id = sts_client.get_caller_identity()["Account"]

    # Map to account name using utils
    account_name = utils.get_account_name(account_id, default=account_id)

    return account_id, account_name

@utils.aws_error_handler("Getting AWS regions", default_return=[
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ca-central-1', 'eu-west-1', 'eu-west-2', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-south-1',
    'sa-east-1'
])
def get_all_regions():
    """
    Get a list of all available AWS regions.

    Returns:
        list: List of region names
    """
    # Create EC2 client to get regions
    ec2_client = utils.get_boto3_client('ec2')

    # Get all regions
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions

@utils.aws_error_handler("Getting task definition details", default_return={})
def get_task_definition_details(ecs_client, task_definition_arn):
    """
    Get details for a specific task definition.

    Args:
        ecs_client: The boto3 ECS client
        task_definition_arn: The task definition ARN

    Returns:
        dict: Task definition details
    """
    response = ecs_client.describe_task_definition(taskDefinition=task_definition_arn)
    return response['taskDefinition']

@utils.aws_error_handler("Getting target group info", default_return={})
def get_target_group_info(elbv2_client, target_group_arn):
    """
    Get details for a specific target group.

    Args:
        elbv2_client: The boto3 ELBv2 client
        target_group_arn: The target group ARN

    Returns:
        dict: Target group details
    """
    response = elbv2_client.describe_target_groups(TargetGroupArns=[target_group_arn])
    if response and 'TargetGroups' in response and response['TargetGroups']:
        return response['TargetGroups'][0]
    return {}

@utils.aws_error_handler("Getting load balancer name", default_return='Unknown')
def get_load_balancer_name(elbv2_client, load_balancer_arn):
    """
    Get the name of a load balancer from its ARN.

    Args:
        elbv2_client: The boto3 ELBv2 client
        load_balancer_arn: The load balancer ARN

    Returns:
        str: The load balancer name
    """
    response = elbv2_client.describe_load_balancers(LoadBalancerArns=[load_balancer_arn])
    if response and 'LoadBalancers' in response and response['LoadBalancers']:
        return response['LoadBalancers'][0].get('LoadBalancerName', 'Unknown')
    return 'Unknown'

def _build_service_context(ecs_client, elbv2_client, service: dict) -> dict[str, Any]:
    """
    Derive the shared per-service fields used by both row builders below.

    Every field is read with ``.get()`` and a safe default so a service
    entry missing an expected key cannot raise a ``KeyError`` here.
    """
    service_name = service.get('serviceName', 'Unknown')
    task_definition_arn = service.get('taskDefinition', 'N/A')
    task_def = get_task_definition_details(ecs_client, task_definition_arn)

    task_family = task_def.get('family', 'Unknown')
    task_revision = task_def.get('revision', 'Unknown')
    cpu_allocation = task_def.get('cpu', 'Unknown')
    memory_allocation = task_def.get('memory', 'Unknown')
    network_mode = task_def.get('networkMode', 'Unknown')

    # Get the IAM role
    execution_role_arn = task_def.get('executionRoleArn', 'None')
    task_role_arn = task_def.get('taskRoleArn', 'None')

    # Extract role name from ARN
    execution_role_name = execution_role_arn.split('/')[-1] if execution_role_arn != 'None' else 'None'
    task_role_name = task_role_arn.split('/')[-1] if task_role_arn != 'None' else 'None'

    # Format roles
    iam_roles = []
    if execution_role_name != 'None':
        iam_roles.append(f"Execution: {execution_role_name}")
    if task_role_name != 'None':
        iam_roles.append(f"Task: {task_role_name}")

    iam_role = ", ".join(iam_roles) if iam_roles else "None"

    # Get launch type
    if 'launchType' in service:
        launch_type = service.get('launchType', 'Unknown')
    elif service.get('capacityProviderStrategy'):
        provider = service['capacityProviderStrategy'][0].get('capacityProvider', 'Unknown')
        launch_type = 'FARGATE' if 'FARGATE' in provider else f"CapacityProvider: {provider}"
    else:
        launch_type = 'Unknown'

    # Get desired and running count
    desired_count = service.get('desiredCount', 0)
    running_count = service.get('runningCount', 0)

    # Get creation time
    created_at = service.get('createdAt', datetime.datetime.now())
    if isinstance(created_at, datetime.datetime):
        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

    # Get load balancer info if available
    elb_target_groups = []
    for lb in service.get('loadBalancers', []) or []:
        target_group_arn = lb.get('targetGroupArn')
        if not target_group_arn:
            continue
        target_group = get_target_group_info(elbv2_client, target_group_arn)
        lb_arns = target_group.get('LoadBalancerArns') if target_group else None

        if target_group and target_group.get('TargetGroupName') and lb_arns:
            lb_name = get_load_balancer_name(elbv2_client, lb_arns[0])
            elb_target_groups.append(f"{lb_name}:{target_group.get('TargetGroupName')}")
        else:
            elb_target_groups.append(target_group_arn.split('/')[-1] if target_group_arn else 'Unknown')

    elb_target_group = ', '.join(elb_target_groups) if elb_target_groups else 'None'

    # Get network configuration if available
    subnet_ids = []
    security_groups = []
    network_configuration = service.get('networkConfiguration', {}) or {}
    vpc_config = network_configuration.get('awsvpcConfiguration')
    if vpc_config:
        subnet_ids = vpc_config.get('subnets', [])
        security_groups = vpc_config.get('securityGroups', [])

    return {
        'service_name': service_name,
        'task_definition_arn': task_definition_arn,
        'task_def': task_def,
        'task_family': task_family,
        'task_revision': task_revision,
        'cpu_allocation': cpu_allocation,
        'memory_allocation': memory_allocation,
        'network_mode': network_mode,
        'iam_role': iam_role,
        'launch_type': launch_type,
        'desired_count': desired_count,
        'running_count': running_count,
        'created_at': created_at,
        'elb_target_group': elb_target_group,
        'subnet_ids': subnet_ids,
        'security_groups': security_groups,
    }


def _build_service_no_tasks_row(cluster_name: str, context: dict) -> dict[str, Any]:
    """Build the export row for a service that currently has no running tasks."""
    subnet_ids = context['subnet_ids']
    security_groups = context['security_groups']

    return {
        'Cluster Name': cluster_name,
        'Service Name': context['service_name'],
        'Task Definition': context['task_definition_arn'].split('/')[-1],
        'Task Family': context['task_family'],
        'Task Revision': context['task_revision'],
        'Task Status': 'No Running Tasks',
        'Launch Type': context['launch_type'],
        'Desired Task Count': context['desired_count'],
        'Running Task Count': context['running_count'],
        'CPU Allocation': context['cpu_allocation'],
        'Memory Allocation': context['memory_allocation'],
        'Container Name': 'N/A',
        'Image Used': 'N/A',
        'Port Mappings': 'N/A',
        'ELB Target Group': context['elb_target_group'],
        'Network Mode': context['network_mode'],
        'Subnet IDs': ', '.join(subnet_ids) if subnet_ids else 'None',
        'Security Groups': ', '.join(security_groups) if security_groups else 'None',
        'IAM Role': context['iam_role'],
        'Created At': context['created_at']
    }


def _build_container_row(cluster_name: str, context: dict, task: dict, container: dict) -> dict[str, Any]:
    """Build the export row for a single container within a running task."""
    task_def = context['task_def']
    container_name = container.get('name', 'Unknown')
    container_image = container.get('image', 'Unknown')

    # Get container definition for port mappings
    container_def = None
    for c in task_def.get('containerDefinitions', []):
        if c.get('name') == container_name:
            container_def = c
            break

    # Extract port mappings
    port_mappings = []
    if container_def and container_def.get('portMappings'):
        for pm in container_def['portMappings']:
            host_port = pm.get('hostPort', 'Auto')
            container_port = pm.get('containerPort', 'Unknown')
            protocol = pm.get('protocol', 'tcp')
            port_mappings.append(f"{container_port}:{host_port}/{protocol}")

    subnet_ids = context['subnet_ids']
    security_groups = context['security_groups']

    return {
        'Cluster Name': cluster_name,
        'Service Name': context['service_name'],
        'Task Definition': context['task_definition_arn'].split('/')[-1],
        'Task Family': context['task_family'],
        'Task Revision': context['task_revision'],
        'Task Status': task.get('lastStatus', 'Unknown'),
        'Launch Type': task.get('launchType', context['launch_type']),
        'Desired Task Count': context['desired_count'],
        'Running Task Count': context['running_count'],
        'CPU Allocation': context['cpu_allocation'],
        'Memory Allocation': context['memory_allocation'],
        'Container Name': container_name,
        'Image Used': container_image,
        'Port Mappings': ', '.join(port_mappings) if port_mappings else 'None',
        'ELB Target Group': context['elb_target_group'],
        'Network Mode': context['network_mode'],
        'Subnet IDs': ', '.join(subnet_ids) if subnet_ids else 'None',
        'Security Groups': ', '.join(security_groups) if security_groups else 'None',
        'IAM Role': context['iam_role'],
        'Created At': context['created_at']
    }


def _build_cluster_rows(ecs_client, elbv2_client, cluster_arn: str, region: str) -> list[dict[str, Any]]:
    """
    Build all export rows (service/task/container entries) for a single cluster.

    Left to raise on error — the caller (``_scan_ecs_region``) wraps each
    cluster in try/except so one malformed cluster is skipped without losing
    the rest of the region's clusters.
    """
    rows: list[dict[str, Any]] = []

    # Get cluster details
    cluster_response = ecs_client.describe_clusters(
        clusters=[cluster_arn],
        include=['SETTINGS', 'CONFIGURATIONS', 'TAGS']
    )

    if not cluster_response['clusters']:
        return rows

    cluster = cluster_response['clusters'][0]
    cluster_name = cluster.get('clusterName', 'Unknown')

    # Get all services in this cluster
    service_arns = []
    services_paginator = ecs_client.get_paginator('list_services')
    for page in services_paginator.paginate(cluster=cluster_arn):
        service_arns.extend(page['serviceArns'])

    if not service_arns:
        print(f"    No services found in cluster {cluster_name}")
        return rows

    print(f"    Found {len(service_arns)} services in cluster {cluster_name}")

    # Process services in batches (describe_services has a limit of 10 services per call)
    for j in range(0, len(service_arns), 10):
        service_batch = service_arns[j:j + 10]

        service_response = ecs_client.describe_services(
            cluster=cluster_arn,
            services=service_batch,
            include=['TAGS']
        )

        for service in service_response['services']:
            service_name = service.get('serviceName', 'Unknown')
            print(f"      Processing service: {service_name}")

            context = _build_service_context(ecs_client, elbv2_client, service)

            # Get tasks for this service to get task status
            task_arns = []
            tasks_paginator = ecs_client.get_paginator('list_tasks')
            for page in tasks_paginator.paginate(cluster=cluster_arn, serviceName=service_name):
                task_arns.extend(page['taskArns'])

            # If there are no tasks, we still want to show the service
            if not task_arns:
                rows.append(_build_service_no_tasks_row(cluster_name, context))
                continue

            # Get details for each task
            for k in range(0, len(task_arns), 100):  # describe_tasks has a limit of 100 tasks per call
                task_batch = task_arns[k:k + 100]

                task_response = ecs_client.describe_tasks(
                    cluster=cluster_arn,
                    tasks=task_batch
                )

                for task in task_response['tasks']:
                    for container in task.get('containers', []):
                        rows.append(_build_container_row(cluster_name, context, task, container))

    return rows


def _scan_ecs_region(region: str) -> list[dict[str, Any]]:
    """
    Collect ECS resources (clusters/services/tasks/containers) from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no ECS resources" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    A single malformed cluster is skipped (logged) rather than aborting the
    whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nCollecting ECS information in region: {region}")
    ecs_resources: list[dict[str, Any]] = []

    ecs_client = utils.get_boto3_client('ecs', region_name=region)
    elbv2_client = utils.get_boto3_client('elbv2', region_name=region)

    # Get all ECS clusters
    cluster_arns = []
    paginator = ecs_client.get_paginator('list_clusters')
    for page in paginator.paginate():
        cluster_arns.extend(page['clusterArns'])

    if not cluster_arns:
        print(f"  No ECS clusters found in {region}")
        return []

    print(f"  Found {len(cluster_arns)} ECS clusters")

    # Get details for each cluster
    for i, cluster_arn in enumerate(cluster_arns, 1):
        print(f"  Processing cluster {i}/{len(cluster_arns)}: {cluster_arn.split('/')[-1]}")

        try:
            ecs_resources.extend(_build_cluster_rows(ecs_client, elbv2_client, cluster_arn, region))
        except Exception as e:
            # One malformed cluster is skipped, not fatal to the region.
            utils.log_error(f"Skipping malformed ECS cluster in {region}: {cluster_arn}", e)
            continue

    return ecs_resources


def get_ecs_resources(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect ECS resource information across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Args:
        regions: List of AWS region names to scan

    Returns:
        tuple: ``(all_resources, failed_regions)`` where ``failed_regions`` is
        a list of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING ECS RESOURCES ===")
    utils.log_info(f"Scanning {len(regions)} regions...")

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_ecs_region,
        show_progress=True,
        collect_failures=True,
    )

    all_resources = []
    for resources_in_region in region_results:
        all_resources.extend(resources_in_region)

    utils.log_success(f"Total ECS resources collected: {len(all_resources)}")
    return all_resources, failed_regions

def get_standalone_tasks_from_region(region: str) -> list[dict[str, Any]]:
    """
    Collect ECS tasks not managed by a service (one-off / scheduled tasks) from a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with standalone task information
    """
    standalone_tasks = []

    if not utils.is_aws_region(region):
        return standalone_tasks

    try:
        ecs_client = utils.get_boto3_client('ecs', region_name=region)

        # List all clusters
        cluster_arns = []
        paginator = ecs_client.get_paginator('list_clusters')
        for page in paginator.paginate():
            cluster_arns.extend(page.get('clusterArns', []))

        for cluster_arn in cluster_arns:
            cluster_name = cluster_arn.split('/')[-1]

            # Get all task ARNs in this cluster (all statuses)
            all_task_arns = []
            for status in ('RUNNING', 'STOPPED'):
                try:
                    task_paginator = ecs_client.get_paginator('list_tasks')
                    for page in task_paginator.paginate(cluster=cluster_arn, desiredStatus=status):
                        all_task_arns.extend(page.get('taskArns', []))
                except Exception:
                    pass

            # Describe in batches of 100
            for i in range(0, len(all_task_arns), 100):
                batch = all_task_arns[i:i + 100]
                try:
                    response = ecs_client.describe_tasks(cluster=cluster_arn, tasks=batch)
                    for task in response.get('tasks', []):
                        group = task.get('group', '')
                        # Service-managed tasks have group = "service:<name>"
                        if group.startswith('service:'):
                            continue

                        standalone_tasks.append({
                            'Region': region,
                            'Cluster Name': cluster_name,
                            'Task ARN': task.get('taskArn', ''),
                            'Task Definition': task.get('taskDefinitionArn', '').split('/')[-1],
                            'Group': group,
                            'Status': task.get('lastStatus', ''),
                            'Desired Status': task.get('desiredStatus', ''),
                            'Launch Type': task.get('launchType', ''),
                            'Started By': task.get('startedBy', ''),
                            'Created At': str(task.get('createdAt', '')),
                            'Started At': str(task.get('startedAt', '')),
                            'Stopped At': str(task.get('stoppedAt', '')),
                            'Stop Code': task.get('stopCode', ''),
                            'Stopped Reason': task.get('stoppedReason', ''),
                            'CPU': task.get('cpu', ''),
                            'Memory': task.get('memory', ''),
                        })
                except Exception as e:
                    utils.log_error(f"Error describing tasks in {cluster_name}/{region}", e)

    except EndpointConnectionError:
        pass
    except Exception as e:
        utils.log_error(f"Error collecting standalone ECS tasks in {region}", e)

    return standalone_tasks


def get_standalone_tasks(regions: list[str]) -> list[dict[str, Any]]:
    """
    Collect standalone ECS tasks from multiple regions concurrently.

    Args:
        regions: List of AWS region names to scan

    Returns:
        list: Combined list of standalone tasks from all regions
    """
    print("\n=== COLLECTING ECS STANDALONE TASKS ===")
    utils.log_info(f"Scanning {len(regions)} regions for standalone tasks...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=get_standalone_tasks_from_region,
        show_progress=True
    )

    all_tasks = [task for tasks_in_region in region_results for task in tasks_in_region]

    utils.log_success(f"Total standalone ECS tasks collected: {len(all_tasks)}")
    return all_tasks


def main():
    """
    Main function to coordinate the ECS export process.
    """
    try:
        # Print the script title and get account information
        utils.setup_logging("ecs-export")
        account_id, account_name = utils.print_script_banner("AWS ECS (ELASTIC CONTAINER SERVICE) RESOURCE EXPORT")

        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Import pandas after checking dependencies
        import pandas as pd

        regions = utils.prompt_region_selection()

        # Primary scope: region failures must propagate as failed_regions,
        # never collapse into "empty" (see silent-collection-failure audit).
        all_ecs_resources, failed_regions = get_ecs_resources(regions)
        standalone_tasks = get_standalone_tasks(regions)

        # Build multi-sheet export
        data_frames = {}
        if all_ecs_resources:
            data_frames['Service Tasks'] = pd.DataFrame(all_ecs_resources)
        if standalone_tasks:
            data_frames['Standalone Tasks'] = pd.DataFrame(standalone_tasks)

        # Create export filename using utils
        filename = utils.create_export_filename(account_name, "ecs-resources", "all")

        # A workbook always lands, even when nothing was collected — PRESERVED
        # from the pre-fix behavior (Tier-3 PARTIAL class).
        if data_frames:
            output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)
        else:
            output_path = utils.save_dataframe_to_excel(pd.DataFrame(), filename)

        if output_path:
            print("\nExport completed successfully!")
            print(f"File saved as: {output_path}")
            print(f"Total service-linked ECS resources: {len(all_ecs_resources)}")
            print(f"Total standalone ECS tasks: {len(standalone_tasks)}")
        else:
            print("\nError exporting data to Excel.")

        # If ANY region failed the primary ECS resource scope collection,
        # make it loud: write a marker and exit non-zero, even though a
        # workbook was still written above. A partial export that looks
        # complete is exactly the failure mode this guards against.
        if failed_regions:
            utils.report_collection_failures(account_name, 'ecs-resources', failed_regions)
            print(
                "\nERROR: ECS export completed with failures — data is incomplete. "
                "See the *-ecs-resources-FAILED-*.txt marker in the output directory."
            )
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
