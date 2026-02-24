#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS DataSync Comprehensive Export Script
Date: NOV-13-2025

Description:
This script exports comprehensive AWS DataSync information including tasks, locations,
agents, and execution history across all selected regions. All data is consolidated
into a single Excel workbook with multiple sheets for comprehensive analysis.

Features:
- Multi-region scanning with progress tracking
- Task configuration and status export
- Location details (S3, EFS, FSx, NFS, SMB, HDFS, Object Storage)
- Agent status and connectivity monitoring
- Recent execution history (last 30 days)
- Summary analytics and status breakdowns
- Error handling with AWS partition awareness
"""

import sys
import datetime
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

utils.setup_logging('datasync-export')


def format_bytes_human_readable(bytes_value: int) -> str:
    """
    Format bytes to human-readable format (GB, TB).

    Args:
        bytes_value: Number of bytes

    Returns:
        str: Formatted string (e.g., "1.23 GB")
    """
    if bytes_value == 0:
        return "0 B"

    # Convert to GB or TB for DataSync-scale operations
    gb_value = bytes_value / (1024 ** 3)

    if gb_value < 1024:
        return f"{gb_value:.2f} GB"
    else:
        tb_value = gb_value / 1024
        return f"{tb_value:.2f} TB"

def determine_location_type(location_arn: str) -> str:
    """
    Determine location type from ARN pattern.

    Args:
        location_arn: DataSync location ARN

    Returns:
        str: Location type identifier
    """
    # ARN format: arn:aws:datasync:region:account:location/loc-xxxxx
    # Type is not directly in ARN, need to use describe operations
    return "Unknown"

@utils.aws_error_handler("Collecting DataSync tasks", default_return=[])
def collect_datasync_tasks(region: str) -> List[Dict[str, Any]]:
    """
    Collect all DataSync tasks in a region.

    Args:
        region: AWS region name

    Returns:
        List of task dictionaries with detailed information
    """
    datasync = utils.get_boto3_client('datasync', region_name=region)
    tasks_data = []

    try:
        # List all tasks with pagination
        paginator = datasync.get_paginator('list_tasks')

        # Count tasks first
        task_arns = []
        for page in paginator.paginate():
            task_arns.extend([task['TaskArn'] for task in page.get('Tasks', [])])

        total_tasks = len(task_arns)
        if total_tasks == 0:
            utils.log_info(f"No DataSync tasks found in {region}")
            return tasks_data

        utils.log_info(f"Found {total_tasks} DataSync tasks in {region}")

        # Process each task
        for idx, task_arn in enumerate(task_arns, 1):
            progress = (idx / total_tasks) * 100
            utils.log_info(f"[{progress:.1f}%] Processing task {idx}/{total_tasks} in {region}")

            try:
                # Get detailed task information
                task_details = datasync.describe_task(TaskArn=task_arn)

                # Extract task name from tags
                task_name = 'N/A'
                if 'Tags' in task_details:
                    for tag in task_details['Tags']:
                        if tag['Key'] == 'Name':
                            task_name = tag['Value']
                            break

                # Parse schedule if present
                schedule = task_details.get('Schedule', {})
                schedule_expression = schedule.get('ScheduleExpression', 'None')

                # Parse options
                options = task_details.get('Options', {})

                # Get filter rules
                includes = task_details.get('Includes', [])
                excludes = task_details.get('Excludes', [])
                filter_summary = f"Includes: {len(includes)}, Excludes: {len(excludes)}"

                task_data = {
                    'Task Name': task_name,
                    'Task ARN': task_arn,
                    'Status': task_details.get('Status', 'N/A'),
                    'Source Location ARN': task_details.get('SourceLocationArn', 'N/A'),
                    'Destination Location ARN': task_details.get('DestinationLocationArn', 'N/A'),
                    'Schedule': schedule_expression,
                    'CloudWatch Log Group': task_details.get('CloudWatchLogGroupArn', 'N/A'),
                    'Current Status': task_details.get('CurrentTaskExecutionArn', 'N/A'),
                    'Creation Time': task_details.get('CreationTime', 'N/A'),
                    'Verify Mode': options.get('VerifyMode', 'N/A'),
                    'Overwrite Mode': options.get('OverwriteMode', 'N/A'),
                    'Atime': options.get('Atime', 'N/A'),
                    'Mtime': options.get('Mtime', 'N/A'),
                    'UID': options.get('Uid', 'N/A'),
                    'GID': options.get('Gid', 'N/A'),
                    'Preserve Deleted Files': options.get('PreserveDeletedFiles', 'N/A'),
                    'Filter Rules': filter_summary,
                    'Region': region
                }

                tasks_data.append(task_data)

            except Exception as e:
                utils.log_warning(f"Error processing task {task_arn} in {region}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error listing tasks in {region}", e)

    return tasks_data

@utils.aws_error_handler("Collecting DataSync locations", default_return=[])
def collect_datasync_locations(region: str) -> List[Dict[str, Any]]:
    """
    Collect all DataSync locations in a region.

    Args:
        region: AWS region name

    Returns:
        List of location dictionaries with detailed information
    """
    datasync = utils.get_boto3_client('datasync', region_name=region)
    locations_data = []

    try:
        # List all locations with pagination
        paginator = datasync.get_paginator('list_locations')

        # Collect all location ARNs
        location_arns = []
        for page in paginator.paginate():
            location_arns.extend([loc['LocationArn'] for loc in page.get('Locations', [])])

        total_locations = len(location_arns)
        if total_locations == 0:
            utils.log_info(f"No DataSync locations found in {region}")
            return locations_data

        utils.log_info(f"Found {total_locations} DataSync locations in {region}")

        # Process each location
        for idx, location_arn in enumerate(location_arns, 1):
            progress = (idx / total_locations) * 100
            utils.log_info(f"[{progress:.1f}%] Processing location {idx}/{total_locations} in {region}")

            try:
                # Determine location type from ARN and describe accordingly
                location_type = 'Unknown'
                location_uri = 'N/A'
                location_config = {}

                # Try each location type's describe operation
                # S3
                try:
                    s3_details = datasync.describe_location_s3(LocationArn=location_arn)
                    location_type = 'S3'
                    location_uri = s3_details.get('LocationUri', 'N/A')
                    location_config = {
                        'Bucket ARN': s3_details.get('S3BucketArn', 'N/A'),
                        'Storage Class': s3_details.get('S3StorageClass', 'N/A'),
                        'Subdirectory': s3_details.get('Subdirectory', 'N/A')
                    }
                except Exception:
                    pass  # intentional: probe both location types

                # EFS
                if location_type == 'Unknown':
                    try:
                        efs_details = datasync.describe_location_efs(LocationArn=location_arn)
                        location_type = 'EFS'
                        location_uri = efs_details.get('LocationUri', 'N/A')
                        location_config = {
                            'EFS ARN': efs_details.get('EfsFilesystemArn', 'N/A'),
                            'Subdirectory': efs_details.get('Subdirectory', 'N/A'),
                            'Subnet ARN': efs_details.get('Ec2Config', {}).get('SubnetArn', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # FSx Windows
                if location_type == 'Unknown':
                    try:
                        fsx_details = datasync.describe_location_fsx_windows(LocationArn=location_arn)
                        location_type = 'FSx-Windows'
                        location_uri = fsx_details.get('LocationUri', 'N/A')
                        location_config = {
                            'FSx ARN': fsx_details.get('FsxFilesystemArn', 'N/A'),
                            'Subdirectory': fsx_details.get('Subdirectory', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # FSx Lustre
                if location_type == 'Unknown':
                    try:
                        fsx_details = datasync.describe_location_fsx_lustre(LocationArn=location_arn)
                        location_type = 'FSx-Lustre'
                        location_uri = fsx_details.get('LocationUri', 'N/A')
                        location_config = {
                            'FSx ARN': fsx_details.get('FsxFilesystemArn', 'N/A'),
                            'Subdirectory': fsx_details.get('Subdirectory', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # FSx OpenZFS
                if location_type == 'Unknown':
                    try:
                        fsx_details = datasync.describe_location_fsx_open_zfs(LocationArn=location_arn)
                        location_type = 'FSx-OpenZFS'
                        location_uri = fsx_details.get('LocationUri', 'N/A')
                        location_config = {
                            'FSx ARN': fsx_details.get('FsxFilesystemArn', 'N/A'),
                            'Subdirectory': fsx_details.get('Subdirectory', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # FSx ONTAP
                if location_type == 'Unknown':
                    try:
                        fsx_details = datasync.describe_location_fsx_ontap(LocationArn=location_arn)
                        location_type = 'FSx-ONTAP'
                        location_uri = fsx_details.get('LocationUri', 'N/A')
                        location_config = {
                            'FSx ARN': fsx_details.get('FsxFilesystemArn', 'N/A'),
                            'Subdirectory': fsx_details.get('Subdirectory', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # NFS
                if location_type == 'Unknown':
                    try:
                        nfs_details = datasync.describe_location_nfs(LocationArn=location_arn)
                        location_type = 'NFS'
                        location_uri = nfs_details.get('LocationUri', 'N/A')
                        on_prem_config = nfs_details.get('OnPremConfig', {})
                        location_config = {
                            'Server Hostname': nfs_details.get('LocationUri', 'N/A').split('://')[1].split('/')[0] if '://' in nfs_details.get('LocationUri', '') else 'N/A',
                            'Subdirectory': nfs_details.get('Subdirectory', 'N/A'),
                            'Agent ARNs': ', '.join(on_prem_config.get('AgentArns', []))
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # SMB
                if location_type == 'Unknown':
                    try:
                        smb_details = datasync.describe_location_smb(LocationArn=location_arn)
                        location_type = 'SMB'
                        location_uri = smb_details.get('LocationUri', 'N/A')
                        location_config = {
                            'Server Hostname': smb_details.get('LocationUri', 'N/A').split('://')[1].split('/')[0] if '://' in smb_details.get('LocationUri', '') else 'N/A',
                            'Subdirectory': smb_details.get('Subdirectory', 'N/A'),
                            'User': smb_details.get('User', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # HDFS
                if location_type == 'Unknown':
                    try:
                        hdfs_details = datasync.describe_location_hdfs(LocationArn=location_arn)
                        location_type = 'HDFS'
                        location_uri = hdfs_details.get('LocationUri', 'N/A')
                        location_config = {
                            'Authentication Type': hdfs_details.get('AuthenticationType', 'N/A'),
                            'NameNodes': str(len(hdfs_details.get('NameNodes', [])))
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # Object Storage
                if location_type == 'Unknown':
                    try:
                        obj_details = datasync.describe_location_object_storage(LocationArn=location_arn)
                        location_type = 'Object Storage'
                        location_uri = obj_details.get('LocationUri', 'N/A')
                        location_config = {
                            'Server Hostname': obj_details.get('ServerHostname', 'N/A'),
                            'Server Port': obj_details.get('ServerPort', 'N/A')
                        }
                    except Exception:
                        pass  # intentional: probe both location types

                # Build location data
                location_data = {
                    'Location ARN': location_arn,
                    'Location Type': location_type,
                    'Location URI': location_uri,
                    'Region': region,
                    'Creation Time': location_config.get('CreationTime', 'N/A')
                }

                # Add type-specific config
                for key, value in location_config.items():
                    if key != 'CreationTime':
                        location_data[key] = value

                locations_data.append(location_data)

            except Exception as e:
                utils.log_warning(f"Error processing location {location_arn} in {region}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error listing locations in {region}", e)

    return locations_data

@utils.aws_error_handler("Collecting DataSync agents", default_return=[])
def collect_datasync_agents(region: str) -> List[Dict[str, Any]]:
    """
    Collect all DataSync agents in a region.

    Args:
        region: AWS region name

    Returns:
        List of agent dictionaries with detailed information
    """
    datasync = utils.get_boto3_client('datasync', region_name=region)
    agents_data = []

    try:
        # List all agents with pagination
        paginator = datasync.get_paginator('list_agents')

        # Collect all agent ARNs
        agent_arns = []
        for page in paginator.paginate():
            agent_arns.extend([agent['AgentArn'] for agent in page.get('Agents', [])])

        total_agents = len(agent_arns)
        if total_agents == 0:
            utils.log_info(f"No DataSync agents found in {region}")
            return agents_data

        utils.log_info(f"Found {total_agents} DataSync agents in {region}")

        # Process each agent
        for idx, agent_arn in enumerate(agent_arns, 1):
            progress = (idx / total_agents) * 100
            utils.log_info(f"[{progress:.1f}%] Processing agent {idx}/{total_agents} in {region}")

            try:
                # Get detailed agent information
                agent_details = datasync.describe_agent(AgentArn=agent_arn)

                # Extract agent name from tags
                agent_name = 'N/A'
                if 'Tags' in agent_details:
                    for tag in agent_details['Tags']:
                        if tag['Key'] == 'Name':
                            agent_name = tag['Value']
                            break

                # Parse platform info
                platform_info = agent_details.get('Platform', {})
                platform_version = platform_info.get('Version', 'N/A')

                # Parse private link config
                private_link_config = agent_details.get('PrivateLinkConfig', {})

                agent_data = {
                    'Agent Name': agent_name,
                    'Agent ARN': agent_arn,
                    'Status': agent_details.get('Status', 'N/A'),
                    'Endpoint Type': agent_details.get('EndpointType', 'N/A'),
                    'Last Heartbeat': agent_details.get('LastConnectionTime', 'N/A'),
                    'Creation Time': agent_details.get('CreationTime', 'N/A'),
                    'Platform Version': platform_version,
                    'VPC Endpoint ID': private_link_config.get('VpcEndpointId', 'N/A'),
                    'Private Link Subnet ARN': private_link_config.get('SubnetArns', ['N/A'])[0] if private_link_config.get('SubnetArns') else 'N/A',
                    'Region': region
                }

                agents_data.append(agent_data)

            except Exception as e:
                utils.log_warning(f"Error processing agent {agent_arn} in {region}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error listing agents in {region}", e)

    return agents_data

@utils.aws_error_handler("Collecting task executions", default_return=[])
def collect_task_executions(region: str, task_arns: List[str]) -> List[Dict[str, Any]]:
    """
    Collect recent task executions (last 30 days) for all tasks in a region.

    Args:
        region: AWS region name
        task_arns: List of task ARNs to query

    Returns:
        List of execution dictionaries with detailed information
    """
    datasync = utils.get_boto3_client('datasync', region_name=region)
    executions_data = []

    if not task_arns:
        utils.log_info(f"No task ARNs provided for execution history in {region}")
        return executions_data

    # Calculate 30 days ago
    thirty_days_ago = datetime.datetime.now() - datetime.timedelta(days=30)

    try:
        for task_arn in task_arns:
            try:
                # List executions for this task
                paginator = datasync.get_paginator('list_task_executions')

                for page in paginator.paginate(TaskArn=task_arn):
                    executions = page.get('TaskExecutions', [])

                    for execution in executions:
                        # Check if execution is within last 30 days
                        exec_arn = execution.get('TaskExecutionArn')
                        status = execution.get('Status', 'N/A')

                        # Get detailed execution info
                        try:
                            exec_details = datasync.describe_task_execution(TaskExecutionArn=exec_arn)

                            start_time = exec_details.get('StartTime')

                            # Skip if older than 30 days
                            if start_time and start_time.replace(tzinfo=None) < thirty_days_ago:
                                continue

                            result = exec_details.get('Result', {})

                            # Calculate duration if both times available
                            duration = 'N/A'
                            end_time = result.get('TransferDuration')
                            if end_time:
                                duration = f"{end_time // 3600}h {(end_time % 3600) // 60}m"

                            # Format bytes transferred
                            bytes_transferred = result.get('BytesTransferred', 0)
                            bytes_failed = result.get('BytesCompressed', 0)  # Using compressed as proxy for failed

                            execution_data = {
                                'Task Execution ARN': exec_arn,
                                'Task ARN': task_arn,
                                'Status': status,
                                'Start Time': start_time if start_time else 'N/A',
                                'Duration': duration,
                                'Files Transferred': result.get('FilesTransferred', 0),
                                'Bytes Transferred': format_bytes_human_readable(bytes_transferred),
                                'Files Failed': result.get('FilesDeleted', 0),  # Using deleted as proxy for failed
                                'Error Code': result.get('ErrorCode', 'None'),
                                'Error Detail': result.get('ErrorDetail', 'None'),
                                'Region': region
                            }

                            executions_data.append(execution_data)

                        except Exception as e:
                            utils.log_warning(f"Error getting execution details for {exec_arn}: {e}")
                            continue

            except Exception as e:
                utils.log_warning(f"Error listing executions for task {task_arn}: {e}")
                continue

        utils.log_info(f"Collected {len(executions_data)} task executions from last 30 days in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting task executions in {region}", e)

    return executions_data

def create_summary_data(tasks: List[Dict], locations: List[Dict],
                       agents: List[Dict], executions: List[Dict]) -> Dict[str, Any]:
    """
    Create summary statistics from collected data.

    Args:
        tasks: List of task dictionaries
        locations: List of location dictionaries
        agents: List of agent dictionaries
        executions: List of execution dictionaries

    Returns:
        Dictionary of summary data
    """
    summary = {
        'Category': [],
        'Count': []
    }

    # Task statistics
    summary['Category'].append('Total Tasks')
    summary['Count'].append(len(tasks))

    if tasks:
        summary['Category'].append('Tasks - AVAILABLE')
        summary['Count'].append(len([t for t in tasks if t.get('Status') == 'AVAILABLE']))

        summary['Category'].append('Tasks - With Schedule')
        summary['Count'].append(len([t for t in tasks if t.get('Schedule', 'None') != 'None']))

    summary['Category'].append('')
    summary['Count'].append('')

    # Location statistics
    summary['Category'].append('Total Locations')
    summary['Count'].append(len(locations))

    if locations:
        location_types = {}
        for loc in locations:
            loc_type = loc.get('Location Type', 'Unknown')
            location_types[loc_type] = location_types.get(loc_type, 0) + 1

        for loc_type, count in sorted(location_types.items()):
            summary['Category'].append(f'Locations - {loc_type}')
            summary['Count'].append(count)

    summary['Category'].append('')
    summary['Count'].append('')

    # Agent statistics
    summary['Category'].append('Total Agents')
    summary['Count'].append(len(agents))

    if agents:
        summary['Category'].append('Agents - ONLINE')
        summary['Count'].append(len([a for a in agents if a.get('Status') == 'ONLINE']))

        summary['Category'].append('Agents - OFFLINE')
        summary['Count'].append(len([a for a in agents if a.get('Status') == 'OFFLINE']))

    summary['Category'].append('')
    summary['Count'].append('')

    # Execution statistics (last 30 days)
    summary['Category'].append('Total Executions (30 days)')
    summary['Count'].append(len(executions))

    if executions:
        summary['Category'].append('Executions - SUCCESS')
        summary['Count'].append(len([e for e in executions if e.get('Status') == 'SUCCESS']))

        summary['Category'].append('Executions - ERROR')
        summary['Count'].append(len([e for e in executions if e.get('Status') == 'ERROR']))

        summary['Category'].append('Executions - In Progress')
        summary['Count'].append(len([e for e in executions if e.get('Status') in ['QUEUED', 'LAUNCHING', 'PREPARING', 'TRANSFERRING', 'VERIFYING']]))

    return summary


def _run_export(account_id: str, account_name: str, regions: List[str]) -> None:
    """Collect DataSync data and write the Excel export."""
    import pandas as pd

    utils.log_info(f"Scanning {len(regions)} region(s): {', '.join(regions)}")

    # Collect data from all regions
    all_tasks = []
    all_locations = []
    all_agents = []
    all_executions = []

    for region in regions:
        utils.log_info(f"Processing region: {region}")
        utils.log_section(f"DataSync data collection - {region}")

        # Collect tasks
        tasks = collect_datasync_tasks(region)
        all_tasks.extend(tasks)

        # Collect locations
        locations = collect_datasync_locations(region)
        all_locations.extend(locations)

        # Collect agents
        agents = collect_datasync_agents(region)
        all_agents.extend(agents)

        # Collect executions for tasks in this region
        task_arns = [t['Task ARN'] for t in tasks]
        if task_arns:
            executions = collect_task_executions(region, task_arns)
            all_executions.extend(executions)

    # Check if we have any data
    if not all_tasks and not all_locations and not all_agents:
        utils.log_warning("No DataSync resources found in any region. Exiting...")
        return

    utils.log_success(f"Collection complete:")
    utils.log_info(f"  Tasks: {len(all_tasks)}")
    utils.log_info(f"  Locations: {len(all_locations)}")
    utils.log_info(f"  Agents: {len(all_agents)}")
    utils.log_info(f"  Executions (30 days): {len(all_executions)}")

    # Create DataFrames
    utils.log_info("Preparing data for export...")

    dataframes = {}

    # Summary sheet
    summary_data = create_summary_data(all_tasks, all_locations, all_agents, all_executions)
    summary_df = pd.DataFrame(summary_data)
    dataframes['Summary'] = utils.prepare_dataframe_for_export(summary_df)

    # Tasks sheet
    if all_tasks:
        tasks_df = pd.DataFrame(all_tasks)
        dataframes['Tasks'] = utils.prepare_dataframe_for_export(tasks_df)

    # Locations sheet
    if all_locations:
        locations_df = pd.DataFrame(all_locations)
        dataframes['Locations'] = utils.prepare_dataframe_for_export(locations_df)

    # Agents sheet
    if all_agents:
        agents_df = pd.DataFrame(all_agents)
        dataframes['Agents'] = utils.prepare_dataframe_for_export(agents_df)

    # Recent Executions sheet
    if all_executions:
        executions_df = pd.DataFrame(all_executions)
        dataframes['Recent Executions'] = utils.prepare_dataframe_for_export(executions_df)

    # Active Tasks sheet (AVAILABLE status)
    active_tasks = [t for t in all_tasks if t.get('Status') == 'AVAILABLE']
    if active_tasks:
        active_tasks_df = pd.DataFrame(active_tasks)
        dataframes['Active Tasks'] = utils.prepare_dataframe_for_export(active_tasks_df)

    # Failed Executions sheet
    failed_executions = [e for e in all_executions if e.get('Status') == 'ERROR']
    if failed_executions:
        failed_df = pd.DataFrame(failed_executions)
        dataframes['Failed Executions'] = utils.prepare_dataframe_for_export(failed_df)

    # Generate filename
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    filename = utils.create_export_filename(
        account_name,
        "datasync",
        "all",
        current_date
    )

    # Export to Excel
    output_path = utils.save_multiple_dataframes_to_excel(dataframes, filename)

    if output_path:
        utils.log_success("AWS DataSync data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        utils.log_info(f"Export contains data from {len(regions)} region(s)")
        utils.log_info(f"Total sheets: {len(dataframes)}")
        print("\nScript execution completed.")
    else:
        utils.log_error("Error exporting data. Please check the logs.")
        sys.exit(1)


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
            return

        account_id, account_name = utils.print_script_banner("AWS DATASYNC COMPREHENSIVE EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="DataSync")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export DataSync data ({region_str})."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                _run_export(account_id, account_name, regions)
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
