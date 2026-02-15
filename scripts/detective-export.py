#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Detective Information Collection Script
Version: v1.1.0
Date: NOV-16-2025

Description:
This script collects comprehensive AWS Detective information from AWS environments
including behavior graphs, member accounts, invitations, data sources, and security
indicators. The data is exported to an Excel spreadsheet with multiple sheets for
complete security investigation capability analysis.

Collected information includes: Detective graphs, member accounts, pending invitations,
data source configurations, volume metrics, and overall investigation capability summary.

Features:
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)

Prerequisites:
- AWS Detective must be enabled in the target account
- Requires IAM permissions: detective:ListGraphs, detective:ListMembers, detective:ListInvitations,
  detective:GetMembers, detective:DescribeOrganizationConfiguration
- Regional service - scans multiple regions
"""

import os
import sys
import boto3
import datetime
import time
from pathlib import Path
from typing import List, Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError

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


def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS DETECTIVE INFORMATION COLLECTION")
    print("====================================================================")
    print("Version: v1.1.0                       Date: NOV-16-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information
    account_id, account_name = utils.get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name


@utils.aws_error_handler("Collecting Detective graphs", default_return=[])
def collect_graphs(region: str) -> List[Dict[str, Any]]:
    """
    Collect Detective graphs from a specific region.

    Args:
        region: AWS region to collect graphs from

    Returns:
        list: List of graph information dictionaries
    """
    graphs_data = []
    client = utils.get_boto3_client('detective', region_name=region)

    try:
        # List graphs
        response = client.list_graphs()
        graphs = response.get('GraphList', [])

        if not graphs:
            utils.log_info(f"No Detective graphs found in {region}")
            return []

        utils.log_info(f"Found {len(graphs)} Detective graph(s) in {region}")

        for graph in graphs:
            graph_arn = graph.get('Arn', 'N/A')

            # Get member count by listing members
            member_count = 0
            try:
                members_response = client.list_members(GraphArn=graph_arn)
                member_count = len(members_response.get('MemberDetails', []))
            except Exception as e:
                utils.log_debug(f"Could not get member count for graph {graph_arn}: {e}")

            graph_info = {
                'Region': region,
                'Graph ARN': graph_arn,
                'Created Time': graph.get('CreatedTime', 'N/A'),
                'Status': 'Active',  # Graphs returned by list_graphs are active
                'Member Count': member_count,
                'Tags': format_tags(graph_arn, client)
            }

            graphs_data.append(graph_info)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            utils.log_warning(f"Detective not available or access denied in {region}")
        else:
            utils.log_error(f"Error collecting Detective graphs from {region}: {error_code}")

    return graphs_data


@utils.aws_error_handler("Collecting Detective members", default_return=[])
def collect_members(region: str, graph_arn: str) -> List[Dict[str, Any]]:
    """
    Collect member accounts for a Detective graph.

    Args:
        region: AWS region
        graph_arn: Graph ARN to get members for

    Returns:
        list: List of member information dictionaries
    """
    members_data = []
    client = utils.get_boto3_client('detective', region_name=region)

    try:
        # List members using paginator
        paginator = client.get_paginator('list_members')

        for page in paginator.paginate(GraphArn=graph_arn):
            members = page.get('MemberDetails', [])

            for member in members:
                member_info = {
                    'Region': region,
                    'Graph ARN': graph_arn,
                    'Account ID': member.get('AccountId', 'N/A'),
                    'Email': member.get('EmailAddress', 'N/A'),
                    'Administrator Account ID': member.get('AdministratorId', 'N/A'),
                    'Status': member.get('Status', 'N/A'),
                    'Disabled Reason': member.get('DisabledReason', 'N/A'),
                    'Invited Time': member.get('InvitedTime', 'N/A'),
                    'Updated Time': member.get('UpdatedTime', 'N/A'),
                    'Volume Usage (GB)': calculate_volume_gb(member.get('VolumeUsageInBytes', 0)),
                    'Percent of Graph Volume': f"{member.get('PercentOfGraphUtilization', 0):.2f}%",
                    'Volume Updated Time': member.get('VolumeUsageUpdatedTime', 'N/A')
                }

                members_data.append(member_info)

    except Exception as e:
        utils.log_error(f"Error collecting members for graph {graph_arn}", e)

    return members_data


@utils.aws_error_handler("Collecting Detective invitations", default_return=[])
def collect_invitations(region: str) -> List[Dict[str, Any]]:
    """
    Collect pending invitations in the account.

    Args:
        region: AWS region

    Returns:
        list: List of invitation information dictionaries
    """
    invitations_data = []
    client = utils.get_boto3_client('detective', region_name=region)

    try:
        # List invitations
        response = client.list_invitations()
        invitations = response.get('Invitations', [])

        if not invitations:
            utils.log_info(f"No pending Detective invitations in {region}")
            return []

        utils.log_info(f"Found {len(invitations)} pending invitation(s) in {region}")

        for invitation in invitations:
            invitation_info = {
                'Region': region,
                'Graph ARN': invitation.get('GraphArn', 'N/A'),
                'Administrator Account ID': invitation.get('AdministratorId', 'N/A'),
                'Email Address': invitation.get('EmailAddress', 'N/A'),
                'Invitation Time': invitation.get('InvitedTime', 'N/A'),
                'Status': invitation.get('Status', 'N/A'),
                'Disabled Reason': invitation.get('DisabledReason', 'N/A'),
                'Message': invitation.get('Message', 'N/A'),
                'Percent of Graph Volume': f"{invitation.get('PercentOfGraphUtilization', 0):.2f}%",
                'Volume Usage (GB)': calculate_volume_gb(invitation.get('VolumeUsageInBytes', 0))
            }

            invitations_data.append(invitation_info)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            utils.log_info(f"No invitations or access denied in {region}")
        else:
            utils.log_error(f"Error collecting invitations from {region}: {error_code}")

    return invitations_data


@utils.aws_error_handler("Collecting organization configuration", default_return={})
def collect_organization_config(region: str, graph_arn: str) -> Dict[str, Any]:
    """
    Collect organization configuration for a Detective graph.

    Args:
        region: AWS region
        graph_arn: Graph ARN

    Returns:
        dict: Organization configuration information
    """
    client = utils.get_boto3_client('detective', region_name=region)

    try:
        response = client.describe_organization_configuration(GraphArn=graph_arn)

        return {
            'Auto Enable': response.get('AutoEnable', False),
            'Auto Enable Date': response.get('AutoEnableDate', 'N/A')
        }
    except Exception as e:
        utils.log_debug(f"Could not get organization config for {graph_arn}: {e}")
        return {
            'Auto Enable': 'N/A',
            'Auto Enable Date': 'N/A'
        }


def calculate_volume_gb(bytes_value: int) -> str:
    """
    Convert bytes to GB for volume display.

    Args:
        bytes_value: Volume in bytes

    Returns:
        str: Formatted GB value
    """
    if bytes_value == 0:
        return "0 GB"
    gb_value = bytes_value / (1024 ** 3)
    return f"{gb_value:.2f} GB"


def format_tags(resource_arn: str, client) -> str:
    """
    Format tags for a resource.

    Args:
        resource_arn: ARN of the resource
        client: Boto3 Detective client

    Returns:
        str: Formatted tags string
    """
    try:
        response = client.list_tags_for_resource(ResourceArn=resource_arn)
        tags = response.get('Tags', {})

        if not tags:
            return 'N/A'

        tag_list = [f"{k}={v}" for k, v in tags.items()]
        return '; '.join(tag_list)
    except Exception:
        return 'N/A'


def collect_all_graphs(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Detective graphs using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of all graph information from all regions
    """
    print("\n=== COLLECTING DETECTIVE GRAPHS ===")
    utils.log_info(f"Scanning {len(regions)} regions for Detective graphs...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_graphs,
        show_progress=True
    )

    # Flatten results
    all_graphs = []
    for graphs_in_region in region_results:
        all_graphs.extend(graphs_in_region)

    utils.log_success(f"Total Detective graphs collected: {len(all_graphs)}")
    return all_graphs


def collect_all_invitations(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Detective invitations using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of all invitation information from all regions
    """
    print("\n=== COLLECTING DETECTIVE INVITATIONS ===")
    utils.log_info(f"Scanning {len(regions)} regions for invitations...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_invitations,
        show_progress=True
    )

    # Flatten results
    all_invitations = []
    for invitations_in_region in region_results:
        all_invitations.extend(invitations_in_region)

    utils.log_success(f"Total invitations collected: {len(all_invitations)}")
    return all_invitations


def export_to_excel(
    graphs_data: List[Dict[str, Any]],
    members_data: List[Dict[str, Any]],
    invitations_data: List[Dict[str, Any]],
    account_name: str
) -> str:
    """
    Export Detective data to Excel file with multiple sheets.

    Args:
        graphs_data: List of graph information
        members_data: List of member information
        invitations_data: List of invitation information
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    try:
        import pandas as pd

        # Generate filename
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(
            account_name,
            "detective",
            "comprehensive",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        # Overall Summary Sheet
        summary_data = {
            'Metric': [
                'Total Graphs',
                'Total Member Accounts',
                'Members - Enabled',
                'Members - Invited',
                'Members - Verification In Progress',
                'Members - Disabled',
                'Pending Invitations',
                'Regions with Detective Enabled'
            ],
            'Count': [
                len(graphs_data),
                len(members_data),
                len([m for m in members_data if m.get('Status') == 'ENABLED']),
                len([m for m in members_data if m.get('Status') == 'INVITED']),
                len([m for m in members_data if m.get('Status') == 'VERIFICATION_IN_PROGRESS']),
                len([m for m in members_data if m.get('Status') == 'DISABLED']),
                len(invitations_data),
                len(set([g['Region'] for g in graphs_data]))
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Graphs Sheet
        if graphs_data:
            graphs_df = pd.DataFrame(graphs_data)
            data_frames['Graphs'] = graphs_df
        else:
            # Create empty DataFrame with expected columns
            data_frames['Graphs'] = pd.DataFrame(columns=[
                'Region', 'Graph ARN', 'Created Time', 'Status', 'Member Count', 'Tags'
            ])

        # Members Sheet
        if members_data:
            members_df = pd.DataFrame(members_data)
            data_frames['Graph Members'] = members_df
        else:
            data_frames['Graph Members'] = pd.DataFrame(columns=[
                'Region', 'Graph ARN', 'Account ID', 'Email', 'Administrator Account ID',
                'Status', 'Disabled Reason', 'Invited Time', 'Updated Time',
                'Volume Usage (GB)', 'Percent of Graph Volume', 'Volume Updated Time'
            ])

        # Invitations Sheet
        if invitations_data:
            invitations_df = pd.DataFrame(invitations_data)
            data_frames['Invitations'] = invitations_df
        else:
            data_frames['Invitations'] = pd.DataFrame(columns=[
                'Region', 'Graph ARN', 'Administrator Account ID', 'Email Address',
                'Invitation Time', 'Status', 'Disabled Reason', 'Message',
                'Percent of Graph Volume', 'Volume Usage (GB)'
            ])

        # Member Status Breakdown
        if members_data:
            status_counts = pd.DataFrame(members_data)['Status'].value_counts().reset_index()
            status_counts.columns = ['Status', 'Count']
            data_frames['Member Status Breakdown'] = status_counts

        # Save using utils function for multi-sheet Excel with preparation
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename, prepare=True)

        if output_path:
            utils.log_success("AWS Detective data exported successfully!")
            utils.log_info(f"File location: {output_path}")

            # Log summary statistics
            total_graphs = len(graphs_data)
            total_members = len(members_data)
            enabled_members = len([m for m in members_data if m.get('Status') == 'ENABLED'])
            utils.log_info(f"Export contains {total_graphs} graph(s) with {total_members} member(s) ({enabled_members} enabled)")

            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None


def main():
    """
    Main function to orchestrate the Detective information collection.
    """
    try:
        # Check dependencies first
        if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
            return

        # Import pandas after dependency check
        import pandas as pd

        # Setup logging
        utils.setup_logging("detective-export")

        # Print title and get account info
        account_id, account_name = print_title()

        # Validate AWS credentials
        try:
            sts = utils.get_boto3_client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")
        except NoCredentialsError:
            utils.log_error("AWS credentials not found. Please configure your credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return
        except Exception as e:
            utils.log_error("Error validating AWS credentials", e)
            return

        utils.log_info("Starting AWS Detective information collection...")
        print("====================================================================")

        # Get regions to scan
        regions = utils.prompt_region_selection(
            prompt_message="Select AWS region(s) to scan for Detective:",
            allow_all=True
        )

        utils.log_info(f"Will scan Detective in regions: {', '.join(regions)}")

        # Collect graphs concurrently
        all_graphs_data = collect_all_graphs(regions)

        # For each graph, collect members (members need graph ARNs, so sequential is OK)
        all_members_data = []
        for graph in all_graphs_data:
            graph_arn = graph.get('Graph ARN')
            region = graph.get('Region')
            if graph_arn and graph_arn != 'N/A':
                utils.log_info(f"Collecting members for graph in {region}...")
                members = collect_members(region, graph_arn)
                all_members_data.extend(members)

        # Collect invitations concurrently
        all_invitations_data = collect_all_invitations(regions)

        # Check if any data was collected
        if not all_graphs_data and not all_invitations_data:
            utils.log_warning("No Detective data found in any region.")
            utils.log_info("Detective may not be enabled in this account.")
            utils.log_info("To enable Detective, visit the AWS Console > Detective > Enable Detective")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(
            all_graphs_data,
            all_members_data,
            all_invitations_data,
            account_name
        )

        if filename:
            utils.log_info(f"Total graphs processed: {len(all_graphs_data)}")
            utils.log_info(f"Total members processed: {len(all_members_data)}")
            utils.log_info(f"Total invitations processed: {len(all_invitations_data)}")
            print("\nScript execution completed.")
        else:
            utils.log_error("Export failed. Please check the logs.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
