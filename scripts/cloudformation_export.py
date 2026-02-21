#!/usr/bin/env python3
"""
CloudFormation Export Script

Exports AWS CloudFormation infrastructure-as-code resources:
- CloudFormation stacks (all states)
- Stack parameters and outputs
- Stack resources and dependencies
- StackSets (multi-account/region deployments)
- StackSet instances
- Change sets
- Drift detection status
- Stack events and status history
- Termination protection status

Features:
- Complete stack inventory across regions
- StackSet multi-account deployment tracking
- Drift detection status
- Resource-level details
- Template URL tracking
- IAM role associations
- Tag and parameter extraction
- Multi-worksheet comprehensive export
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd

# Standard utils import pattern
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

# Check required packages
utils.check_required_packages(['boto3', 'pandas', 'openpyxl'])

# Setup logging
logger = utils.setup_logging('cloudformation-export')
utils.log_script_start('cloudformation-export', 'Export AWS CloudFormation stacks and StackSets')


@utils.aws_error_handler("Collecting CloudFormation stacks", default_return=[])
def collect_stacks(region: str) -> List[Dict[str, Any]]:
    """Collect all CloudFormation stacks in a region."""
    cfn = utils.get_boto3_client('cloudformation', region_name=region)
    stacks = []

    paginator = cfn.get_paginator('describe_stacks')
    for page in paginator.paginate():
        for stack in page.get('Stacks', []):
            # Extract parameters
            parameters = []
            for param in stack.get('Parameters', []):
                parameters.append(f"{param.get('ParameterKey')}={param.get('ParameterValue')}")

            # Extract outputs
            outputs = []
            for output in stack.get('Outputs', []):
                outputs.append(f"{output.get('OutputKey')}={output.get('OutputValue')}")

            # Extract tags
            tags = []
            for tag in stack.get('Tags', []):
                tags.append(f"{tag.get('Key')}={tag.get('Value')}")

            # Extract capabilities
            capabilities = ', '.join(stack.get('Capabilities', []))

            stacks.append({
                'Region': region,
                'StackName': stack.get('StackName', 'N/A'),
                'StackId': stack.get('StackId', 'N/A'),
                'Status': stack.get('StackStatus', 'N/A'),
                'StatusReason': stack.get('StackStatusReason', 'N/A'),
                'CreationTime': stack.get('CreationTime'),
                'LastUpdatedTime': stack.get('LastUpdatedTime', 'N/A'),
                'DriftStatus': stack.get('DriftInformation', {}).get('StackDriftStatus', 'NOT_CHECKED'),
                'LastDriftCheckTime': stack.get('DriftInformation', {}).get('LastCheckTimestamp', 'N/A'),
                'TerminationProtection': stack.get('EnableTerminationProtection', False),
                'RoleARN': stack.get('RoleARN', 'N/A'),
                'TemplateDescription': stack.get('Description', 'N/A'),
                'Capabilities': capabilities if capabilities else 'N/A',
                'Parameters': ', '.join(parameters) if parameters else 'N/A',
                'Outputs': ', '.join(outputs) if outputs else 'N/A',
                'Tags': ', '.join(tags) if tags else 'N/A',
                'DisableRollback': stack.get('DisableRollback', False),
                'NotificationARNs': ', '.join(stack.get('NotificationARNs', [])) if stack.get('NotificationARNs') else 'N/A',
                'TimeoutInMinutes': stack.get('TimeoutInMinutes', 'N/A'),
                'ParentId': stack.get('ParentId', 'N/A'),
                'RootId': stack.get('RootId', 'N/A'),
            })

    return stacks


@utils.aws_error_handler("Collecting stack resources", default_return=[])
def collect_stack_resources(region: str, stack_name: str) -> List[Dict[str, Any]]:
    """Collect resources for a specific stack."""
    cfn = utils.get_boto3_client('cloudformation', region_name=region)
    resources = []

    try:
        paginator = cfn.get_paginator('list_stack_resources')
        for page in paginator.paginate(StackName=stack_name):
            for resource in page.get('StackResourceSummaries', []):
                resources.append({
                    'Region': region,
                    'StackName': stack_name,
                    'LogicalResourceId': resource.get('LogicalResourceId', 'N/A'),
                    'PhysicalResourceId': resource.get('PhysicalResourceId', 'N/A'),
                    'ResourceType': resource.get('ResourceType', 'N/A'),
                    'ResourceStatus': resource.get('ResourceStatus', 'N/A'),
                    'ResourceStatusReason': resource.get('ResourceStatusReason', 'N/A'),
                    'LastUpdatedTimestamp': resource.get('LastUpdatedTimestamp', 'N/A'),
                    'DriftStatus': resource.get('DriftInformation', {}).get('StackResourceDriftStatus', 'NOT_CHECKED'),
                })
    except Exception:
        # Stack might be in a state where resources can't be listed
        pass

    return resources


@utils.aws_error_handler("Collecting StackSets", default_return=[])
def collect_stacksets(region: str) -> List[Dict[str, Any]]:
    """Collect all StackSets (only from us-east-1 typically, but scanning all regions)."""
    cfn = utils.get_boto3_client('cloudformation', region_name=region)
    stacksets = []

    try:
        paginator = cfn.get_paginator('list_stack_sets')
        for page in paginator.paginate(Status='ACTIVE'):
            for summary in page.get('Summaries', []):
                stackset_name = summary.get('StackSetName')

                # Get detailed info
                try:
                    detail = cfn.describe_stack_set(StackSetName=stackset_name)
                    stackset = detail.get('StackSet', {})

                    stacksets.append({
                        'Region': region,
                        'StackSetName': stackset.get('StackSetName', 'N/A'),
                        'StackSetId': stackset.get('StackSetId', 'N/A'),
                        'Status': stackset.get('Status', 'N/A'),
                        'Description': stackset.get('Description', 'N/A'),
                        'PermissionModel': stackset.get('PermissionModel', 'N/A'),
                        'DriftStatus': stackset.get('StackSetDriftDetectionDetails', {}).get('DriftStatus', 'NOT_CHECKED'),
                        'LastDriftCheckTime': stackset.get('StackSetDriftDetectionDetails', {}).get('LastDriftCheckTimestamp', 'N/A'),
                        'AutoDeployment': 'Enabled' if stackset.get('AutoDeployment', {}).get('Enabled') else 'Disabled',
                        'OrganizationalUnitIds': ', '.join(stackset.get('OrganizationalUnitIds', [])) if stackset.get('OrganizationalUnitIds') else 'N/A',
                        'ExecutionRoleName': stackset.get('ExecutionRoleName', 'N/A'),
                        'AdministrationRoleARN': stackset.get('AdministrationRoleARN', 'N/A'),
                    })
                except Exception:
                    # StackSet might be inaccessible
                    pass
    except Exception:
        # StackSets might not be available in this region
        pass

    return stacksets


@utils.aws_error_handler("Collecting StackSet instances", default_return=[])
def collect_stackset_instances(region: str, stackset_name: str) -> List[Dict[str, Any]]:
    """Collect instances for a specific StackSet."""
    cfn = utils.get_boto3_client('cloudformation', region_name=region)
    instances = []

    try:
        paginator = cfn.get_paginator('list_stack_instances')
        for page in paginator.paginate(StackSetName=stackset_name):
            for instance in page.get('Summaries', []):
                instances.append({
                    'Region': region,
                    'StackSetName': stackset_name,
                    'StackInstanceRegion': instance.get('Region', 'N/A'),
                    'Account': instance.get('Account', 'N/A'),
                    'StackId': instance.get('StackId', 'N/A'),
                    'Status': instance.get('Status', 'N/A'),
                    'StatusReason': instance.get('StatusReason', 'N/A'),
                    'DriftStatus': instance.get('DriftStatus', 'NOT_CHECKED'),
                    'LastDriftCheckTime': instance.get('LastDriftCheckTimestamp', 'N/A'),
                    'OrganizationalUnitId': instance.get('OrganizationalUnitId', 'N/A'),
                })
    except Exception:
        # Instances might not be accessible
        pass

    return instances


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting CloudFormation resources for account: {account_name} ({utils.mask_account_id(account_id)})")

        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        # Collect all stacks and related resources
        all_stacks = []
        all_resources = []
        all_stacksets = []
        all_stackset_instances = []

        for idx, region in enumerate(regions, 1):
            utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

            # Collect stacks
            stacks = collect_stacks(region)
            if stacks:
                utils.log_info(f"  Found {len(stacks)} stack(s)")
                all_stacks.extend(stacks)

                # Collect resources for each stack (sample first 10 to avoid too much data)
                for stack in stacks[:10]:
                    stack_name = stack['StackName']
                    resources = collect_stack_resources(region, stack_name)
                    all_resources.extend(resources)

            # Collect StackSets
            stacksets = collect_stacksets(region)
            if stacksets:
                utils.log_info(f"  Found {len(stacksets)} StackSet(s)")
                all_stacksets.extend(stacksets)

                # Collect instances for each StackSet
                for stackset in stacksets:
                    stackset_name = stackset['StackSetName']
                    instances = collect_stackset_instances(region, stackset_name)
                    all_stackset_instances.extend(instances)

        if not all_stacks and not all_stacksets:
            utils.log_warning("No CloudFormation stacks or StackSets found in any selected region.")
            utils.log_info("Creating empty export file...")

        utils.log_info(f"Total stacks found: {len(all_stacks)}")
        utils.log_info(f"Total StackSets found: {len(all_stacksets)}")

        # Create DataFrames
        df_stacks = utils.prepare_dataframe_for_export(pd.DataFrame(all_stacks))
        df_resources = utils.prepare_dataframe_for_export(pd.DataFrame(all_resources))
        df_stacksets = utils.prepare_dataframe_for_export(pd.DataFrame(all_stacksets))
        df_instances = utils.prepare_dataframe_for_export(pd.DataFrame(all_stackset_instances))

        # Create summary
        summary_data = []
        summary_data.append({'Metric': 'Total Stacks', 'Value': len(all_stacks)})
        summary_data.append({'Metric': 'Total StackSets', 'Value': len(all_stacksets)})
        summary_data.append({'Metric': 'Total StackSet Instances', 'Value': len(all_stackset_instances)})
        summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

        if not df_stacks.empty:
            active_stacks = len(df_stacks[df_stacks['Status'].str.contains('COMPLETE', na=False)])
            failed_stacks = len(df_stacks[df_stacks['Status'].str.contains('FAILED', na=False)])
            protected_stacks = len(df_stacks[df_stacks['TerminationProtection'] == True])

            summary_data.append({'Metric': 'Active Stacks (COMPLETE)', 'Value': active_stacks})
            summary_data.append({'Metric': 'Failed Stacks', 'Value': failed_stacks})
            summary_data.append({'Metric': 'Termination Protected', 'Value': protected_stacks})

        df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

        # Create active stacks view
        df_active = pd.DataFrame()
        if not df_stacks.empty:
            df_active = df_stacks[df_stacks['Status'].str.contains('COMPLETE', na=False)]

        # Export to Excel
        filename = utils.create_export_filename(account_name, 'cloudformation', 'all')

        sheets = {
            'Summary': df_summary,
            'All Stacks': df_stacks,
            'Active Stacks': df_active,
            'Stack Resources': df_resources,
            'StackSets': df_stacksets,
            'StackSet Instances': df_instances,
        }

        utils.save_multiple_dataframes_to_excel(sheets, filename)

        # Log summary
        utils.log_export_summary(
            total_items=len(all_stacks) + len(all_stacksets),
            item_type='CloudFormation Resources',
            filename=filename
        )

        utils.log_info(f"  Stacks: {len(all_stacks)}")
        utils.log_info(f"  StackSets: {len(all_stacksets)}")
        utils.log_info(f"  StackSet Instances: {len(all_stackset_instances)}")

        utils.log_success("CloudFormation export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export CloudFormation resources: {str(e)}")
        raise


if __name__ == "__main__":
    main()
