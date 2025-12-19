#!/usr/bin/env python3
"""
AWS CodePipeline Export Script for StratusScan

Exports comprehensive AWS CodePipeline CI/CD orchestration information including:
- Pipelines with stage and action configurations
- Pipeline executions with status and timing
- Webhooks for automated triggering
- Action type definitions

Output: Multi-worksheet Excel file with CodePipeline resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import json

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)


def check_dependencies():
    """Check if required dependencies are installed."""
    utils.log_info("Checking dependencies...")

    missing = []

    try:
        import pandas
        utils.log_info("✓ pandas is installed")
    except ImportError:
        missing.append("pandas")

    try:
        import openpyxl
        utils.log_info("✓ openpyxl is installed")
    except ImportError:
        missing.append("openpyxl")

    try:
        import boto3
        utils.log_info("✓ boto3 is installed")
    except ImportError:
        missing.append("boto3")

    if missing:
        utils.log_error(f"Missing dependencies: {', '.join(missing)}")
        utils.log_error("Please install using: pip install " + " ".join(missing))
        sys.exit(1)

    utils.log_success("All dependencies are installed")


def _scan_pipelines_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for CodePipeline pipelines."""
    pipelines_data = []

    try:
        codepipeline_client = utils.get_boto3_client('codepipeline', region_name=region)

        # List all pipelines
        paginator = codepipeline_client.get_paginator('list_pipelines')
        for page in paginator.paginate():
            pipeline_summaries = page.get('pipelines', [])

            for pipeline_summary in pipeline_summaries:
                pipeline_name = pipeline_summary.get('name', 'N/A')

                # Get detailed pipeline information
                try:
                    pipeline_response = codepipeline_client.get_pipeline(name=pipeline_name)
                    pipeline = pipeline_response.get('pipeline', {})
                    metadata = pipeline_response.get('metadata', {})

                    # Basic info
                    arn = metadata.get('pipelineArn', 'N/A')

                    created = pipeline_summary.get('created', metadata.get('created', 'N/A'))
                    if created != 'N/A':
                        created = created.strftime('%Y-%m-%d %H:%M:%S')

                    updated = pipeline_summary.get('updated', metadata.get('updated', 'N/A'))
                    if updated != 'N/A':
                        updated = updated.strftime('%Y-%m-%d %H:%M:%S')

                    # Version
                    version = pipeline_summary.get('version', pipeline.get('version', 'N/A'))

                    # Role
                    role_arn = pipeline.get('roleArn', 'N/A')

                    # Artifact store
                    artifact_store = pipeline.get('artifactStore', {})
                    artifact_type = artifact_store.get('type', 'N/A')
                    artifact_location = artifact_store.get('location', 'N/A')

                    # Encryption key
                    encryption_key = artifact_store.get('encryptionKey', {})
                    kms_key_id = encryption_key.get('id', 'None')

                    # Stages
                    stages = pipeline.get('stages', [])
                    stage_count = len(stages)
                    stage_names = [s.get('name', 'N/A') for s in stages]
                    stages_str = ' → '.join(stage_names)

                    # Count actions across all stages
                    total_actions = sum(len(stage.get('actions', [])) for stage in stages)

                    # Get pipeline state for execution info
                    try:
                        state_response = codepipeline_client.get_pipeline_state(name=pipeline_name)
                        state = state_response

                        # Latest execution
                        stage_states = state.get('stageStates', [])
                        if stage_states:
                            latest_execution = stage_states[0].get('latestExecution', {})
                            latest_status = latest_execution.get('status', 'N/A')
                        else:
                            latest_status = 'No Executions'

                    except Exception:
                        latest_status = 'Unknown'

                    pipelines_data.append({
                        'Region': region,
                        'Pipeline Name': pipeline_name,
                        'ARN': arn,
                        'Version': version,
                        'Created': created,
                        'Updated': updated,
                        'Latest Status': latest_status,
                        'Stage Count': stage_count,
                        'Total Actions': total_actions,
                        'Stages': stages_str,
                        'Role ARN': role_arn,
                        'Artifact Store Type': artifact_type,
                        'Artifact Location': artifact_location,
                        'KMS Key ID': kms_key_id
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for pipeline {pipeline_name} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_error(f"Error scanning CodePipeline pipelines in {region}", e)

    return pipelines_data


@utils.aws_error_handler("Collecting CodePipeline pipelines", default_return=[])
def collect_pipelines(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodePipeline pipeline information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_pipelines_region)
    all_pipelines = [pipeline for result in results for pipeline in result]
    utils.log_success(f"Collected {len(all_pipelines)} CodePipeline pipelines")
    return all_pipelines


def _scan_executions_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for pipeline executions."""
    executions_data = []

    try:
        codepipeline_client = utils.get_boto3_client('codepipeline', region_name=region)

        # List all pipelines first
        paginator = codepipeline_client.get_paginator('list_pipelines')
        for page in paginator.paginate():
            pipeline_summaries = page.get('pipelines', [])

            for pipeline_summary in pipeline_summaries:
                pipeline_name = pipeline_summary.get('name', 'N/A')

                # Get executions for this pipeline (limit to 10 most recent)
                try:
                    exec_paginator = codepipeline_client.get_paginator('list_pipeline_executions')
                    exec_count = 0
                    for exec_page in exec_paginator.paginate(
                        pipelineName=pipeline_name,
                        PaginationConfig={'MaxItems': 10}
                    ):
                        executions = exec_page.get('pipelineExecutionSummaries', [])

                        for execution in executions:
                            execution_id = execution.get('pipelineExecutionId', 'N/A')
                            status = execution.get('status', 'N/A')

                            start_time = execution.get('startTime', 'N/A')
                            if start_time != 'N/A':
                                start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')

                            last_update = execution.get('lastUpdateTime', 'N/A')
                            if last_update != 'N/A':
                                last_update = last_update.strftime('%Y-%m-%d %H:%M:%S')

                            # Duration
                            if execution.get('startTime') and execution.get('lastUpdateTime'):
                                duration_seconds = (execution.get('lastUpdateTime') - execution.get('startTime')).total_seconds()
                                duration_minutes = duration_seconds / 60
                                duration_str = f"{duration_minutes:.1f} minutes"
                            else:
                                duration_str = 'N/A'

                            # Source revisions
                            source_revisions = execution.get('sourceRevisions', [])
                            source_info = 'N/A'
                            if source_revisions:
                                first_rev = source_revisions[0]
                                action_name = first_rev.get('actionName', 'N/A')
                                revision_id = first_rev.get('revisionId', 'N/A')
                                source_info = f"{action_name}: {revision_id[:8]}" if revision_id != 'N/A' else action_name

                            # Trigger
                            trigger = execution.get('trigger', {})
                            trigger_type = trigger.get('triggerType', 'N/A')
                            trigger_detail = trigger.get('triggerDetail', 'N/A')

                            executions_data.append({
                                'Region': region,
                                'Pipeline Name': pipeline_name,
                                'Execution ID': execution_id,
                                'Status': status,
                                'Start Time': start_time,
                                'Last Update': last_update,
                                'Duration': duration_str,
                                'Source': source_info,
                                'Trigger Type': trigger_type,
                                'Trigger Detail': trigger_detail
                            })

                            exec_count += 1
                            if exec_count >= 10:
                                break

                except Exception as e:
                    utils.log_warning(f"Could not get executions for pipeline {pipeline_name}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_error(f"Error collecting pipeline executions in {region}", e)

    return executions_data


@utils.aws_error_handler("Collecting pipeline executions", default_return=[])
def collect_executions(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect recent pipeline execution information (limited to 10 most recent per pipeline)."""
    results = utils.scan_regions_concurrent(regions, _scan_executions_region)
    all_executions = [execution for result in results for execution in result]
    utils.log_success(f"Collected {len(all_executions)} pipeline executions (limited to 10 most recent per pipeline)")
    return all_executions


def _scan_webhooks_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for pipeline webhooks."""
    webhooks_data = []

    try:
        codepipeline_client = utils.get_boto3_client('codepipeline', region_name=region)

        # List webhooks
        paginator = codepipeline_client.get_paginator('list_webhooks')
        for page in paginator.paginate():
            webhooks = page.get('webhooks', [])

            for webhook in webhooks:
                definition = webhook.get('definition', {})

                webhook_name = definition.get('name', 'N/A')
                target_pipeline = definition.get('targetPipeline', 'N/A')
                target_action = definition.get('targetAction', 'N/A')

                # Filters
                filters = definition.get('filters', [])
                filter_count = len(filters)

                # Authentication
                authentication = definition.get('authentication', 'N/A')
                auth_config = definition.get('authenticationConfiguration', {})

                # URL and ARN
                url = webhook.get('url', 'N/A')
                arn = webhook.get('arn', 'N/A')

                # Error info
                error_message = webhook.get('errorMessage', 'None')
                error_code = webhook.get('errorCode', 'None')

                # Last triggered
                last_triggered = webhook.get('lastTriggered', 'N/A')
                if last_triggered != 'N/A':
                    last_triggered = last_triggered.strftime('%Y-%m-%d %H:%M:%S')

                webhooks_data.append({
                    'Region': region,
                    'Webhook Name': webhook_name,
                    'ARN': arn,
                    'Target Pipeline': target_pipeline,
                    'Target Action': target_action,
                    'Filter Count': filter_count,
                    'Authentication': authentication,
                    'URL': url,
                    'Last Triggered': last_triggered,
                    'Error Code': error_code,
                    'Error Message': error_message
                })

    except Exception as e:
        utils.log_error(f"Error collecting webhooks in {region}", e)

    return webhooks_data


@utils.aws_error_handler("Collecting pipeline webhooks", default_return=[])
def collect_webhooks(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodePipeline webhook information."""
    results = utils.scan_regions_concurrent(regions, _scan_webhooks_region)
    all_webhooks = [webhook for result in results for webhook in result]
    utils.log_success(f"Collected {len(all_webhooks)} webhooks")
    return all_webhooks


def generate_summary(pipelines: List[Dict[str, Any]],
                     executions: List[Dict[str, Any]],
                     webhooks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for CodePipeline resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Pipelines summary
    total_pipelines = len(pipelines)
    summary.append({
        'Metric': 'Total Pipelines',
        'Count': total_pipelines,
        'Details': 'CodePipeline CI/CD orchestration pipelines'
    })

    # Average stages per pipeline
    if pipelines:
        total_stages = sum(p.get('Stage Count', 0) for p in pipelines)
        avg_stages = total_stages / total_pipelines if total_pipelines > 0 else 0
        summary.append({
            'Metric': 'Average Stages per Pipeline',
            'Count': f"{avg_stages:.1f}",
            'Details': f'Total stages across all pipelines: {total_stages}'
        })

    # Executions summary
    total_executions = len(executions)
    succeeded_execs = sum(1 for e in executions if e.get('Status', '') == 'Succeeded')
    failed_execs = sum(1 for e in executions if e.get('Status', '') == 'Failed')
    in_progress = sum(1 for e in executions if e.get('Status', '') == 'InProgress')

    summary.append({
        'Metric': 'Recent Executions (Sample)',
        'Count': total_executions,
        'Details': f'Succeeded: {succeeded_execs}, Failed: {failed_execs}, In Progress: {in_progress}'
    })

    # Webhooks summary
    total_webhooks = len(webhooks)
    summary.append({
        'Metric': 'Total Webhooks',
        'Count': total_webhooks,
        'Details': 'Automated pipeline triggers from source repositories'
    })

    # Webhook errors
    webhook_errors = sum(1 for w in webhooks if w.get('Error Code', 'None') != 'None')
    if webhook_errors > 0:
        summary.append({
            'Metric': '⚠️ Webhooks with Errors',
            'Count': webhook_errors,
            'Details': 'Webhooks experiencing delivery or authentication issues'
        })

    # Regional distribution
    if pipelines:
        df = pd.DataFrame(pipelines)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Pipelines in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS CodePipeline Export Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Detect partition for region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print("\nCodePipeline is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where CodePipeline is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                # Default regions
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
            elif region_choice == '2':
                # All available regions
                regions = utils.get_partition_regions(partition, all_regions=True)
                print(f"\nScanning all {len(regions)} available regions")
            elif region_choice == '3':
                # Specific region - show numbered list
                available_regions = utils.get_partition_regions(
                    partition, all_regions=True
                )
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx}. {region}")
                print("-" * 68)

                # Get region selection
                region_selected = False
                while not region_selected:
                    try:
                        region_num = input(
                            f"\nEnter region number (1-{len(available_regions)}): "
                        ).strip()
                        region_idx = int(region_num) - 1

                        if 0 <= region_idx < len(available_regions):
                            selected_region = available_regions[region_idx]
                            regions = [selected_region]
                            print(f"\nSelected region: {selected_region}")
                            region_selected = True
                        else:
                            print(
                                f"Invalid selection. Please enter a number "
                                f"between 1 and {len(available_regions)}."
                            )
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                    except KeyboardInterrupt:
                        print("\n\nOperation cancelled by user.")
                        sys.exit(0)
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    # Collect data
    print("\nCollecting AWS CodePipeline data...")

    pipelines = collect_pipelines(regions)
    executions = collect_executions(regions)
    webhooks = collect_webhooks(regions)
    summary = generate_summary(pipelines, executions, webhooks)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if pipelines:
        df_pipelines = pd.DataFrame(pipelines)
        df_pipelines = utils.prepare_dataframe_for_export(df_pipelines)
        dataframes['Pipelines'] = df_pipelines

    if executions:
        df_executions = pd.DataFrame(executions)
        df_executions = utils.prepare_dataframe_for_export(df_executions)
        dataframes['Recent Executions'] = df_executions

    if webhooks:
        df_webhooks = pd.DataFrame(webhooks)
        df_webhooks = utils.prepare_dataframe_for_export(df_webhooks)
        dataframes['Webhooks'] = df_webhooks

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'codepipeline', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Pipelines': len(pipelines),
            'Recent Executions': len(executions),
            'Webhooks': len(webhooks)
        })
    else:
        utils.log_warning("No AWS CodePipeline data found to export")

    utils.log_success("AWS CodePipeline export completed successfully")


if __name__ == "__main__":
    main()
