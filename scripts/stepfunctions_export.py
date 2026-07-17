#!/usr/bin/env python3
"""
AWS Step Functions Export Script for StratusScan

Exports comprehensive AWS Step Functions workflow orchestration information
including state machines, executions, activities, and configuration details.

Features:
- State Machines: Workflow definitions, types (STANDARD/EXPRESS), IAM roles
- Executions: Recent workflow executions with status and timing
- Activities: Long-running task coordination
- Summary: State machine counts, execution statistics, and metrics

Output: Excel file with 4 worksheets
"""

import json
import sys
from pathlib import Path
from typing import Any

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils
args = utils.parse_script_args("Export Step Functions state machines to Excel")

def _build_state_machine_row(sm_summary: dict[str, Any], region: str, sfn_client) -> dict[str, Any]:
    """
    Build a single Step Functions state machine export row.

    Extracted so the per-item processing can be wrapped in try/except by the
    caller: a malformed/unexpected state machine entry is logged and skipped
    rather than discarding the whole region's results. Every field is read
    with ``.get()`` — a hard subscript (e.g. ``sm['X-Ray Tracing']``) on a
    divergent resource variant is exactly the RDS-Custom failure mode from
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``.
    """
    state_machine_arn = sm_summary.get('stateMachineArn', 'N/A')
    name = sm_summary.get('name', 'N/A')
    sm_type = sm_summary.get('type', 'N/A')

    creation_date = sm_summary.get('creationDate')
    creation_date_str = creation_date.strftime('%Y-%m-%d %H:%M:%S') if creation_date else 'N/A'

    try:
        sm_response = sfn_client.describe_state_machine(stateMachineArn=state_machine_arn)
        role_arn = sm_response.get('roleArn', 'N/A')
        role_name = role_arn.split('/')[-1] if role_arn != 'N/A' and '/' in role_arn else 'N/A'

        definition = sm_response.get('definition', 'N/A')
        state_count = 'N/A'
        try:
            if definition != 'N/A':
                definition_json = json.loads(definition)
                state_count = len(definition_json.get('States', {}))
        except Exception:
            state_count = 'Parse Error'

        logging_config = sm_response.get('loggingConfiguration', {})
        log_destinations = logging_config.get('destinations', [])
        log_groups = []
        for dest in log_destinations:
            arn = dest.get('cloudWatchLogsLogGroup', {}).get('logGroupArn', '')
            if ':log-group:' in arn:
                log_groups.append(arn.split(':log-group:')[-1].split(':')[0])

        tracing_config = sm_response.get('tracingConfiguration', {})

        return {
            'Region': region,
            'State Machine Name': name,
            'Type': sm_type,
            'Status': sm_response.get('status', 'N/A'),
            'Role': role_name,
            'State Count': state_count,
            'Logging Level': logging_config.get('level', 'OFF'),
            'Include Execution Data': 'Yes' if logging_config.get('includeExecutionData', False) else 'No',
            'Log Groups': ', '.join(log_groups) if log_groups else 'None',
            'X-Ray Tracing': 'Enabled' if tracing_config.get('enabled', False) else 'Disabled',
            'Label': sm_response.get('label', 'N/A'),
            'Created': creation_date_str,
            'ARN': state_machine_arn,
        }
    except Exception as e:
        utils.log_warning(f"Could not get details for state machine {name}: {str(e)}")
        return {
            'Region': region, 'State Machine Name': name, 'Type': sm_type,
            'Status': 'Unknown', 'Role': 'N/A', 'State Count': 'N/A',
            'Logging Level': 'N/A', 'Include Execution Data': 'N/A',
            'Log Groups': 'N/A', 'X-Ray Tracing': 'N/A', 'Label': 'N/A',
            'Created': creation_date_str, 'ARN': state_machine_arn,
        }


def _scan_state_machines_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Step Functions state machines from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no state machines" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed state machines are skipped (logged) rather than
    aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    state_machines_data = []

    sfn_client = utils.get_boto3_client('stepfunctions', region_name=region)
    paginator = sfn_client.get_paginator('list_state_machines')

    for page in paginator.paginate():
        for sm_summary in page.get('stateMachines', []):
            try:
                state_machines_data.append(_build_state_machine_row(sm_summary, region, sfn_client))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Step Functions state machine in {region}: "
                    f"{sm_summary.get('name', '<unknown>')}",
                    e,
                )
                continue

    return state_machines_data


def collect_state_machines(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Step Functions state machine information across regions,
    surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(state_machines, failed_regions)`` where ``failed_regions``
        is a list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_state_machines_region,
        show_progress=True,
        collect_failures=True,
    )
    all_state_machines = [sm for result in region_results for sm in result]
    utils.log_success(f"Collected {len(all_state_machines)} Step Functions state machines")
    return all_state_machines, failed_regions


@utils.aws_error_handler("Collecting Step Functions executions", default_return=[])
def collect_executions(regions: list[str], state_machines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collect recent Step Functions execution information from AWS regions."""
    all_executions = []

    for region in regions:
        utils.log_info(f"Scanning Step Functions executions in {region}...")
        sfn_client = utils.get_boto3_client('stepfunctions', region_name=region)

        # Get executions for each state machine (limit to recent executions)
        region_state_machines = [sm for sm in state_machines if sm.get('Region') == region]

        for sm in region_state_machines:
            state_machine_arn = sm.get('ARN', 'N/A')
            state_machine_name = sm.get('State Machine Name', 'N/A')

            try:
                # Get recent executions (default max results is 100)
                paginator = sfn_client.get_paginator('list_executions')
                execution_count = 0

                for page in paginator.paginate(stateMachineArn=state_machine_arn, maxResults=10):
                    executions = page.get('executions', [])

                    for execution in executions:
                        execution_arn = execution.get('executionArn', 'N/A')
                        execution_name = execution.get('name', 'N/A')
                        status = execution.get('status', 'N/A')

                        # Start and stop times
                        start_date = execution.get('startDate')
                        if start_date:
                            start_date_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            start_date_str = 'N/A'

                        stop_date = execution.get('stopDate')
                        if stop_date:
                            stop_date_str = stop_date.strftime('%Y-%m-%d %H:%M:%S')
                            # Calculate duration
                            if start_date:
                                duration = stop_date - start_date
                                duration_seconds = duration.total_seconds()
                                duration_str = f"{duration_seconds:.2f}s"
                            else:
                                duration_str = 'N/A'
                        else:
                            stop_date_str = 'Running' if status == 'RUNNING' else 'N/A'
                            duration_str = 'N/A'

                        all_executions.append({
                            'Region': region,
                            'State Machine': state_machine_name,
                            'Execution Name': execution_name,
                            'Status': status,
                            'Started': start_date_str,
                            'Stopped': stop_date_str,
                            'Duration': duration_str,
                            'Execution ARN': execution_arn,
                        })

                        execution_count += 1
                        if execution_count >= 10:  # Limit to 10 most recent per state machine
                            break

                    if execution_count >= 10:
                        break

            except Exception as e:
                utils.log_warning(f"Could not get executions for state machine {state_machine_name}: {str(e)}")
                continue

        utils.log_success(f"Collected {len([e for e in all_executions if e['Region'] == region])} Step Functions executions from {region}")

    return all_executions


def _scan_activities_region(region: str) -> list[dict[str, Any]]:
    """Scan a single region for Step Functions activities."""
    activities_data = []

    try:
        sfn_client = utils.get_boto3_client('stepfunctions', region_name=region)
        paginator = sfn_client.get_paginator('list_activities')

        for page in paginator.paginate():
            for activity in page.get('activities', []):
                creation_date = activity.get('creationDate')
                activities_data.append({
                    'Region': region,
                    'Activity Name': activity.get('name', 'N/A'),
                    'Created': creation_date.strftime('%Y-%m-%d %H:%M:%S') if creation_date else 'N/A',
                    'Activity ARN': activity.get('activityArn', 'N/A'),
                })
    except Exception as e:
        utils.log_error(f"Error scanning activities in {region}", e)

    return activities_data


@utils.aws_error_handler("Collecting Step Functions activities", default_return=[])
def collect_activities(regions: list[str]) -> list[dict[str, Any]]:
    """Collect Step Functions activity information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_activities_region)
    all_activities = [a for result in results for a in result]
    utils.log_success(f"Collected {len(all_activities)} Step Functions activities")
    return all_activities


def generate_summary(state_machines: list[dict[str, Any]],
                     executions: list[dict[str, Any]],
                     activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate summary statistics for Step Functions resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total State Machines',
        'Count': len(state_machines),
        'Details': f"{len([sm for sm in state_machines if sm.get('Status') == 'ACTIVE'])} active"
    })

    summary.append({
        'Metric': 'Total Recent Executions',
        'Count': len(executions),
        'Details': "Last 10 executions per state machine"
    })

    summary.append({
        'Metric': 'Total Activities',
        'Count': len(activities),
        'Details': f"{len(activities)} long-running task activities"
    })

    # State machine types
    if state_machines:
        types = {}
        for sm in state_machines:
            sm_type = sm['Type']
            types[sm_type] = types.get(sm_type, 0) + 1

        type_details = ', '.join([f"{stype}: {count}" for stype, count in sorted(types.items())])
        summary.append({
            'Metric': 'State Machine Types',
            'Count': len(types),
            'Details': type_details
        })

    # Execution status distribution
    if executions:
        statuses = {}
        for execution in executions:
            status = execution.get('Status', 'N/A')
            statuses[status] = statuses.get(status, 0) + 1

        status_details = ', '.join([f"{status}: {count}" for status, count in sorted(statuses.items())])
        summary.append({
            'Metric': 'Execution Status Distribution',
            'Count': len(statuses),
            'Details': status_details
        })

    # Logging enabled
    if state_machines:
        logging_enabled = len([sm for sm in state_machines if sm.get('Logging Level') not in ['OFF', 'N/A']])
        summary.append({
            'Metric': 'State Machines with Logging',
            'Count': logging_enabled,
            'Details': f"{logging_enabled}/{len(state_machines)} have CloudWatch logging enabled"
        })

    # X-Ray tracing
    if state_machines:
        tracing_enabled = len([sm for sm in state_machines if sm.get('X-Ray Tracing') == 'Enabled'])
        summary.append({
            'Metric': 'State Machines with X-Ray Tracing',
            'Count': tracing_enabled,
            'Details': f"{tracing_enabled}/{len(state_machines)} have X-Ray tracing enabled"
        })

    # State machines by region
    if state_machines:
        regions = {}
        for sm in state_machines:
            region = sm.get('Region', 'N/A')
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'State Machines by Region',
            'Count': len(regions),
            'Details': region_details
        })

    # Average state count
    if state_machines:
        state_counts = [sm.get('State Count') for sm in state_machines
                       if isinstance(sm.get('State Count'), int)]
        if state_counts:
            avg_states = sum(state_counts) / len(state_counts)
            summary.append({
                'Metric': 'Average States per State Machine',
                'Count': round(avg_states, 1),
                'Details': f"{round(avg_states, 1)} states on average"
            })

    return summary


def _run_export(account_id: str, account_name: str, regions: list[str]) -> None:
    """Collect Step Functions data and write the Excel export."""
    # Collect data. State machines is the primary scope — region failures
    # must propagate as failed_regions, never collapse into "empty".
    print("\n=== Collecting Step Functions Data ===")
    state_machines, failed_regions = collect_state_machines(regions)
    executions = collect_executions(regions, state_machines)
    activities = collect_activities(regions)

    # Generate summary
    summary = generate_summary(state_machines, executions, activities)

    # Convert to DataFrames
    state_machines_df = pd.DataFrame(state_machines) if state_machines else pd.DataFrame()
    executions_df = pd.DataFrame(executions) if executions else pd.DataFrame()
    activities_df = pd.DataFrame(activities) if activities else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not state_machines_df.empty:
        state_machines_df = utils.prepare_dataframe_for_export(state_machines_df)
    if not executions_df.empty:
        executions_df = utils.prepare_dataframe_for_export(executions_df)
    if not activities_df.empty:
        activities_df = utils.prepare_dataframe_for_export(activities_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'stepfunctions', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'State Machines': state_machines_df,
        'Recent Executions': executions_df,
        'Activities': activities_df,
        'Summary': summary_df
    }

    utils.save_multiple_dataframes_to_excel(dataframes, filename)

    # If ANY region failed the primary state-machine scope collection, make
    # it loud: write a marker and exit non-zero, even though the Summary
    # sheet always lands. A complete-looking workbook that hides a zero-row
    # data sheet is exactly the failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'stepfunctions', failed_regions)
        print(
            "\nERROR: Step Functions export completed with failures — data is incomplete. "
            "See the *-stepfunctions-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    global pd
    import pandas as pd
    utils.setup_logging("stepfunctions-export")

    try:
        account_id, account_name = utils.print_script_banner("AWS STEP FUNCTIONS EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="Step Functions")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export Step Functions data ({region_str})."
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
