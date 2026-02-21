#!/usr/bin/env python3
"""
AWS Control Tower Export Script for StratusScan

Exports comprehensive AWS Control Tower configuration including:
- Organizational units under Control Tower management
- Enabled controls with detailed metadata (service, name, description, behavior)
- Control drift detection and compliance status
- Failed and drifted controls in separate tabs

Note: Control Tower is a global service accessed via the management account.
      Requires controlcatalog:GetControl permission for full control metadata.

Output: Multi-worksheet Excel file with:
  - Organizational Units: Complete OU hierarchy
  - Enabled Controls: All enabled controls with metadata and status
  - Drifted Controls: Controls with detected drift
  - Failed Controls: Controls that failed to enable
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
@utils.aws_error_handler("Collecting landing zone information", default_return={})
def collect_landing_zone() -> Dict[str, Any]:
    """Collect AWS Control Tower landing zone information (global service)."""
    print("\n=== COLLECTING LANDING ZONE INFORMATION ===")

    # Control Tower is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ct_client = utils.get_boto3_client('controltower', region_name=home_region)

    try:
        # List landing zones
        landing_zones = ct_client.list_landing_zones()
        lz_list = landing_zones.get('landingZones', [])

        if not lz_list:
            utils.log_warning("No landing zone found. Control Tower may not be set up.")
            return {}

        # Get details for the first (and typically only) landing zone
        lz_arn = lz_list[0].get('arn', '')

        if not lz_arn:
            utils.log_warning("Landing zone ARN not found")
            return {}

        # Get detailed landing zone information
        lz_response = ct_client.get_landing_zone(landingZoneIdentifier=lz_arn)
        lz_details = lz_response.get('landingZone', {})

        # Parse manifest if available
        manifest = lz_details.get('manifest', {})
        if isinstance(manifest, str):
            try:
                manifest = json.loads(manifest)
            except json.JSONDecodeError:
                manifest = {'raw': manifest}

        # Get governed regions
        governed_regions = manifest.get('governedRegions', []) if isinstance(manifest, dict) else []

        # Drift status
        drift_status_summary = lz_details.get('driftStatus', {})
        drift_status = drift_status_summary.get('status', 'N/A')

        landing_zone_info = {
            'ARN': lz_details.get('arn', 'N/A'),
            'Version': lz_details.get('version', 'N/A'),
            'Latest Available Version': lz_details.get('latestAvailableVersion', 'N/A'),
            'Status': lz_details.get('status', 'N/A'),
            'Drift Status': drift_status,
            'Governed Regions': ', '.join(governed_regions) if governed_regions else 'N/A',
            'Number of Governed Regions': len(governed_regions) if governed_regions else 0,
            'Manifest': json.dumps(manifest, indent=2) if isinstance(manifest, dict) else str(manifest)
        }

        utils.log_success(f"Landing zone found: Version {landing_zone_info['Version']}, Status: {landing_zone_info['Status']}")
        return landing_zone_info

    except Exception as e:
        utils.log_warning(f"Could not retrieve landing zone information: {str(e)}")
        return {}


@utils.aws_error_handler("Collecting organizational units", default_return=[])
def collect_organizational_units() -> List[Dict[str, Any]]:
    """Collect organizational units from AWS Organizations."""
    print("\n=== COLLECTING ORGANIZATIONAL UNITS ===")
    all_ous = []

    # Organizations is a global service - partition-aware
    org_client = utils.get_boto3_client('organizations')

    try:
        # Get organization root
        roots = org_client.list_roots()['Roots']
        if not roots:
            utils.log_warning("No organization root found")
            return []

        root_id = roots[0]['Id']
        root_arn = roots[0]['Arn']

        # Add root to the list
        all_ous.append({
            'OU ID': root_id,
            'OU ARN': root_arn,
            'OU Name': roots[0]['Name'],
            'Type': 'Root'
        })

        # List OUs recursively
        def list_ous_recursive(parent_id):
            try:
                paginator = org_client.get_paginator('list_organizational_units_for_parent')
                for page in paginator.paginate(ParentId=parent_id):
                    for ou in page.get('OrganizationalUnits', []):
                        ou_id = ou.get('Id', 'N/A')
                        ou_arn = ou.get('Arn', 'N/A')
                        ou_name = ou.get('Name', 'N/A')

                        all_ous.append({
                            'OU ID': ou_id,
                            'OU ARN': ou_arn,
                            'OU Name': ou_name,
                            'Type': 'Organizational Unit'
                        })

                        # Recursively list child OUs
                        list_ous_recursive(ou_id)
            except Exception as e:
                utils.log_warning(f"Error listing OUs for parent {parent_id}: {str(e)}")

        list_ous_recursive(root_id)

    except Exception as e:
        utils.log_warning(f"Error collecting organizational units: {str(e)}")

    utils.log_success(f"Total organizational units collected: {len(all_ous)}")
    return all_ous


def extract_service_from_control_identifier(control_id: str) -> str:
    """
    Extract service name from control identifier.

    Examples:
        - arn:aws:controltower:us-east-1::control/AWS-GR_CLOUDTRAIL_ENABLED -> CloudTrail
        - arn:aws:controlcatalog:::control/abc123 with alias CT.S3.PR.1 -> S3
        - Control identifier like AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP -> EC2
    """
    # Try extracting from control identifier patterns
    if 'CLOUDTRAIL' in control_id.upper():
        return 'CloudTrail'
    elif 'EC2' in control_id.upper():
        return 'EC2'
    elif 'S3' in control_id.upper():
        return 'S3'
    elif 'IAM' in control_id.upper():
        return 'IAM'
    elif 'LAMBDA' in control_id.upper():
        return 'Lambda'
    elif 'RDS' in control_id.upper():
        return 'RDS'
    elif 'VPC' in control_id.upper():
        return 'VPC'
    elif 'KMS' in control_id.upper():
        return 'KMS'
    elif 'CLOUDWATCH' in control_id.upper():
        return 'CloudWatch'
    elif 'CONFIG' in control_id.upper():
        return 'Config'
    elif 'SNS' in control_id.upper():
        return 'SNS'
    elif 'SQS' in control_id.upper():
        return 'SQS'
    elif 'BACKUP' in control_id.upper():
        return 'Backup'
    elif 'DYNAMODB' in control_id.upper():
        return 'DynamoDB'
    elif 'EBS' in control_id.upper():
        return 'EBS'
    elif 'ELB' in control_id.upper():
        return 'ELB'
    elif 'ELASTICLOADBALANCING' in control_id.upper():
        return 'ELB'
    elif 'REDSHIFT' in control_id.upper():
        return 'Redshift'
    elif 'SAGEMAKER' in control_id.upper():
        return 'SageMaker'
    elif 'SECRETSMANAGER' in control_id.upper():
        return 'Secrets Manager'
    elif 'ECS' in control_id.upper():
        return 'ECS'
    elif 'EKS' in control_id.upper():
        return 'EKS'
    elif 'APIGATEWAY' in control_id.upper() or 'API_GW' in control_id.upper():
        return 'API Gateway'
    elif 'CODEBUILD' in control_id.upper():
        return 'CodeBuild'
    elif 'CODEPIPELINE' in control_id.upper():
        return 'CodePipeline'
    elif 'OPENSEARCH' in control_id.upper() or 'ELASTICSEARCH' in control_id.upper():
        return 'OpenSearch'
    elif 'GUARDDUTY' in control_id.upper():
        return 'GuardDuty'
    elif 'SECURITYHUB' in control_id.upper():
        return 'Security Hub'
    else:
        return 'Other'


@utils.aws_error_handler("Collecting enabled controls", default_return=[])
def collect_enabled_controls(ous: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect enabled controls for all organizational units."""
    print("\n=== COLLECTING ENABLED CONTROLS ===")
    all_controls = []

    # Control Tower is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ct_client = utils.get_boto3_client('controltower', region_name=home_region)

    # Create controlcatalog client for getting control metadata
    catalog_client = utils.get_boto3_client('controlcatalog', region_name=home_region)

    total_ous = len(ous)
    for idx, ou in enumerate(ous, 1):
        ou_arn = ou.get('OU ARN', '')
        ou_name = ou.get('OU Name', '')
        ou_type = ou.get('Type', '')

        if not ou_arn:
            continue

        # Skip Root OU - Control Tower doesn't apply controls to Root
        if ou_type == 'Root':
            utils.log_info(f"[{idx}/{total_ous}] Skipping OU: {ou_name} (controls cannot be applied to Root)")
            continue

        utils.log_info(f"[{idx}/{total_ous}] Checking controls for OU: {ou_name}")

        try:
            # List enabled controls for this OU
            paginator = ct_client.get_paginator('list_enabled_controls')

            for page in paginator.paginate(targetIdentifier=ou_arn):
                enabled_controls = page.get('enabledControls', [])

                for control in enabled_controls:
                    control_id = control.get('controlIdentifier', 'N/A')
                    control_arn = control.get('arn', 'N/A')

                    # Status summary
                    status_summary = control.get('statusSummary', {})
                    status = status_summary.get('status', 'N/A')
                    last_operation = status_summary.get('lastOperationIdentifier', 'N/A')

                    # Drift status
                    drift_summary = control.get('driftStatusSummary', {})
                    drift_status = drift_summary.get('driftStatus', 'N/A')

                    # Drift types
                    drift_types = drift_summary.get('types', {})
                    inheritance_drift = drift_types.get('inheritance', {}).get('status', 'N/A')
                    resource_drift = drift_types.get('resource', {}).get('status', 'N/A')

                    # Initialize control metadata
                    control_name = control_id  # Default to identifier
                    control_description = 'N/A'
                    control_behavior = 'N/A'
                    control_guidance = 'N/A'
                    service_name = 'N/A'
                    params_str = 'None'

                    try:
                        # Get control details from GetEnabledControl for parameters
                        enabled_control_details = ct_client.get_enabled_control(
                            enabledControlIdentifier=control_arn
                        )

                        enabled_control = enabled_control_details.get('enabledControlDetails', {})

                        # Get parameters if available
                        parameters = enabled_control.get('parameters', [])
                        if parameters:
                            params_list = []
                            for param in parameters:
                                key = param.get('key', '')
                                value = param.get('value', '')
                                if key and value:
                                    params_list.append(f"{key}: {value}")
                            params_str = ', '.join(params_list) if params_list else 'None'

                    except Exception as e:
                        utils.log_warning(f"Could not get enabled control details for {control_id}: {str(e)}")

                    # Try to get control metadata from control catalog
                    try:
                        # Use controlcatalog client to get full metadata
                        catalog_response = catalog_client.get_control(ControlArn=control_id)

                        # Extract metadata from control catalog response
                        control_name = catalog_response.get('Name', control_id)
                        control_description = catalog_response.get('Description', 'N/A')
                        control_behavior = catalog_response.get('Behavior', 'N/A')

                        # Control catalog doesn't have "Guidance" field - this is Control Tower specific
                        # We'll need to infer it or mark as N/A
                        control_guidance = 'N/A'

                        # Extract service from aliases if available
                        aliases = catalog_response.get('Aliases', [])
                        if aliases:
                            # Aliases often have format like "CT.S3.PR.1" or "SH.S3.1"
                            for alias in aliases:
                                if '.' in alias:
                                    parts = alias.split('.')
                                    if len(parts) >= 2:
                                        service_name = parts[1]  # e.g., "S3" from "CT.S3.PR.1"
                                        break

                        # If service not found from alias, try extracting from control identifier
                        if service_name == 'N/A':
                            service_name = extract_service_from_control_identifier(control_id)

                    except Exception as e:
                        # Fallback: try extracting service from identifier even if catalog call fails
                        service_name = extract_service_from_control_identifier(control_id)
                        utils.log_warning(f"Could not get catalog details for control {control_id}: {str(e)}")

                    all_controls.append({
                        'OU Name': ou_name,
                        'OU ARN': ou_arn,
                        'Control Identifier': control_id,
                        'Service': service_name,
                        'Control Name': control_name,
                        'Control ARN': control_arn,
                        'Status': status,
                        'Drift Status': drift_status,
                        'Inheritance Drift': inheritance_drift,
                        'Resource Drift': resource_drift,
                        'Behavior': control_behavior,
                        'Guidance': control_guidance,
                        'Description': control_description,
                        'Parameters': params_str,
                        'Last Operation ID': last_operation
                    })

        except Exception as e:
            utils.log_warning(f"Error listing controls for OU {ou_name}: {str(e)}")
            continue

    utils.log_success(f"Total enabled controls collected: {len(all_controls)}")
    return all_controls


def generate_summary(landing_zone: Dict[str, Any],
                     ous: List[Dict[str, Any]],
                     controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Control Tower resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Landing zone summary
    if landing_zone:
        lz_status = landing_zone.get('Status', 'N/A')
        lz_version = landing_zone.get('Version', 'N/A')
        drift_status = landing_zone.get('Drift Status', 'N/A')

        summary.append({
            'Metric': 'Landing Zone Status',
            'Value': lz_status,
            'Details': f'Version: {lz_version}, Drift: {drift_status}'
        })

        governed_regions = landing_zone.get('Number of Governed Regions', 0)
        summary.append({
            'Metric': 'Governed Regions',
            'Value': governed_regions,
            'Details': landing_zone.get('Governed Regions', 'N/A')
        })

    # OUs summary
    summary.append({
        'Metric': 'Total Organizational Units',
        'Value': len(ous),
        'Details': 'Including Root and all nested OUs'
    })

    # Controls summary
    total_controls = len(controls)
    summary.append({
        'Metric': 'Total Enabled Controls',
        'Value': total_controls,
        'Details': 'Across all organizational units'
    })

    if controls:
        df = pd.DataFrame(controls)

        # Status breakdown
        if 'Status' in df.columns:
            succeeded = len(df[df['Status'] == 'SUCCEEDED'])
            failed = len(df[df['Status'] == 'FAILED'])
            summary.append({
                'Metric': 'Control Status',
                'Value': f'Success: {succeeded}, Failed: {failed}',
                'Details': f'{succeeded} controls successfully enabled'
            })

        # Drift status breakdown
        if 'Drift Status' in df.columns:
            drifted = len(df[df['Drift Status'] == 'DRIFTED'])
            in_sync = len(df[df['Drift Status'] == 'IN_SYNC'])
            summary.append({
                'Metric': 'Control Drift',
                'Value': f'Drifted: {drifted}, In Sync: {in_sync}',
                'Details': 'Drift indicates configuration changes outside Control Tower'
            })

        # Behavior breakdown
        if 'Behavior' in df.columns:
            behaviors = df['Behavior'].value_counts().to_dict()
            for behavior, count in behaviors.items():
                if behavior != 'N/A':
                    summary.append({
                        'Metric': f'{behavior} Controls',
                        'Value': count,
                        'Details': f'Controls with {behavior} behavior'
                    })

        # Guidance breakdown
        if 'Guidance' in df.columns:
            guidance_types = df['Guidance'].value_counts().to_dict()
            for guidance, count in guidance_types.items():
                if guidance != 'N/A':
                    summary.append({
                        'Metric': f'{guidance} Controls',
                        'Value': count,
                        'Details': f'Controls with {guidance} guidance level'
                    })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS Control Tower Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition and display appropriate messaging
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

    print(f"\nNote: AWS Control Tower is a global service in {partition_name}.")
    print("This script requires Control Tower to be set up and must be run from the management account.")
    print("\nRequired IAM Permissions:")
    print("  - controltower:ListLandingZones, controltower:GetLandingZone")
    print("  - controltower:ListEnabledControls, controltower:GetEnabledControl")
    print("  - controlcatalog:GetControl (for detailed control metadata)")
    print("  - organizations:ListRoots, organizations:ListOrganizationalUnitsForParent")

    if partition == 'aws-us-gov':
        print("\nGovCloud Limitations:")
        print("  - Audit and Log Archive accounts must pre-exist before Landing Zone setup")
        print("  - Account creation only via CreateGovCloudAccount API from Commercial region")
        print("  - Some controls have limited functionality in GovCloud")

    # Collect data
    print("\nCollecting AWS Control Tower configuration...")

    landing_zone = collect_landing_zone()

    if not landing_zone:
        utils.log_warning("No Control Tower landing zone found. Exiting.")
        return

    ous = collect_organizational_units()
    controls = collect_enabled_controls(ous)
    summary = generate_summary(landing_zone, ous, controls)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    # Add Enabled Controls first (user preference)
    if controls:
        df_controls = pd.DataFrame(controls)

        # Reorder columns for better readability
        column_order = [
            'OU Name',
            'OU ARN',
            'Control Identifier',
            'Control ARN',
            'Control Name',
            'Description',
            'Service',
            'Behavior',
            'Guidance',
            'Status',
            'Drift Status',
            'Inheritance Drift',
            'Resource Drift',
            'Parameters',
            'Last Operation ID'
        ]

        # Reorder columns (only include columns that exist)
        existing_columns = [col for col in column_order if col in df_controls.columns]
        df_controls = df_controls[existing_columns]

        df_controls = utils.prepare_dataframe_for_export(df_controls)
        dataframes['Enabled Controls'] = df_controls

        # Create filtered views for drifted and failed controls only
        df_drifted = df_controls[df_controls['Drift Status'] == 'DRIFTED']
        if not df_drifted.empty:
            dataframes['Drifted Controls'] = df_drifted

        df_failed = df_controls[df_controls['Status'] == 'FAILED']
        if not df_failed.empty:
            dataframes['Failed Controls'] = df_failed

    # Add Organizational Units second (user preference)
    if ous:
        df_ous = pd.DataFrame(ous)
        df_ous = utils.prepare_dataframe_for_export(df_ous)
        dataframes['Organizational Units'] = df_ous

    # Export to Excel
    if dataframes:
        filename = utils.create_export_filename(account_name, 'controltower', 'global')

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary using correct function signature
        total_resources = len(controls)
        utils.log_export_summary('Control Tower Resources', total_resources, filename)
    else:
        utils.log_warning("No Control Tower data found to export")

    utils.log_success("Control Tower export completed successfully")


if __name__ == "__main__":
    main()
