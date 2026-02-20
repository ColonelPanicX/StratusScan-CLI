#!/usr/bin/env python3
"""
Amazon Rekognition Export Script for StratusScan

Exports comprehensive Amazon Rekognition computer vision information including:
- Custom models (projects and project versions)
- Face collections for facial recognition
- Stream processors for video analysis
- Datasets for model training

Output: Multi-worksheet Excel file with Rekognition resources
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
@utils.aws_error_handler("Collecting Rekognition projects", default_return=[])
def collect_projects(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Rekognition custom model projects from AWS regions."""
    all_projects = []

    for region in regions:
        utils.log_info(f"Collecting Rekognition projects in {region}...")
        rekognition_client = utils.get_boto3_client('rekognition', region_name=region)

        try:
            paginator = rekognition_client.get_paginator('describe_projects')
            for page in paginator.paginate():
                projects = page.get('ProjectDescriptions', [])

                for project in projects:
                    project_arn = project.get('ProjectArn', 'N/A')
                    creation_timestamp = project.get('CreationTimestamp', 'N/A')
                    status = project.get('Status', 'N/A')

                    if creation_timestamp != 'N/A':
                        creation_timestamp = creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')

                    # Extract project name from ARN
                    # ARN format: arn:aws:rekognition:region:account-id:project/project-name/timestamp
                    project_name = 'N/A'
                    if project_arn != 'N/A' and '/project/' in project_arn:
                        parts = project_arn.split('/project/')
                        if len(parts) > 1:
                            project_name = parts[1].split('/')[0]

                    all_projects.append({
                        'Region': region,
                        'Project Name': project_name,
                        'Project ARN': project_arn,
                        'Status': status,
                        'Created': creation_timestamp
                    })

        except Exception as e:
            utils.log_warning(f"Error listing Rekognition projects in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_projects)} projects")
    return all_projects


@utils.aws_error_handler("Collecting Rekognition project versions", default_return=[])
def collect_project_versions(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Rekognition project versions (trained models)."""
    all_versions = []

    for region in regions:
        utils.log_info(f"Collecting project versions in {region}...")
        rekognition_client = utils.get_boto3_client('rekognition', region_name=region)

        try:
            # First get all projects
            project_paginator = rekognition_client.get_paginator('describe_projects')
            for project_page in project_paginator.paginate():
                projects = project_page.get('ProjectDescriptions', [])

                for project in projects:
                    project_arn = project.get('ProjectArn', 'N/A')
                    project_name = 'N/A'
                    if project_arn != 'N/A' and '/project/' in project_arn:
                        parts = project_arn.split('/project/')
                        if len(parts) > 1:
                            project_name = parts[1].split('/')[0]

                    # Get versions for this project
                    try:
                        version_paginator = rekognition_client.get_paginator('describe_project_versions')
                        for version_page in version_paginator.paginate(ProjectArn=project_arn):
                            versions = version_page.get('ProjectVersionDescriptions', [])

                            for version in versions:
                                version_arn = version.get('ProjectVersionArn', 'N/A')
                                status = version.get('Status', 'N/A')

                                creation_timestamp = version.get('CreationTimestamp', 'N/A')
                                if creation_timestamp != 'N/A':
                                    creation_timestamp = creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')

                                # Training metrics
                                evaluation_result = version.get('EvaluationResult', {})
                                f1_score = evaluation_result.get('F1Score', 'N/A')
                                summary = evaluation_result.get('Summary', {})
                                s3_object = summary.get('S3Object', {})
                                eval_manifest_s3 = s3_object.get('Name', 'N/A')

                                # Training details
                                training_end = version.get('TrainingEndTimestamp', 'N/A')
                                if training_end != 'N/A':
                                    training_end = training_end.strftime('%Y-%m-%d %H:%M:%S')

                                # Billable training time
                                billable_training_time = version.get('BillableTrainingTimeInSeconds', 0)
                                billable_hours = billable_training_time / 3600 if billable_training_time else 0

                                # Output config
                                output_config = version.get('OutputConfig', {})
                                output_s3_bucket = output_config.get('S3Bucket', 'N/A')

                                # Status message
                                status_message = version.get('StatusMessage', 'N/A')

                                # Min inference units
                                min_inference_units = version.get('MinInferenceUnits', 'N/A')

                                all_versions.append({
                                    'Region': region,
                                    'Project Name': project_name,
                                    'Version ARN': version_arn,
                                    'Status': status,
                                    'Created': creation_timestamp,
                                    'Training End': training_end,
                                    'Billable Training Hours': f"{billable_hours:.2f}" if billable_hours else 'N/A',
                                    'F1 Score': f"{f1_score:.4f}" if isinstance(f1_score, (int, float)) else f1_score,
                                    'Min Inference Units': min_inference_units,
                                    'Output S3 Bucket': output_s3_bucket,
                                    'Status Message': status_message
                                })

                    except Exception as e:
                        utils.log_warning(f"Could not get versions for project {project_arn}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error collecting project versions in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_versions)} project versions")
    return all_versions


@utils.aws_error_handler("Collecting Rekognition collections", default_return=[])
def collect_collections(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Rekognition face collections."""
    all_collections = []

    for region in regions:
        utils.log_info(f"Collecting face collections in {region}...")
        rekognition_client = utils.get_boto3_client('rekognition', region_name=region)

        try:
            paginator = rekognition_client.get_paginator('list_collections')
            for page in paginator.paginate():
                collection_ids = page.get('CollectionIds', [])
                face_model_versions = page.get('FaceModelVersions', [])

                for idx, collection_id in enumerate(collection_ids):
                    face_model_version = face_model_versions[idx] if idx < len(face_model_versions) else 'N/A'

                    # Get collection details
                    try:
                        collection_response = rekognition_client.describe_collection(
                            CollectionId=collection_id
                        )

                        face_count = collection_response.get('FaceCount', 0)
                        collection_arn = collection_response.get('CollectionARN', 'N/A')
                        creation_timestamp = collection_response.get('CreationTimestamp', 'N/A')

                        if creation_timestamp != 'N/A':
                            creation_timestamp = creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')

                        all_collections.append({
                            'Region': region,
                            'Collection ID': collection_id,
                            'Collection ARN': collection_arn,
                            'Face Count': face_count,
                            'Face Model Version': face_model_version,
                            'Created': creation_timestamp
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not describe collection {collection_id}: {str(e)}")
                        # Add basic info
                        all_collections.append({
                            'Region': region,
                            'Collection ID': collection_id,
                            'Collection ARN': 'N/A',
                            'Face Count': 0,
                            'Face Model Version': face_model_version,
                            'Created': 'N/A'
                        })

        except Exception as e:
            utils.log_warning(f"Error listing collections in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_collections)} face collections")
    return all_collections


@utils.aws_error_handler("Collecting Rekognition stream processors", default_return=[])
def collect_stream_processors(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Rekognition stream processors for video analysis."""
    all_processors = []

    for region in regions:
        utils.log_info(f"Collecting stream processors in {region}...")
        rekognition_client = utils.get_boto3_client('rekognition', region_name=region)

        try:
            paginator = rekognition_client.get_paginator('list_stream_processors')
            for page in paginator.paginate():
                processors = page.get('StreamProcessors', [])

                for processor_summary in processors:
                    processor_name = processor_summary.get('Name', 'N/A')
                    status = processor_summary.get('Status', 'N/A')

                    # Get detailed processor information
                    try:
                        processor_response = rekognition_client.describe_stream_processor(
                            Name=processor_name
                        )

                        processor_arn = processor_response.get('StreamProcessorArn', 'N/A')
                        creation_timestamp = processor_response.get('CreationTimestamp', 'N/A')

                        if creation_timestamp != 'N/A':
                            creation_timestamp = creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')

                        last_update = processor_response.get('LastUpdateTimestamp', 'N/A')
                        if last_update != 'N/A':
                            last_update = last_update.strftime('%Y-%m-%d %H:%M:%S')

                        # Input config
                        input_config = processor_response.get('Input', {})
                        kinesis_video_stream = input_config.get('KinesisVideoStream', {})
                        input_stream_arn = kinesis_video_stream.get('Arn', 'N/A')

                        # Output config
                        output_config = processor_response.get('Output', {})
                        kinesis_data_stream = output_config.get('KinesisDataStream', {})
                        output_stream_arn = kinesis_data_stream.get('Arn', 'N/A')

                        # Settings
                        settings = processor_response.get('Settings', {})

                        # Face search settings
                        face_search = settings.get('FaceSearch', {})
                        collection_id = face_search.get('CollectionId', 'N/A')
                        face_match_threshold = face_search.get('FaceMatchThreshold', 'N/A')

                        # Connected home settings
                        connected_home = settings.get('ConnectedHome', {})
                        connected_home_labels = connected_home.get('Labels', [])
                        connected_home_enabled = len(connected_home_labels) > 0

                        # Role ARN
                        role_arn = processor_response.get('RoleArn', 'N/A')

                        # Status message
                        status_message = processor_response.get('StatusMessage', 'N/A')

                        all_processors.append({
                            'Region': region,
                            'Processor Name': processor_name,
                            'ARN': processor_arn,
                            'Status': status,
                            'Created': creation_timestamp,
                            'Last Updated': last_update,
                            'Input Stream ARN': input_stream_arn,
                            'Output Stream ARN': output_stream_arn,
                            'Face Collection ID': collection_id,
                            'Face Match Threshold': face_match_threshold,
                            'Connected Home Enabled': connected_home_enabled,
                            'Role ARN': role_arn,
                            'Status Message': status_message
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not describe stream processor {processor_name}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error listing stream processors in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_processors)} stream processors")
    return all_processors


def generate_summary(projects: List[Dict[str, Any]],
                     versions: List[Dict[str, Any]],
                     collections: List[Dict[str, Any]],
                     stream_processors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Rekognition resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Projects summary
    total_projects = len(projects)
    summary.append({
        'Metric': 'Total Custom Model Projects',
        'Count': total_projects,
        'Details': 'Custom Label Detection and PPE Detection projects'
    })

    # Project versions
    total_versions = len(versions)
    trained_versions = sum(1 for v in versions if v.get('Status', '') == 'TRAINING_COMPLETED')
    running_versions = sum(1 for v in versions if v.get('Status', '') == 'RUNNING')

    summary.append({
        'Metric': 'Total Project Versions',
        'Count': total_versions,
        'Details': f'Trained: {trained_versions}, Running: {running_versions}'
    })

    # Collections summary
    total_collections = len(collections)
    total_faces = sum(c.get('Face Count', 0) for c in collections)

    summary.append({
        'Metric': 'Total Face Collections',
        'Count': total_collections,
        'Details': f'Total indexed faces: {total_faces:,}'
    })

    # Stream processors
    total_processors = len(stream_processors)
    running_processors = sum(1 for p in stream_processors if p.get('Status', '') == 'RUNNING')

    summary.append({
        'Metric': 'Total Stream Processors',
        'Count': total_processors,
        'Details': f'Running: {running_processors}'
    })

    # Regional distribution
    if projects:
        df = pd.DataFrame(projects)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Projects in {region}',
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
    print("Amazon Rekognition Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

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
    print("\nAmazon Rekognition is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where Amazon Rekognition is available)")
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
    print("\nCollecting Amazon Rekognition data...")

    projects = collect_projects(regions)
    versions = collect_project_versions(regions)
    collections = collect_collections(regions)
    stream_processors = collect_stream_processors(regions)
    summary = generate_summary(projects, versions, collections, stream_processors)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if projects:
        df_projects = pd.DataFrame(projects)
        df_projects = utils.prepare_dataframe_for_export(df_projects)
        dataframes['Projects'] = df_projects

    if versions:
        df_versions = pd.DataFrame(versions)
        df_versions = utils.prepare_dataframe_for_export(df_versions)
        dataframes['Project Versions'] = df_versions

    if collections:
        df_collections = pd.DataFrame(collections)
        df_collections = utils.prepare_dataframe_for_export(df_collections)
        dataframes['Face Collections'] = df_collections

    if stream_processors:
        df_processors = pd.DataFrame(stream_processors)
        df_processors = utils.prepare_dataframe_for_export(df_processors)
        dataframes['Stream Processors'] = df_processors

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'rekognition', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Projects': len(projects),
            'Project Versions': len(versions),
            'Face Collections': len(collections),
            'Stream Processors': len(stream_processors)
        })
    else:
        utils.log_warning("No Amazon Rekognition data found to export")

    utils.log_success("Amazon Rekognition export completed successfully")


if __name__ == "__main__":
    main()
