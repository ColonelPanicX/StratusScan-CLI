#!/usr/bin/env python3
"""
Amazon Comprehend Export Script for StratusScan

Exports comprehensive Amazon Comprehend natural language processing information including:
- Document classification jobs
- Entity recognition jobs
- Sentiment analysis jobs
- Custom entity recognizers
- Custom document classifiers
- Endpoints for real-time inference

Output: Multi-worksheet Excel file with Comprehend resources
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
@utils.aws_error_handler("Collecting Comprehend entity recognizers", default_return=[])
def collect_entity_recognizers(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect custom entity recognizer information from AWS regions."""
    all_recognizers = []

    for region in regions:
        utils.log_info(f"Collecting entity recognizers in {region}...")
        comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

        try:
            paginator = comprehend_client.get_paginator('list_entity_recognizers')
            for page in paginator.paginate():
                recognizers = page.get('EntityRecognizerPropertiesList', [])

                for recognizer in recognizers:
                    recognizer_arn = recognizer.get('EntityRecognizerArn', 'N/A')
                    language_code = recognizer.get('LanguageCode', 'N/A')
                    status = recognizer.get('Status', 'N/A')

                    submit_time = recognizer.get('SubmitTime', 'N/A')
                    if submit_time != 'N/A':
                        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

                    end_time = recognizer.get('EndTime', 'N/A')
                    if end_time != 'N/A':
                        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Training metrics
                    recognizer_metadata = recognizer.get('RecognizerMetadata', {})
                    number_of_trained_documents = recognizer_metadata.get('NumberOfTrainedDocuments', 0)
                    number_of_test_documents = recognizer_metadata.get('NumberOfTestDocuments', 0)

                    # Evaluation metrics
                    eval_metrics = recognizer_metadata.get('EvaluationMetrics', {})
                    precision = eval_metrics.get('Precision', 0)
                    recall = eval_metrics.get('Recall', 0)
                    f1_score = eval_metrics.get('F1Score', 0)

                    # Extract recognizer name from ARN
                    recognizer_name = 'N/A'
                    if recognizer_arn != 'N/A' and '/' in recognizer_arn:
                        recognizer_name = recognizer_arn.split('/')[-1]

                    # Data access role
                    data_access_role = recognizer.get('DataAccessRoleArn', 'N/A')

                    # Input config
                    input_config = recognizer.get('InputDataConfig', {})
                    input_s3_uri = input_config.get('DataFormat', 'N/A')

                    # Message
                    message = recognizer.get('Message', 'N/A')

                    all_recognizers.append({
                        'Region': region,
                        'Recognizer Name': recognizer_name,
                        'ARN': recognizer_arn,
                        'Language': language_code,
                        'Status': status,
                        'Submitted': submit_time,
                        'Ended': end_time,
                        'Trained Documents': number_of_trained_documents,
                        'Test Documents': number_of_test_documents,
                        'Precision': f"{precision:.4f}" if precision else 'N/A',
                        'Recall': f"{recall:.4f}" if recall else 'N/A',
                        'F1 Score': f"{f1_score:.4f}" if f1_score else 'N/A',
                        'Data Access Role ARN': data_access_role,
                        'Message': message
                    })

        except Exception as e:
            utils.log_warning(f"Error listing entity recognizers in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_recognizers)} entity recognizers")
    return all_recognizers


@utils.aws_error_handler("Collecting Comprehend document classifiers", default_return=[])
def collect_document_classifiers(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect custom document classifier information."""
    all_classifiers = []

    for region in regions:
        utils.log_info(f"Collecting document classifiers in {region}...")
        comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

        try:
            paginator = comprehend_client.get_paginator('list_document_classifiers')
            for page in paginator.paginate():
                classifiers = page.get('DocumentClassifierPropertiesList', [])

                for classifier in classifiers:
                    classifier_arn = classifier.get('DocumentClassifierArn', 'N/A')
                    language_code = classifier.get('LanguageCode', 'N/A')
                    status = classifier.get('Status', 'N/A')
                    mode = classifier.get('Mode', 'N/A')

                    submit_time = classifier.get('SubmitTime', 'N/A')
                    if submit_time != 'N/A':
                        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

                    end_time = classifier.get('EndTime', 'N/A')
                    if end_time != 'N/A':
                        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Training metrics
                    classifier_metadata = classifier.get('ClassifierMetadata', {})
                    number_of_labels = classifier_metadata.get('NumberOfLabels', 0)
                    number_of_trained_documents = classifier_metadata.get('NumberOfTrainedDocuments', 0)
                    number_of_test_documents = classifier_metadata.get('NumberOfTestDocuments', 0)

                    # Evaluation metrics
                    eval_metrics = classifier_metadata.get('EvaluationMetrics', {})
                    accuracy = eval_metrics.get('Accuracy', 0)
                    precision = eval_metrics.get('Precision', 0)
                    recall = eval_metrics.get('Recall', 0)
                    f1_score = eval_metrics.get('F1Score', 0)
                    micro_precision = eval_metrics.get('MicroPrecision', 0)
                    micro_recall = eval_metrics.get('MicroRecall', 0)
                    micro_f1 = eval_metrics.get('MicroF1Score', 0)

                    # Extract classifier name from ARN
                    classifier_name = 'N/A'
                    if classifier_arn != 'N/A' and '/' in classifier_arn:
                        classifier_name = classifier_arn.split('/')[-1]

                    # Data access role
                    data_access_role = classifier.get('DataAccessRoleArn', 'N/A')

                    # Message
                    message = classifier.get('Message', 'N/A')

                    all_classifiers.append({
                        'Region': region,
                        'Classifier Name': classifier_name,
                        'ARN': classifier_arn,
                        'Language': language_code,
                        'Mode': mode,
                        'Status': status,
                        'Submitted': submit_time,
                        'Ended': end_time,
                        'Number of Labels': number_of_labels,
                        'Trained Documents': number_of_trained_documents,
                        'Test Documents': number_of_test_documents,
                        'Accuracy': f"{accuracy:.4f}" if accuracy else 'N/A',
                        'Precision': f"{precision:.4f}" if precision else 'N/A',
                        'Recall': f"{recall:.4f}" if recall else 'N/A',
                        'F1 Score': f"{f1_score:.4f}" if f1_score else 'N/A',
                        'Micro Precision': f"{micro_precision:.4f}" if micro_precision else 'N/A',
                        'Micro Recall': f"{micro_recall:.4f}" if micro_recall else 'N/A',
                        'Micro F1': f"{micro_f1:.4f}" if micro_f1 else 'N/A',
                        'Data Access Role ARN': data_access_role,
                        'Message': message
                    })

        except Exception as e:
            utils.log_warning(f"Error listing document classifiers in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_classifiers)} document classifiers")
    return all_classifiers


@utils.aws_error_handler("Collecting Comprehend endpoints", default_return=[])
def collect_endpoints(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Comprehend endpoint information for real-time inference."""
    all_endpoints = []

    for region in regions:
        utils.log_info(f"Collecting endpoints in {region}...")
        comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

        try:
            paginator = comprehend_client.get_paginator('list_endpoints')
            for page in paginator.paginate():
                endpoints = page.get('EndpointPropertiesList', [])

                for endpoint in endpoints:
                    endpoint_arn = endpoint.get('EndpointArn', 'N/A')
                    status = endpoint.get('Status', 'N/A')

                    # Model ARN
                    model_arn = endpoint.get('ModelArn', 'N/A')

                    # Extract model type
                    model_type = 'N/A'
                    if 'entity-recognizer' in model_arn:
                        model_type = 'Entity Recognizer'
                    elif 'document-classifier' in model_arn:
                        model_type = 'Document Classifier'

                    # Extract endpoint name from ARN
                    endpoint_name = 'N/A'
                    if endpoint_arn != 'N/A' and '/' in endpoint_arn:
                        endpoint_name = endpoint_arn.split('/')[-1]

                    # Desired inference units
                    desired_inference_units = endpoint.get('DesiredInferenceUnits', 0)
                    current_inference_units = endpoint.get('CurrentInferenceUnits', 0)

                    # Desired model ARN
                    desired_model_arn = endpoint.get('DesiredModelArn', model_arn)

                    creation_time = endpoint.get('CreationTime', 'N/A')
                    if creation_time != 'N/A':
                        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                    last_modified = endpoint.get('LastModifiedTime', 'N/A')
                    if last_modified != 'N/A':
                        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                    # Data access role
                    data_access_role = endpoint.get('DataAccessRoleArn', 'N/A')

                    # Message
                    message = endpoint.get('Message', 'N/A')

                    all_endpoints.append({
                        'Region': region,
                        'Endpoint Name': endpoint_name,
                        'ARN': endpoint_arn,
                        'Status': status,
                        'Model Type': model_type,
                        'Model ARN': model_arn,
                        'Created': creation_time,
                        'Last Modified': last_modified,
                        'Desired Inference Units': desired_inference_units,
                        'Current Inference Units': current_inference_units,
                        'Data Access Role ARN': data_access_role,
                        'Message': message
                    })

        except Exception as e:
            utils.log_warning(f"Error listing endpoints in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_endpoints)} endpoints")
    return all_endpoints


@utils.aws_error_handler("Collecting Comprehend document classification jobs", default_return=[])
def collect_document_classification_jobs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect document classification job information (limited to recent 30 per region)."""
    all_jobs = []

    for region in regions:
        utils.log_info(f"Collecting document classification jobs in {region}...")
        comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

        try:
            # List recent jobs (limit to 30)
            paginator = comprehend_client.get_paginator('list_document_classification_jobs')
            job_count = 0
            for page in paginator.paginate(PaginationConfig={'MaxItems': 30}):
                jobs = page.get('DocumentClassificationJobPropertiesList', [])

                for job in jobs:
                    job_id = job.get('JobId', 'N/A')
                    job_name = job.get('JobName', 'N/A')
                    job_status = job.get('JobStatus', 'N/A')

                    submit_time = job.get('SubmitTime', 'N/A')
                    if submit_time != 'N/A':
                        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

                    end_time = job.get('EndTime', 'N/A')
                    if end_time != 'N/A':
                        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Document classifier ARN
                    document_classifier_arn = job.get('DocumentClassifierArn', 'N/A')

                    # Input config
                    input_config = job.get('InputDataConfig', {})
                    input_s3_uri = input_config.get('S3Uri', 'N/A')

                    # Output config
                    output_config = job.get('OutputDataConfig', {})
                    output_s3_uri = output_config.get('S3Uri', 'N/A')

                    # Data access role
                    data_access_role = job.get('DataAccessRoleArn', 'N/A')

                    # Message
                    message = job.get('Message', 'N/A')

                    all_jobs.append({
                        'Region': region,
                        'Job ID': job_id,
                        'Job Name': job_name,
                        'Status': job_status,
                        'Submitted': submit_time,
                        'Ended': end_time,
                        'Document Classifier ARN': document_classifier_arn,
                        'Input S3 URI': input_s3_uri,
                        'Output S3 URI': output_s3_uri,
                        'Data Access Role ARN': data_access_role,
                        'Message': message
                    })

                    job_count += 1
                    if job_count >= 30:
                        break

        except Exception as e:
            utils.log_warning(f"Error listing document classification jobs in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_jobs)} document classification jobs (limited to 30 most recent per region)")
    return all_jobs


@utils.aws_error_handler("Collecting Comprehend entities detection jobs", default_return=[])
def collect_entities_detection_jobs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect entities detection job information (limited to recent 30 per region)."""
    all_jobs = []

    for region in regions:
        utils.log_info(f"Collecting entities detection jobs in {region}...")
        comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

        try:
            # List recent jobs (limit to 30)
            paginator = comprehend_client.get_paginator('list_entities_detection_jobs')
            job_count = 0
            for page in paginator.paginate(PaginationConfig={'MaxItems': 30}):
                jobs = page.get('EntitiesDetectionJobPropertiesList', [])

                for job in jobs:
                    job_id = job.get('JobId', 'N/A')
                    job_name = job.get('JobName', 'N/A')
                    job_status = job.get('JobStatus', 'N/A')
                    language_code = job.get('LanguageCode', 'N/A')

                    submit_time = job.get('SubmitTime', 'N/A')
                    if submit_time != 'N/A':
                        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

                    end_time = job.get('EndTime', 'N/A')
                    if end_time != 'N/A':
                        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Entity recognizer ARN (if custom)
                    entity_recognizer_arn = job.get('EntityRecognizerArn', 'Built-in')

                    # Input config
                    input_config = job.get('InputDataConfig', {})
                    input_s3_uri = input_config.get('S3Uri', 'N/A')

                    # Output config
                    output_config = job.get('OutputDataConfig', {})
                    output_s3_uri = output_config.get('S3Uri', 'N/A')

                    # Data access role
                    data_access_role = job.get('DataAccessRoleArn', 'N/A')

                    # Message
                    message = job.get('Message', 'N/A')

                    all_jobs.append({
                        'Region': region,
                        'Job ID': job_id,
                        'Job Name': job_name,
                        'Status': job_status,
                        'Language': language_code,
                        'Submitted': submit_time,
                        'Ended': end_time,
                        'Entity Recognizer ARN': entity_recognizer_arn,
                        'Input S3 URI': input_s3_uri,
                        'Output S3 URI': output_s3_uri,
                        'Data Access Role ARN': data_access_role,
                        'Message': message
                    })

                    job_count += 1
                    if job_count >= 30:
                        break

        except Exception as e:
            utils.log_warning(f"Error listing entities detection jobs in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_jobs)} entities detection jobs (limited to 30 most recent per region)")
    return all_jobs


def generate_summary(recognizers: List[Dict[str, Any]],
                     classifiers: List[Dict[str, Any]],
                     endpoints: List[Dict[str, Any]],
                     classification_jobs: List[Dict[str, Any]],
                     entities_jobs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Comprehend resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Entity recognizers
    total_recognizers = len(recognizers)
    trained_recognizers = sum(1 for r in recognizers if r.get('Status', '') == 'TRAINED')

    summary.append({
        'Metric': 'Total Entity Recognizers',
        'Count': total_recognizers,
        'Details': f'Trained: {trained_recognizers}'
    })

    # Document classifiers
    total_classifiers = len(classifiers)
    trained_classifiers = sum(1 for c in classifiers if c.get('Status', '') == 'TRAINED')

    summary.append({
        'Metric': 'Total Document Classifiers',
        'Count': total_classifiers,
        'Details': f'Trained: {trained_classifiers}'
    })

    # Endpoints
    total_endpoints = len(endpoints)
    in_service_endpoints = sum(1 for e in endpoints if e.get('Status', '') == 'IN_SERVICE')

    summary.append({
        'Metric': 'Total Endpoints',
        'Count': total_endpoints,
        'Details': f'In Service: {in_service_endpoints}'
    })

    # Classification jobs
    total_classification = len(classification_jobs)
    completed_classification = sum(1 for j in classification_jobs if j.get('Status', '') == 'COMPLETED')

    summary.append({
        'Metric': 'Document Classification Jobs (Sample)',
        'Count': total_classification,
        'Details': f'Completed: {completed_classification}'
    })

    # Entities detection jobs
    total_entities = len(entities_jobs)
    completed_entities = sum(1 for j in entities_jobs if j.get('Status', '') == 'COMPLETED')

    summary.append({
        'Metric': 'Entities Detection Jobs (Sample)',
        'Count': total_entities,
        'Details': f'Completed: {completed_entities}'
    })

    # Language distribution
    if recognizers:
        df = pd.DataFrame(recognizers)
        languages = df['Language'].value_counts().to_dict()
        for language, count in languages.items():
            summary.append({
                'Metric': f'Entity Recognizers - {language}',
                'Count': count,
                'Details': 'Language distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("Amazon Comprehend Export Tool")
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
    print("\nAmazon Comprehend is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where Amazon Comprehend is available)")
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
    print("\nCollecting Amazon Comprehend data...")

    recognizers = collect_entity_recognizers(regions)
    classifiers = collect_document_classifiers(regions)
    endpoints = collect_endpoints(regions)
    classification_jobs = collect_document_classification_jobs(regions)
    entities_jobs = collect_entities_detection_jobs(regions)
    summary = generate_summary(recognizers, classifiers, endpoints,
                                classification_jobs, entities_jobs)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if recognizers:
        df_recognizers = pd.DataFrame(recognizers)
        df_recognizers = utils.prepare_dataframe_for_export(df_recognizers)
        dataframes['Entity Recognizers'] = df_recognizers

    if classifiers:
        df_classifiers = pd.DataFrame(classifiers)
        df_classifiers = utils.prepare_dataframe_for_export(df_classifiers)
        dataframes['Document Classifiers'] = df_classifiers

    if endpoints:
        df_endpoints = pd.DataFrame(endpoints)
        df_endpoints = utils.prepare_dataframe_for_export(df_endpoints)
        dataframes['Endpoints'] = df_endpoints

    if classification_jobs:
        df_classification = pd.DataFrame(classification_jobs)
        df_classification = utils.prepare_dataframe_for_export(df_classification)
        dataframes['Classification Jobs'] = df_classification

    if entities_jobs:
        df_entities = pd.DataFrame(entities_jobs)
        df_entities = utils.prepare_dataframe_for_export(df_entities)
        dataframes['Entities Detection Jobs'] = df_entities

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'comprehend', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Entity Recognizers': len(recognizers),
            'Document Classifiers': len(classifiers),
            'Endpoints': len(endpoints),
            'Classification Jobs': len(classification_jobs),
            'Entities Detection Jobs': len(entities_jobs)
        })
    else:
        utils.log_warning("No Amazon Comprehend data found to export")

    utils.log_success("Amazon Comprehend export completed successfully")


if __name__ == "__main__":
    main()
