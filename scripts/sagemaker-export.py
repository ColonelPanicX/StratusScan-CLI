#!/usr/bin/env python3
"""
SageMaker Export Script for StratusScan

Exports comprehensive Amazon SageMaker machine learning information including:
- Notebook instances for ML development
- Training jobs and model training configurations
- Models and model packages
- Endpoints and endpoint configurations for inference
- Processing jobs for data processing
- Transform jobs for batch inference

Output: Multi-worksheet Excel file with SageMaker resources
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


def _scan_notebook_instances_region(region: str) -> List[Dict[str, Any]]:
    """Scan SageMaker notebook instances in a single region."""
    regional_notebooks = []

    try:
        sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

        try:
            paginator = sagemaker_client.get_paginator('list_notebook_instances')
            for page in paginator.paginate():
                notebooks = page.get('NotebookInstances', [])

                for notebook in notebooks:
                    notebook_name = notebook.get('NotebookInstanceName', 'N/A')

                    # Get detailed notebook information
                    try:
                        notebook_response = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=notebook_name
                        )

                        instance_type = notebook_response.get('InstanceType', 'N/A')
                        status = notebook_response.get('NotebookInstanceStatus', 'N/A')
                        arn = notebook_response.get('NotebookInstanceArn', 'N/A')

                        creation_time = notebook_response.get('CreationTime', 'N/A')
                        if creation_time != 'N/A':
                            creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                        last_modified = notebook_response.get('LastModifiedTime', 'N/A')
                        if last_modified != 'N/A':
                            last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                        # Network configuration
                        subnet_id = notebook_response.get('SubnetId', 'N/A')
                        security_groups = notebook_response.get('SecurityGroups', [])
                        security_groups_str = ', '.join(security_groups) if security_groups else 'None'

                        # Access settings
                        direct_internet_access = notebook_response.get('DirectInternetAccess', 'Enabled')
                        root_access = notebook_response.get('RootAccess', 'Enabled')

                        # IAM role
                        role_arn = notebook_response.get('RoleArn', 'N/A')

                        # Volume settings
                        volume_size_gb = notebook_response.get('VolumeSizeInGB', 'N/A')

                        # Platform identifier
                        platform_identifier = notebook_response.get('PlatformIdentifier', 'N/A')

                        # URL
                        url = notebook_response.get('Url', 'N/A')

                        # Lifecycle config
                        lifecycle_config = notebook_response.get('NotebookInstanceLifecycleConfigName', 'None')

                        # KMS key
                        kms_key = notebook_response.get('KmsKeyId', 'None')

                        # Failure reason
                        failure_reason = notebook_response.get('FailureReason', 'N/A')

                        regional_notebooks.append({
                            'Region': region,
                            'Notebook Name': notebook_name,
                            'ARN': arn,
                            'Status': status,
                            'Instance Type': instance_type,
                            'Platform': platform_identifier,
                            'Created': creation_time,
                            'Last Modified': last_modified,
                            'Volume Size (GB)': volume_size_gb,
                            'Direct Internet Access': direct_internet_access,
                            'Root Access': root_access,
                            'Subnet ID': subnet_id,
                            'Security Groups': security_groups_str,
                            'IAM Role ARN': role_arn,
                            'Lifecycle Config': lifecycle_config,
                            'KMS Key': kms_key,
                            'URL': url,
                            'Failure Reason': failure_reason
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get details for notebook {notebook_name} in {region}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error listing notebook instances in {region}: {str(e)}")

    except Exception as e:
        utils.log_error(f"Error collecting notebook instances in {region}", e)

    return regional_notebooks


@utils.aws_error_handler("Collecting SageMaker notebook instances", default_return=[])
def collect_notebook_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SageMaker notebook instance information from AWS regions."""
    print("\n=== COLLECTING SAGEMAKER NOTEBOOK INSTANCES ===")
    results = utils.scan_regions_concurrent(regions, _scan_notebook_instances_region)
    all_notebooks = [nb for result in results for nb in result]
    utils.log_success(f"Total notebook instances collected: {len(all_notebooks)}")
    return all_notebooks


def _scan_training_jobs_region(region: str) -> List[Dict[str, Any]]:
    """Scan SageMaker training jobs in a single region (limited to 50 most recent)."""
    regional_jobs = []

    try:
        sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

        try:
            # List recent training jobs (limit to 50)
            paginator = sagemaker_client.get_paginator('list_training_jobs')
            job_count = 0
            for page in paginator.paginate(
                SortBy='CreationTime',
                SortOrder='Descending',
                PaginationConfig={'MaxItems': 50}
            ):
                jobs = page.get('TrainingJobSummaries', [])

                for job in jobs:
                    job_name = job.get('TrainingJobName', 'N/A')

                    # Get detailed job information
                    try:
                        job_response = sagemaker_client.describe_training_job(
                            TrainingJobName=job_name
                        )

                        status = job_response.get('TrainingJobStatus', 'N/A')
                        arn = job_response.get('TrainingJobArn', 'N/A')

                        creation_time = job_response.get('CreationTime', 'N/A')
                        if creation_time != 'N/A':
                            creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                        training_start = job_response.get('TrainingStartTime', 'N/A')
                        if training_start != 'N/A':
                            training_start = training_start.strftime('%Y-%m-%d %H:%M:%S')

                        training_end = job_response.get('TrainingEndTime', 'N/A')
                        if training_end != 'N/A':
                            training_end = training_end.strftime('%Y-%m-%d %H:%M:%S')

                        # Training duration
                        training_time_seconds = job_response.get('TrainingTimeInSeconds', 0)
                        training_time_str = f"{training_time_seconds / 60:.1f} minutes" if training_time_seconds else 'N/A'

                        # Billable time
                        billable_seconds = job_response.get('BillableTimeInSeconds', 0)
                        billable_time_str = f"{billable_seconds / 60:.1f} minutes" if billable_seconds else 'N/A'

                        # Algorithm
                        algorithm_spec = job_response.get('AlgorithmSpecification', {})
                        training_image = algorithm_spec.get('TrainingImage', 'N/A')
                        algorithm_name = algorithm_spec.get('AlgorithmName', 'N/A')

                        # Extract algorithm type from image
                        algorithm_type = 'Custom'
                        if 'xgboost' in training_image.lower():
                            algorithm_type = 'XGBoost'
                        elif 'blazingtext' in training_image.lower():
                            algorithm_type = 'BlazingText'
                        elif 'linear-learner' in training_image.lower():
                            algorithm_type = 'Linear Learner'
                        elif algorithm_name != 'N/A':
                            algorithm_type = algorithm_name

                        # Resource config
                        resource_config = job_response.get('ResourceConfig', {})
                        instance_type = resource_config.get('InstanceType', 'N/A')
                        instance_count = resource_config.get('InstanceCount', 0)
                        volume_size_gb = resource_config.get('VolumeSizeInGB', 'N/A')

                        # Hyperparameters
                        hyperparameters = job_response.get('HyperParameters', {})
                        hyperparam_count = len(hyperparameters)

                        # Metrics
                        final_metrics = job_response.get('FinalMetricDataList', [])
                        metric_count = len(final_metrics)

                        # Output
                        model_artifacts = job_response.get('ModelArtifacts', {})
                        s3_model_artifacts = model_artifacts.get('S3ModelArtifacts', 'N/A')

                        # Failure reason
                        failure_reason = job_response.get('FailureReason', 'N/A')

                        regional_jobs.append({
                            'Region': region,
                            'Job Name': job_name,
                            'ARN': arn,
                            'Status': status,
                            'Algorithm Type': algorithm_type,
                            'Instance Type': instance_type,
                            'Instance Count': instance_count,
                            'Volume Size (GB)': volume_size_gb,
                            'Created': creation_time,
                            'Training Start': training_start,
                            'Training End': training_end,
                            'Training Time': training_time_str,
                            'Billable Time': billable_time_str,
                            'Hyperparameters': hyperparam_count,
                            'Final Metrics': metric_count,
                            'Model Artifacts': s3_model_artifacts,
                            'Failure Reason': failure_reason
                        })

                        job_count += 1

                    except Exception as e:
                        utils.log_warning(f"Could not get details for training job {job_name}: {str(e)}")
                        continue

                if job_count >= 50:
                    break

        except Exception as e:
            utils.log_warning(f"Error listing training jobs in {region}: {str(e)}")

    except Exception as e:
        utils.log_error(f"Error collecting training jobs in {region}", e)

    return regional_jobs


@utils.aws_error_handler("Collecting SageMaker training jobs", default_return=[])
def collect_training_jobs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SageMaker training job information (limited to recent 50 per region)."""
    print("\n=== COLLECTING SAGEMAKER TRAINING JOBS ===")
    results = utils.scan_regions_concurrent(regions, _scan_training_jobs_region)
    all_jobs = [job for result in results for job in result]
    utils.log_success(f"Total training jobs collected: {len(all_jobs)} (limited to 50 per region)")
    return all_jobs


def _scan_models_region(region: str) -> List[Dict[str, Any]]:
    """Scan SageMaker models in a single region."""
    regional_models = []

    try:
        sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

        try:
            paginator = sagemaker_client.get_paginator('list_models')
            for page in paginator.paginate():
                models = page.get('Models', [])

                for model in models:
                    model_name = model.get('ModelName', 'N/A')

                    # Get detailed model information
                    try:
                        model_response = sagemaker_client.describe_model(ModelName=model_name)

                        arn = model_response.get('ModelArn', 'N/A')
                        role_arn = model_response.get('ExecutionRoleArn', 'N/A')

                        creation_time = model_response.get('CreationTime', 'N/A')
                        if creation_time != 'N/A':
                            creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                        # Primary container
                        primary_container = model_response.get('PrimaryContainer', {})
                        container_image = primary_container.get('Image', 'N/A')
                        model_data_url = primary_container.get('ModelDataUrl', 'N/A')
                        container_mode = primary_container.get('Mode', 'N/A')

                        # VPC config
                        vpc_config = model_response.get('VpcConfig', {})
                        subnets = vpc_config.get('Subnets', [])
                        security_groups = vpc_config.get('SecurityGroupIds', [])
                        vpc_enabled = 'Yes' if subnets else 'No'

                        # Network isolation
                        enable_network_isolation = model_response.get('EnableNetworkIsolation', False)

                        # Containers
                        containers = model_response.get('Containers', [])
                        container_count = len(containers) if containers else (1 if primary_container else 0)

                        regional_models.append({
                            'Region': region,
                            'Model Name': model_name,
                            'ARN': arn,
                            'Created': creation_time,
                            'Execution Role ARN': role_arn,
                            'Container Image': container_image,
                            'Model Data URL': model_data_url,
                            'Container Mode': container_mode,
                            'Container Count': container_count,
                            'VPC Enabled': vpc_enabled,
                            'Network Isolation': enable_network_isolation
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get details for model {model_name}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error listing models in {region}: {str(e)}")

    except Exception as e:
        utils.log_error(f"Error collecting models in {region}", e)

    return regional_models


@utils.aws_error_handler("Collecting SageMaker models", default_return=[])
def collect_models(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SageMaker model information."""
    print("\n=== COLLECTING SAGEMAKER MODELS ===")
    results = utils.scan_regions_concurrent(regions, _scan_models_region)
    all_models = [model for result in results for model in result]
    utils.log_success(f"Total models collected: {len(all_models)}")
    return all_models


def _scan_endpoints_region(region: str) -> List[Dict[str, Any]]:
    """Scan SageMaker endpoints in a single region."""
    regional_endpoints = []

    try:
        sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

        try:
            paginator = sagemaker_client.get_paginator('list_endpoints')
            for page in paginator.paginate():
                endpoints = page.get('Endpoints', [])

                for endpoint in endpoints:
                    endpoint_name = endpoint.get('EndpointName', 'N/A')

                    # Get detailed endpoint information
                    try:
                        endpoint_response = sagemaker_client.describe_endpoint(
                            EndpointName=endpoint_name
                        )

                        status = endpoint_response.get('EndpointStatus', 'N/A')
                        arn = endpoint_response.get('EndpointArn', 'N/A')
                        config_name = endpoint_response.get('EndpointConfigName', 'N/A')

                        creation_time = endpoint_response.get('CreationTime', 'N/A')
                        if creation_time != 'N/A':
                            creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                        last_modified = endpoint_response.get('LastModifiedTime', 'N/A')
                        if last_modified != 'N/A':
                            last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                        # Production variants
                        production_variants = endpoint_response.get('ProductionVariants', [])
                        variant_count = len(production_variants)

                        # Get instance info from first variant
                        instance_type = 'N/A'
                        current_instance_count = 0
                        desired_instance_count = 0

                        if production_variants:
                            first_variant = production_variants[0]
                            instance_type = first_variant.get('InstanceType', 'N/A')
                            current_instance_count = first_variant.get('CurrentInstanceCount', 0)
                            desired_instance_count = first_variant.get('DesiredInstanceCount', 0)

                        # Data capture config
                        data_capture_config = endpoint_response.get('DataCaptureConfig', {})
                        data_capture_enabled = data_capture_config.get('EnableCapture', False)

                        # Failure reason
                        failure_reason = endpoint_response.get('FailureReason', 'N/A')

                        regional_endpoints.append({
                            'Region': region,
                            'Endpoint Name': endpoint_name,
                            'ARN': arn,
                            'Status': status,
                            'Config Name': config_name,
                            'Created': creation_time,
                            'Last Modified': last_modified,
                            'Instance Type': instance_type,
                            'Current Instances': current_instance_count,
                            'Desired Instances': desired_instance_count,
                            'Production Variants': variant_count,
                            'Data Capture Enabled': data_capture_enabled,
                            'Failure Reason': failure_reason
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get details for endpoint {endpoint_name}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error listing endpoints in {region}: {str(e)}")

    except Exception as e:
        utils.log_error(f"Error collecting endpoints in {region}", e)

    return regional_endpoints


@utils.aws_error_handler("Collecting SageMaker endpoints", default_return=[])
def collect_endpoints(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SageMaker endpoint information."""
    print("\n=== COLLECTING SAGEMAKER ENDPOINTS ===")
    results = utils.scan_regions_concurrent(regions, _scan_endpoints_region)
    all_endpoints = [ep for result in results for ep in result]
    utils.log_success(f"Total endpoints collected: {len(all_endpoints)}")
    return all_endpoints


def _scan_processing_jobs_region(region: str) -> List[Dict[str, Any]]:
    """Scan SageMaker processing jobs in a single region (limited to 30 most recent)."""
    regional_jobs = []

    try:
        sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

        try:
            # List recent processing jobs (limit to 30)
            paginator = sagemaker_client.get_paginator('list_processing_jobs')
            job_count = 0
            for page in paginator.paginate(
                SortBy='CreationTime',
                SortOrder='Descending',
                PaginationConfig={'MaxItems': 30}
            ):
                jobs = page.get('ProcessingJobSummaries', [])

                for job in jobs:
                    job_name = job.get('ProcessingJobName', 'N/A')
                    status = job.get('ProcessingJobStatus', 'N/A')
                    arn = job.get('ProcessingJobArn', 'N/A')

                    creation_time = job.get('CreationTime', 'N/A')
                    if creation_time != 'N/A':
                        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                    processing_end = job.get('ProcessingEndTime', 'N/A')
                    if processing_end != 'N/A':
                        processing_end = processing_end.strftime('%Y-%m-%d %H:%M:%S')

                    # Get additional details if needed
                    failure_reason = job.get('FailureReason', 'N/A')

                    regional_jobs.append({
                        'Region': region,
                        'Job Name': job_name,
                        'ARN': arn,
                        'Status': status,
                        'Created': creation_time,
                        'Processing End': processing_end,
                        'Failure Reason': failure_reason
                    })

                    job_count += 1
                    if job_count >= 30:
                        break

        except Exception as e:
            utils.log_warning(f"Error listing processing jobs in {region}: {str(e)}")

    except Exception as e:
        utils.log_error(f"Error collecting processing jobs in {region}", e)

    return regional_jobs


@utils.aws_error_handler("Collecting SageMaker processing jobs", default_return=[])
def collect_processing_jobs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SageMaker processing job information (limited to recent 30 per region)."""
    print("\n=== COLLECTING SAGEMAKER PROCESSING JOBS ===")
    results = utils.scan_regions_concurrent(regions, _scan_processing_jobs_region)
    all_jobs = [job for result in results for job in result]
    utils.log_success(f"Total processing jobs collected: {len(all_jobs)} (limited to 30 per region)")
    return all_jobs


def generate_summary(notebooks: List[Dict[str, Any]],
                     training_jobs: List[Dict[str, Any]],
                     models: List[Dict[str, Any]],
                     endpoints: List[Dict[str, Any]],
                     processing_jobs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for SageMaker resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Notebooks summary
    total_notebooks = len(notebooks)
    running_notebooks = sum(1 for n in notebooks if n.get('Status', '') == 'InService')

    summary.append({
        'Metric': 'Total Notebook Instances',
        'Count': total_notebooks,
        'Details': f'Running: {running_notebooks}'
    })

    # Internet access warning
    direct_internet = sum(1 for n in notebooks if n.get('Direct Internet Access', '') == 'Enabled')
    if direct_internet > 0:
        summary.append({
            'Metric': '⚠️ Notebooks with Direct Internet',
            'Count': direct_internet,
            'Details': 'SECURITY: Consider VPC-only access for production notebooks'
        })

    # Training jobs summary
    total_training = len(training_jobs)
    completed_training = sum(1 for j in training_jobs if j.get('Status', '') == 'Completed')
    failed_training = sum(1 for j in training_jobs if j.get('Status', '') == 'Failed')

    summary.append({
        'Metric': 'Total Training Jobs (Sample)',
        'Count': total_training,
        'Details': f'Completed: {completed_training}, Failed: {failed_training}'
    })

    # Models summary
    total_models = len(models)
    summary.append({
        'Metric': 'Total Models',
        'Count': total_models,
        'Details': 'Trained ML models ready for deployment'
    })

    # Endpoints summary
    total_endpoints = len(endpoints)
    in_service_endpoints = sum(1 for e in endpoints if e.get('Status', '') == 'InService')

    summary.append({
        'Metric': 'Total Endpoints',
        'Count': total_endpoints,
        'Details': f'InService: {in_service_endpoints}'
    })

    # Processing jobs summary
    total_processing = len(processing_jobs)
    summary.append({
        'Metric': 'Total Processing Jobs (Sample)',
        'Count': total_processing,
        'Details': 'Data processing and feature engineering jobs'
    })

    # Regional distribution
    if notebooks:
        df = pd.DataFrame(notebooks)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Notebook Instances in {region}',
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
    print("SageMaker Export Tool")
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
    all_available_regions = utils.get_partition_regions(partition, all_regions=True)
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_suffix = ""
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
    elif selection_int == 2:
        regions = all_available_regions
        region_suffix = ""
        utils.log_info(f"Scanning all {len(regions)} AWS regions")
    else:  # selection_int == 3
        # Display numbered list of regions
        print("\n" + "=" * 68)
        print("AVAILABLE AWS REGIONS")
        print("=" * 68)
        print()
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx:2}. {region}")
        print()

        # Get region selection with validation
        while True:
            try:
                region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_num) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_suffix = selected_region
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")
            region_suffix = ""

    # Collect data
    print("\nCollecting SageMaker data...")

    notebooks = collect_notebook_instances(regions)
    training_jobs = collect_training_jobs(regions)
    models = collect_models(regions)
    endpoints = collect_endpoints(regions)
    processing_jobs = collect_processing_jobs(regions)
    summary = generate_summary(notebooks, training_jobs, models, endpoints, processing_jobs)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if notebooks:
        df_notebooks = pd.DataFrame(notebooks)
        df_notebooks = utils.prepare_dataframe_for_export(df_notebooks)
        dataframes['Notebook Instances'] = df_notebooks

    if training_jobs:
        df_training = pd.DataFrame(training_jobs)
        df_training = utils.prepare_dataframe_for_export(df_training)
        dataframes['Training Jobs'] = df_training

    if models:
        df_models = pd.DataFrame(models)
        df_models = utils.prepare_dataframe_for_export(df_models)
        dataframes['Models'] = df_models

    if endpoints:
        df_endpoints = pd.DataFrame(endpoints)
        df_endpoints = utils.prepare_dataframe_for_export(df_endpoints)
        dataframes['Endpoints'] = df_endpoints

    if processing_jobs:
        df_processing = pd.DataFrame(processing_jobs)
        df_processing = utils.prepare_dataframe_for_export(df_processing)
        dataframes['Processing Jobs'] = df_processing

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'sagemaker', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Notebook Instances': len(notebooks),
            'Training Jobs': len(training_jobs),
            'Models': len(models),
            'Endpoints': len(endpoints),
            'Processing Jobs': len(processing_jobs)
        })
    else:
        utils.log_warning("No SageMaker data found to export")

    utils.log_success("SageMaker export completed successfully")


if __name__ == "__main__":
    main()
