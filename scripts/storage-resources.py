#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Storage Resources All-in-One Export Script
Version: v0.1.0
Date: SEP-25-2025

Description:
This script performs a comprehensive export of all storage resources from AWS
environments including EBS volumes, EBS snapshots, and S3 buckets. Each resource type
is exported to a separate Excel file, and all files are automatically archived into a
single zip file for easy distribution and storage.

Collected information includes:
- EBS volumes with detailed configuration, encryption, and attachment information
- EBS snapshots with creation details, encryption status, and sharing permissions
- S3 buckets with configuration, security settings, and usage statistics
- Automatic archiving of all exports into a single zip file
"""

import os
import sys
import datetime
import time
import json
import zipfile
import subprocess
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

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

# Setup logging
logger = utils.setup_logging('storage-resources')

def check_dependencies():
    """
    Check if required dependencies are installed and offer to install them if missing.

    Returns:
        bool: True if all dependencies are satisfied, False otherwise
    """
    required_packages = ['pandas', 'openpyxl']
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        utils.log_warning(f"Packages required but not installed: {', '.join(missing_packages)}")
        response = input("Would you like to install these packages now? (y/n): ").lower().strip()

        if response == 'y':
            import subprocess
            for package in missing_packages:
                utils.log_info(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"{package} installed successfully")
                except subprocess.CalledProcessError as e:
                    utils.log_error(f"Error installing {package}", e)
                    return False
        else:
            print("Cannot continue without required packages. Exiting.")
            return False

    return True

@utils.aws_error_handler("Getting account information", default_return=("Unknown", "Unknown-AWS-Account"))
def get_account_info():
    """
    Get the current AWS account ID and name with AWS validation.

    Returns:
        tuple: (account_id, account_name)
    """
    sts = utils.get_boto3_client('sts')
    account_id = sts.get_caller_identity()['Account']

    # Validate AWS environment
    caller_arn = sts.get_caller_identity()['Arn']
    account_name = utils.get_account_name(account_id, default=f"AWS-ACCOUNT-{account_id}")

    return account_id, account_name

def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS STORAGE RESOURCES ALL-IN-ONE COLLECTION")
    print("====================================================================")
    print("Version: v0.1.0                       Date: SEP-25-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information
    account_id, account_name = get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

def get_region_selection():
    """
    Get region selection from user for storage resources scanning.

    Returns:
        list: List of selected regions to scan
    """
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
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)

    # Get regions based on selection
    all_available_regions = utils.get_partition_regions(partition, all_regions=True)
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
    elif selection_int == 2:
        regions = all_available_regions
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
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.")
                sys.exit(0)

    return regions

def run_individual_script(script_path, script_name, regions):
    """
    Run an individual export script and capture its output file.

    Args:
        script_path: Path to the script to run
        script_name: Human-readable name of the script
        regions: List of regions to process

    Returns:
        str: Path to generated output file or None if failed
    """
    try:
        utils.log_info(f"Starting {script_name} export...")
        print(f"\n{'='*70}")
        print(f"EXECUTING {script_name.upper()} EXPORT")
        print(f"{'='*70}")

        # Check if script exists
        if not script_path.exists():
            utils.log_error(f"Script not found: {script_path}")
            return None

        # Run the script
        env = os.environ.copy()

        # Set environment variables to indicate automated run if needed
        env['STRATUSSCAN_AUTO_RUN'] = '1'
        env['STRATUSSCAN_REGIONS'] = ','.join(regions)

        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=False,  # Allow real-time output
            text=True,
            env=env,
            timeout=1800  # 30-minute timeout
        )

        if result.returncode == 0:
            utils.log_success(f"{script_name} export completed successfully")

            # Try to find the most recent output file
            output_dir = script_path.parent.parent / "output"
            if output_dir.exists():
                # Look for recent files that match the script pattern
                pattern_map = {
                    'EBS Volumes': '*ebs*volume*export*.xlsx',
                    'EBS Snapshots': '*ebs*snapshot*export*.xlsx',
                    'S3': '*s3*export*.xlsx'
                }

                pattern = pattern_map.get(script_name, f'*{script_name.lower().replace(" ", "*")}*.xlsx')

                # Find the most recent matching file
                matching_files = list(output_dir.glob(pattern))
                if matching_files:
                    # Sort by modification time, get most recent
                    most_recent = max(matching_files, key=lambda f: f.stat().st_mtime)
                    utils.log_info(f"Found output file: {most_recent.name}")
                    return str(most_recent)
                else:
                    utils.log_warning(f"Could not find output file for {script_name}")

                    # Fallback: try broader pattern matching
                    all_xlsx_files = list(output_dir.glob('*.xlsx'))
                    if all_xlsx_files:
                        # Get the most recent xlsx file
                        most_recent = max(all_xlsx_files, key=lambda f: f.stat().st_mtime)

                        # Check if it might be from our script based on timestamp
                        file_time = most_recent.stat().st_mtime
                        current_time = time.time()

                        # If file was created in the last 5 minutes, assume it's ours
                        if (current_time - file_time) < 300:
                            utils.log_info(f"Found recent output file (fallback): {most_recent.name}")
                            return str(most_recent)

                    return None
            else:
                utils.log_warning("Output directory not found")
                return None
        else:
            utils.log_error(f"{script_name} export failed with return code {result.returncode}")
            return None

    except subprocess.TimeoutExpired:
        utils.log_error(f"{script_name} export timed out after 30 minutes")
        return None
    except Exception as e:
        utils.log_error(f"Error running {script_name} export", e)
        return None

def create_storage_archive(output_files, account_name):
    """
    Create a zip archive containing all storage resource exports.

    Args:
        output_files: List of output file paths
        account_name: AWS account name for filename

    Returns:
        str: Path to created archive or None if failed
    """
    try:
        # Filter out None values (failed exports)
        valid_files = [f for f in output_files if f and Path(f).exists()]

        if not valid_files:
            utils.log_error("No valid output files to archive")
            return None

        # Generate archive filename
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        archive_filename = utils.create_export_filename(
            account_name,
            "storage-resources-all",
            "",
            current_date,
            extension=".zip"
        )

        utils.log_info(f"Creating archive: {archive_filename}")
        print(f"\n{'='*70}")
        print(f"CREATING STORAGE RESOURCES ARCHIVE")
        print(f"{'='*70}")

        # Create the zip file
        with zipfile.ZipFile(archive_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in valid_files:
                file_path_obj = Path(file_path)
                if file_path_obj.exists():
                    # Add file to zip with just the filename (no path)
                    zipf.write(file_path_obj, file_path_obj.name)
                    utils.log_info(f"Added to archive: {file_path_obj.name}")

        if Path(archive_filename).exists():
            archive_size = Path(archive_filename).stat().st_size / (1024 * 1024)  # MB
            utils.log_success(f"Archive created successfully: {archive_filename}")
            utils.log_info(f"Archive size: {archive_size:.2f} MB")
            utils.log_info(f"Files included: {len(valid_files)}")
            return archive_filename
        else:
            utils.log_error("Archive creation failed")
            return None

    except Exception as e:
        utils.log_error("Error creating archive", e)
        return None

def cleanup_individual_files(output_files, keep_originals=False):
    """
    Optionally clean up individual export files after archiving.

    Args:
        output_files: List of output file paths
        keep_originals: Whether to keep the original files
    """
    if keep_originals:
        utils.log_info("Keeping original export files as requested")
        return

    try:
        valid_files = [f for f in output_files if f and Path(f).exists()]

        if not valid_files:
            return

        # Ask user if they want to keep individual files
        print(f"\nCleanup Options:")
        print(f"Archive created with {len(valid_files)} files.")
        response = input("Keep individual export files? (y/n): ").lower().strip()

        if response == 'n':
            utils.log_info("Removing individual export files...")
            removed_count = 0
            for file_path in valid_files:
                try:
                    Path(file_path).unlink()
                    utils.log_info(f"Removed: {Path(file_path).name}")
                    removed_count += 1
                except Exception as e:
                    utils.log_warning(f"Could not remove {Path(file_path).name}: {e}")

            utils.log_success(f"Removed {removed_count} individual files")
        else:
            utils.log_info("Keeping individual export files")

    except Exception as e:
        utils.log_error("Error during cleanup", e)

def main():
    """
    Main function to orchestrate the all-in-one storage resources collection.
    """
    try:
        # Check dependencies first
        if not check_dependencies():
            return

        # Print title and get account info
        account_id, account_name = print_title()

        # Validate AWS credentials
        try:
            # Test AWS credentials
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

        # Get region selection
        selected_regions = get_region_selection()

        utils.log_info(f"Starting comprehensive storage resources collection from AWS...")
        utils.log_info(f"Selected regions: {', '.join(selected_regions)}")
        print(f"\n{'='*70}")
        print(f"STORAGE RESOURCES ALL-IN-ONE EXPORT")
        print(f"Regions: {', '.join(selected_regions)}")
        print(f"{'='*70}")

        # Define storage resource scripts to run
        scripts_dir = Path(__file__).parent
        storage_scripts = [
            {
                'name': 'EBS Volumes',
                'script': scripts_dir / 'ebs-volumes-export.py',
                'description': 'EBS volumes with attachment and encryption details'
            },
            {
                'name': 'EBS Snapshots',
                'script': scripts_dir / 'ebs-snapshots-export.py',
                'description': 'EBS snapshots with creation and sharing information'
            },
            {
                'name': 'S3',
                'script': scripts_dir / 's3-export.py',
                'description': 'S3 buckets with configuration and security settings'
            }
        ]

        # Track output files and execution results
        output_files = []
        execution_results = {}
        start_time = datetime.datetime.now()

        print(f"\nPlanned exports:")
        for i, script_info in enumerate(storage_scripts, 1):
            print(f"  {i}. {script_info['name']}: {script_info['description']}")

        print(f"\nStarting exports...\n")

        # Execute each script
        for i, script_info in enumerate(storage_scripts, 1):
            script_start = datetime.datetime.now()

            utils.log_info(f"[{i}/{len(storage_scripts)}] Processing {script_info['name']}...")

            output_file = run_individual_script(
                script_info['script'],
                script_info['name'],
                selected_regions
            )

            script_end = datetime.datetime.now()
            execution_time = (script_end - script_start).total_seconds()

            if output_file:
                output_files.append(output_file)
                execution_results[script_info['name']] = {
                    'status': 'SUCCESS',
                    'file': output_file,
                    'duration': execution_time
                }
                utils.log_success(f"{script_info['name']} completed in {execution_time:.1f} seconds")
            else:
                execution_results[script_info['name']] = {
                    'status': 'FAILED',
                    'file': None,
                    'duration': execution_time
                }
                utils.log_error(f"{script_info['name']} failed after {execution_time:.1f} seconds")

        # Summary of individual exports
        total_time = (datetime.datetime.now() - start_time).total_seconds()

        print(f"\n{'='*70}")
        print(f"INDIVIDUAL EXPORTS SUMMARY")
        print(f"{'='*70}")

        successful_exports = []
        failed_exports = []

        for script_name, result in execution_results.items():
            status_symbol = "✓" if result['status'] == 'SUCCESS' else "✗"
            duration = result['duration']

            print(f"{status_symbol} {script_name:<15} {result['status']:<10} ({duration:.1f}s)")

            if result['status'] == 'SUCCESS':
                successful_exports.append(script_name)
                if result['file']:
                    print(f"    Output: {Path(result['file']).name}")
            else:
                failed_exports.append(script_name)

        print(f"\nExecution Summary:")
        print(f"  Total time: {total_time:.1f} seconds")
        print(f"  Successful: {len(successful_exports)}/{len(storage_scripts)}")
        print(f"  Failed: {len(failed_exports)}")

        if failed_exports:
            utils.log_warning(f"Failed exports: {', '.join(failed_exports)}")

        # Create archive if we have any successful exports
        if output_files:
            utils.log_info(f"Creating comprehensive archive with {len(output_files)} files...")
            archive_path = create_storage_archive(output_files, account_name)

            if archive_path:
                print(f"\n{'='*70}")
                print(f"ALL-IN-ONE EXPORT COMPLETED SUCCESSFULLY")
                print(f"{'='*70}")

                utils.log_info(f"Storage resources archive created with AWS compliance markers")
                utils.log_info(f"Archive location: {archive_path}")
                utils.log_info(f"Total execution time: {total_time:.1f} seconds")

                # Cleanup individual files
                cleanup_individual_files(output_files)

                print(f"\nStorage Resources All-in-One Export Summary:")
                print(f"  ✓ Archive: {Path(archive_path).name}")
                print(f"  ✓ Resources: {', '.join(successful_exports)}")
                print(f"  ✓ Regions: {', '.join(selected_regions)}")
                if failed_exports:
                    print(f"  ! Failed: {', '.join(failed_exports)}")
            else:
                utils.log_error("Failed to create archive")
        else:
            utils.log_error("No successful exports to archive")
            print(f"\nAll exports failed. Please check the logs and try individual scripts.")

        print(f"\nScript execution completed.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()