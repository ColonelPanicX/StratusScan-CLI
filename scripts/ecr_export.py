#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Elastic Container Registry (ECR) Export Tool
Date: NOV-09-2025

Description:
This script exports AWS ECR repository and image information from all regions into an Excel file
with multiple worksheets. The output includes repository configurations, images with tags and
digests, lifecycle policies, and scanning configurations.

Features:
- ECR repository overview with URI and creation date
- Repository policies and permissions
- Image scanning configuration
- Lifecycle policies
- Image details with tags, sizes, and vulnerability scan results
- Encryption settings
- Image tag mutability
"""

import datetime
import sys
from pathlib import Path
from typing import Any

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()

    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))

    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)
args = utils.parse_script_args("Export Elastic Container Registry repositories and images to Excel")


def _build_repo_row(repo: dict[str, Any], region: str, ecr_client=None) -> dict[str, Any]:
    """
    Build a single ECR repository export row from a describe_repositories entry.

    Extracted so the per-repository processing can be wrapped in try/except by
    the caller: a malformed repository entry is logged and skipped rather than
    discarding the whole region's results.

    Args:
        repo: A single repository entry from describe_repositories.
        region: AWS region name.
        ecr_client: Optional pre-built ECR client (reused across repos in a
            region to avoid recreating one per row). Created on demand if
            not supplied.

    Returns:
        dict: The assembled repository row.
    """
    repository_name = repo.get('repositoryName', '')
    print(f"  Processing repository: {repository_name}")

    # Basic information
    repository_arn = repo.get('repositoryArn', '')
    repository_uri = repo.get('repositoryUri', '')
    registry_id = repo.get('registryId', '')

    # Creation date
    created_at = repo.get('createdAt', '')
    if created_at:
        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_at, datetime.datetime) else str(created_at)

    # Image tag mutability
    image_tag_mutability = repo.get('imageTagMutability', 'MUTABLE')

    # Image scanning configuration
    image_scanning_config = repo.get('imageScanningConfiguration', {})
    scan_on_push = image_scanning_config.get('scanOnPush', False)

    # Encryption configuration
    encryption_config = repo.get('encryptionConfiguration', {})
    encryption_type = encryption_config.get('encryptionType', 'AES256')
    kms_key = encryption_config.get('kmsKey', 'N/A')

    # Get image count (paginated — maxResults=1000 was silently capping).
    # Per-field enrichment: gracefully degrades to 'Unknown' rather than
    # failing the whole repository row.
    image_count: Any
    try:
        image_count = 0
        client = ecr_client if ecr_client is not None else utils.get_boto3_client('ecr', region_name=region)
        image_paginator = client.get_paginator('describe_images')
        for img_page in image_paginator.paginate(repositoryName=repository_name):
            image_count += len(img_page.get('imageDetails', []))
    except Exception:
        image_count = 'Unknown'

    return {
        'Region': region,
        'Repository Name': repository_name,
        'Repository URI': repository_uri,
        'Registry ID': registry_id,
        'Image Count': image_count,
        'Image Tag Mutability': image_tag_mutability,
        'Scan on Push': scan_on_push,
        'Encryption Type': encryption_type,
        'KMS Key': kms_key,
        'Created At': created_at,
        'Repository ARN': repository_arn
    }


def scan_ecr_repositories_in_region(region: str) -> list[dict[str, Any]]:
    """
    Scan ECR repositories in a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no ECR repositories" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed repositories are skipped (logged) rather than
    aborting the whole region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with ECR repository information from this region

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nProcessing region: {region}")

    ecr_client = utils.get_boto3_client('ecr', region_name=region)

    # Get ECR repositories
    paginator = ecr_client.get_paginator('describe_repositories')
    regional_repos = []
    repo_count = 0

    for page in paginator.paginate():
        repositories = page.get('repositories', [])
        repo_count += len(repositories)

        for repo in repositories:
            try:
                regional_repos.append(_build_repo_row(repo, region, ecr_client))
            except Exception as e:
                # One malformed repository is skipped, not fatal to the region.
                utils.log_error(
                    f"Skipping malformed ECR repository in {region}: "
                    f"{repo.get('repositoryName', '<unknown>')}",
                    e,
                )
                continue

    utils.log_info(f"Found {repo_count} ECR repositories in {region}")
    return regional_repos


def collect_ecr_repositories(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect ECR repository information from AWS regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(repos, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING ECR REPOSITORIES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_ecr_repositories_in_region,
        show_progress=True,
        collect_failures=True,
    )
    all_repos = [repo for result in region_results for repo in result]

    utils.log_success(f"Total ECR repositories collected: {len(all_repos)}")
    return all_repos, failed_regions


def scan_ecr_images_in_region(region: str) -> list[dict[str, Any]]:
    """
    Scan ECR images in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with ECR image information from this region
    """
    regional_images = []

    try:
        ecr_client = utils.get_boto3_client('ecr', region_name=region)

        # Get all repositories first
        repo_paginator = ecr_client.get_paginator('describe_repositories')

        for repo_page in repo_paginator.paginate():
            repositories = repo_page.get('repositories', [])

            for repo in repositories:
                repository_name = repo.get('repositoryName', '')

                try:
                    # Get images for this repository
                    image_paginator = ecr_client.get_paginator('describe_images')

                    for image_page in image_paginator.paginate(repositoryName=repository_name):
                        images = image_page.get('imageDetails', [])

                        for image in images:
                            image_digest = image.get('imageDigest', '')

                            # Get image tags
                            image_tags = image.get('imageTags', [])
                            tags_str = ', '.join(image_tags) if image_tags else 'Untagged'

                            # Image size
                            image_size_bytes = image.get('imageSizeInBytes', 0)
                            image_size_mb = round(image_size_bytes / (1024 * 1024), 2) if image_size_bytes else 0

                            # Pushed at
                            pushed_at = image.get('imagePushedAt', '')
                            if pushed_at:
                                pushed_at = pushed_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(pushed_at, datetime.datetime) else str(pushed_at)

                            # Scan findings
                            scan_status = image.get('imageScanStatus', {}).get('status', 'N/A')
                            scan_findings_summary = image.get('imageScanFindingsSummary', {})

                            if scan_findings_summary:
                                finding_severity_counts = scan_findings_summary.get('findingSeverityCounts', {})
                                critical = finding_severity_counts.get('CRITICAL', 0)
                                high = finding_severity_counts.get('HIGH', 0)
                                medium = finding_severity_counts.get('MEDIUM', 0)
                                low = finding_severity_counts.get('LOW', 0)

                                vulnerabilities = f"Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}"
                            else:
                                vulnerabilities = 'N/A'

                            # Artifact media type
                            artifact_media_type = image.get('artifactMediaType', 'N/A')

                            regional_images.append({
                                'Region': region,
                                'Repository Name': repository_name,
                                'Image Tags': tags_str,
                                'Image Digest': image_digest[:16] + '...',  # Truncate for readability
                                'Size (MB)': image_size_mb,
                                'Pushed At': pushed_at,
                                'Scan Status': scan_status,
                                'Vulnerabilities': vulnerabilities,
                                'Artifact Media Type': artifact_media_type
                            })

                except Exception as e:
                    utils.log_warning(f"Could not get images for repository {repository_name}: {e}")

        utils.log_info(f"Found {len(regional_images)} ECR images in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting ECR images in region {region}", e)

    return regional_images


@utils.aws_error_handler("Collecting ECR images", default_return=[])
def collect_ecr_images(regions: list[str]) -> list[dict[str, Any]]:
    """
    Collect ECR image information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with ECR image information
    """
    print("\n=== COLLECTING ECR IMAGES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    all_images = []
    for region_images in utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_ecr_images_in_region,
    ):
        all_images.extend(region_images)

    utils.log_success(f"Total ECR images collected: {len(all_images)}")
    return all_images


def scan_lifecycle_policies_in_region(region: str) -> list[dict[str, Any]]:
    """
    Scan ECR lifecycle policies in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with lifecycle policy information from this region
    """
    regional_policies = []

    try:
        ecr_client = utils.get_boto3_client('ecr', region_name=region)

        # Get all repositories
        repo_paginator = ecr_client.get_paginator('describe_repositories')

        for repo_page in repo_paginator.paginate():
            repositories = repo_page.get('repositories', [])

            for repo in repositories:
                repository_name = repo.get('repositoryName', '')

                try:
                    # Get lifecycle policy for this repository
                    policy_response = ecr_client.get_lifecycle_policy(
                        repositoryName=repository_name
                    )

                    policy_text = policy_response.get('lifecyclePolicyText', '')
                    last_evaluated = policy_response.get('lastEvaluatedAt', '')

                    if last_evaluated:
                        last_evaluated = last_evaluated.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_evaluated, datetime.datetime) else str(last_evaluated)

                    # Parse policy to count rules (JSON)
                    import json
                    try:
                        policy_json = json.loads(policy_text)
                        rules = policy_json.get('rules', [])
                        rule_count = len(rules)
                    except Exception:
                        rule_count = 'Unknown'

                    regional_policies.append({
                        'Region': region,
                        'Repository Name': repository_name,
                        'Rule Count': rule_count,
                        'Last Evaluated': last_evaluated if last_evaluated else 'Never',
                        'Has Policy': True
                    })

                except ecr_client.exceptions.LifecyclePolicyNotFoundException:
                    # No lifecycle policy for this repository
                    regional_policies.append({
                        'Region': region,
                        'Repository Name': repository_name,
                        'Rule Count': 0,
                        'Last Evaluated': 'N/A',
                        'Has Policy': False
                    })
                except Exception as e:
                    utils.log_warning(f"Could not get lifecycle policy for {repository_name}: {e}")

        utils.log_info(f"Found {len(regional_policies)} lifecycle policy records in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting lifecycle policies in region {region}", e)

    return regional_policies


@utils.aws_error_handler("Collecting lifecycle policies", default_return=[])
def collect_lifecycle_policies(regions: list[str]) -> list[dict[str, Any]]:
    """
    Collect ECR lifecycle policy information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with lifecycle policy information
    """
    print("\n=== COLLECTING LIFECYCLE POLICIES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    all_policies = []
    for region_policies in utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_lifecycle_policies_in_region,
    ):
        all_policies.extend(region_policies)

    utils.log_success(f"Total lifecycle policy records collected: {len(all_policies)}")
    return all_policies


def export_ecr_data(account_id: str, account_name: str):
    """
    Export ECR information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect ECR repositories (primary scope — region failures must
    # propagate as failed_regions, never collapse into "empty").
    repos, failed_regions = collect_ecr_repositories(regions)
    if repos:
        data_frames['ECR Repositories'] = pd.DataFrame(repos)

    # STEP 2: Collect images (enrichment — degrades gracefully; a region-level
    # failure here does not fail the whole export).
    images = collect_ecr_images(regions)
    if images:
        data_frames['Images'] = pd.DataFrame(images)

    # STEP 3: Collect lifecycle policies (enrichment — degrades gracefully; a
    # region-level failure here does not fail the whole export).
    policies = collect_lifecycle_policies(regions)
    if policies:
        data_frames['Lifecycle Policies'] = pd.DataFrame(policies)

    # Export whatever succeeded first — a partial export is required even
    # when some regions failed (see the silent-collection-failure blast-radius
    # audit).
    if data_frames:
        # STEP 4: Prepare all DataFrames for export
        for sheet_name in data_frames:
            data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

        # STEP 5: Create filename and export
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        final_excel_file = utils.create_export_filename(
            account_name,
            'ecr',
            region_suffix,
            current_date
        )

        # Save using utils module for consistent formatting
        try:
            output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

            if output_path:
                utils.log_success("ECR data exported successfully!")
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

                # Summary of exported data
                for sheet_name, df in data_frames.items():
                    utils.log_info(f"  - {sheet_name}: {len(df)} records")
                    print(f"  - {sheet_name}: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)
    elif not failed_regions:
        # Genuinely empty account: every region succeeded and returned nothing.
        utils.log_warning("No ECR data was collected. Nothing to export.")
        print("\nNo ECR repositories found in the selected region(s).")

    # If ANY region failed the ECR Repositories scope collection, make it
    # loud: write a marker and exit non-zero, even if some data (from this
    # scope or the enrichment sheets) was exported. A partial export that
    # looks complete is exactly the failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'ecr', failed_regions)
        print(
            "\nERROR: ECR export completed with failures — data is incomplete. "
            "See the *-ecr-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("ecr-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("ecr-export.py", "AWS Elastic Container Registry Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS ELASTIC CONTAINER REGISTRY (ECR) EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
            print("Exiting script...")
            sys.exit(0)

        # Export ECR data
        export_ecr_data(account_id, account_name)

        print("\nECR export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("ecr-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()
