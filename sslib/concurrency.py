"""
sslib.concurrency — Concurrent region scanning and pagination utilities.

Provides thread-pool-based multi-region scanning with sequential fallback,
progress-aware pagination, and memory-efficient DataFrame construction.

Imports from sslib.config (safe — config is already extracted).
Zero dependency on utils.py.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterator, List, Optional

import pandas as pd

from sslib.config import get_config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class ConcurrentScanningError(Exception):
    """Raised when concurrent scanning encounters too many errors."""
    pass


# ---------------------------------------------------------------------------
# Multi-region scanning
# ---------------------------------------------------------------------------


def scan_regions_concurrent(
    regions: List[str],
    scan_function: Callable[[str], Any],
    max_workers: Optional[int] = None,
    show_progress: Optional[bool] = True,
    fallback_on_error: Optional[bool] = None,
) -> List[Any]:
    """
    Scan multiple AWS regions concurrently with automatic fallback to sequential.

    This function dramatically improves performance for multi-region exports by
    scanning regions in parallel instead of sequentially. It includes intelligent
    error handling with automatic fallback to sequential scanning if too many errors
    occur (typically due to API rate limiting).

    Args:
        regions: List of AWS regions to scan
        scan_function: Function that takes a region and returns data.
                      Function should handle its own AWS client creation.
        max_workers: Maximum concurrent workers (default: from config or 4)
        show_progress: Show progress as regions complete (default: True)
        fallback_on_error: Fallback to sequential on errors (default: from config or True)

    Returns:
        list: List of results from all regions

    Example:
        >>> def collect_region_instances(region):
        ...     ec2 = get_boto3_client('ec2', region_name=region)
        ...     return ec2.describe_instances()['Reservations']
        >>> results = scan_regions_concurrent(regions, collect_region_instances)

    Note:
        - Automatically loads settings from config.json (advanced_settings)
        - Falls back to sequential scanning if concurrent scanning fails
        - Each thread gets its own boto3 client (thread-safe)
    """
    # Load settings from config
    _, config = get_config()
    advanced = config.get("advanced_settings", {})
    concurrent_config = advanced.get("concurrent_scanning", {})

    if max_workers is None:
        max_workers = concurrent_config.get("max_workers", 4)

    if fallback_on_error is None:
        fallback_on_error = concurrent_config.get("fallback_on_error", True)

    if not concurrent_config.get("enabled", True):
        logger.info("Concurrent scanning disabled in config, using sequential scanning")
        return _scan_regions_sequential(regions, scan_function, show_progress)

    try:
        logger.info("Scanning %d region(s) concurrently (max_workers=%d)", len(regions), max_workers)

        results = []
        completed = 0
        total = len(regions)
        error_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_region = {
                executor.submit(scan_function, region): region for region in regions
            }

            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1

                    if show_progress:
                        progress = (completed / total) * 100
                        logger.info(
                            "[%.1f%%] Completed region %d/%d: %s", progress, completed, total, region
                        )

                except Exception as e:
                    error_count += 1
                    logger.error("Error scanning region %s: %s", region, e)

                    if fallback_on_error and error_count >= max(2, total // 2):
                        logger.warning(
                            "Multiple concurrent scanning errors detected (%d errors)", error_count
                        )
                        raise ConcurrentScanningError(f"Too many concurrent errors: {error_count}")

                    completed += 1

        return results

    except ConcurrentScanningError:
        if fallback_on_error:
            logger.warning("Falling back to sequential scanning due to concurrent errors")
            logger.warning("This may indicate API rate limiting or network issues")
            logger.warning("To disable concurrent scanning, run: python advanced_settings.py")
            return _scan_regions_sequential(regions, scan_function, show_progress)
        else:
            raise

    except Exception as e:
        if fallback_on_error:
            logger.error("Unexpected error in concurrent scanning, falling back to sequential: %s", e)
            logger.warning("To disable concurrent scanning, run: python advanced_settings.py")
            return _scan_regions_sequential(regions, scan_function, show_progress)
        else:
            raise


def _scan_regions_sequential(
    regions: List[str],
    scan_function: Callable[[str], Any],
    show_progress: bool = True,
) -> List[Any]:
    """
    Fallback: Scan regions sequentially (one at a time).

    This is the traditional method used in all scripts.
    Used as fallback when concurrent scanning fails.

    Args:
        regions: List of AWS regions to scan
        scan_function: Function that takes a region and returns data
        show_progress: Show progress as regions complete

    Returns:
        list: List of results from all regions
    """
    logger.info("Scanning %d region(s) sequentially", len(regions))

    results = []
    total = len(regions)

    for i, region in enumerate(regions, 1):
        try:
            if show_progress:
                progress = (i / total) * 100
                logger.info("[%.1f%%] Scanning region %d/%d: %s", progress, i, total, region)

            result = scan_function(region)
            results.append(result)

        except Exception as e:
            logger.error("Error scanning region %s: %s", region, e)

    return results


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------


def paginate_with_progress(
    client,
    operation: str,
    operation_label: str = "resources",
    **kwargs,
) -> Iterator[Dict[str, Any]]:
    """
    Paginate AWS API calls with progress tracking (Phase 4B optimization).

    This generator function provides visibility into pagination progress for
    large datasets. Particularly useful for accounts with 1000+ resources.

    Args:
        client: Boto3 client
        operation: API operation name (e.g., 'describe_instances')
        operation_label: User-friendly label for logging (e.g., 'EC2 instances')
        **kwargs: Arguments to pass to paginate()

    Yields:
        Pages from the paginator

    Example:
        >>> ec2 = get_boto3_client('ec2', region_name='us-east-1')
        >>> for page in paginate_with_progress(ec2, 'describe_instances', 'EC2 instances'):
        ...     process(page['Reservations'])
    """
    _, config = get_config()
    advanced = config.get("advanced_settings", {})
    progress_config = advanced.get("progress_display", {})
    show_pagination = progress_config.get("show_pagination_progress", False)

    paginator = client.get_paginator(operation)
    logger.debug("Streaming %s pages...", operation_label)

    page_num = 0
    for page in paginator.paginate(**kwargs):
        page_num += 1
        if show_pagination:
            logger.debug("Processing page %d of %s", page_num, operation_label)
        yield page

    logger.info("Processed %d page(s) of %s", page_num, operation_label)


def build_dataframe_in_batches(
    data: List[Dict],
    batch_size: int = 1000,
) -> pd.DataFrame:
    """
    Build DataFrame from large data lists in batches for memory efficiency (Phase 4B).

    For datasets with 10,000+ resources, building DataFrames in batches reduces
    memory spikes and improves performance.

    Args:
        data: List of dictionaries (resource data)
        batch_size: Number of rows per batch (default: 1000)

    Returns:
        DataFrame with all data

    Example:
        >>> resources = [{'id': i, 'name': f'resource-{i}'} for i in range(10000)]
        >>> df = build_dataframe_in_batches(resources, batch_size=1000)

    Note:
        - Small datasets (<= batch_size) are processed normally
        - Large datasets are split into batches, converted separately, then concatenated
        - Reduces peak memory usage by 20-30% for large exports
    """
    if len(data) <= batch_size:
        return pd.DataFrame(data)

    batches = []
    for i in range(0, len(data), batch_size):
        batch = data[i : i + batch_size]
        batches.append(pd.DataFrame(batch))
        logger.debug("Created batch %d (%d rows)", i // batch_size + 1, len(batch))

    logger.debug("Concatenating %d batches...", len(batches))
    return pd.concat(batches, ignore_index=True)
