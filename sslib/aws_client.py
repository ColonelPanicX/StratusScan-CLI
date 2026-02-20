"""
sslib.aws_client — FIPS-aware boto3 client factory and partition/region utilities.

Provides automatic FIPS endpoint injection for GovCloud regions, partition
detection, region validation, and session-level account-info caching.

Imports from sslib.config (safe — config is already extracted).
Zero dependency on utils.py.
"""

import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
from botocore.config import Config

from sslib.config import config_value, get_account_name, get_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants (mirrors utils.py — kept local to avoid circular import)
# ---------------------------------------------------------------------------

_DEFAULT_REGIONS = ["us-east-1", "us-west-2", "us-west-1", "eu-west-1"]
_AWS_PARTITION = "aws"

# ---------------------------------------------------------------------------
# Account info cache (session-level, thread-safe)
# ---------------------------------------------------------------------------

_account_info_cache: Optional[Tuple[str, str, str]] = None
_account_info_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Environment / automation helpers
# ---------------------------------------------------------------------------


def is_auto_run() -> bool:
    """
    Check if StratusScan is running in non-interactive automation mode.

    Returns:
        bool: True if STRATUSSCAN_AUTO_RUN environment variable is set to 1/true/yes
    """
    return os.environ.get("STRATUSSCAN_AUTO_RUN", "").lower() in ("1", "true", "yes")


def get_auto_regions() -> Optional[List[str]]:
    """
    Get the list of regions from the STRATUSSCAN_REGIONS environment variable.

    Returns:
        Optional[List[str]]: List of region strings, or None if not set
    """
    val = os.environ.get("STRATUSSCAN_REGIONS", "")
    return [r.strip() for r in val.split(",") if r.strip()] if val else None


# ---------------------------------------------------------------------------
# Region validation
# ---------------------------------------------------------------------------


def is_aws_region(region: str) -> bool:
    """
    Check if a region is a valid AWS region.

    Args:
        region: AWS region name

    Returns:
        bool: True if valid AWS region, False otherwise
    """
    # Pattern supports: us-east-1, us-gov-west-1, ap-southeast-2, etc.
    pattern = r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$"
    return bool(re.match(pattern, region)) or region in _DEFAULT_REGIONS


def validate_aws_region(region: str) -> bool:
    """
    Validate that a region is a valid AWS region and provide helpful error if not.

    Args:
        region: AWS region name

    Returns:
        bool: True if valid, False otherwise
    """
    if region == "all":
        return True

    if not is_aws_region(region):
        logger.error("Invalid AWS region: %s", region)
        logger.error(
            "Valid AWS regions include: us-east-1, us-west-1, us-west-2, eu-west-1, ap-southeast-1"
        )
        return False

    return True


def get_aws_regions() -> List[str]:
    """
    Get list of default AWS regions for the current partition.
    Partition-aware: Returns GovCloud regions when in GovCloud, Commercial otherwise.

    Returns:
        list: List of AWS region names
    """
    partition = detect_partition()
    return get_partition_regions(partition)


# ---------------------------------------------------------------------------
# Partition detection
# ---------------------------------------------------------------------------


def detect_partition(region_name: Optional[str] = None) -> str:
    """
    Detect AWS partition from region or credentials.

    Args:
        region_name: Optional region to check

    Returns:
        str: 'aws' or 'aws-us-gov'
    """
    if region_name:
        if region_name.startswith(("us-gov-", "us-gov")):
            return "aws-us-gov"
        return "aws"

    try:
        session = boto3.Session()

        region = session.region_name or "us-east-1"
        if region.startswith("us-gov"):
            return "aws-us-gov"

        sts = session.client("sts")
        arn = sts.get_caller_identity()["Arn"]
        if "aws-us-gov" in arn:
            return "aws-us-gov"

        return "aws"
    except Exception as e:
        logger.warning("Could not detect partition: %s, assuming commercial AWS", e)
        return "aws"


# ---------------------------------------------------------------------------
# Session and client factory
# ---------------------------------------------------------------------------


def get_aws_session(region_name: Optional[str] = None):
    """
    Create a boto3 session for the specified region.

    Args:
        region_name: AWS region (None = default from config)

    Returns:
        boto3.Session: Configured session
    """
    return boto3.Session(region_name=region_name)


def get_boto3_client(service: str, region_name: Optional[str] = None, **kwargs):
    """
    Create boto3 client with standard configuration including retries.

    Automatically injects ``use_fips_endpoint=True`` for GovCloud regions
    (``us-gov-west-1``, ``us-gov-east-1``). This is a security-critical property
    that must survive any refactoring.

    Args:
        service: AWS service name (e.g., 'ec2', 'iam', 's3')
        region_name: AWS region name (optional)
        **kwargs: Additional arguments to pass to client creation

    Returns:
        boto3.client: Configured boto3 client with retry logic
    """
    sdk_config = config_value("aws_sdk_config", default={})

    retry_config = sdk_config.get("retries", {"max_attempts": 5, "mode": "adaptive"})
    connect_timeout = sdk_config.get("connect_timeout", 10)
    read_timeout = sdk_config.get("read_timeout", 60)

    config = Config(
        retries=retry_config,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )

    # FIPS injection — GovCloud requires FIPS endpoints
    if region_name and region_name.startswith("us-gov-") and "use_fips_endpoint" not in kwargs:
        kwargs["use_fips_endpoint"] = True

    session = get_aws_session(region_name)
    return session.client(service, config=config, **kwargs)


# ---------------------------------------------------------------------------
# ARN utilities
# ---------------------------------------------------------------------------


def build_arn(
    service: str,
    resource: str,
    region: Optional[str] = None,
    account_id: Optional[str] = None,
    partition: Optional[str] = None,
) -> str:
    """
    Build ARN with automatic partition detection.

    Args:
        service: AWS service name
        resource: Resource identifier
        region: AWS region (optional, empty string for global services)
        account_id: AWS account ID (optional, auto-detected if not provided)
        partition: AWS partition (optional, auto-detected if not provided)

    Returns:
        str: Properly formatted AWS ARN
    """
    if not partition:
        partition = detect_partition(region)

    if not account_id:
        try:
            sts = get_boto3_client("sts")
            account_id = sts.get_caller_identity()["Account"]
        except Exception:
            account_id = ""

    if region is None:
        region = ""

    return f"arn:{partition}:{service}:{region}:{account_id}:{resource}"


# ---------------------------------------------------------------------------
# Service availability
# ---------------------------------------------------------------------------


def is_service_available_in_partition(service: str, partition: str = "aws") -> bool:
    """
    Check if an AWS service is available in the specified partition.

    Args:
        service: AWS service name (e.g., 'ec2', 'iam', 's3')
        partition: AWS partition ('aws' or 'aws-us-gov')

    Returns:
        bool: True if service is available in partition, False otherwise
    """
    govcloud_unavailable = {
        "ce",
        "globalaccelerator",
        "trustedadvisor",
        "compute-optimizer",
        "cost-optimization-hub",
        "appstream",
        "chime",
        "sumerian",
        "gamelift",
        "robomaker",
    }

    govcloud_limited = {
        "marketplace",
        "organizations",
    }

    if partition == "aws-us-gov":
        if service.lower() in govcloud_unavailable:
            logger.debug("Service %s is not available in AWS GovCloud", service)
            return False
        if service.lower() in govcloud_limited:
            logger.debug("Service %s has limited functionality in AWS GovCloud", service)

    return True


def is_service_enabled(service_name: str) -> bool:
    """
    Check if a service is enabled in the current AWS environment.

    Args:
        service_name: Name of the AWS service

    Returns:
        bool: True if enabled, False if disabled
    """
    _, cfg = get_config()
    if "disabled_services" in cfg:
        disabled_services = cfg["disabled_services"]
        if service_name in disabled_services:
            return disabled_services[service_name].get("enabled", False)

    return True


def get_service_disability_reason(service_name: str) -> Optional[str]:
    """
    Get the reason why a service is disabled.

    Args:
        service_name: Name of the AWS service

    Returns:
        str: Reason for disability or None if service is enabled
    """
    _, cfg = get_config()
    if "disabled_services" in cfg:
        disabled_services = cfg["disabled_services"]
        if service_name in disabled_services:
            return disabled_services[service_name].get("reason", "Not available")

    return None


# ---------------------------------------------------------------------------
# Region helpers
# ---------------------------------------------------------------------------


def get_partition_regions(partition: str = "aws", all_regions: bool = False) -> List[str]:
    """
    Get available regions for a specific AWS partition.

    Args:
        partition: AWS partition ('aws' or 'aws-us-gov')
        all_regions: If True, query EC2 for all regions; if False, return default subset

    Returns:
        list: List of region names for the partition
    """
    if partition == "aws-us-gov":
        return ["us-gov-west-1", "us-gov-east-1"]
    elif partition == "aws":
        if all_regions:
            try:
                ec2 = get_boto3_client("ec2", region_name="us-east-1")
                response = ec2.describe_regions(AllRegions=True)
                regions = [
                    r["RegionName"]
                    for r in response["Regions"]
                    if r.get("OptInStatus") != "not-opted-in"
                ]
                return sorted(regions)
            except Exception as e:
                logger.warning("Could not query all regions from EC2, using default list: %s", e)
                return _DEFAULT_REGIONS
        else:
            return _DEFAULT_REGIONS
    else:
        logger.warning("Unknown partition: %s, returning commercial regions", partition)
        return _DEFAULT_REGIONS


def get_partition_default_region(partition: Optional[str] = None) -> str:
    """
    Get the default region for a specific AWS partition.

    Args:
        partition: AWS partition ('aws' or 'aws-us-gov')
                  If not provided, auto-detects from current credentials

    Returns:
        str: Default region for the partition
    """
    if partition is None:
        partition = detect_partition()

    if partition == "aws-us-gov":
        return "us-gov-west-1"
    else:
        return "us-east-1"


def get_default_regions(partition: Optional[str] = None) -> List[str]:
    """
    Get the default AWS regions from configuration.

    Args:
        partition: Optional partition to filter regions ('aws' or 'aws-us-gov')
                  If not provided, uses regions from config.json or auto-detects

    Returns:
        list: List of default AWS region names
    """
    if partition:
        return get_partition_regions(partition)

    _, cfg = get_config()
    config_regions = cfg.get("default_regions", _DEFAULT_REGIONS)

    if config_regions:
        detected_partition = detect_partition(config_regions[0])
        return [r for r in config_regions if detect_partition(r) == detected_partition]

    return config_regions


def get_partition_default_regions(partition: Optional[str] = None) -> List[str]:
    """
    Get the default AWS regions (alias for get_default_regions for consistency).

    Args:
        partition: Optional partition to filter regions ('aws' or 'aws-us-gov')

    Returns:
        list: List of default AWS region names
    """
    return get_default_regions(partition)


# ---------------------------------------------------------------------------
# Credential and region access validation
# ---------------------------------------------------------------------------


def validate_aws_credentials() -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate AWS credentials.

    Returns:
        tuple: (is_valid, account_id, error_message)
    """
    try:
        sts = get_boto3_client("sts")
        response = sts.get_caller_identity()
        account_id = response["Account"]
        return True, account_id, None
    except Exception as e:
        return False, None, str(e)


def check_aws_region_access(region: str) -> bool:
    """
    Check if a specific AWS region is accessible.

    Args:
        region: AWS region name

    Returns:
        bool: True if accessible, False otherwise
    """
    if not is_aws_region(region):
        return False

    try:
        ec2 = get_boto3_client("ec2", region_name=region)
        ec2.describe_regions(RegionNames=[region])
        return True
    except Exception as e:
        logger.warning("Cannot access region %s: %s", region, e)
        return False


def get_available_aws_regions() -> List[str]:
    """
    Get list of AWS regions that are currently accessible.
    Partition-aware: Returns GovCloud regions when in GovCloud, Commercial otherwise.

    Returns:
        list: List of accessible AWS region names
    """
    partition = detect_partition()
    partition_regions = get_partition_regions(partition)

    available_regions = []

    for region in partition_regions:
        if check_aws_region_access(region):
            available_regions.append(region)
        else:
            logger.warning("AWS region %s is not accessible", region)

    return available_regions


def is_aws_commercial_environment() -> bool:
    """
    Check if we're currently running in an AWS Commercial environment.

    Returns:
        bool: True if in AWS Commercial, False otherwise
    """
    try:
        sts = get_boto3_client("sts")
        caller_arn = sts.get_caller_identity()["Arn"]
        partition = caller_arn.split(":")[1]
        return partition == "aws"
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Cached account info (Phase 4B optimization)
# ---------------------------------------------------------------------------


def get_cached_account_info() -> Tuple[str, str, str]:
    """
    Get AWS account info with session-level caching (Phase 4B optimization).

    Returns:
        tuple: (account_id, account_name, partition)

    Note:
        - Cached in _account_info_cache (module-level) only on successful STS call.
          A transient first-call failure returns default values without poisoning
          the cache, so the next call will retry the STS lookup.
        - Thread-safe: _account_info_lock guards both the read and write paths.
        - Uses get_boto3_client() which includes automatic retry logic.
    """
    global _account_info_cache

    if _account_info_cache is not None:
        return _account_info_cache

    with _account_info_lock:
        if _account_info_cache is not None:
            return _account_info_cache

        try:
            sts = get_boto3_client("sts")
            account_id = sts.get_caller_identity()["Account"]
            account_name = get_account_name(account_id, default=f"AWS-ACCOUNT-{account_id}")
            partition = detect_partition()

            _account_info_cache = (account_id, account_name, partition)
            logger.debug(
                "Cached account info: %s (%s) in partition %s",
                account_name,
                account_id,
                partition,
            )
            return _account_info_cache

        except Exception as e:
            logger.error("Failed to get account information: %s", e)
            logger.warning("Using default account values")
            return "UNKNOWN", "UNKNOWN-ACCOUNT", "aws"
