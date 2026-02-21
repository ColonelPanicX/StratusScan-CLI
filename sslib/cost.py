"""
sslib.cost — Cost estimation utilities for StratusScan.

All pricing figures are based on us-east-1 (N. Virginia) On-Demand rates.
Actual costs will differ in other regions and under Reserved or Savings Plan
pricing.  For accurate pricing use AWS Pricing Calculator or Cost Explorer.

Zero dependency on utils.py — uses only stdlib + third-party packages.
"""

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd  # noqa: F401 – used for type hint in _estimate_excel_size

logger = logging.getLogger(__name__)

# Path to the reference/ directory (two levels up from this file: sslib/ → repo root → reference/)
_REFERENCE_DIR = Path(__file__).parent.parent / "reference"


def _load_pricing_csv(filename: str, key_col: str, val_col: str, default: Dict[str, float]) -> Dict[str, float]:
    """
    Load a two-column pricing CSV from the reference/ directory.

    Falls back to ``default`` on any I/O or parse error so cost estimation
    continues to work even when the CSV is missing or malformed.

    Args:
        filename: CSV filename inside reference/ (e.g. 's3-pricing.csv')
        key_col:  Name of the column to use as dict key
        val_col:  Name of the column to use as dict value (must be numeric)
        default:  Fallback dict returned on error

    Returns:
        Dict mapping key_col values → float(val_col values)
    """
    csv_path = _REFERENCE_DIR / filename
    try:
        pricing: Dict[str, float] = {}
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                key = row.get(key_col, "").strip()
                val_str = row.get(val_col, "").strip()
                if key and val_str:
                    pricing[key] = float(val_str)
        if pricing:
            return pricing
        logger.warning("Pricing CSV %s is empty — using built-in defaults", filename)
    except FileNotFoundError:
        logger.warning("Pricing CSV not found: %s — using built-in defaults", csv_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error reading pricing CSV %s: %s — using built-in defaults", filename, exc)
    return default


# =============================================================================
# EXCEL SIZE ESTIMATION
# =============================================================================


def _estimate_excel_size(df) -> int:
    """
    Estimate Excel file size for a DataFrame.

    Args:
        df: pandas DataFrame

    Returns:
        int: Estimated file size in bytes
    """
    # Rough estimation: 100 bytes per cell + overhead
    num_cells = len(df) * len(df.columns)
    base_size = num_cells * 100

    # Add overhead for Excel formatting
    overhead = base_size * 0.2

    return int(base_size + overhead)


# =============================================================================
# COST ESTIMATION UTILITIES
# =============================================================================


def estimate_rds_monthly_cost(
    instance_class: str,
    engine: str,
    storage_gb: int,
    storage_type: str = "gp2",
    multi_az: bool = False,
) -> Dict[str, Any]:
    """
    Estimate monthly cost for RDS database instance.

    NOTE: All pricing figures are based on us-east-1 (N. Virginia) On-Demand rates.
    Actual costs will differ in other regions and under Reserved or Savings Plan pricing.
    For accurate pricing, consult AWS Pricing Calculator or AWS Cost Explorer.

    Args:
        instance_class: RDS instance class (e.g., 'db.t3.micro')
        engine: Database engine (e.g., 'mysql', 'postgres', 'oracle')
        storage_gb: Allocated storage in GB
        storage_type: Storage type ('gp2', 'gp3', 'io1')
        multi_az: Whether Multi-AZ deployment is enabled

    Returns:
        dict: Cost breakdown with instance, storage, and total costs

    Example:
        >>> cost = estimate_rds_monthly_cost('db.t3.micro', 'mysql', 20)
        >>> print(f"Estimated monthly cost: ${cost['total']:.2f}")

    Note:
        - Uses approximate pricing for us-east-1 region
        - Does not include data transfer, backups, or other charges
        - Multi-AZ deployments approximately double instance costs
    """
    # Approximate instance pricing per hour (us-east-1, on-demand)
    _instance_defaults: Dict[str, float] = {
        "db.t3.micro": 0.017,
        "db.t3.small": 0.034,
        "db.t3.medium": 0.068,
        "db.t3.large": 0.136,
        "db.t3.xlarge": 0.272,
        "db.t3.2xlarge": 0.544,
        "db.m5.large": 0.192,
        "db.m5.xlarge": 0.384,
        "db.m5.2xlarge": 0.768,
        "db.m5.4xlarge": 1.536,
        "db.r5.large": 0.24,
        "db.r5.xlarge": 0.48,
        "db.r5.2xlarge": 0.96,
        "db.r5.4xlarge": 1.92,
    }
    instance_pricing = _load_pricing_csv(
        "rds-instance-pricing.csv", "instance_class", "hourly_rate_usd", _instance_defaults
    )

    # Storage pricing per GB/month
    _storage_defaults: Dict[str, float] = {
        "gp2": 0.115,
        "gp3": 0.08,
        "io1": 0.125,
        "magnetic": 0.10,
    }
    storage_pricing = _load_pricing_csv(
        "rds-storage-pricing.csv", "storage_type", "price_per_gb_month", _storage_defaults
    )

    # Get instance cost
    hourly_instance_cost = instance_pricing.get(instance_class, 0.10)
    monthly_instance_cost = hourly_instance_cost * 730  # 730 hours per month

    # Apply Multi-AZ multiplier (approximately 2x for instance)
    if multi_az:
        monthly_instance_cost *= 2

    # Get storage cost
    storage_price_per_gb = storage_pricing.get(storage_type, 0.115)
    monthly_storage_cost = storage_gb * storage_price_per_gb

    # Calculate total
    total_monthly_cost = monthly_instance_cost + monthly_storage_cost

    result = {
        "instance_cost": round(monthly_instance_cost, 2),
        "storage_cost": round(monthly_storage_cost, 2),
        "total": round(total_monthly_cost, 2),
        "multi_az_enabled": multi_az,
        "note": "Approximate estimate - see AWS Pricing Calculator for accurate costs",
    }

    logger.debug("RDS cost estimate for %s: $%.2f/month", instance_class, result["total"])
    return result


def estimate_s3_monthly_cost(
    total_size_gb: float,
    storage_class: str = "STANDARD",
    requests_per_month: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Estimate monthly cost for S3 storage.

    This provides rough cost estimates for S3 buckets. For accurate pricing,
    consult AWS Pricing Calculator or AWS Cost Explorer.

    Args:
        total_size_gb: Total storage size in GB
        storage_class: S3 storage class ('STANDARD', 'INTELLIGENT_TIERING', 'GLACIER', etc.)
        requests_per_month: Optional number of requests per month

    Returns:
        dict: Cost breakdown with storage, request, and total costs

    Example:
        >>> cost = estimate_s3_monthly_cost(1000, 'STANDARD')
        >>> print(f"Estimated monthly cost: ${cost['total']:.2f}")

    Note:
        - Uses approximate pricing for us-east-1 region
        - Does not include data transfer costs
        - Request costs are minimal unless very high volume
    """
    # S3 storage pricing per GB/month (us-east-1)
    _s3_defaults: Dict[str, float] = {
        "STANDARD": 0.023,
        "INTELLIGENT_TIERING": 0.023,
        "STANDARD_IA": 0.0125,
        "ONEZONE_IA": 0.01,
        "GLACIER": 0.004,
        "GLACIER_IR": 0.0036,
        "DEEP_ARCHIVE": 0.00099,
    }
    storage_pricing = _load_pricing_csv(
        "s3-pricing.csv", "storage_class", "price_per_gb_month", _s3_defaults
    )

    # Request pricing (per 1,000 requests)
    request_pricing = {
        "STANDARD": {"PUT": 0.005, "GET": 0.0004},
        "INTELLIGENT_TIERING": {"PUT": 0.005, "GET": 0.0004},
    }

    # Calculate storage cost
    storage_price_per_gb = storage_pricing.get(storage_class, 0.023)
    monthly_storage_cost = total_size_gb * storage_price_per_gb

    # Calculate request costs (if provided)
    monthly_request_cost = 0.0
    if requests_per_month and storage_class in request_pricing:
        put_requests = requests_per_month * 0.5
        get_requests = requests_per_month * 0.5

        put_cost = (put_requests / 1000) * request_pricing[storage_class]["PUT"]
        get_cost = (get_requests / 1000) * request_pricing[storage_class]["GET"]

        monthly_request_cost = put_cost + get_cost

    # Add monitoring fee for Intelligent-Tiering
    monitoring_cost = 0.0
    if storage_class == "INTELLIGENT_TIERING":
        # $0.0025 per 1,000 objects monitored
        estimated_objects = (total_size_gb * 1024) / 10
        monitoring_cost = (estimated_objects / 1000) * 0.0025

    total_cost = monthly_storage_cost + monthly_request_cost + monitoring_cost

    result = {
        "storage_cost": round(monthly_storage_cost, 2),
        "request_cost": round(monthly_request_cost, 2),
        "monitoring_cost": round(monitoring_cost, 2),
        "total": round(total_cost, 2),
        "storage_class": storage_class,
        "note": "Approximate estimate - does not include data transfer costs",
    }

    logger.debug(
        "S3 cost estimate for %.1fGB (%s): $%.2f/month",
        total_size_gb,
        storage_class,
        result["total"],
    )
    return result


def calculate_nat_gateway_monthly_cost(
    hours_per_month: int = 730,
    data_processed_gb: float = 0.0,
) -> Dict[str, Any]:
    """
    Calculate monthly cost for NAT Gateway.

    NAT Gateways have both hourly and data processing charges.

    Args:
        hours_per_month: Number of hours the NAT Gateway is running (default: 730 for full month)
        data_processed_gb: Amount of data processed in GB per month

    Returns:
        dict: Cost breakdown with hourly, data processing, and total costs

    Example:
        >>> cost = calculate_nat_gateway_monthly_cost(730, 500)
        >>> print(f"Estimated monthly cost: ${cost['total']:.2f}")

    Note:
        - Uses pricing for us-east-1 region
        - Actual pricing varies by region
        - Each NAT Gateway incurs these costs independently
    """
    # NAT Gateway pricing (us-east-1)
    _natgw_defaults: Dict[str, float] = {
        "hourly": 0.045,
        "data_processing_per_gb": 0.045,
    }
    natgw_pricing = _load_pricing_csv(
        "natgw-pricing.csv", "rate_type", "rate_usd", _natgw_defaults
    )
    hourly_rate = natgw_pricing.get("hourly", 0.045)
    data_processing_rate = natgw_pricing.get("data_processing_per_gb", 0.045)

    hourly_cost = hours_per_month * hourly_rate
    data_processing_cost = data_processed_gb * data_processing_rate

    total_cost = hourly_cost + data_processing_cost

    result = {
        "hourly_cost": round(hourly_cost, 2),
        "data_processing_cost": round(data_processing_cost, 2),
        "total": round(total_cost, 2),
        "hours": hours_per_month,
        "data_processed_gb": data_processed_gb,
        "warning": (
            "NAT Gateway costs can be significant - "
            "consider alternatives for dev/test environments"
        ),
    }

    logger.debug(
        "NAT Gateway cost: $%.2f/month (%dh, %.1fGB)",
        result["total"],
        hours_per_month,
        data_processed_gb,
    )
    return result


def generate_cost_optimization_recommendations(
    resource_type: str,
    resource_data: Dict[str, Any],
) -> List[str]:
    """
    Generate cost optimization recommendations for AWS resources.

    This function analyzes resource configurations and suggests potential
    cost savings opportunities.

    Args:
        resource_type: Type of resource ('ec2', 'rds', 's3', 'vpc', etc.)
        resource_data: Dictionary containing resource configuration details

    Returns:
        list: List of recommendation strings

    Example:
        >>> recommendations = generate_cost_optimization_recommendations(
        ...     'ec2',
        ...     {'state': 'stopped', 'instance_type': 't3.large', 'days_stopped': 30}
        ... )
        >>> for rec in recommendations:
        ...     print(f"- {rec}")

    Note:
        - Recommendations are general guidelines, not specific financial advice
        - Consider business requirements before implementing changes
    """
    recommendations = []

    if resource_type == "ec2":
        state = resource_data.get("state", "").lower()
        instance_type = resource_data.get("instance_type", "")
        days_stopped = resource_data.get("days_stopped", 0)

        if state == "stopped" and days_stopped > 7:
            recommendations.append(
                f"Instance stopped for {days_stopped} days - consider terminating if no longer needed"
            )

        if instance_type.startswith("t2."):
            recommendations.append(
                "Consider upgrading to t3 instance family for better price/performance"
            )

        if resource_data.get("ebs_optimized", False) and instance_type.startswith("t3."):
            recommendations.append(
                "EBS-optimized is included free for t3 instances - no change needed"
            )

    elif resource_type == "rds":
        multi_az = resource_data.get("multi_az", False)
        environment = resource_data.get("environment", "").lower()

        if multi_az and environment in ["dev", "test", "staging"]:
            recommendations.append(
                "Multi-AZ enabled in non-production environment - consider single-AZ for cost savings"
            )

        backup_retention = resource_data.get("backup_retention_period", 0)
        if backup_retention > 7 and environment in ["dev", "test"]:
            recommendations.append(
                f"Backup retention is {backup_retention} days - consider reducing for non-production"
            )

    elif resource_type == "s3":
        storage_class = resource_data.get("storage_class", "STANDARD")
        size_gb = resource_data.get("size_gb", 0)
        last_accessed = resource_data.get("days_since_last_access", 0)

        if storage_class == "STANDARD" and last_accessed > 90:
            recommendations.append(
                "Objects not accessed in 90+ days - consider moving to STANDARD_IA or GLACIER"
            )

        if storage_class == "STANDARD" and size_gb > 1000:
            recommendations.append(
                "Large bucket - consider enabling Intelligent-Tiering for automatic cost optimization"
            )

    elif resource_type == "nat_gateway":
        data_processed_gb = resource_data.get("data_processed_gb", 0)
        environment = resource_data.get("environment", "").lower()

        if environment in ["dev", "test"]:
            recommendations.append(
                "NAT Gateway in non-production - consider NAT instances or removing for cost savings"
            )

        if data_processed_gb > 5000:
            recommendations.append(
                "High data transfer - verify traffic patterns and consider VPC endpoints for AWS services"
            )

    if not recommendations:
        recommendations.append("No specific cost optimization recommendations at this time")

    return recommendations
