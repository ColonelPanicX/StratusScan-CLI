#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: StratusScan Utilities Module
Version: v0.1.0
Date: NOV-15-2025

Description:
Shared utility functions for StratusScan scripts with multi-partition support.
Works seamlessly in both AWS Commercial and AWS GovCloud environments with
automatic partition detection. This module provides common functionality such as
path handling, file operations, standardized output formatting, account mapping,
region and partition handling, and cross-partition resource management.

Features:
- Multi-partition support (AWS Commercial & GovCloud)
- Automatic partition detection from credentials
- Partition-aware region selection and ARN building
- Service availability validation by partition
- Full service availability including Trusted Advisor (Commercial)
- Zero-configuration cross-environment compatibility
- Phase 4B Performance Optimization (concurrent region scanning, session-level caching)
"""

import os
import platform
import sys
import datetime
import json
import logging
import re
import subprocess
import threading
import warnings
from contextlib import contextmanager
from functools import wraps
from importlib.metadata import version as _pkg_version, PackageNotFoundError
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Callable, TypeVar

from openpyxl.utils import get_column_letter

# Global logger instance
logger = None
# Tracks whether setup_logging() has been explicitly called
_logging_configured = False


def get_version() -> str:
    """Return the installed package version, or 'dev' if not installed."""
    try:
        return _pkg_version("stratusscan-cli")
    except PackageNotFoundError:
        return "dev"


def _cleanup_old_logs(logs_dir: Path, log_retention_days: int = 14) -> None:
    """
    Remove log files older than log_retention_days from the logs directory.

    Args:
        logs_dir: Path to the logs directory
        log_retention_days: Number of days to retain log files (default: 14)
    """
    try:
        cutoff = datetime.datetime.now() - datetime.timedelta(days=log_retention_days)
        cutoff_timestamp = cutoff.timestamp()
        removed = 0
        for log_file in logs_dir.glob("*.log"):
            try:
                if log_file.stat().st_mtime < cutoff_timestamp:
                    log_file.unlink()
                    removed += 1
            except Exception:
                pass  # Skip files we cannot stat or remove
        if removed:
            logging.getLogger('stratusscan').debug(
                f"Cleaned up {removed} log file(s) older than {log_retention_days} days"
            )
    except Exception:
        pass  # Log cleanup is best-effort; never raise


def setup_logging(script_name: str = "stratusscan", log_to_file: bool = True) -> logging.Logger:
    """
    Setup comprehensive logging for StratusScan with both console and file output.

    Args:
        script_name (str): Name of the script for log file naming
        log_to_file (bool): Whether to log to file in addition to console

    Returns:
        logging.Logger: Configured logger instance
    """
    global logger, _logging_configured

    # Create logger
    logger = logging.getLogger('stratusscan')
    logger.setLevel(logging.DEBUG)

    # Clear any existing handlers
    logger.handlers = []

    # Create formatters
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if enabled)
    if log_to_file:
        try:
            # Create logs directory if it doesn't exist
            logs_dir = Path(__file__).parent / "logs"
            logs_dir.mkdir(exist_ok=True)

            # Remove stale log files before creating the new one
            _cleanup_old_logs(logs_dir)

            # Generate timestamp for log filename: MM.DD.YYYY-HHMM
            timestamp = datetime.datetime.now().strftime("%m.%d.%Y-%H%M")
            log_filename = f"logs-{script_name}-{timestamp}.log"
            log_filepath = logs_dir / log_filename

            # File handler
            file_handler = logging.FileHandler(log_filepath, mode='w', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

            # Log the initialization
            logger.info(f"StratusScan logging initialized - Log file: {log_filepath}")
            logger.info(f"Script: {script_name}")
            logger.info(f"Timestamp: {timestamp}")
            logger.info("=" * 80)

        except Exception as e:
            # If file logging fails, continue with console only
            logger.error(f"Failed to setup file logging: {e}")
            logger.warning("Continuing with console logging only")

    _logging_configured = True
    return logger

def get_logger() -> logging.Logger:
    """
    Get the current logger instance, creating one if it doesn't exist.
    If setup_logging() has not yet been called, returns a logger with a
    NullHandler so that library usage does not emit spurious output.

    Returns:
        logging.Logger: Logger instance
    """
    global logger, _logging_configured
    if logger is None:
        if _logging_configured:
            # setup_logging() was called but logger was somehow cleared — reinitialise
            logger = setup_logging()
        else:
            # setup_logging() has not been called yet; return a silent logger
            # so importing utils as a library doesn't emit unexpected output
            _null_logger = logging.getLogger('stratusscan')
            if not _null_logger.handlers:
                _null_logger.addHandler(logging.NullHandler())
            return _null_logger
    return logger

# Do NOT call setup_logging() or get_logger() at module import time.
# Scripts must call utils.setup_logging() explicitly to activate logging.
# This prevents side effects (file creation, console output) on import.

# AWS Commercial constants
DEFAULT_REGIONS = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1']
AWS_PARTITION = 'aws'

def prompt_region_selection(
    service_name: Optional[str] = None,
    prompt_message: Optional[str] = None,
    default_to_all: bool = False,
    allow_all: bool = True
) -> List[str]:
    """
    Prompt user for AWS region selection with standardized 3-option menu.

    This function provides a consistent user experience across all export scripts
    with partition-aware region examples and robust input validation.

    Args:
        service_name: Name of the AWS service (e.g., "Lambda", "S3")
                     Used to customize the prompt message if prompt_message not provided
        prompt_message: Custom message to display before menu
                       If provided, overrides service_name in message
        default_to_all: If True, make "All Regions" the default choice
                       If False, make "Default Regions" the default choice
        allow_all: If True, include "All Regions" option (default: True)

    Returns:
        list: List of selected AWS region names

    Examples:
        # Basic usage with service name
        regions = utils.prompt_region_selection(service_name="Lambda")

        # Custom prompt message
        regions = utils.prompt_region_selection(
            prompt_message="Select regions for DataSync export:",
            allow_all=True
        )

        # Default to all regions
        regions = utils.prompt_region_selection(
            service_name="Detective",
            default_to_all=False
        )
    """
    # Automation mode: bypass interactive prompts when STRATUSSCAN_AUTO_RUN is set
    if is_auto_run():
        auto_regions = get_auto_regions()
        if auto_regions:
            return auto_regions
        # Fall through: return all regions when auto-run set but no STRATUSSCAN_REGIONS
        _partition = detect_partition()
        return get_partition_regions(_partition, all_regions=True)

    # Detect partition for region examples
    partition = detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Build prompt message
    if prompt_message:
        print(f"\n{prompt_message}")
    elif service_name:
        print(f"\n{service_name} is a regional service.")

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")

    if allow_all:
        print("\n  2. All Available Regions")
        print("     (Scan all regions where the service is available)")
        print("\n  3. Specific Region")
        print("     (Enter a specific AWS region code)")
    else:
        print("\n  2. Specific Region")
        print("     (Enter a specific AWS region code)")

    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            if allow_all:
                region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()
            else:
                region_choice = input("\nEnter your choice (1 or 2): ").strip()

            if region_choice == '1':
                # Default regions
                regions = get_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")

            elif region_choice == '2':
                if allow_all:
                    # All available regions
                    regions = get_partition_regions(partition, all_regions=True)
                    print(f"\nScanning all {len(regions)} available regions")
                else:
                    # Specific region (when allow_all=False, option 2 is specific region)
                    available_regions = get_partition_regions(partition, all_regions=True)
                    print("\n" + "=" * 68)
                    print("AVAILABLE REGIONS")
                    print("=" * 68)
                    for idx, region in enumerate(available_regions, 1):
                        print(f"  {idx:2d}. {region}")
                    print("=" * 68)

                    # Get region selection with validation
                    region_selected = False
                    while not region_selected:
                        try:
                            region_num = input(f"\nEnter region number (1-{len(available_regions)}): ").strip()
                            region_idx = int(region_num) - 1

                            if 0 <= region_idx < len(available_regions):
                                selected_region = available_regions[region_idx]
                                regions = [selected_region]
                                print(f"\nSelected region: {selected_region}")
                                region_selected = True
                            else:
                                print(f"Invalid selection. Please enter a number between 1 and {len(available_regions)}.")
                        except ValueError:
                            print("Invalid input. Please enter a number.")
                        except KeyboardInterrupt:
                            print("\n\nOperation cancelled by user.")
                            sys.exit(0)

            elif region_choice == '3' and allow_all:
                # Specific region (when allow_all=True, option 3 is specific region)
                available_regions = get_partition_regions(partition, all_regions=True)
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx:2d}. {region}")
                print("=" * 68)

                # Get region selection with validation
                region_selected = False
                while not region_selected:
                    try:
                        region_num = input(f"\nEnter region number (1-{len(available_regions)}): ").strip()
                        region_idx = int(region_num) - 1

                        if 0 <= region_idx < len(available_regions):
                            selected_region = available_regions[region_idx]
                            regions = [selected_region]
                            print(f"\nSelected region: {selected_region}")
                            region_selected = True
                        else:
                            print(f"Invalid selection. Please enter a number between 1 and {len(available_regions)}.")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                    except KeyboardInterrupt:
                        print("\n\nOperation cancelled by user.")
                        sys.exit(0)
            else:
                if allow_all:
                    print("\nInvalid choice. Please enter 1, 2, or 3.")
                else:
                    print("\nInvalid choice. Please enter 1 or 2.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    return regions

def get_organization_name() -> str:
    """
    Get the organization name from configuration.

    Returns:
        str: Organization name or default
    """
    _, cfg = get_config()
    return cfg.get('organization_name', 'YOUR-ORGANIZATION')

def get_aws_environment() -> str:
    """
    Get the AWS environment type from configuration.

    Returns:
        str: Environment type (e.g., 'production', 'staging') or default
    """
    _, cfg = get_config()
    return cfg.get('aws_environment', 'production')

def log_error(error_message: str, error_obj: Optional[Exception] = None) -> None:
    """
    Log an error message to both console and file.

    Args:
        error_message: The error message to display
        error_obj: Optional exception object
    """
    current_logger = get_logger()
    if error_obj:
        current_logger.error(f"{error_message}: {str(error_obj)}")
        # Log stack trace for debugging
        current_logger.debug(f"Exception details: {error_obj}", exc_info=True)
    else:
        current_logger.error(error_message)

def log_warning(warning_message: str) -> None:
    """
    Log a warning message to both console and file.

    Args:
        warning_message: The warning message to display
    """
    current_logger = get_logger()
    current_logger.warning(warning_message)

def log_info(info_message: str) -> None:
    """
    Log an informational message to both console and file.

    Args:
        info_message: The information message to display
    """
    current_logger = get_logger()
    current_logger.info(info_message)

def log_debug(debug_message: str) -> None:
    """
    Log a debug message (file only, not console).

    Args:
        debug_message: The debug message to log
    """
    current_logger = get_logger()
    current_logger.debug(debug_message)

def log_success(success_message: str) -> None:
    """
    Log a success message to both console and file.

    Args:
        success_message: The success message to display
    """
    current_logger = get_logger()
    current_logger.info(f"SUCCESS: {success_message}")

def log_aws_info(message: str) -> None:
    """
    Log AWS-specific informational message to both console and file.

    Args:
        message: The AWS-specific message to display
    """
    current_logger = get_logger()
    current_logger.info(f"AWS: {message}")

def log_partition_info(partition: str, regions: List[str]) -> None:
    """
    Log AWS partition information for user awareness.

    Args:
        partition: AWS partition ('aws' or 'aws-us-gov')
        regions: List of regions being used
    """
    current_logger = get_logger()
    partition_name = "AWS GovCloud" if partition == 'aws-us-gov' else "AWS Commercial"
    current_logger.info(f"AWS PARTITION: {partition_name} ({partition})")
    current_logger.info(f"REGIONS: {', '.join(regions)}")

    if partition == 'aws-us-gov':
        current_logger.info("NOTE: GovCloud has different service availability - some features may not be available")

def log_script_start(script_name: str, description: str = "") -> None:
    """
    Log the start of a script execution with standardized format.

    Args:
        script_name: Name of the script being executed
        description: Optional description of the script's purpose
    """
    current_logger = get_logger()
    current_logger.info("=" * 80)
    current_logger.info(f"SCRIPT START: {script_name}")
    if description:
        current_logger.info(f"DESCRIPTION: {description}")
    current_logger.info(f"START TIME: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    current_logger.info("=" * 80)

def log_script_end(script_name: str, start_time: Optional[datetime.datetime] = None) -> None:
    """
    Log the end of a script execution with standardized format.

    Args:
        script_name: Name of the script that was executed
        start_time: Optional start time to calculate duration
    """
    current_logger = get_logger()
    end_time = datetime.datetime.now()

    current_logger.info("=" * 80)
    current_logger.info(f"SCRIPT END: {script_name}")
    current_logger.info(f"END TIME: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

    if start_time:
        duration = end_time - start_time
        current_logger.info(f"DURATION: {duration}")

    current_logger.info("=" * 80)

def log_section(section_name: str) -> None:
    """
    Log a section header for better log organization.

    Args:
        section_name: Name of the section
    """
    current_logger = get_logger()
    current_logger.info("-" * 50)
    current_logger.info(f"SECTION: {section_name}")
    current_logger.info("-" * 50)

def log_aws_operation(operation_name: str, service: str, region: Optional[str] = None, details: str = "") -> None:
    """
    Log AWS API operations for audit trail.

    Args:
        operation_name: Name of the AWS operation (e.g., describe_instances)
        service: AWS service name (e.g., EC2)
        region: AWS region (optional)
        details: Additional details about the operation
    """
    current_logger = get_logger()
    region_info = f" in {region}" if region else ""
    details_info = f" - {details}" if details else ""
    current_logger.info(f"AWS API: {service}.{operation_name}{region_info}{details_info}")

def log_export_summary(resource_type: str, count: int, output_file: str) -> None:
    """
    Log export operation summary.

    Args:
        resource_type: Type of resource exported
        count: Number of resources exported
        output_file: Path to output file
    """
    current_logger = get_logger()
    current_logger.info(f"EXPORT SUMMARY: {resource_type}")
    current_logger.info(f"  Resources exported: {count}")
    current_logger.info(f"  Output file: {output_file}")

def log_system_info() -> None:
    """
    Log system information for debugging purposes.
    """
    current_logger = get_logger()
    current_logger.info("SYSTEM INFORMATION:")
    current_logger.info(f"  Platform: {platform.system()} {platform.release()}")
    current_logger.info(f"  Python version: {sys.version}")
    current_logger.info(f"  Working directory: {os.getcwd()}")
    current_logger.info(f"  Script location: {Path(__file__).parent}")

def log_menu_selection(menu_path: str, selection_name: str) -> None:
    """
    Log menu selections for user activity tracking.

    Args:
        menu_path: Path through menu (e.g., "4.2.1")
        selection_name: Name of the selected option
    """
    current_logger = get_logger()
    current_logger.info(f"MENU SELECTION: {menu_path} - {selection_name}")

def get_current_log_file() -> Optional[str]:
    """
    Get the path to the current log file if file logging is enabled.

    Returns:
        str: Path to current log file or None if not file logging
    """
    current_logger = get_logger()
    for handler in current_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            return handler.baseFilename
    return None

def prompt_for_confirmation(message: str = "Do you want to continue?", default: bool = True) -> bool:
    """
    Prompt the user for confirmation.

    Args:
        message: Message to display
        default: Default response if user just presses Enter

    Returns:
        bool: True if confirmed, False otherwise
    """
    # TODO: Issue #C — add b/x navigation support here
    default_prompt = " (Y/n): " if default else " (y/N): "
    response = input(f"{message}{default_prompt}").strip().lower()
    
    if not response:
        return default
    
    return response.lower() in ['y', 'yes']

def format_bytes(size_bytes: Union[int, float]) -> str:
    """
    Format bytes to human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        str: Formatted size string (e.g., "1.23 GB")
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def get_log_timestamp() -> str:
    """
    Get current timestamp in ISO-style format for log messages.

    Returns:
        str: Timestamp string in ``YYYY-MM-DD HH:MM:SS`` format
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_export_date() -> str:
    """
    Get current date in the StratusScan export-filename format.

    Returns:
        str: Date string in ``MM.DD.YYYY`` format
    """
    return datetime.datetime.now().strftime("%m.%d.%Y")


def get_current_timestamp() -> str:
    """
    Get current timestamp in a standardized format.

    .. deprecated::
        Use :func:`get_log_timestamp` (ISO format) or :func:`get_export_date`
        (``MM.DD.YYYY`` for filenames) instead.

    Returns:
        str: Formatted timestamp
    """
    warnings.warn(
        "get_current_timestamp() is deprecated; use get_log_timestamp() or get_export_date().",
        DeprecationWarning,
        stacklevel=2,
    )
    return get_log_timestamp()

def resource_list_to_dataframe(resource_list: List[Dict[str, Any]], columns: Optional[List[str]] = None) -> Any:
    """
    Convert a list of dictionaries to a pandas DataFrame with specific columns.

    Args:
        resource_list: List of resource dictionaries
        columns: Optional list of columns to include

    Returns:
        DataFrame: pandas DataFrame
    """
    import pandas as pd
    
    if not resource_list:
        return pd.DataFrame()
    
    df = pd.DataFrame(resource_list)
    
    if columns:
        # Keep only specified columns that exist in the DataFrame
        existing_columns = [col for col in columns if col in df.columns]
        df = df[existing_columns]
    
    return df

def get_stratusscan_root() -> Path:
    """
    Get the root directory of the StratusScan package.

    If the script using this function is in the scripts/ directory,
    this will return the parent directory. If the script is in the
    root directory, this will return that directory.

    Returns:
        Path: Path to the StratusScan root directory
    """
    # Anchor to this file (utils.py) rather than sys.argv[0] so the path is
    # correct regardless of how Python was invoked (e.g. pytest, subprocess, etc.)
    calling_script = Path(__file__).absolute()
    script_dir = calling_script.parent

    # Check if we're in a 'scripts' subdirectory
    if script_dir.name.lower() == 'scripts':
        # Return the parent (StratusScan root)
        return script_dir.parent
    else:
        # Assume we're already at the root
        return script_dir

def get_scripts_dir() -> Path:
    """
    Get the path to the scripts directory.

    Returns:
        Path: Path to the scripts directory
    """
    # Get StratusScan root directory
    root_dir = get_stratusscan_root()

    # Define the scripts directory path
    scripts_dir = root_dir / "scripts"

    return scripts_dir


def get_output_dir() -> Path:
    """
    Get the path to the output directory and create it if it doesn't exist.

    Returns:
        Path: Path to the output directory
    """
    # Get StratusScan root directory
    root_dir = get_stratusscan_root()

    # Define the output directory path
    output_dir = root_dir / "output"

    # Create the directory if it doesn't exist
    output_dir.mkdir(exist_ok=True)

    return output_dir

def get_output_filepath(filename: str) -> Path:
    """
    Get the full path for a file in the output directory.

    Args:
        filename: The name of the file

    Returns:
        Path: Full path to the file in the output directory
    """
    return get_output_dir() / filename

def create_export_filename(
    account_name: str,
    resource_type: str,
    suffix: str = "",
    current_date: Optional[str] = None
) -> str:
    """
    Create a standardized filename for exported data.

    Args:
        account_name: AWS account name
        resource_type: Type of resource being exported (e.g., "ec2", "vpc")
        suffix: Optional suffix for the filename (e.g., "running", "all")
        current_date: Date to use in the filename (defaults to today)

    Returns:
        str: Standardized filename with path
    """
    # Get current date if not provided
    if not current_date:
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

    # Build the base filename
    if suffix:
        base_filename = f"{account_name}-{resource_type}-{suffix}-export-{current_date}.xlsx"
    else:
        base_filename = f"{account_name}-{resource_type}-export-{current_date}.xlsx"

    # Same-day overwrite protection: append -v2, -v3, etc. until the name is unique
    output_dir = get_output_dir()
    candidate = base_filename
    version = 2
    while (output_dir / candidate).exists():
        stem = base_filename[: -len(".xlsx")]
        candidate = f"{stem}-v{version}.xlsx"
        version += 1

    return candidate

def _adjust_column_widths(worksheet, df) -> None:
    """Set Excel column widths to fit content (max 50 chars)."""
    for i, column in enumerate(df.columns):
        column_width = max(df[column].astype(str).map(len).max(), len(column)) + 2
        column_width = min(column_width, 50)
        worksheet.column_dimensions[get_column_letter(i + 1)].width = column_width


def save_dataframe_to_excel(df, filename: str, sheet_name: str = "Data", auto_adjust_columns: bool = True, prepare: bool = False) -> Optional[str]:
    """
    Save a pandas DataFrame to an Excel file in the output directory.

    Args:
        df: pandas DataFrame to save
        filename: Name of the file to save
        sheet_name: Name of the sheet in Excel
        auto_adjust_columns: Whether to auto-adjust column widths
        prepare: If True, apply prepare_dataframe_for_export() before saving (default: False)

    Returns:
        str: Full path to the saved file
    """
    try:
        # Import pandas here to avoid dependency issues
        import pandas as pd

        # Prepare DataFrame if requested
        if prepare:
            df = prepare_dataframe_for_export(df)

        # Get the full path
        output_path = get_output_filepath(filename)

        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save to Excel
        if auto_adjust_columns:
            # Create Excel writer using context manager to ensure proper close/save
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Write DataFrame to Excel
                df.to_excel(writer, sheet_name=sheet_name, index=False)

                # Auto-adjust column widths (skip if DataFrame is empty)
                if not df.empty:
                    _adjust_column_widths(writer.sheets[sheet_name], df)
        else:
            # Save directly without adjusting columns
            df.to_excel(output_path, sheet_name=sheet_name, index=False)
        
        logger.info(f"Data successfully exported to: {output_path}")
        
        return str(output_path)
    
    except Exception as e:
        logger.error(f"Error saving Excel file: {e}")
        
        # Try CSV as fallback
        try:
            csv_filename = filename.replace('.xlsx', '.csv')
            csv_path = get_output_filepath(csv_filename)
            
            df.to_csv(csv_path, index=False)
            logger.info(f"Saved as CSV instead: {csv_path}")
            return str(csv_path)
            
        except Exception as csv_e:
            logger.error(f"Error saving CSV file: {csv_e}")
            return None

def save_multiple_dataframes_to_excel(dataframes_dict: Dict[str, Any], filename: str, prepare: bool = False) -> Optional[str]:
    """
    Save multiple pandas DataFrames to a single Excel file with multiple sheets.

    Args:
        dataframes_dict: Dictionary of {sheet_name: dataframe}
        filename: Name of the file to save
        prepare: If True, apply prepare_dataframe_for_export() to each DataFrame (default: False)

    Returns:
        str: Full path to the saved file
    """
    try:
        # Import pandas here to avoid dependency issues
        import pandas as pd

        # Prepare DataFrames if requested
        if prepare:
            dataframes_dict = {
                sheet_name: prepare_dataframe_for_export(df)
                for sheet_name, df in dataframes_dict.items()
            }

        # Get the full path
        output_path = get_output_filepath(filename)

        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Create Excel writer using context manager to ensure proper close/save
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Write each DataFrame to a separate sheet
            for sheet_name, df in dataframes_dict.items():
                df.to_excel(writer, sheet_name=sheet_name, index=False)

                # Auto-adjust column widths (skip if DataFrame is empty)
                if not df.empty:
                    _adjust_column_widths(writer.sheets[sheet_name], df)
        
        logger.info(f"Data successfully exported to: {output_path}")
        return str(output_path)
    
    except Exception as e:
        logger.error(f"Error saving Excel file: {e}")
        return None

def create_aws_arn(service: str, resource: str, region: Optional[str] = None, account_id: Optional[str] = None) -> str:
    """
    Create a properly formatted AWS ARN.

    DEPRECATED: Use build_arn() instead for partition-aware ARN construction.

    Args:
        service: AWS service name
        resource: Resource identifier
        region: AWS region (optional)
        account_id: AWS account ID (optional)

    Returns:
        str: Properly formatted AWS ARN
    """
    warnings.warn(
        "create_aws_arn() is deprecated; use build_arn() for partition-aware ARN construction.",
        DeprecationWarning,
        stacklevel=2,
    )
    # Delegate to the new partition-aware function
    return build_arn(service, resource, region=region, account_id=account_id)

def parse_aws_arn(arn: str) -> Optional[Dict[str, str]]:
    """
    Parse an AWS ARN into its components (partition-aware).

    Args:
        arn: AWS ARN string

    Returns:
        dict: Dictionary with ARN components or None if invalid
    """
    try:
        parts = arn.split(':')
        # Accept both 'aws' and 'aws-us-gov' partitions
        if len(parts) >= 6 and parts[0] == 'arn' and parts[1] in ['aws', 'aws-us-gov']:
            return {
                'partition': parts[1],
                'service': parts[2],
                'region': parts[3],
                'account_id': parts[4],
                'resource': ':'.join(parts[5:])
            }
    except Exception as e:
        logger.warning(f"Error parsing ARN '{arn}': {e}")

    return None


# =============================================================================
# STANDARDIZED ERROR HANDLING
# =============================================================================

# TypeVar for generic return types
T = TypeVar('T')


def aws_error_handler(
    operation_name: str,
    default_return: Any = None,
    reraise: bool = False
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for standardized AWS error handling.

    This decorator provides consistent error handling for AWS operations,
    including specific handling for NoCredentialsError, ClientError, and
    generic exceptions. All errors are logged using the existing logging
    infrastructure.

    Args:
        operation_name: Human-readable operation description for logging
        default_return: Value to return on error (if not reraising)
        reraise: Whether to re-raise the exception after logging

    Returns:
        Decorator function that wraps the target function

    Example:
        @aws_error_handler("Collecting IAM users", default_return=[])
        def collect_iam_users() -> List[Dict[str, Any]]:
            iam = get_boto3_client('iam')
            users = []
            for user in iam.list_users()['Users']:
                users.append(user)
            return users

        @aws_error_handler("Creating EC2 instance", reraise=True)
        def create_instance(instance_type: str) -> str:
            ec2 = get_boto3_client('ec2', region_name='us-east-1')
            response = ec2.run_instances(
                ImageId='ami-12345',
                InstanceType=instance_type,
                MinCount=1,
                MaxCount=1
            )
            return response['Instances'][0]['InstanceId']
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Import here to avoid circular imports
                try:
                    from botocore.exceptions import NoCredentialsError, ClientError

                    # Handle NoCredentialsError specifically
                    if isinstance(e, NoCredentialsError):
                        log_error(
                            f"{operation_name}: No AWS credentials found. "
                            "Please configure credentials using 'aws configure' or environment variables."
                        )
                        if reraise:
                            raise
                        return default_return

                    # Handle ClientError with error code extraction
                    elif isinstance(e, ClientError):
                        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                        error_msg = e.response.get('Error', {}).get('Message', str(e))
                        log_error(f"{operation_name}: AWS error [{error_code}]: {error_msg}")
                        if reraise:
                            raise
                        return default_return

                    # Handle all other exceptions
                    else:
                        log_error(f"{operation_name}: Unexpected error", e)
                        if reraise:
                            raise
                        return default_return

                except ImportError:
                    # Fallback if botocore is not available
                    log_error(f"{operation_name}: Error occurred", e)
                    if reraise:
                        raise
                    return default_return

        return wrapper
    return decorator


@contextmanager
def handle_aws_operation(
    operation_name: str,
    default_return: Any = None,
    suppress_errors: bool = False
):
    """
    Context manager for AWS operations with standardized error handling.

    This context manager provides flexible error handling for AWS operations
    when more control is needed than the decorator provides. It allows for
    custom logic within the try block while maintaining consistent error logging.

    Args:
        operation_name: Human-readable operation description for logging
        default_return: Value to return on error (if suppress_errors=True)
        suppress_errors: Whether to suppress exceptions (False = reraise)

    Yields:
        None - allows execution of the with block

    Raises:
        Exception: Re-raises the caught exception if suppress_errors=False

    Example:
        # Suppress errors and return default value
        with handle_aws_operation("Fetching EC2 pricing", default_return={}, suppress_errors=True):
            pricing_client = get_boto3_client('pricing', region_name='us-east-1')
            response = pricing_client.get_products(ServiceCode='AmazonEC2')
            pricing_data = response['PriceList']

        # Re-raise errors after logging
        with handle_aws_operation("Creating S3 bucket", suppress_errors=False):
            s3 = get_boto3_client('s3')
            s3.create_bucket(Bucket='my-bucket')
            log_success("Bucket created successfully")

        # Multiple operations in one block
        with handle_aws_operation("Multi-step deployment", suppress_errors=False):
            ec2 = get_boto3_client('ec2', region_name='us-east-1')

            # Step 1: Create VPC
            vpc_response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
            vpc_id = vpc_response['Vpc']['VpcId']
            log_info(f"Created VPC: {vpc_id}")

            # Step 2: Create subnet
            subnet_response = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock='10.0.1.0/24'
            )
            subnet_id = subnet_response['Subnet']['SubnetId']
            log_info(f"Created subnet: {subnet_id}")
    """
    try:
        yield
    except Exception as e:
        # Import here to avoid circular imports
        try:
            from botocore.exceptions import NoCredentialsError, ClientError

            # Handle NoCredentialsError specifically
            if isinstance(e, NoCredentialsError):
                log_error(
                    f"{operation_name}: No AWS credentials found. "
                    "Please configure credentials using 'aws configure' or environment variables."
                )
                if not suppress_errors:
                    raise
                return default_return

            # Handle ClientError with error code extraction
            elif isinstance(e, ClientError):
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                log_error(f"{operation_name}: AWS error [{error_code}]: {error_msg}")
                if not suppress_errors:
                    raise
                return default_return

            # Handle all other exceptions
            else:
                log_error(f"{operation_name}: Unexpected error", e)
                if not suppress_errors:
                    raise
                return default_return

        except ImportError:
            # Fallback if botocore is not available
            log_error(f"{operation_name}: Error occurred", e)
            if not suppress_errors:
                raise
            return default_return


# =============================================================================
# SHARED UTILITY FUNCTIONS FOR SCRIPTS
# =============================================================================


def ensure_dependencies(*packages: str) -> bool:
    """
    Check and optionally install required dependencies.

    This function checks if the specified packages are installed and offers to
    install any missing packages via pip. It's designed to eliminate duplicate
    dependency checking code across StratusScan scripts.

    Args:
        *packages: Variable number of package names to check/install

    Returns:
        bool: True if all dependencies are satisfied, False otherwise

    Examples:
        >>> # Check single package
        >>> if not ensure_dependencies('pandas'):
        ...     sys.exit(1)

        >>> # Check multiple packages
        >>> if not ensure_dependencies('pandas', 'openpyxl', 'boto3'):
        ...     sys.exit(1)

        >>> # Typical usage in scripts
        >>> def main():
        ...     if not utils.ensure_dependencies('pandas', 'openpyxl'):
        ...         return
        ...     import pandas as pd
        ...     # Continue with script logic
    """
    missing = []

    # Check each package
    for package in packages:
        try:
            __import__(package)
            log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing.append(package)
            log_warning(f"[MISSING] {package} is not installed")

    # All dependencies satisfied
    if not missing:
        log_success("All required dependencies are installed")
        return True

    # Prompt user to install missing packages
    log_warning(f"Missing packages: {', '.join(missing)}")

    # In automation mode, never block on interactive prompts
    if is_auto_run():
        log_error(
            f"Cannot install missing packages in auto-run mode: {', '.join(missing)}. "
            "Run 'pip install " + " ".join(missing) + "' manually, then retry."
        )
        return False

    print(f"\nThe following packages are required but not installed: {', '.join(missing)}")
    response = input("Would you like to install these packages now? (y/n): ").lower().strip()

    if response != 'y':
        log_error("Cannot continue without required packages")
        print("Exiting. Please install required packages manually with:")
        print(f"  pip install {' '.join(missing)}")
        return False

    # Install missing packages
    log_info("Installing missing packages...")
    for package in missing:
        try:
            log_info(f"Installing {package}...")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", package],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            log_success(f"Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            log_error(f"Failed to install {package}", e)
            return False
        except Exception as e:
            log_error(f"Unexpected error installing {package}", e)
            return False

    log_success("All dependencies installed successfully")
    return True


def mask_account_id(account_id: str) -> str:
    """
    Mask an AWS account ID for safe inclusion in INFO-level log output.

    Returns the last 4 digits prefixed with '...' so log consumers can identify
    the account without the full 12-digit ID being indexed by log aggregators.
    Full account IDs should be logged at DEBUG level for troubleshooting.

    Examples:
        >>> mask_account_id('123456789012')
        '...9012'
        >>> mask_account_id('')
        ''
    """
    if not account_id or len(account_id) < 4:
        return account_id
    return f"...{account_id[-4:]}"


def get_account_info() -> Tuple[str, str]:
    """
    Get AWS account ID and name with caching.

    This function retrieves the current AWS account ID using STS and maps it to
    a friendly name using the account mappings from config.json. Results are
    cached to avoid repeated STS API calls.

    Returns:
        tuple: (account_id, account_name) where account_id is the 12-digit AWS
               account ID and account_name is the friendly name from config.json
               or a default value if not found. Returns ("UNKNOWN", "UNKNOWN-ACCOUNT")
               if unable to retrieve account information.

    Examples:
        >>> # Get account info
        >>> account_id, account_name = utils.get_account_info()
        >>> print(f"Account: {account_name} ({account_id})")
        Account: PROD-ACCOUNT (123456789012)

        >>> # Use in filename generation
        >>> account_id, account_name = utils.get_account_info()
        >>> filename = utils.create_export_filename(
        ...     account_name,
        ...     "ec2",
        ...     "running"
        ... )

        >>> # Typical usage pattern in scripts
        >>> def main():
        ...     account_id, account_name = utils.get_account_info()
        ...     utils.log_info(f"Scanning account: {account_name}")

    Note:
        - Delegates to get_cached_account_info() to avoid duplicate STS calls
        - Uses get_boto3_client() which includes automatic retry logic
        - Falls back to UNKNOWN values on error rather than raising exceptions
    """
    account_id, account_name, _ = get_cached_account_info()
    return account_id, account_name


def print_script_banner(subtitle: str) -> Tuple[str, str]:
    """
    Print a standardized export script banner and return AWS account information.

    Prints a consistent 60-character banner using the provided subtitle, then
    retrieves and returns the current AWS account ID and name. Replaces the
    per-script print_title() / print_header() functions that previously
    duplicated this logic across every exporter.

    Args:
        subtitle: The script-specific title line displayed in the banner,
                  e.g. "AWS EC2 INSTANCE EXPORT". Should be ALL CAPS with
                  no trailing "TOOL", "SCRIPT", or "EXPORT TOOL" suffix.

    Returns:
        tuple: (account_id, account_name) as returned by get_account_info().

    Example:
        >>> account_id, account_name = utils.print_script_banner("AWS EC2 INSTANCE EXPORT")
        >>> # Prints:
        >>> # ============================================================
        >>> # AWS EC2 INSTANCE EXPORT
        >>> # ============================================================
    """
    print("\n" + "=" * 60)
    print(subtitle)
    print("=" * 60)
    return get_account_info()


# =============================================================================
# DATAFRAME PREPARATION & EXPORT UTILITIES
# =============================================================================


def prepare_dataframe_for_export(
    df,
    remove_timezone: bool = True,
    fill_na: str = 'N/A',
    truncate_strings: Optional[int] = None,
    max_column_width: int = 50
):
    """
    Prepare a pandas DataFrame for Excel export by standardizing data types and values.

    This function handles common issues that prevent clean Excel exports:
    - Removes timezone information from datetime columns (Excel doesn't support timezone-aware datetimes)
    - Standardizes NaN/None values to a consistent string
    - Truncates excessively long strings to prevent Excel cell overflow
    - Ensures all data types are Excel-compatible

    Args:
        df: Input pandas DataFrame to prepare
        remove_timezone: If True, remove timezone info from datetime columns (default: True)
        fill_na: String to replace NaN/None values (default: 'N/A')
        truncate_strings: Max string length before truncation, None to disable (default: 1000)
        max_column_width: Used for documentation, doesn't affect processing (default: 50)

    Returns:
        Cleaned DataFrame ready for Excel export

    Example:
        >>> df = collect_ec2_instances()
        >>> df = utils.prepare_dataframe_for_export(df)
        >>> utils.save_dataframe_to_excel(df, filename)

    Note:
        - This function creates a copy of the input DataFrame to avoid modifying the original
        - Empty DataFrames are returned unchanged
        - The max_column_width parameter is for reference only (used by save functions)
    """
    # Import pandas here to avoid requiring it at module load time
    import pandas as pd

    # Handle empty DataFrame
    if df is None or df.empty:
        log_debug("Empty DataFrame provided to prepare_dataframe_for_export, returning as-is")
        return df if df is not None else pd.DataFrame()

    # Make a copy to avoid modifying the original
    df_clean = df.copy()

    # Remove timezone information from datetime columns
    if remove_timezone:
        try:
            # Find datetime columns with timezone information
            datetime_cols = df_clean.select_dtypes(include=['datetime64[ns, UTC]', 'datetimetz']).columns

            # Also check for object columns that might contain datetime objects
            for col in df_clean.columns:
                if df_clean[col].dtype == 'object':
                    # Sample first non-null value to check if it's a datetime
                    sample = df_clean[col].dropna().head(1)
                    if not sample.empty and hasattr(sample.iloc[0], 'tzinfo') and sample.iloc[0].tzinfo is not None:
                        datetime_cols = datetime_cols.union(pd.Index([col]))

            # Remove timezone from identified columns
            for col in datetime_cols:
                try:
                    # Try pandas datetime conversion first
                    df_clean[col] = pd.to_datetime(df_clean[col]).dt.tz_localize(None)
                    log_debug(f"Removed timezone from column: {col}")
                except Exception as e:
                    log_debug(f"Could not remove timezone from {col}: {e}")
                    # Try alternative approach for object columns
                    try:
                        df_clean[col] = df_clean[col].apply(
                            lambda x: x.replace(tzinfo=None) if hasattr(x, 'replace') and hasattr(x, 'tzinfo') else x
                        )
                    except Exception as e2:
                        log_warning(f"Failed to remove timezone from column {col}: {e2}")
        except Exception as e:
            log_warning(f"Error processing datetime columns for timezone removal: {e}")

    # Fill NaN values with standard placeholder
    try:
        df_clean = df_clean.fillna(fill_na)
        log_debug(f"Filled NaN values with '{fill_na}'")
    except Exception as e:
        log_warning(f"Error filling NaN values: {e}")

    # Truncate excessively long strings
    if truncate_strings and truncate_strings > 0:
        try:
            # Get object (string) columns
            object_cols = df_clean.select_dtypes(include=['object']).columns

            for col in object_cols:
                try:
                    # Apply truncation only to strings longer than the limit
                    df_clean[col] = df_clean[col].apply(
                        lambda x: (str(x)[:truncate_strings] + '...' if isinstance(x, str) and len(x) > truncate_strings else x)
                    )
                except Exception as e:
                    log_debug(f"Could not truncate strings in column {col}: {e}")

            log_debug(f"Truncated strings longer than {truncate_strings} characters")
        except Exception as e:
            log_warning(f"Error truncating string columns: {e}")

    log_debug(f"DataFrame preparation complete: {len(df_clean)} rows, {len(df_clean.columns)} columns")
    return df_clean


def sanitize_for_export(
    df,
    sensitive_patterns: Optional[List[str]] = None,
    mask_string: str = '***REDACTED***'
):
    """
    Sanitize potentially sensitive data in DataFrame before export.

    This function searches for sensitive data patterns (passwords, API keys, tokens, credentials)
    in DataFrame values and masks them. Particularly useful for tag columns that may contain
    sensitive configuration data.

    Args:
        df: Input pandas DataFrame to sanitize
        sensitive_patterns: List of regex patterns to search for (default: common sensitive patterns)
        mask_string: String to replace sensitive data with (default: '***REDACTED***')

    Returns:
        Sanitized DataFrame with sensitive data masked

    Example:
        >>> df = collect_resources_with_tags()
        >>> df = utils.sanitize_for_export(df)
        >>> utils.save_dataframe_to_excel(df, filename)

    Note:
        - This function creates a copy of the input DataFrame to avoid modifying the original
        - Default patterns catch common secret formats in tags and environment variables
        - Case-insensitive pattern matching
        - Processes only string (object) columns
    """
    # Import pandas here to avoid requiring it at module load time
    import pandas as pd

    # Handle empty DataFrame
    if df is None or df.empty:
        log_debug("Empty DataFrame provided to sanitize_for_export, returning as-is")
        return df if df is not None else pd.DataFrame()

    # Make a copy to avoid modifying the original
    df_sanitized = df.copy()

    # Define default sensitive patterns if none provided
    if sensitive_patterns is None:
        sensitive_patterns = [
            r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+',
            r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+',
            r'(?i)(access[_-]?key|accesskey)\s*[:=]\s*\S+',
            r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*\S+',
            r'(?i)(token)\s*[:=]\s*\S+',
            r'(?i)(credential|cred)\s*[:=]\s*\S+',
            r'(?i)(auth)\s*[:=]\s*\S+',
        ]

    # Compile regex patterns for efficiency
    try:
        compiled_patterns = [re.compile(pattern) for pattern in sensitive_patterns]
        log_debug(f"Compiled {len(compiled_patterns)} sensitive data patterns")
    except Exception as e:
        log_error(f"Error compiling regex patterns: {e}")
        return df_sanitized

    # Track sanitization statistics
    total_masked = 0
    columns_affected = []

    # Get object (string) columns only
    try:
        object_cols = df_sanitized.select_dtypes(include=['object']).columns

        for col in object_cols:
            col_masked = 0
            try:
                # Apply sanitization to each cell in the column
                def mask_sensitive(cell_value):
                    nonlocal col_masked
                    if not isinstance(cell_value, str):
                        return cell_value

                    # Check each pattern
                    modified = cell_value
                    for pattern in compiled_patterns:
                        matches = pattern.findall(modified)
                        if matches:
                            col_masked += len(matches)
                            # Replace sensitive data while preserving the key name
                            modified = pattern.sub(lambda m: m.group(1) + mask_string, modified)

                    return modified

                # Apply the masking function
                df_sanitized[col] = df_sanitized[col].apply(mask_sensitive)

                if col_masked > 0:
                    total_masked += col_masked
                    columns_affected.append(col)
                    log_debug(f"Masked {col_masked} sensitive values in column: {col}")

            except Exception as e:
                log_warning(f"Error sanitizing column {col}: {e}")

        # Log summary
        if total_masked > 0:
            log_info(f"Sanitized {total_masked} sensitive values across {len(columns_affected)} columns")
            log_debug(f"Affected columns: {', '.join(columns_affected)}")
        else:
            log_debug("No sensitive data patterns found in DataFrame")

    except Exception as e:
        log_error(f"Error during DataFrame sanitization: {e}")

    return df_sanitized


# =============================================================================
# PROGRESS CHECKPOINTING & RESUME CAPABILITY
# =============================================================================


class ProgressCheckpoint:
    """
    Progress checkpointing system for long-running AWS operations.

    This class allows scripts to save their progress periodically and resume
    from the last checkpoint if interrupted. Useful for large-scale exports
    across multiple regions or accounts.

    Example:
        >>> checkpoint = ProgressCheckpoint('ec2-export', total_items=100)
        >>>
        >>> for i, instance in enumerate(instances):
        >>>     # Process instance
        >>>     process_instance(instance)
        >>>
        >>>     # Save checkpoint every 10 items
        >>>     checkpoint.save(current_index=i, data={'last_instance_id': instance['InstanceId']})
        >>>
        >>> checkpoint.mark_complete()
        >>> checkpoint.cleanup()
    """

    def __init__(self, operation_name: str, total_items: Optional[int] = None, checkpoint_dir: Optional[Path] = None):
        """
        Initialize progress checkpoint.

        Args:
            operation_name: Unique name for this operation
            total_items: Total number of items to process (optional)
            checkpoint_dir: Directory to store checkpoints (default: .checkpoints/)
        """
        self.operation_name = operation_name
        self.total_items = total_items

        # Set up checkpoint directory
        if checkpoint_dir is None:
            root_dir = get_stratusscan_root()
            checkpoint_dir = root_dir / '.checkpoints'

        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)

        # Checkpoint file path
        timestamp = datetime.datetime.now().strftime("%Y%m%d")
        self.checkpoint_file = self.checkpoint_dir / f"{operation_name}_{timestamp}.json"

        # Load existing checkpoint if available
        self.checkpoint_data = self._load()

        log_debug(f"Initialized checkpoint for {operation_name}")

    def _load(self) -> Dict[str, Any]:
        """Load checkpoint data from file if it exists."""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                log_info(f"Loaded checkpoint from {self.checkpoint_file}")
                log_info(f"Previous progress: {data.get('current_index', 0)}/{self.total_items or '?'}")
                return data
            except Exception as e:
                log_warning(f"Failed to load checkpoint: {e}")
                return {}
        return {}

    def save(self, current_index: int, data: Optional[Dict[str, Any]] = None):
        """
        Save current progress to checkpoint file.

        Args:
            current_index: Current position in the operation
            data: Additional data to save with checkpoint
        """
        try:
            checkpoint_data = {
                'operation_name': self.operation_name,
                'current_index': current_index,
                'total_items': self.total_items,
                'timestamp': datetime.datetime.now().isoformat(),
                'data': data or {}
            }

            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(checkpoint_data, f)

            # Log progress percentage if total known
            if self.total_items:
                progress_pct = (current_index / self.total_items) * 100
                log_debug(f"Checkpoint saved: {current_index}/{self.total_items} ({progress_pct:.1f}%)")
            else:
                log_debug(f"Checkpoint saved: {current_index} items processed")

        except Exception as e:
            log_warning(f"Failed to save checkpoint: {e}")

    def is_complete(self) -> bool:
        """Check if operation was previously completed."""
        return self.checkpoint_data.get('completed', False)

    def mark_complete(self):
        """Mark operation as complete."""
        try:
            self.checkpoint_data['completed'] = True
            self.checkpoint_data['completion_time'] = datetime.datetime.now().isoformat()

            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(self.checkpoint_data, f)

            log_success(f"Operation {self.operation_name} marked as complete")
        except Exception as e:
            log_warning(f"Failed to mark checkpoint as complete: {e}")

    def get_data(self, key: str, default: Any = None) -> Any:
        """Get value from checkpoint data."""
        return self.checkpoint_data.get('data', {}).get(key, default)

    def get_completed_count(self) -> int:
        """Get number of items already processed."""
        return self.checkpoint_data.get('current_index', 0)

    def cleanup(self):
        """Remove checkpoint file after successful completion."""
        try:
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
                log_info(f"Cleaned up checkpoint file: {self.checkpoint_file}")
        except Exception as e:
            log_warning(f"Failed to cleanup checkpoint: {e}")


# =============================================================================
# DRY-RUN MODE & VALIDATION
# =============================================================================


def validate_export(
    df,
    resource_type: str,
    required_columns: Optional[List[str]] = None,
    dry_run: bool = False
) -> Tuple[bool, str]:
    """
    Validate DataFrame before export (supports dry-run mode).

    This function validates that a DataFrame is ready for export by checking:
    - DataFrame is not empty
    - Required columns are present
    - Estimated file size is reasonable

    Args:
        df: DataFrame to validate
        resource_type: Type of resource being exported (for logging)
        required_columns: List of columns that must be present
        dry_run: If True, only validate without actually exporting

    Returns:
        tuple: (is_valid, error_message)

    Example:
        >>> df = collect_ec2_instances(region)
        >>> is_valid, error = utils.validate_export(df, 'EC2', required_columns=['InstanceId'])
        >>> if not is_valid:
        >>>     utils.log_error(f"Validation failed: {error}")
        >>>     return
    """
    import pandas as pd

    # Check if DataFrame is None or empty
    if df is None or df.empty:
        error_msg = f"No {resource_type} resources found to export"
        log_warning(error_msg)
        return False, error_msg

    # Check required columns
    if required_columns:
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            error_msg = f"Missing required columns: {', '.join(missing_cols)}"
            log_error(error_msg)
            return False, error_msg

    # Estimate file size
    estimated_size = _estimate_excel_size(df)
    log_info(f"Estimated export size: {format_bytes(estimated_size)}")

    # Warn if file is very large
    if estimated_size > 100 * 1024 * 1024:  # 100 MB
        log_warning(f"Large export detected ({format_bytes(estimated_size)}). Consider filtering data.")

    # Log summary
    log_info(f"Validation summary for {resource_type}:")
    log_info(f"  Rows: {len(df)}")
    log_info(f"  Columns: {len(df.columns)}")
    log_info(f"  Estimated size: {format_bytes(estimated_size)}")

    if dry_run:
        log_info("DRY-RUN MODE: Validation complete, skipping actual export")
        log_info(f"Would export {len(df)} {resource_type} resources")
        return True, "Dry-run validation passed"

    return True, "Validation passed"

# =============================================================================
# Sprint 4 compatibility shims — remove once all callers updated
# =============================================================================

from sslib.cost import (  # noqa: E402
    _estimate_excel_size,
    estimate_rds_monthly_cost,
    estimate_s3_monthly_cost,
    calculate_nat_gateway_monthly_cost,
    generate_cost_optimization_recommendations,
)

from sslib.config import (  # noqa: E402
    ACCOUNT_MAPPINGS,
    CONFIG_DATA,
    _CONFIG_LOADED,
    _CONFIG_LOCK,
    is_valid_aws_account_id,
    load_config,
    get_config,
    config_value,
    get_resource_preference,
    add_account_mapping,
    get_account_name,
    get_account_name_formatted,
)

from sslib.concurrency import (  # noqa: E402
    ConcurrentScanningError,
    scan_regions_concurrent,
    _scan_regions_sequential,
    paginate_with_progress,
    build_dataframe_in_batches,
)

from sslib.aws_client import (  # noqa: E402
    _account_info_cache,
    _account_info_lock,
    detect_partition,
    get_aws_session,
    get_boto3_client,
    build_arn,
    is_service_available_in_partition,
    is_service_enabled,
    get_service_disability_reason,
    get_partition_regions,
    get_partition_default_region,
    get_default_regions,
    get_partition_default_regions,
    is_aws_region,
    validate_aws_region,
    get_aws_regions,
    is_aws_commercial_environment,
    is_auto_run,
    get_auto_regions,
    validate_aws_credentials,
    check_aws_region_access,
    get_available_aws_regions,
    get_cached_account_info,
)
