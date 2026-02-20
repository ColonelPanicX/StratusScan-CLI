"""
sslib.config — Configuration singleton and account-mapping utilities.

Provides thread-safe lazy loading of config.json, account ID→name mapping,
and resource preference lookups.

Zero dependency on utils.py — uses only stdlib.
"""

import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state (config singleton)
# ---------------------------------------------------------------------------

ACCOUNT_MAPPINGS: Dict[str, str] = {}
CONFIG_DATA: Dict[str, Any] = {}
_CONFIG_LOADED: bool = False
_CONFIG_LOCK: threading.Lock = threading.Lock()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _config_path() -> Path:
    """Return the absolute path to config.json (sibling of utils.py)."""
    # sslib/config.py lives one level below the project root
    return Path(__file__).parent.parent / "config.json"


# ---------------------------------------------------------------------------
# Account ID validation
# ---------------------------------------------------------------------------


def is_valid_aws_account_id(account_id: Union[str, int]) -> bool:
    """
    Check if a string is a valid AWS account ID (12 digits).

    Args:
        account_id: The account ID to check

    Returns:
        bool: True if valid, False otherwise
    """
    pattern = re.compile(r"^\d{12}$")
    return bool(pattern.match(str(account_id)))


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def load_config() -> Tuple[Dict[str, str], Dict[str, Any]]:
    """
    Load configuration from config.json file.

    Returns:
        tuple: (ACCOUNT_MAPPINGS, CONFIG_DATA)
    """
    global ACCOUNT_MAPPINGS, CONFIG_DATA

    try:
        config_file = _config_path()

        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as f:
                CONFIG_DATA = json.load(f)

            if "account_mappings" in CONFIG_DATA:
                ACCOUNT_MAPPINGS = CONFIG_DATA["account_mappings"]
                logger.debug("Loaded %d account mappings from config.json", len(ACCOUNT_MAPPINGS))

            logger.debug("Configuration loaded successfully")
        else:
            logger.warning("config.json not found. Using default AWS configuration.")

            default_config = {
                "__comment": "StratusScan Configuration - Customize this file for your environment",
                "account_mappings": {},
                "organization_name": "YOUR-ORGANIZATION",
                "default_regions": ["us-east-1", "us-west-2", "us-west-1", "eu-west-1"],
                "aws_environment": "production",
                "resource_preferences": {
                    "ec2": {
                        "default_filter": "all",
                        "include_stopped": True,
                        "default_region": "us-east-1",
                    },
                    "vpc": {
                        "default_export_type": "all",
                        "default_region": "us-east-1",
                    },
                    "compute_optimizer": {
                        "enabled": True,
                        "note": "Available in commercial AWS",
                    },
                },
                "enabled_services": {
                    "trusted_advisor": {
                        "enabled": True,
                        "note": "Available in commercial AWS",
                    },
                    "cost_explorer": {
                        "enabled": True,
                        "note": "Available in commercial AWS",
                    },
                },
            }

            try:
                with open(config_file, "w", encoding="utf-8") as f:
                    json.dump(default_config, f, indent=2)

                msg = (
                    f"Created default config.json at {config_file}. "
                    "Please run 'python configure.py' to set your account mappings and preferences."
                )
                logger.info(msg)
                print(f"[StratusScan] {msg}")

                CONFIG_DATA = default_config
                ACCOUNT_MAPPINGS = {}
            except Exception as e:
                logger.error("Failed to create default config.json: %s", e)

    except Exception as e:
        logger.error("Error loading configuration: %s", e)

    return ACCOUNT_MAPPINGS, CONFIG_DATA


def get_config() -> Tuple[Dict[str, str], Dict[str, Any]]:
    """
    Lazy-load configuration. First call loads from disk; subsequent calls return cached values.
    Thread-safe: uses _CONFIG_LOCK to prevent concurrent initialization.

    Returns:
        tuple: (ACCOUNT_MAPPINGS, CONFIG_DATA)
    """
    global _CONFIG_LOADED, ACCOUNT_MAPPINGS, CONFIG_DATA
    with _CONFIG_LOCK:
        if not _CONFIG_LOADED:
            ACCOUNT_MAPPINGS, CONFIG_DATA = load_config()
            _CONFIG_LOADED = True
    return ACCOUNT_MAPPINGS, CONFIG_DATA


# ---------------------------------------------------------------------------
# Config value accessors
# ---------------------------------------------------------------------------


def config_value(key: str, default: Any = None, section: Optional[str] = None) -> Any:
    """
    Get a value from the configuration.

    Args:
        key: Configuration key
        default: Default value if key is not found
        section: Optional section in the configuration

    Returns:
        The configuration value or default
    """
    _, cfg = get_config()
    if not cfg:
        return default

    try:
        if section:
            if section in cfg and key in cfg[section]:
                return cfg[section][key]
        else:
            if key in cfg:
                return cfg[key]
    except Exception as e:
        logger.warning("Error reading config value '%s': %s", key, e)

    return default


def get_resource_preference(resource_type: str, preference: str, default: Any = None) -> Any:
    """
    Get a resource-specific preference from the configuration.

    Args:
        resource_type: Type of resource (e.g., 'ec2', 'vpc')
        preference: Preference name
        default: Default value if preference is not found

    Returns:
        The preference value or default
    """
    _, cfg = get_config()
    if "resource_preferences" in cfg:
        resource_prefs = cfg["resource_preferences"]
        if resource_type in resource_prefs and preference in resource_prefs[resource_type]:
            return resource_prefs[resource_type][preference]

    return default


# ---------------------------------------------------------------------------
# Account mapping management
# ---------------------------------------------------------------------------


def add_account_mapping(account_id: str, account_name: str) -> bool:
    """
    Add a new account mapping to the configuration.

    Args:
        account_id: AWS account ID
        account_name: Account name

    Returns:
        bool: True if successful, False otherwise
    """
    if not is_valid_aws_account_id(account_id):
        logger.error("Invalid AWS account ID: %s", account_id)
        return False

    try:
        # Trigger lazy load outside the lock to avoid re-entrant lock deadlock
        get_config()

        config_file = _config_path()

        # Acquire lock only around file I/O to avoid deadlock with get_config()
        with _CONFIG_LOCK:
            if config_file.exists():
                with open(config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)

                if "account_mappings" not in config:
                    config["account_mappings"] = {}

                config["account_mappings"][account_id] = account_name

                # Atomic write: serialize to .tmp then os.replace for crash safety
                tmp_path = config_file.with_suffix(".json.tmp")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2)
                os.replace(tmp_path, config_file)

                # Update in-memory cache only after successful file write
                ACCOUNT_MAPPINGS[account_id] = account_name

                logger.info("Added account mapping: %s → %s", account_id, account_name)
                return True
            else:
                logger.error("config.json not found")
                return False

    except Exception as e:
        logger.error("Failed to add account mapping: %s", e)
        return False


def get_account_name(account_id: str, default: str = "UNKNOWN-ACCOUNT") -> str:
    """
    Get account name from account ID using configured mappings.

    Args:
        account_id: The AWS account ID
        default: Default value to return if account_id is not found in mappings

    Returns:
        str: The account name or default value
    """
    mappings, _ = get_config()
    return mappings.get(account_id, default)


def get_account_name_formatted(owner_id: str) -> str:
    """
    Get the formatted account name with ID from the owner ID.

    Args:
        owner_id: The AWS account owner ID

    Returns:
        str: Formatted as "ACCOUNT-NAME (ID)" if mapping exists, otherwise just the ID
    """
    mappings, _ = get_config()
    if owner_id in mappings:
        return f"{mappings[owner_id]} ({owner_id})"
    return owner_id
