"""
Smart Scan - Intelligent script recommendation and batch execution.

This package analyzes services-in-use export output and recommends
relevant StratusScan export scripts to run based on discovered services.
"""

import sys
from pathlib import Path

try:
    import utils
except ImportError:
    _script_dir = Path(__file__).parent.absolute()
    # smart_scan is inside scripts/, so go two levels up for project root
    sys.path.append(str(_script_dir.parent.parent))
    import utils

__version__ = utils.get_version()

from .analyzer import (
    ServiceAnalyzer,
    analyze_services,
    analyze_services_from_dict,
    find_latest_services_export,
    generate_recommendations,
    map_services_to_scripts,
    parse_services_from_excel,
)
from .executor import ExecutionResult, ScriptExecutor, execute_scripts
from .mapping import (
    ALWAYS_RUN_SCRIPTS,
    SCRIPT_CATEGORIES,
    SERVICE_ALIASES,
    SERVICE_SCRIPT_MAP,
    get_canonical_service_name,
    get_scripts_for_service,
)
from .selector import QUESTIONARY_AVAILABLE, SmartScanSelector, interactive_select

__all__ = [
    # Analyzer functions
    "find_latest_services_export",
    "parse_services_from_excel",
    "map_services_to_scripts",
    "generate_recommendations",
    "analyze_services",
    "analyze_services_from_dict",
    "ServiceAnalyzer",
    # Mapping data
    "SERVICE_SCRIPT_MAP",
    "SERVICE_ALIASES",
    "SCRIPT_CATEGORIES",
    "ALWAYS_RUN_SCRIPTS",
    "get_canonical_service_name",
    "get_scripts_for_service",
    # Selector functions
    "interactive_select",
    "SmartScanSelector",
    "QUESTIONARY_AVAILABLE",
    # Executor functions
    "execute_scripts",
    "ScriptExecutor",
    "ExecutionResult",
]
