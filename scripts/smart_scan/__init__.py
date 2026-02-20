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
    find_latest_services_export,
    parse_services_from_excel,
    map_services_to_scripts,
    generate_recommendations,
    analyze_services,
    ServiceAnalyzer,
)
from .mapping import (
    SERVICE_SCRIPT_MAP,
    SERVICE_ALIASES,
    SCRIPT_CATEGORIES,
    ALWAYS_RUN_SCRIPTS,
    get_canonical_service_name,
    get_scripts_for_service,
)
from .selector import interactive_select, SmartScanSelector, QUESTIONARY_AVAILABLE
from .executor import execute_scripts, ScriptExecutor, ExecutionResult

__all__ = [
    # Analyzer functions
    "find_latest_services_export",
    "parse_services_from_excel",
    "map_services_to_scripts",
    "generate_recommendations",
    "analyze_services",
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
