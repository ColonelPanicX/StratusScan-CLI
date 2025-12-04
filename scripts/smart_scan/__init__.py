"""
Smart Scan - Intelligent script recommendation and batch execution.

This package analyzes services-in-use export output and recommends
relevant StratusScan export scripts to run based on discovered services.
"""

__version__ = "1.0.0"

from .analyzer import (
    find_latest_services_export,
    parse_services_from_excel,
    map_services_to_scripts,
    generate_recommendations,
)
from .mapping import SERVICE_SCRIPT_MAP, SERVICE_ALIASES, SCRIPT_CATEGORIES

__all__ = [
    "find_latest_services_export",
    "parse_services_from_excel",
    "map_services_to_scripts",
    "generate_recommendations",
    "SERVICE_SCRIPT_MAP",
    "SERVICE_ALIASES",
    "SCRIPT_CATEGORIES",
]
