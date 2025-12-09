"""
Smart Scan Analyzer

Analyzes services-in-use export output and maps discovered services
to relevant export scripts. Core intelligence engine for Smart Scan.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd

# Add parent directory to path for utils import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import utils

from .mapping import (
    ALWAYS_RUN_SCRIPTS,
    SERVICE_SCRIPT_MAP,
    get_canonical_service_name,
    get_scripts_for_service,
    get_category_for_script,
    get_all_scripts,
)


class ServiceAnalyzer:
    """Analyzes services-in-use data and recommends relevant export scripts."""

    def __init__(self, services_file: Optional[str] = None):
        """
        Initialize the analyzer.

        Args:
            services_file: Path to services-in-use export file (optional)
                          If not provided, will search for latest export
        """
        self.services_file = services_file
        self.discovered_services: Set[str] = set()
        self.recommended_scripts: Dict[str, List[str]] = {}
        self.services_data: Optional[pd.DataFrame] = None

    def find_latest_services_export(self, search_dir: Optional[str] = None) -> Optional[str]:
        """
        Find the most recent services-in-use export file.

        Args:
            search_dir: Directory to search (uses utils.get_output_dir() if None)

        Returns:
            Path to latest export file, or None if not found
        """
        try:
            pattern = "*-services-in-use-*-export-*.xlsx"

            # Use utils to get the proper output directory
            if search_dir is None:
                output_dir = utils.get_output_dir()
            else:
                output_dir = Path(search_dir)

            # Find all matching files in output directory
            export_files = list(output_dir.glob(pattern))

            if not export_files:
                utils.log_warning(f"No services-in-use export files found in {output_dir}")
                return None

            # Sort by modification time (newest first)
            export_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            latest_file = str(export_files[0])

            utils.log_info(f"Found latest services export: {latest_file}")
            return latest_file

        except Exception as e:
            utils.log_error("Error finding latest services export", e)
            return None

    def parse_services_from_excel(self, file_path: str) -> Set[str]:
        """
        Extract service names from services-in-use export Excel file.

        The export typically has a worksheet with service names in a column.
        We'll look for columns named "Service", "Service Name", or similar.

        Args:
            file_path: Path to services-in-use export Excel file

        Returns:
            Set of discovered service names
        """
        try:
            utils.log_info(f"Parsing services from {file_path}")

            # Read the Excel file
            excel_data = pd.read_excel(file_path, sheet_name=None)

            services = set()

            # Check each worksheet
            for sheet_name, df in excel_data.items():
                utils.log_debug(f"Checking worksheet: {sheet_name}")

                # Look for service-related columns
                service_columns = [
                    col
                    for col in df.columns
                    if any(
                        term in col.lower()
                        for term in ["service", "aws service", "service name"]
                    )
                ]

                if service_columns:
                    # Extract unique service names from first matching column
                    col = service_columns[0]
                    service_names = df[col].dropna().unique()
                    services.update(str(s).strip() for s in service_names if s)
                    utils.log_info(
                        f"Found {len(service_names)} services in {sheet_name}.{col}"
                    )

            utils.log_info(f"Total unique services discovered: {len(services)}")
            self.discovered_services = services
            self.services_data = excel_data.get(list(excel_data.keys())[0])  # First sheet

            return services

        except Exception as e:
            utils.log_error("Error parsing services from Excel", e)
            return set()

    def map_services_to_scripts(
        self, services: Optional[Set[str]] = None
    ) -> Dict[str, List[str]]:
        """
        Map discovered services to their corresponding export scripts.

        Args:
            services: Set of service names to map (uses self.discovered_services if None)

        Returns:
            Dictionary mapping service names to list of script filenames
        """
        if services is None:
            services = self.discovered_services

        if not services:
            utils.log_warning("No services to map")
            return {}

        service_script_mapping = {}

        for service in services:
            # Get canonical name and find scripts
            canonical = get_canonical_service_name(service)
            scripts = get_scripts_for_service(canonical)

            if scripts:
                service_script_mapping[service] = scripts
                utils.log_debug(f"Mapped '{service}' → {len(scripts)} script(s)")
            else:
                utils.log_debug(f"No scripts found for service: {service}")

        utils.log_info(
            f"Mapped {len(service_script_mapping)}/{len(services)} services to scripts"
        )
        self.recommended_scripts = service_script_mapping

        return service_script_mapping

    def generate_recommendations(
        self, include_always_run: bool = True
    ) -> Dict[str, any]:
        """
        Generate comprehensive script recommendations with categorization.

        Args:
            include_always_run: Whether to include ALWAYS_RUN scripts

        Returns:
            Dictionary with recommendation details:
                - always_run: List of security/compliance scripts to always run
                - service_based: Dict of service → scripts based on discovery
                - all_scripts: Set of all unique recommended scripts
                - by_category: Scripts organized by category
                - coverage_stats: Statistics about coverage
        """
        try:
            recommendations = {
                "always_run": [],
                "service_based": {},
                "all_scripts": set(),
                "by_category": {},
                "coverage_stats": {},
            }

            # Add always-run scripts if requested
            if include_always_run:
                recommendations["always_run"] = ALWAYS_RUN_SCRIPTS.copy()
                recommendations["all_scripts"].update(ALWAYS_RUN_SCRIPTS)

            # Add service-based recommendations
            if self.recommended_scripts:
                recommendations["service_based"] = self.recommended_scripts.copy()

                # Collect all unique scripts
                for scripts in self.recommended_scripts.values():
                    recommendations["all_scripts"].update(scripts)

            # Organize by category
            all_scripts = recommendations["all_scripts"]
            category_map = {}

            for script in all_scripts:
                category = get_category_for_script(script)
                if category not in category_map:
                    category_map[category] = []
                category_map[category].append(script)

            # Sort scripts within each category
            for category in category_map:
                category_map[category].sort()

            recommendations["by_category"] = category_map

            # Calculate coverage statistics
            total_available = len(get_all_scripts())
            total_recommended = len(all_scripts)
            service_based_count = len(
                set(
                    script
                    for scripts in self.recommended_scripts.values()
                    for script in scripts
                )
            )

            recommendations["coverage_stats"] = {
                "total_services_found": len(self.discovered_services),
                "services_with_scripts": len(self.recommended_scripts),
                "total_scripts_available": total_available,
                "total_scripts_recommended": total_recommended,
                "always_run_count": len(ALWAYS_RUN_SCRIPTS) if include_always_run else 0,
                "service_based_count": service_based_count,
                "coverage_percentage": (
                    round((total_recommended / total_available) * 100, 1)
                    if total_available > 0
                    else 0
                ),
            }

            utils.log_info(
                f"Generated recommendations: {total_recommended} scripts "
                f"({recommendations['coverage_stats']['coverage_percentage']}% coverage)"
            )

            return recommendations

        except Exception as e:
            utils.log_error("Error generating recommendations", e)
            return {
                "always_run": [],
                "service_based": {},
                "all_scripts": set(),
                "by_category": {},
                "coverage_stats": {},
            }

    def analyze(
        self, services_file: Optional[str] = None, include_always_run: bool = True
    ) -> Dict[str, any]:
        """
        Complete analysis workflow: find, parse, map, and recommend.

        Args:
            services_file: Path to services export (uses latest if None)
            include_always_run: Include security/compliance scripts

        Returns:
            Complete recommendations dictionary
        """
        try:
            # Find services file if not provided
            if services_file is None:
                services_file = self.find_latest_services_export()

            if not services_file:
                utils.log_error_with_exit(
                    "No services-in-use export file found. "
                    "Please run services-in-use-export.py first."
                )

            self.services_file = services_file

            # Parse services from Excel
            services = self.parse_services_from_excel(services_file)

            if not services:
                utils.log_warning("No services discovered from export file")
                return self.generate_recommendations(include_always_run)

            # Map services to scripts
            self.map_services_to_scripts(services)

            # Generate recommendations
            recommendations = self.generate_recommendations(include_always_run)

            return recommendations

        except Exception as e:
            utils.log_error("Error during analysis", e)
            return {
                "always_run": [],
                "service_based": {},
                "all_scripts": set(),
                "by_category": {},
                "coverage_stats": {},
            }


# Standalone functions for backward compatibility and direct use


def find_latest_services_export(search_dir: str = ".") -> Optional[str]:
    """
    Find the most recent services-in-use export file.

    Searches in multiple locations including output/ directory.

    Args:
        search_dir: Directory to search for export files

    Returns:
        Path to latest export file, or None if not found
    """
    analyzer = ServiceAnalyzer()
    return analyzer.find_latest_services_export(search_dir)


def parse_services_from_excel(file_path: str) -> Set[str]:
    """
    Extract service names from services-in-use export Excel file.

    Args:
        file_path: Path to services-in-use export Excel file

    Returns:
        Set of discovered service names
    """
    analyzer = ServiceAnalyzer()
    return analyzer.parse_services_from_excel(file_path)


def map_services_to_scripts(services: Set[str]) -> Dict[str, List[str]]:
    """
    Map discovered services to their corresponding export scripts.

    Args:
        services: Set of service names to map

    Returns:
        Dictionary mapping service names to list of script filenames
    """
    analyzer = ServiceAnalyzer()
    return analyzer.map_services_to_scripts(services)


def generate_recommendations(
    service_script_mapping: Dict[str, List[str]], include_always_run: bool = True
) -> Dict[str, any]:
    """
    Generate comprehensive script recommendations with categorization.

    Args:
        service_script_mapping: Mapping of services to scripts
        include_always_run: Whether to include ALWAYS_RUN scripts

    Returns:
        Dictionary with recommendation details
    """
    analyzer = ServiceAnalyzer()
    analyzer.recommended_scripts = service_script_mapping
    return analyzer.generate_recommendations(include_always_run)


def analyze_services(
    services_file: Optional[str] = None, include_always_run: bool = True
) -> Dict[str, any]:
    """
    Complete analysis: find latest export, parse services, and generate recommendations.

    Args:
        services_file: Path to services export (uses latest if None)
        include_always_run: Include security/compliance scripts

    Returns:
        Complete recommendations dictionary
    """
    analyzer = ServiceAnalyzer()
    return analyzer.analyze(services_file, include_always_run)
