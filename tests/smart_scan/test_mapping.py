#!/usr/bin/env python3
"""
Comprehensive tests for smart_scan.mapping module.
Tests service-to-script mapping, aliases, and categorization.
"""

import sys
import os
import pytest

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.mapping import (
    SERVICE_SCRIPT_MAP,
    SERVICE_ALIASES,
    SCRIPT_CATEGORIES,
    ALWAYS_RUN_SCRIPTS,
    get_canonical_service_name,
    get_scripts_for_service,
    get_category_for_script,
)


class TestServiceScriptMapping:
    """Test SERVICE_SCRIPT_MAP structure and content."""

    def test_map_exists_and_not_empty(self):
        """Verify SERVICE_SCRIPT_MAP is populated."""
        assert SERVICE_SCRIPT_MAP is not None
        assert len(SERVICE_SCRIPT_MAP) > 0
        assert isinstance(SERVICE_SCRIPT_MAP, dict)

    def test_all_values_are_lists(self):
        """Verify all values in SERVICE_SCRIPT_MAP are lists."""
        for service, scripts in SERVICE_SCRIPT_MAP.items():
            assert isinstance(scripts, list), f"{service} has non-list value"
            assert len(scripts) > 0, f"{service} has empty script list"

    def test_all_scripts_end_with_py(self):
        """Verify all script names end with .py."""
        for service, scripts in SERVICE_SCRIPT_MAP.items():
            for script in scripts:
                assert script.endswith(".py"), f"Invalid script name: {script}"

    def test_common_services_present(self):
        """Verify common AWS services are in the map."""
        expected_services = [
            "Amazon Elastic Compute Cloud",
            "Amazon Simple Storage Service",
            "Amazon Relational Database Service",
            "AWS Lambda",
            "Amazon Virtual Private Cloud",
        ]
        for service in expected_services:
            assert service in SERVICE_SCRIPT_MAP, f"Missing common service: {service}"


class TestServiceAliases:
    """Test SERVICE_ALIASES structure and functionality."""

    def test_aliases_exist_and_not_empty(self):
        """Verify SERVICE_ALIASES is populated."""
        assert SERVICE_ALIASES is not None
        assert len(SERVICE_ALIASES) > 0
        assert isinstance(SERVICE_ALIASES, dict)

    def test_all_aliases_map_to_canonical_names(self):
        """Verify all aliases map to valid canonical service names."""
        for alias, canonical in SERVICE_ALIASES.items():
            assert canonical in SERVICE_SCRIPT_MAP, f"Alias {alias} maps to unknown service: {canonical}"

    def test_common_aliases(self):
        """Test common service aliases resolve correctly."""
        test_cases = [
            ("ec2", "Amazon Elastic Compute Cloud"),
            ("s3", "Amazon Simple Storage Service"),
            ("rds", "Amazon Relational Database Service"),
            ("lambda", "AWS Lambda"),
            ("vpc", "Amazon Virtual Private Cloud"),
        ]
        for alias, expected_canonical in test_cases:
            assert alias in SERVICE_ALIASES, f"Missing common alias: {alias}"
            assert SERVICE_ALIASES[alias] == expected_canonical

    def test_lowercase_variations(self):
        """Test lowercase service name variations."""
        # These were specifically fixed during development
        assert "amazon ec2" in SERVICE_ALIASES
        assert "amazon s3" in SERVICE_ALIASES
        assert SERVICE_ALIASES["amazon ec2"] == "Amazon Elastic Compute Cloud"
        assert SERVICE_ALIASES["amazon s3"] == "Amazon Simple Storage Service"


class TestScriptCategories:
    """Test SCRIPT_CATEGORIES structure and content."""

    def test_categories_exist_and_not_empty(self):
        """Verify SCRIPT_CATEGORIES is populated."""
        assert SCRIPT_CATEGORIES is not None
        assert len(SCRIPT_CATEGORIES) > 0
        assert isinstance(SCRIPT_CATEGORIES, dict)

    def test_expected_categories_present(self):
        """Verify expected categories exist."""
        expected_categories = [
            "Compute Resources",
            "Storage Resources",
            "Network Resources",
            "IAM & Identity",
            "Security & Compliance",
            "Cost Optimization",
        ]
        for category in expected_categories:
            assert category in SCRIPT_CATEGORIES, f"Missing category: {category}"

    def test_all_category_scripts_end_with_py(self):
        """Verify all scripts in categories end with .py."""
        for category, scripts in SCRIPT_CATEGORIES.items():
            assert isinstance(scripts, list), f"{category} has non-list value"
            for script in scripts:
                assert script.endswith(".py"), f"Invalid script in {category}: {script}"

    def test_categories_not_empty(self):
        """Verify all categories have scripts."""
        for category, scripts in SCRIPT_CATEGORIES.items():
            assert len(scripts) > 0, f"Category {category} has no scripts"


class TestAlwaysRunScripts:
    """Test ALWAYS_RUN_SCRIPTS structure and content."""

    def test_always_run_exists_and_not_empty(self):
        """Verify ALWAYS_RUN_SCRIPTS is populated."""
        assert ALWAYS_RUN_SCRIPTS is not None
        assert len(ALWAYS_RUN_SCRIPTS) > 0
        assert isinstance(ALWAYS_RUN_SCRIPTS, list)

    def test_all_always_run_end_with_py(self):
        """Verify all always-run scripts end with .py."""
        for script in ALWAYS_RUN_SCRIPTS:
            assert script.endswith(".py"), f"Invalid always-run script: {script}"

    def test_security_scripts_in_always_run(self):
        """Verify critical security scripts are in always-run."""
        expected_scripts = [
            "iam-comprehensive-export.py",
            "cloudtrail-export.py",
            "guardduty-export.py",
            "security-groups-export.py",
        ]
        for script in expected_scripts:
            assert script in ALWAYS_RUN_SCRIPTS, f"Missing critical script: {script}"


class TestGetCanonicalServiceName:
    """Test get_canonical_service_name function."""

    def test_canonical_name_unchanged(self):
        """Test that canonical names return unchanged."""
        canonical = "Amazon Elastic Compute Cloud"
        assert get_canonical_service_name(canonical) == canonical

    def test_alias_resolution(self):
        """Test alias resolution to canonical name."""
        assert get_canonical_service_name("ec2") == "Amazon Elastic Compute Cloud"
        assert get_canonical_service_name("s3") == "Amazon Simple Storage Service"
        assert get_canonical_service_name("rds") == "Amazon Relational Database Service"

    def test_lowercase_full_name(self):
        """Test lowercase full service name resolution."""
        assert get_canonical_service_name("amazon ec2") == "Amazon Elastic Compute Cloud"
        assert get_canonical_service_name("amazon s3") == "Amazon Simple Storage Service"

    def test_unknown_service_returns_original(self):
        """Test that unknown services return original string."""
        unknown = "Unknown Service XYZ"
        assert get_canonical_service_name(unknown) == unknown

    def test_case_sensitivity(self):
        """Test that aliases are case-sensitive."""
        # "EC2" (uppercase) is likely not in aliases, should return as-is
        assert get_canonical_service_name("EC2") == "EC2"
        # "ec2" (lowercase) should resolve
        assert get_canonical_service_name("ec2") == "Amazon Elastic Compute Cloud"


class TestGetScriptsForService:
    """Test get_scripts_for_service function."""

    def test_canonical_service_name(self):
        """Test getting scripts for canonical service name."""
        scripts = get_scripts_for_service("Amazon Elastic Compute Cloud")
        assert scripts is not None
        assert len(scripts) > 0
        assert "ec2-export.py" in scripts

    def test_alias_service_name(self):
        """Test getting scripts via alias."""
        scripts = get_scripts_for_service("ec2")
        assert scripts is not None
        assert len(scripts) > 0
        assert "ec2-export.py" in scripts

    def test_unknown_service_returns_empty(self):
        """Test that unknown services return empty list."""
        scripts = get_scripts_for_service("Unknown Service XYZ")
        assert scripts == []

    def test_multiple_scripts_for_service(self):
        """Test services that map to multiple scripts."""
        scripts = get_scripts_for_service("Amazon Elastic Compute Cloud")
        # EC2 should have ec2-export.py, ami-export.py, autoscaling-export.py, etc.
        assert len(scripts) >= 3

    def test_s3_service(self):
        """Test S3 service specifically."""
        scripts = get_scripts_for_service("s3")
        assert "s3-export.py" in scripts


class TestMappingStatistics:
    """Test overall mapping statistics and consistency."""

    def test_service_count(self):
        """Verify we have a reasonable number of services mapped."""
        # Should have 160+ services
        assert len(SERVICE_SCRIPT_MAP) >= 160

    def test_alias_count(self):
        """Verify we have a reasonable number of aliases."""
        # Should have 112+ aliases
        assert len(SERVICE_ALIASES) >= 112

    def test_always_run_count(self):
        """Verify we have expected number of always-run scripts."""
        # Should have 10 always-run scripts
        assert len(ALWAYS_RUN_SCRIPTS) == 10

    def test_no_duplicate_scripts_in_service_map(self):
        """Verify no service lists the same script twice."""
        for service, scripts in SERVICE_SCRIPT_MAP.items():
            assert len(scripts) == len(set(scripts)), f"{service} has duplicate scripts"

    def test_all_always_run_in_categories(self):
        """Verify all always-run scripts are in at least one category."""
        all_categorized_scripts = set()
        for scripts in SCRIPT_CATEGORIES.values():
            all_categorized_scripts.update(scripts)

        for script in ALWAYS_RUN_SCRIPTS:
            assert script in all_categorized_scripts, f"Always-run script {script} not in any category"


class TestGetCategoryForScript:
    """Test get_category_for_script function."""

    def test_compute_script(self):
        """Test categorization of a compute script."""
        assert get_category_for_script("ec2-export.py") == "Compute"

    def test_storage_script(self):
        """Test categorization of a storage script."""
        assert get_category_for_script("s3-export.py") == "Storage"

    def test_database_script(self):
        """Test categorization of a database script."""
        assert get_category_for_script("rds-export.py") == "Database"

    def test_networking_script(self):
        """Test categorization of a networking script."""
        assert get_category_for_script("vpc-data-export.py") == "Networking"

    def test_security_script(self):
        """Test categorization of a security script."""
        assert get_category_for_script("iam-comprehensive-export.py") == "Security & Compliance"

    def test_cost_management_script(self):
        """Test categorization of a cost management script."""
        assert get_category_for_script("budgets-export.py") == "Cost Management"

    def test_management_monitoring_script(self):
        """Test categorization of a management/monitoring script."""
        assert get_category_for_script("cloudwatch-export.py") == "Management & Monitoring"

    def test_unknown_script_returns_other(self):
        """Test that an uncategorized script returns 'Other'."""
        assert get_category_for_script("nonexistent-script.py") == "Other"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
