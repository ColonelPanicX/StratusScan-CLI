#!/usr/bin/env python3
"""
Comprehensive tests for smart_scan.mapping module.
Tests service-to-script mapping, aliases, and categorization.
"""

import os
import sys
from pathlib import Path

import pytest

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.mapping import (
    ALWAYS_RUN_SCRIPTS,
    SCRIPT_CATEGORIES,
    SERVICE_ALIASES,
    SERVICE_SCRIPT_MAP,
    get_canonical_service_name,
    get_category_for_script,
    get_scripts_for_service,
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
        for _service, scripts in SERVICE_SCRIPT_MAP.items():
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
            "Compute",
            "Storage",
            "Networking",
            "Security & Compliance",
            "Cost Management",
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
            "iam_export.py",
            "cloudtrail_export.py",
            "guardduty_export.py",
            "security_groups_export.py",
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
        """Test alias lookup is case-insensitive (input is lowercased before lookup)."""
        # get_canonical_service_name lowercases the input before alias lookup,
        # so "EC2" resolves the same as "ec2".
        assert get_canonical_service_name("EC2") == "Amazon Elastic Compute Cloud"
        assert get_canonical_service_name("ec2") == "Amazon Elastic Compute Cloud"


class TestGetScriptsForService:
    """Test get_scripts_for_service function."""

    def test_canonical_service_name(self):
        """Test getting scripts for canonical service name."""
        scripts = get_scripts_for_service("Amazon Elastic Compute Cloud")
        assert scripts is not None
        assert len(scripts) > 0
        assert "ec2_export.py" in scripts

    def test_alias_service_name(self):
        """Test getting scripts via alias."""
        scripts = get_scripts_for_service("ec2")
        assert scripts is not None
        assert len(scripts) > 0
        assert "ec2_export.py" in scripts

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
        assert "s3_export.py" in scripts


class TestMappingStatistics:
    """Test overall mapping statistics and consistency."""

    def test_service_count(self):
        """Verify we have a reasonable number of services mapped."""
        assert len(SERVICE_SCRIPT_MAP) >= 90

    def test_alias_count(self):
        """Verify we have a reasonable number of aliases."""
        assert len(SERVICE_ALIASES) >= 90

    def test_always_run_count(self):
        """Verify we have expected number of always-run scripts."""
        assert len(ALWAYS_RUN_SCRIPTS) == 11

    def test_billing_is_mandatory(self):
        """Billing must be an always-run script (every account has a bill)."""
        assert "billing_export.py" in ALWAYS_RUN_SCRIPTS

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
        assert get_category_for_script("ec2_export.py") == "Compute"

    def test_storage_script(self):
        """Test categorization of a storage script."""
        assert get_category_for_script("s3_export.py") == "Storage"

    def test_database_script(self):
        """Test categorization of a database script."""
        assert get_category_for_script("rds_export.py") == "Database"

    def test_networking_script(self):
        """Test categorization of a networking script."""
        assert get_category_for_script("vpc_data_export.py") == "Networking"

    def test_security_script(self):
        """Test categorization of a security script."""
        assert get_category_for_script("iam_export.py") == "Security & Compliance"

    def test_cost_management_script(self):
        """Test categorization of a cost management script."""
        assert get_category_for_script("budgets_export.py") == "Cost Management"

    def test_management_monitoring_script(self):
        """Test categorization of a management/monitoring script."""
        assert get_category_for_script("cloudwatch_export.py") == "Management & Monitoring"

    def test_unknown_script_returns_other(self):
        """Test that an uncategorized script returns 'Other'."""
        assert get_category_for_script("nonexistent_script.py") == "Other"


class TestDiscoveryCatalogResolves:
    """
    Guard against silent drift between the service-discovery catalog
    (SERVICE_CHECKS in services_in_use_export.py) and the script mapping
    (SERVICE_SCRIPT_MAP / SERVICE_ALIASES).

    The discovery catalog keys on friendly names ("Amazon RDS") while the
    mapping keys on canonical names ("Amazon Relational Database Service").
    If a discovered service does not resolve to at least one script, it is
    silently dropped from Deep Scan execution — meaning the audit reports a
    service as present but never collects its resources. That is the exact
    failure this test exists to prevent.
    """

    # Services that the discovery catalog can detect but for which no exporter
    # script exists yet. These are KNOWN coverage gaps, not naming bugs. Adding
    # an exporter for any of these should also remove it from this allowlist.
    KNOWN_NO_EXPORTER = {
        "Amazon Lightsail",
        "AWS Batch",
        "Amazon Timestream",
        "Amazon EMR",
        "Amazon Kinesis",
        "Amazon CloudWatch Logs",
        "AWS Amplify",
    }

    @staticmethod
    def _catalog_service_names():
        """Flatten SERVICE_CHECKS (category -> {service: config}) to service names."""
        import services_in_use_export

        names = set()
        for services in services_in_use_export.SERVICE_CHECKS.values():
            names.update(services.keys())
        return names

    def test_every_discovered_service_resolves_to_a_script(self):
        """Every discovery-catalog service must map to >=1 script (or be a known gap)."""
        unresolved = sorted(
            name
            for name in self._catalog_service_names()
            if not get_scripts_for_service(name)
            and name not in self.KNOWN_NO_EXPORTER
        )
        assert not unresolved, (
            "Discovery catalog services that resolve to NO export script "
            "(they would be silently dropped from Deep Scan): "
            f"{unresolved}. Add an alias in SERVICE_ALIASES mapping each to its "
            "canonical name, or add it to KNOWN_NO_EXPORTER if no exporter exists yet."
        )

    def test_rds_specifically_resolves(self):
        """Regression: 'Amazon RDS' must resolve to rds_export.py (the original bug)."""
        assert "rds_export.py" in get_scripts_for_service("Amazon RDS")

    def test_known_no_exporter_list_is_accurate(self):
        """KNOWN_NO_EXPORTER must not list services that actually DO have a script."""
        wrongly_listed = sorted(
            name for name in self.KNOWN_NO_EXPORTER if get_scripts_for_service(name)
        )
        assert not wrongly_listed, (
            "These services are in KNOWN_NO_EXPORTER but now resolve to a script "
            f"— remove them from the allowlist: {wrongly_listed}"
        )

    def test_known_no_exporter_entries_are_in_catalog(self):
        """KNOWN_NO_EXPORTER must only list services the catalog can actually detect."""
        catalog = self._catalog_service_names()
        stale = sorted(name for name in self.KNOWN_NO_EXPORTER if name not in catalog)
        assert not stale, (
            "These services are in KNOWN_NO_EXPORTER but no longer exist in the "
            f"discovery catalog — remove them: {stale}"
        )


class TestExporterReachability:
    """
    The inverse of TestDiscoveryCatalogResolves: every exporter that exists on
    disk must be reachable through a Deep Scan — either the discovery catalog
    detects its service, or it is in the always-run baseline. An exporter that
    is neither can never run via smart scan, so its data silently never gets
    collected. This is the broader version of the original RDS bug.
    """

    # Scripts that intentionally do NOT participate in discovery-driven runs:
    #   - the discovery script itself (it produces the catalog; it must not
    #     recommend running itself)
    #   - legacy aggregate helpers kept for direct/manual invocation
    NON_DISCOVERABLE = {
        "services_in_use_export.py",
        "compute_resources.py",
        "network_resources.py",
        "storage_resources.py",
    }

    @staticmethod
    def _scripts_dir():
        return Path(scripts_dir)

    @staticmethod
    def _reachable_scripts():
        """Scripts a Deep Scan can run: catalog-detected services + always-run."""
        import services_in_use_export

        catalog = set()
        for services in services_in_use_export.SERVICE_CHECKS.values():
            catalog.update(services.keys())

        reachable = set(ALWAYS_RUN_SCRIPTS)
        for name in catalog:
            reachable.update(get_scripts_for_service(name))
        return reachable

    def test_every_exporter_is_reachable(self):
        """Every *_export.py on disk must be reachable via discovery or always-run."""
        disk = {p.name for p in self._scripts_dir().glob("*_export.py")}
        unreachable = sorted(
            disk - self._reachable_scripts() - self.NON_DISCOVERABLE
        )
        assert not unreachable, (
            "Exporters on disk that a Deep Scan can never run (no catalog "
            f"detector and not always-run): {unreachable}. Add a detector to "
            "SERVICE_CHECKS, add the script to ALWAYS_RUN_SCRIPTS, or list it in "
            "NON_DISCOVERABLE if it is intentionally manual-only."
        )

    def test_non_discoverable_entries_exist(self):
        """NON_DISCOVERABLE must only name scripts that actually exist on disk."""
        missing = sorted(
            s for s in self.NON_DISCOVERABLE if not (self._scripts_dir() / s).exists()
        )
        assert not missing, f"NON_DISCOVERABLE names nonexistent scripts: {missing}"


class TestServiceCheckStructure:
    """Validate every discovery-catalog detector is structurally well-formed."""

    @staticmethod
    def _all_configs():
        import services_in_use_export

        for category, services in services_in_use_export.SERVICE_CHECKS.items():
            for name, config in services.items():
                yield category, name, config

    def test_required_keys_present(self):
        """Every detector needs client, check (callable), unit, and regional flag."""
        for _category, name, config in self._all_configs():
            assert "client" in config, f"{name}: missing 'client'"
            assert callable(config.get("check")), f"{name}: 'check' must be callable"
            assert "unit" in config, f"{name}: missing 'unit'"
            assert isinstance(config.get("regional"), bool), f"{name}: 'regional' must be bool"

    def test_global_region_not_also_regional(self):
        """A global_region service is account-global; it cannot also be regional."""
        for _category, name, config in self._all_configs():
            if config.get("global_region"):
                assert config["regional"] is False, (
                    f"{name}: global_region services must have regional=False"
                )

    def test_client_strings_are_valid_boto3_services(self):
        """Every detector's client must be a real botocore service (offline check)."""
        import botocore.session

        session = botocore.session.get_session()
        valid = set(session.get_available_services())
        for _category, name, config in self._all_configs():
            assert config["client"] in valid, (
                f"{name}: '{config['client']}' is not a valid boto3 service"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
