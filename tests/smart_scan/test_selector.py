#!/usr/bin/env python3
"""
Tests for smart_scan.selector module.
Tests import structure, class instantiation, and method availability.
"""

import sys
import os
import pytest

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.selector import SmartScanSelector, interactive_select, QUESTIONARY_AVAILABLE

MOCK_RECOMMENDATIONS = {
    "always_run": ["iam_comprehensive_export.py", "cloudtrail_export.py"],
    "service_based": {
        "Amazon EC2": ["ec2_export.py", "ami_export.py"],
        "Amazon S3": ["s3_export.py"],
    },
    "all_scripts": {
        "iam_comprehensive_export.py",
        "cloudtrail_export.py",
        "ec2_export.py",
        "ami_export.py",
        "s3_export.py",
    },
    "by_category": {
        "Security & Compliance": ["iam_comprehensive_export.py", "cloudtrail_export.py"],
        "Compute": ["ec2_export.py", "ami_export.py"],
        "Storage": ["s3_export.py"],
    },
    "coverage_stats": {
        "total_services_found": 2,
        "services_with_scripts": 2,
        "total_scripts_available": 166,
        "total_scripts_recommended": 5,
        "always_run_count": 2,
        "service_based_count": 3,
        "coverage_percentage": 3.0,
    },
}


class TestSelectorImports:
    """Test that selector module symbols are importable and have correct types."""

    def test_questionary_available_is_bool(self):
        """Verify QUESTIONARY_AVAILABLE is a boolean flag."""
        assert isinstance(QUESTIONARY_AVAILABLE, bool)

    def test_interactive_select_is_callable(self):
        """Verify interactive_select is a callable function."""
        assert callable(interactive_select)

    def test_smart_scan_selector_is_class(self):
        """Verify SmartScanSelector is a class."""
        assert isinstance(SmartScanSelector, type)


@pytest.mark.skipif(not QUESTIONARY_AVAILABLE, reason="questionary not installed")
class TestSmartScanSelectorStructure:
    """Test SmartScanSelector class structure (requires questionary)."""

    def test_selector_instantiation(self):
        """Verify SmartScanSelector can be instantiated with mock recommendations."""
        selector = SmartScanSelector(MOCK_RECOMMENDATIONS)
        assert selector is not None
        assert isinstance(selector, SmartScanSelector)

    def test_selector_has_required_methods(self):
        """Verify SmartScanSelector has all required public methods."""
        selector = SmartScanSelector(MOCK_RECOMMENDATIONS)
        required_methods = [
            "show_welcome",
            "show_main_menu",
            "quick_scan_confirm",
            "custom_selection_by_category",
            "custom_selection_by_service",
            "view_checklist",
            "save_checklist",
            "run_interactive",
        ]
        for method in required_methods:
            assert hasattr(selector, method), f"Missing method: {method}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
