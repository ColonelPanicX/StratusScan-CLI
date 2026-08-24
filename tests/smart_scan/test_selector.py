#!/usr/bin/env python3
"""
Tests for smart_scan.selector module.
Tests import structure, class instantiation, and method availability.
"""

import os
import sys
from unittest.mock import patch

import pytest

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.selector import QUESTIONARY_AVAILABLE, SmartScanSelector, interactive_select

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


class TestPlainTextFallback:
    """The no-questionary path must offer a real plain-text selection,
    not silently degrade to 'run everything' (the pre-fix bug)."""

    SORTED = sorted(MOCK_RECOMMENDATIONS["all_scripts"])

    def test_fallback_returns_selected_subset(self):
        import utils
        from smart_scan import selector
        # sorted(all_scripts): rows 1..N. Pick rows 1 and 3.
        with patch.object(selector, "QUESTIONARY_AVAILABLE", False), \
             patch.object(utils, "prompt_multiselect", return_value=[1, 3]):
            result = selector.interactive_select(MOCK_RECOMMENDATIONS)
        assert result == {self.SORTED[0], self.SORTED[2]}

    def test_fallback_back_returns_none(self):
        import utils
        from smart_scan import selector
        with patch.object(selector, "QUESTIONARY_AVAILABLE", False), \
             patch.object(utils, "prompt_multiselect", side_effect=utils.BackSignal):
            result = selector.interactive_select(MOCK_RECOMMENDATIONS)
        assert result is None

    def test_fallback_empty_recommendations_returns_none(self):
        from smart_scan import selector
        with patch.object(selector, "QUESTIONARY_AVAILABLE", False):
            result = selector.interactive_select({"all_scripts": set()})
        assert result is None


@pytest.fixture
def make_selector():
    """Build a SmartScanSelector without requiring questionary to be installed.

    The constructor guards on QUESTIONARY_AVAILABLE, but save_checklist() is a
    plain file writer that never touches questionary.
    """
    from smart_scan import selector as selector_module

    def _make(recommendations=MOCK_RECOMMENDATIONS):
        with patch.object(selector_module, "QUESTIONARY_AVAILABLE", True):
            return SmartScanSelector(recommendations)

    return _make


class TestSaveChecklistContainment:
    """save_checklist() writes into output/ — previously it wrote to a bare
    relative path, dropping the checklist in the caller's CWD (CWE-73)."""

    def test_checklist_written_to_output_dir(self, tmp_path, monkeypatch, make_selector):
        import utils

        monkeypatch.setattr(utils, "get_output_dir", lambda: tmp_path)
        selector = make_selector()

        assert selector.save_checklist("checklist.txt") is True
        assert (tmp_path / "checklist.txt").exists()

    def test_checklist_not_written_to_cwd(self, tmp_path, monkeypatch, make_selector):
        """Regression: the file must not land in the current working directory."""
        import utils

        cwd = tmp_path / "cwd"
        cwd.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.chdir(cwd)
        monkeypatch.setattr(utils, "get_output_dir", lambda: out)
        selector = make_selector()

        assert selector.save_checklist("checklist.txt") is True
        assert (out / "checklist.txt").exists()
        assert not (cwd / "checklist.txt").exists()

    def test_traversing_name_stays_contained(self, tmp_path, monkeypatch, make_selector):
        import utils

        monkeypatch.setattr(utils, "get_output_dir", lambda: tmp_path)
        selector = make_selector()

        assert selector.save_checklist("../../escaped.txt") is True
        assert (tmp_path / "escaped.txt").exists()

    def test_unusable_name_returns_false(self, tmp_path, monkeypatch, make_selector):
        import utils

        monkeypatch.setattr(utils, "get_output_dir", lambda: tmp_path)
        selector = make_selector()

        assert selector.save_checklist("..") is False
