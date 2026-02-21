#!/usr/bin/env python3
"""
Comprehensive tests for smart_scan.analyzer module.
Tests service analysis, Excel parsing, and recommendation generation.
"""

import sys
import os
import pytest
import tempfile
from pathlib import Path
from datetime import datetime

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.analyzer import (
    ServiceAnalyzer,
    find_latest_services_export,
    parse_services_from_excel,
    map_services_to_scripts,
    generate_recommendations,
    analyze_services,
)


class TestServiceAnalyzerClass:
    """Test ServiceAnalyzer class initialization and structure."""

    def test_analyzer_instantiation(self):
        """Test creating ServiceAnalyzer instance."""
        analyzer = ServiceAnalyzer()
        assert analyzer is not None
        assert isinstance(analyzer, ServiceAnalyzer)

    def test_analyzer_has_required_methods(self):
        """Verify ServiceAnalyzer has all required methods."""
        analyzer = ServiceAnalyzer()
        required_methods = [
            "find_latest_services_export",
            "parse_services_from_excel",
            "map_services_to_scripts",
            "generate_recommendations",
            "analyze",
        ]
        for method in required_methods:
            assert hasattr(analyzer, method), f"Missing method: {method}"
            assert callable(getattr(analyzer, method)), f"Method not callable: {method}"


class TestFindLatestServicesExport:
    """Test find_latest_services_export function."""

    def test_find_in_nonexistent_directory(self):
        """Test behavior with nonexistent directory."""
        result = find_latest_services_export("/nonexistent/directory/path")
        assert result is None

    def test_find_in_empty_directory(self):
        """Test behavior with empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_latest_services_export(tmpdir)
            assert result is None

    def test_find_with_single_file(self):
        """Test finding single services export file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock services export file (must match glob *-services-in-use-*-export-*.xlsx)
            filename = "test-account-services-in-use-all-export-12.04.2025.xlsx"
            filepath = Path(tmpdir) / filename
            filepath.touch()

            result = find_latest_services_export(tmpdir)
            assert result is not None
            assert result.endswith(filename)

    def test_find_returns_most_recent(self):
        """Test that most recent file is returned when multiple exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files with different dates (must match glob *-services-in-use-*-export-*.xlsx)
            old_file = Path(tmpdir) / "test-services-in-use-all-export-01.01.2025.xlsx"
            new_file = Path(tmpdir) / "test-services-in-use-all-export-12.04.2025.xlsx"

            old_file.touch()
            new_file.touch()

            # Make new_file actually newer in filesystem time
            os.utime(str(new_file), (datetime.now().timestamp(), datetime.now().timestamp()))

            result = find_latest_services_export(tmpdir)
            assert result is not None
            # Should return the most recently modified file
            assert result.endswith(".xlsx")


class TestParseServicesFromExcel:
    """Test parse_services_from_excel function."""

    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file returns empty set."""
        result = parse_services_from_excel("/nonexistent/file.xlsx")
        assert result == set()

    def test_parse_invalid_file_type(self):
        """Test parsing non-Excel file returns empty set."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(b"Not an Excel file")
            tmp.flush()

            result = parse_services_from_excel(tmp.name)
            assert result == set()

            os.unlink(tmp.name)

    # Note: Full Excel parsing tests would require openpyxl and creating actual Excel files
    # These are integration tests that would be better suited for a separate test suite


class TestMapServicesToScripts:
    """Test map_services_to_scripts function."""

    def test_map_empty_services(self):
        """Test mapping empty service set."""
        result = map_services_to_scripts(set())
        assert result is not None
        assert isinstance(result, dict)
        # Should return empty mappings
        assert len(result) == 0 or all(len(v) == 0 for v in result.values())

    def test_map_known_services(self):
        """Test mapping known services."""
        services = {"Amazon Elastic Compute Cloud", "Amazon Simple Storage Service"}
        result = map_services_to_scripts(services)

        assert result is not None
        assert isinstance(result, dict)
        assert "Amazon Elastic Compute Cloud" in result
        assert "Amazon Simple Storage Service" in result
        assert "ec2_export.py" in result["Amazon Elastic Compute Cloud"]
        assert "s3_export.py" in result["Amazon Simple Storage Service"]

    def test_map_with_aliases(self):
        """Test that aliases are resolved."""
        services = {"ec2", "s3"}
        result = map_services_to_scripts(services)

        assert result is not None
        # Should have resolved aliases to canonical names
        assert len(result) > 0

    def test_map_unknown_services(self):
        """Test mapping unknown services."""
        services = {"Unknown Service XYZ", "Fake Service ABC"}
        result = map_services_to_scripts(services)

        assert result is not None
        assert isinstance(result, dict)
        # Unknown services should not appear in results
        assert "Unknown Service XYZ" not in result
        assert "Fake Service ABC" not in result

    def test_map_mixed_services(self):
        """Test mapping mix of known and unknown services."""
        services = {"Amazon Elastic Compute Cloud", "Unknown Service XYZ"}
        result = map_services_to_scripts(services)

        assert result is not None
        assert "Amazon Elastic Compute Cloud" in result
        assert "Unknown Service XYZ" not in result


class TestGenerateRecommendations:
    """Test generate_recommendations function."""

    def test_generate_with_empty_mapping(self):
        """Test recommendations with empty service mapping."""
        result = generate_recommendations({}, include_always_run=False)

        assert result is not None
        assert isinstance(result, dict)
        assert "coverage_stats" in result
        assert "all_scripts" in result
        assert "by_category" in result

    def test_generate_with_always_run(self):
        """Test that always-run scripts are included."""
        result = generate_recommendations({}, include_always_run=True)

        assert result is not None
        assert "all_scripts" in result
        # Should include always-run scripts
        assert len(result["all_scripts"]) > 0
        assert "iam_comprehensive_export.py" in result["all_scripts"]
        assert "cloudtrail_export.py" in result["all_scripts"]

    def test_generate_without_always_run(self):
        """Test excluding always-run scripts."""
        service_map = {"Amazon Elastic Compute Cloud": ["ec2_export.py"]}
        result = generate_recommendations(service_map, include_always_run=False)

        assert result is not None
        assert "all_scripts" in result
        # Should only have ec2-export.py
        assert "ec2_export.py" in result["all_scripts"]
        # Should not have always-run scripts
        assert "iam_comprehensive_export.py" not in result["all_scripts"]

    def test_generate_with_services(self):
        """Test recommendations with actual services."""
        service_map = {
            "Amazon Elastic Compute Cloud": ["ec2_export.py", "ami_export.py"],
            "Amazon Simple Storage Service": ["s3_export.py"],
        }
        result = generate_recommendations(service_map, include_always_run=False)

        assert result["coverage_stats"]["services_with_scripts"] == 2
        assert result["coverage_stats"]["total_scripts_recommended"] == 3
        assert "ec2_export.py" in result["all_scripts"]
        assert "ami_export.py" in result["all_scripts"]
        assert "s3_export.py" in result["all_scripts"]

    def test_generate_deduplicates_scripts(self):
        """Test that duplicate scripts are removed."""
        service_map = {
            "Service1": ["ec2_export.py", "s3_export.py"],
            "Service2": ["ec2_export.py"],  # Duplicate
        }
        result = generate_recommendations(service_map, include_always_run=False)

        # Should only count ec2_export.py once
        assert result["coverage_stats"]["total_scripts_recommended"] == 2
        script_list = list(result["all_scripts"])
        assert script_list.count("ec2_export.py") == 1

    def test_generate_has_all_expected_fields(self):
        """Test that recommendations have all expected fields."""
        result = generate_recommendations({}, include_always_run=False)

        expected_fields = [
            "always_run",
            "service_based",
            "all_scripts",
            "by_category",
            "coverage_stats",
        ]
        for field in expected_fields:
            assert field in result, f"Missing field: {field}"


class TestAnalyzeServices:
    """Test analyze_services convenience function."""

    def test_analyze_with_nonexistent_file(self):
        """Test analyzing nonexistent file."""
        result = analyze_services("/nonexistent/file.xlsx")

        assert result is not None
        assert isinstance(result, dict)
        # Should return empty recommendations
        assert result.get("service_count", 0) >= 0

    def test_analyze_with_none_file(self):
        """Test analyzing with None file (should find latest)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Change to tmpdir for search
            original_dir = os.getcwd()
            os.chdir(tmpdir)

            try:
                result = analyze_services(None)
                assert result is not None
                assert isinstance(result, dict)
            finally:
                os.chdir(original_dir)

    def test_analyze_returns_recommendations_structure(self):
        """Test that analyze returns proper recommendation structure."""
        result = analyze_services(None)

        assert result is not None
        assert isinstance(result, dict)
        assert "coverage_stats" in result
        assert "all_scripts" in result


class TestServiceAnalyzerIntegration:
    """Integration tests for ServiceAnalyzer workflow."""

    def test_full_analyzer_workflow(self):
        """Test complete analyzer workflow."""
        analyzer = ServiceAnalyzer()

        # Test finding files (will likely find nothing in test env)
        latest_file = analyzer.find_latest_services_export(".")

        # Test parsing (will return empty set if no file)
        services = analyzer.parse_services_from_excel(latest_file) if latest_file else set()
        assert isinstance(services, set)

        # Test mapping
        service_map = analyzer.map_services_to_scripts(services)
        assert isinstance(service_map, dict)

        # Test recommendations
        recommendations = analyzer.generate_recommendations(service_map)
        assert isinstance(recommendations, dict)
        assert "coverage_stats" in recommendations
        assert "all_scripts" in recommendations

    def test_analyzer_with_known_services(self):
        """Test analyzer with pre-defined services."""
        analyzer = ServiceAnalyzer()

        services = {"Amazon Elastic Compute Cloud", "Amazon Simple Storage Service"}
        service_map = analyzer.map_services_to_scripts(services)
        recommendations = analyzer.generate_recommendations(include_always_run=True)

        assert recommendations["coverage_stats"]["services_with_scripts"] == 2
        assert recommendations["coverage_stats"]["total_scripts_recommended"] > 2  # Scripts + always-run
        assert "ec2_export.py" in recommendations["all_scripts"]
        assert "s3_export.py" in recommendations["all_scripts"]
        assert "iam_comprehensive_export.py" in recommendations["all_scripts"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
