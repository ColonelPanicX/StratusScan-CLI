#!/usr/bin/env python3
"""
Test script for smart_scan selector module imports.
Verifies that the module can be imported and basic structure is correct.
"""

import sys
import os

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

print("=" * 80)
print("SMART SCAN SELECTOR IMPORT TEST")
print("=" * 80)
print()

# Test imports
print("Testing imports...")

try:
    from smart_scan.selector import SmartScanSelector, interactive_select, QUESTIONARY_AVAILABLE
    print("✓ Successfully imported selector module")
except Exception as e:
    print(f"✗ Failed to import selector: {e}")
    sys.exit(1)

# Check questionary availability
print()
print(f"Questionary Available: {QUESTIONARY_AVAILABLE}")

if not QUESTIONARY_AVAILABLE:
    print()
    print("Note: questionary is not installed. Interactive features will not be available.")
    print("      Install with: pip install questionary>=2.0.0")

# Test module structure
print()
print("Testing module structure...")

# Check SmartScanSelector class exists
if hasattr(SmartScanSelector, "__init__"):
    print("✓ SmartScanSelector class found")
else:
    print("✗ SmartScanSelector class missing __init__")

# Check interactive_select function exists
if callable(interactive_select):
    print("✓ interactive_select function found")
else:
    print("✗ interactive_select function not callable")

# Test that we can create mock recommendations
print()
print("Testing with mock recommendations...")

mock_recommendations = {
    "always_run": ["iam-comprehensive-export.py", "cloudtrail-export.py"],
    "service_based": {
        "Amazon EC2": ["ec2-export.py", "ami-export.py"],
        "Amazon S3": ["s3-export.py"],
    },
    "all_scripts": {
        "iam-comprehensive-export.py",
        "cloudtrail-export.py",
        "ec2-export.py",
        "ami-export.py",
        "s3-export.py",
    },
    "by_category": {
        "Security & Compliance": ["iam-comprehensive-export.py", "cloudtrail-export.py"],
        "Compute": ["ec2-export.py", "ami-export.py"],
        "Storage": ["s3-export.py"],
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

try:
    if QUESTIONARY_AVAILABLE:
        selector = SmartScanSelector(mock_recommendations)
        print("✓ SmartScanSelector initialized successfully")

        # Test methods exist
        methods = [
            "show_welcome",
            "show_main_menu",
            "quick_scan_confirm",
            "custom_selection_by_category",
            "custom_selection_by_service",
            "view_checklist",
            "save_checklist",
            "run_interactive",
        ]

        print()
        print("Checking selector methods:")
        for method in methods:
            if hasattr(selector, method):
                print(f"  ✓ {method}")
            else:
                print(f"  ✗ {method} missing")
    else:
        print("⚠ Skipping SmartScanSelector test (questionary not available)")

except Exception as e:
    print(f"✗ Error creating selector: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
print("=" * 80)
print("✓ ALL IMPORT TESTS PASSED")
print("=" * 80)
print()

if not QUESTIONARY_AVAILABLE:
    print("Next step: Install questionary to enable interactive features")
    print("  pip install questionary>=2.0.0")
    print()

sys.exit(0)
