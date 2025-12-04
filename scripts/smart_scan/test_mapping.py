#!/usr/bin/env python3
"""
Test script for smart_scan mapping functionality.
Verifies service-to-script mappings work correctly.
"""

import sys
import os

# Add scripts directory to path so we can import smart_scan
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.mapping import (
    get_canonical_service_name,
    get_scripts_for_service,
    get_category_for_script,
    get_all_scripts,
    SERVICE_ALIASES,
    SERVICE_SCRIPT_MAP,
    ALWAYS_RUN_SCRIPTS,
)


def test_service_aliases():
    """Test service name alias resolution."""
    print("=" * 80)
    print("Testing Service Aliases")
    print("=" * 80)

    test_cases = [
        ("ec2", "Amazon Elastic Compute Cloud"),
        ("s3", "Amazon Simple Storage Service"),
        ("lambda", "AWS Lambda"),
        ("rds", "Amazon Relational Database Service"),
        ("vpc", "Amazon Virtual Private Cloud"),
        ("iam", "AWS Identity and Access Management"),
        ("Amazon EC2", "Amazon Elastic Compute Cloud"),
        ("Amazon S3", "Amazon Simple Storage Service"),
    ]

    passed = 0
    failed = 0

    for alias, expected in test_cases:
        result = get_canonical_service_name(alias)
        if result == expected:
            print(f"✓ '{alias}' → '{result}'")
            passed += 1
        else:
            print(f"✗ '{alias}' → '{result}' (expected '{expected}')")
            failed += 1

    print(f"\nAlias Tests: {passed} passed, {failed} failed\n")
    return failed == 0


def test_script_mapping():
    """Test service-to-script mapping."""
    print("=" * 80)
    print("Testing Script Mapping")
    print("=" * 80)

    test_cases = [
        ("Amazon Elastic Compute Cloud", ["ec2-export.py", "ami-export.py", "autoscaling-export.py", "ebs-volumes-export.py", "ebs-snapshots-export.py"]),
        ("AWS Lambda", ["lambda-export.py"]),
        ("Amazon Simple Storage Service", ["s3-export.py", "s3-accesspoints-export.py"]),
        ("ec2", ["ec2-export.py", "ami-export.py", "autoscaling-export.py", "ebs-volumes-export.py", "ebs-snapshots-export.py"]),  # Test alias
        ("s3", ["s3-export.py", "s3-accesspoints-export.py"]),  # Test alias
    ]

    passed = 0
    failed = 0

    for service, expected_scripts in test_cases:
        scripts = get_scripts_for_service(service)
        if set(scripts) == set(expected_scripts):
            print(f"✓ '{service}' → {len(scripts)} script(s)")
            passed += 1
        else:
            print(f"✗ '{service}' → {scripts}")
            print(f"  Expected: {expected_scripts}")
            failed += 1

    print(f"\nMapping Tests: {passed} passed, {failed} failed\n")
    return failed == 0


def test_categories():
    """Test script categorization."""
    print("=" * 80)
    print("Testing Script Categories")
    print("=" * 80)

    test_cases = [
        ("ec2-export.py", "Compute"),
        ("s3-export.py", "Storage"),
        ("rds-export.py", "Database"),
        ("vpc-data-export.py", "Networking"),
        ("iam-comprehensive-export.py", "Security & Compliance"),
        ("cost-explorer-export.py", "Cost Management"),
        ("cloudwatch-export.py", "Management & Monitoring"),
    ]

    passed = 0
    failed = 0

    for script, expected_category in test_cases:
        category = get_category_for_script(script)
        if category == expected_category:
            print(f"✓ '{script}' → '{category}'")
            passed += 1
        else:
            print(f"✗ '{script}' → '{category}' (expected '{expected_category}')")
            failed += 1

    print(f"\nCategory Tests: {passed} passed, {failed} failed\n")
    return failed == 0


def test_statistics():
    """Display mapping statistics."""
    print("=" * 80)
    print("Mapping Statistics")
    print("=" * 80)

    total_services = len(SERVICE_SCRIPT_MAP)
    total_aliases = len(SERVICE_ALIASES)
    total_scripts = len(get_all_scripts())
    always_run = len(ALWAYS_RUN_SCRIPTS)

    print(f"Total Services Mapped: {total_services}")
    print(f"Total Aliases Defined: {total_aliases}")
    print(f"Total Unique Scripts: {total_scripts}")
    print(f"Always-Run Scripts: {always_run}")

    # Count scripts per service
    scripts_per_service = [len(scripts) for scripts in SERVICE_SCRIPT_MAP.values()]
    avg_scripts = sum(scripts_per_service) / len(scripts_per_service)
    max_scripts = max(scripts_per_service)

    print(f"\nAverage Scripts per Service: {avg_scripts:.1f}")
    print(f"Maximum Scripts for One Service: {max_scripts}")

    # Find service with most scripts
    for service, scripts in SERVICE_SCRIPT_MAP.items():
        if len(scripts) == max_scripts:
            print(f"Service with most scripts: {service} ({max_scripts} scripts)")
            break

    print()
    return True


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("SMART SCAN MAPPING TESTS")
    print("=" * 80 + "\n")

    results = []
    results.append(("Aliases", test_service_aliases()))
    results.append(("Mapping", test_script_mapping()))
    results.append(("Categories", test_categories()))
    results.append(("Statistics", test_statistics()))

    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    all_passed = True
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False

    print("=" * 80)

    if all_passed:
        print("\n✓ All tests passed!\n")
        return 0
    else:
        print("\n✗ Some tests failed!\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
