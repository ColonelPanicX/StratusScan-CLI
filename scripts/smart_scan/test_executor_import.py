#!/usr/bin/env python3
"""
Test script for smart_scan executor module imports.
Verifies that the executor module can be imported and basic structure is correct.
"""

import sys
import os

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

print("=" * 80)
print("SMART SCAN EXECUTOR IMPORT TEST")
print("=" * 80)
print()

# Test imports
print("Testing imports...")

try:
    from smart_scan.executor import ScriptExecutor, ExecutionResult, execute_scripts
    print("✓ Successfully imported executor module")
except Exception as e:
    print(f"✗ Failed to import executor: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test ExecutionResult dataclass
print()
print("Testing ExecutionResult dataclass...")

from datetime import datetime

try:
    result = ExecutionResult(
        script="test-script.py",
        success=True,
        start_time=datetime(2025, 12, 4, 10, 0, 0),
        end_time=datetime(2025, 12, 4, 10, 2, 30),
        duration_seconds=150.0,
        return_code=0,
        output_file="test-output.xlsx",
    )

    print(f"✓ ExecutionResult created: {result.script}")
    print(f"  Duration formatted: {result.duration_formatted}")

    if result.duration_formatted == "2m 30s":
        print("✓ Duration formatting works correctly")
    else:
        print(f"✗ Duration formatting incorrect: {result.duration_formatted}")

except Exception as e:
    print(f"✗ Error creating ExecutionResult: {e}")
    sys.exit(1)

# Test ScriptExecutor class
print()
print("Testing ScriptExecutor class...")

try:
    test_scripts = {"test1.py", "test2.py", "test3.py"}
    executor = ScriptExecutor(test_scripts)

    print(f"✓ ScriptExecutor created with {executor.total_scripts} scripts")

    # Check methods exist
    methods = [
        "_find_script_path",
        "_execute_script",
        "_find_output_file",
        "_show_progress_header",
        "_show_progress",
        "_show_execution_summary",
        "execute_all",
        "save_execution_log",
    ]

    print()
    print("Checking executor methods:")
    all_methods_exist = True
    for method in methods:
        if hasattr(executor, method):
            print(f"  ✓ {method}")
        else:
            print(f"  ✗ {method} missing")
            all_methods_exist = False

    if not all_methods_exist:
        sys.exit(1)

except Exception as e:
    print(f"✗ Error creating ScriptExecutor: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test execute_scripts function
print()
print("Testing execute_scripts function...")

try:
    if callable(execute_scripts):
        print("✓ execute_scripts function is callable")
    else:
        print("✗ execute_scripts is not callable")
        sys.exit(1)
except Exception as e:
    print(f"✗ Error checking execute_scripts: {e}")
    sys.exit(1)

print()
print("=" * 80)
print("✓ ALL EXECUTOR IMPORT TESTS PASSED")
print("=" * 80)
print()

sys.exit(0)
