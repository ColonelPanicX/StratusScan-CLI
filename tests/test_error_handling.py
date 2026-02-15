#!/usr/bin/env python3
"""
Test script for standardized error handling patterns.

This script demonstrates and tests the new aws_error_handler decorator
and handle_aws_operation context manager.
"""

import sys
from pathlib import Path
from typing import List, Dict, Any

# Standard utils import pattern
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    sys.path.append(str(script_dir))
    import utils


# =============================================================================
# Test Functions Using @aws_error_handler Decorator
# =============================================================================

@utils.aws_error_handler("Test: Simple operation with default return", default_return=[])
def test_decorator_default_return() -> List[str]:
    """Test decorator that returns empty list on error."""
    # This will succeed if credentials are configured
    sts = utils.get_boto3_client('sts')
    identity = sts.get_caller_identity()
    return [identity['Account'], identity['Arn']]


@utils.aws_error_handler("Test: Operation with reraise", reraise=True)
def test_decorator_reraise() -> str:
    """Test decorator that reraises exceptions."""
    # This will fail with NoCredentialsError if not configured
    ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')
    response = ec2.describe_instances(InstanceIds=['i-invalid12345'])
    return "Success"


@utils.aws_error_handler("Test: Invalid instance lookup", default_return=None)
def test_decorator_client_error() -> Dict[str, Any]:
    """Test decorator handling ClientError."""
    ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')
    # This should trigger a ClientError
    response = ec2.describe_instances(InstanceIds=['i-doesnotexist123'])
    return response


# =============================================================================
# Test Functions Using handle_aws_operation Context Manager
# =============================================================================

def test_context_manager_suppress() -> List[str]:
    """Test context manager with error suppression."""
    result = []

    with utils.handle_aws_operation(
        "Test: Context manager with suppression",
        default_return=[],
        suppress_errors=True
    ):
        sts = utils.get_boto3_client('sts')
        identity = sts.get_caller_identity()
        result.append(identity['Account'])
        result.append(identity['Arn'])

    return result


def test_context_manager_reraise() -> bool:
    """Test context manager that reraises exceptions."""
    with utils.handle_aws_operation(
        "Test: Context manager with reraise",
        suppress_errors=False
    ):
        ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')
        # This should trigger an error
        ec2.describe_instances(InstanceIds=['i-invalid'])

    return True


def test_multi_step_operation() -> Dict[str, Any]:
    """Test context manager with multiple steps."""
    results = {
        'account': None,
        'regions': [],
        'error': None
    }

    with utils.handle_aws_operation(
        "Test: Multi-step AWS operation",
        suppress_errors=True
    ):
        # Step 1: Get account info
        sts = utils.get_boto3_client('sts')
        identity = sts.get_caller_identity()
        results['account'] = identity['Account']
        utils.log_info(f"Got account ID: {results['account']}")

        # Step 2: List regions
        ec2 = utils.get_boto3_client('ec2', region_name='us-east-1')
        response = ec2.describe_regions()
        results['regions'] = [r['RegionName'] for r in response['Regions']]
        utils.log_info(f"Found {len(results['regions'])} regions")

    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def main():
    """Run all error handling tests."""
    utils.setup_logging("test-error-handling")
    utils.log_script_start("test-error-handling", "Test standardized error handling patterns")

    print("\n" + "="*80)
    print("STANDARDIZED ERROR HANDLING TESTS")
    print("="*80 + "\n")

    # Test 1: Decorator with default return (should succeed)
    print("\n--- Test 1: Decorator with Default Return ---")
    try:
        result = test_decorator_default_return()
        if result:
            utils.log_success(f"Test 1 PASSED: Got account info: {result[0]}")
        else:
            utils.log_warning("Test 1: Returned empty list (credentials may not be configured)")
    except Exception as e:
        utils.log_error("Test 1 FAILED", e)

    # Test 2: Context manager with suppression (should succeed)
    print("\n--- Test 2: Context Manager with Suppression ---")
    try:
        result = test_context_manager_suppress()
        if result:
            utils.log_success(f"Test 2 PASSED: Got account info via context manager")
        else:
            utils.log_warning("Test 2: Returned empty list (credentials may not be configured)")
    except Exception as e:
        utils.log_error("Test 2 FAILED", e)

    # Test 3: Multi-step operation (should succeed)
    print("\n--- Test 3: Multi-Step Operation ---")
    try:
        result = test_multi_step_operation()
        if result['account']:
            utils.log_success(f"Test 3 PASSED: Account={result['account']}, Regions={len(result['regions'])}")
        else:
            utils.log_warning("Test 3: No data returned (credentials may not be configured)")
    except Exception as e:
        utils.log_error("Test 3 FAILED", e)

    # Test 4: Decorator handling ClientError (should fail gracefully)
    print("\n--- Test 4: Decorator Handling ClientError ---")
    try:
        result = test_decorator_client_error()
        if result is None:
            utils.log_success("Test 4 PASSED: ClientError handled correctly, returned None")
        else:
            utils.log_warning(f"Test 4: Unexpected result: {result}")
    except Exception as e:
        utils.log_error("Test 4 FAILED (exception not suppressed)", e)

    # Test 5: Decorator with reraise (should raise exception)
    print("\n--- Test 5: Decorator with Reraise ---")
    try:
        result = test_decorator_reraise()
        utils.log_warning("Test 5: No exception raised (unexpected)")
    except Exception as e:
        utils.log_success(f"Test 5 PASSED: Exception reraised correctly: {type(e).__name__}")

    # Test 6: Context manager with reraise (should raise exception)
    print("\n--- Test 6: Context Manager with Reraise ---")
    try:
        result = test_context_manager_reraise()
        utils.log_warning("Test 6: No exception raised (unexpected)")
    except Exception as e:
        utils.log_success(f"Test 6 PASSED: Exception reraised correctly: {type(e).__name__}")

    print("\n" + "="*80)
    print("TESTS COMPLETE")
    print("="*80 + "\n")

    utils.log_info("Check logs for detailed error messages")
    log_file = utils.get_current_log_file()
    if log_file:
        utils.log_info(f"Log file: {log_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Test script failed", e)
        sys.exit(1)
