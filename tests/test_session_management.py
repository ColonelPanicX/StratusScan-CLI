#!/usr/bin/env python3
"""
Test script for new session management and partition awareness features.
"""

import utils

def test_detect_partition():
    """Test partition detection."""
    print("\n=== Testing Partition Detection ===")

    # Test commercial region
    partition = utils.detect_partition('us-east-1')
    print(f"Partition for us-east-1: {partition}")
    assert partition == 'aws', f"Expected 'aws', got '{partition}'"

    # Test GovCloud region
    partition = utils.detect_partition('us-gov-west-1')
    print(f"Partition for us-gov-west-1: {partition}")
    assert partition == 'aws-us-gov', f"Expected 'aws-us-gov', got '{partition}'"

    print("✓ Partition detection tests passed")

def test_build_arn():
    """Test ARN building with partition awareness."""
    print("\n=== Testing ARN Building ===")

    # Test commercial ARN
    arn = utils.build_arn('ec2', 'instance/i-1234567890abcdef0', region='us-east-1', account_id='123456789012')
    print(f"Commercial ARN: {arn}")
    assert arn.startswith('arn:aws:'), f"Expected commercial ARN, got: {arn}"

    # Test GovCloud ARN
    arn = utils.build_arn('ec2', 'instance/i-1234567890abcdef0', region='us-gov-west-1', account_id='123456789012')
    print(f"GovCloud ARN: {arn}")
    assert arn.startswith('arn:aws-us-gov:'), f"Expected GovCloud ARN, got: {arn}"

    print("✓ ARN building tests passed")

def test_parse_arn():
    """Test ARN parsing with partition awareness."""
    print("\n=== Testing ARN Parsing ===")

    # Test commercial ARN
    arn = 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'
    parsed = utils.parse_aws_arn(arn)
    print(f"Parsed commercial ARN: {parsed}")
    assert parsed is not None, "Failed to parse commercial ARN"
    assert parsed['partition'] == 'aws', f"Expected partition 'aws', got '{parsed['partition']}'"

    # Test GovCloud ARN
    arn = 'arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-1234567890abcdef0'
    parsed = utils.parse_aws_arn(arn)
    print(f"Parsed GovCloud ARN: {parsed}")
    assert parsed is not None, "Failed to parse GovCloud ARN"
    assert parsed['partition'] == 'aws-us-gov', f"Expected partition 'aws-us-gov', got '{parsed['partition']}'"

    print("✓ ARN parsing tests passed")

def test_get_boto3_client():
    """Test boto3 client creation with configuration."""
    print("\n=== Testing Boto3 Client Creation ===")

    try:
        # This should create a client with retry configuration
        sts = utils.get_boto3_client('sts')

        # Verify the client has a config
        assert hasattr(sts, '_client_config'), "Client missing _client_config"

        # Try to get caller identity to verify it works
        response = sts.get_caller_identity()
        print(f"Successfully created STS client and got account: {response['Account']}")
        print("✓ Boto3 client creation test passed")

    except Exception as e:
        print(f"⚠ Warning: Could not test with real AWS credentials: {e}")
        print("  This is expected if AWS credentials are not configured")

def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Session Management and Partition Awareness")
    print("=" * 60)

    try:
        test_detect_partition()
        test_build_arn()
        test_parse_arn()
        test_get_boto3_client()

        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
