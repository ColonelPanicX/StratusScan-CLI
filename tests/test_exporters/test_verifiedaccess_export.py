#!/usr/bin/env python3
"""
Tests for verifiedaccess_export.py.

Regression coverage for issue #208: the exporter created its client with the
non-existent boto3 service name 'verifiedaccess'. Verified Access APIs live
under 'ec2'. Because every collector is wrapped in @aws_error_handler, the
invalid client surfaced as a silently empty export rather than a crash — so the
import-only smoke test never caught it. These tests assert every collector
creates its client with a *real* boto3 service.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.session
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import verifiedaccess_export as va  # noqa: E402

REGION = "us-east-1"

# Every collector and how to invoke it (collect_access_logs_config needs the
# already-collected instances list).
COLLECTORS = [
    ("collect_verified_access_instances", lambda f: f(REGION)),
    ("collect_trust_providers", lambda f: f(REGION)),
    ("collect_verified_access_groups", lambda f: f(REGION)),
    ("collect_verified_access_endpoints", lambda f: f(REGION)),
    ("collect_access_logs_config", lambda f: f(REGION, [])),
]


def _empty_client():
    """A mock client that yields no resources for any paginated/direct call."""
    m = MagicMock()
    m.get_paginator.return_value.paginate.return_value = []
    m.describe_verified_access_instance_logging_configurations.return_value = {}
    return m


@pytest.mark.parametrize("fn_name,invoke", COLLECTORS)
def test_collectors_use_valid_boto3_service(monkeypatch, fn_name, invoke):
    """Each collector must build its client from a real boto3 service (issue #208)."""
    valid_services = set(botocore.session.get_session().get_available_services())
    requested = []

    def spy(service, region_name=None, **kwargs):
        requested.append(service)
        return _empty_client()

    monkeypatch.setattr(va.utils, "get_boto3_client", spy)

    invoke(getattr(va, fn_name))

    assert requested, f"{fn_name} never created a client"
    invalid = [s for s in requested if s not in valid_services]
    assert not invalid, (
        f"{fn_name} created a client with invalid boto3 service(s): {invalid}. "
        "Verified Access APIs live under 'ec2'."
    )
    # Verified Access is specifically an EC2 API surface.
    assert all(s == "ec2" for s in requested), (
        f"{fn_name} should use the 'ec2' client; got {requested}"
    )


def test_collect_instances_parses_data(monkeypatch):
    """With the corrected client, instance data is parsed end to end."""
    page = {
        "VerifiedAccessInstances": [
            {
                "VerifiedAccessInstanceId": "vai-0123456789abcdef0",
                "Description": "prod zero-trust",
                "VerifiedAccessTrustProviders": [{"VerifiedAccessTrustProviderId": "vatp-1"}],
                "Tags": [{"Key": "env", "Value": "prod"}],
            }
        ]
    }
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [page]

    captured = {}

    def spy(service, region_name=None, **kwargs):
        captured["service"] = service
        return client

    monkeypatch.setattr(va.utils, "get_boto3_client", spy)

    rows = va.collect_verified_access_instances(REGION)

    assert captured["service"] == "ec2"
    assert len(rows) == 1
    assert rows[0]["Instance ID"] == "vai-0123456789abcdef0"
    assert rows[0]["Trust Provider Count"] == 1
    assert rows[0]["Tags"] == "env=prod"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
