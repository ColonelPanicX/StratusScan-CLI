#!/usr/bin/env python3
"""
Tests for iam_rolesanywhere_export.py.

Covers:
- collect_trust_anchors() / collect_profiles() per-item guarding and
  account-scope failure propagation
- main()'s failed-scope tracking, finalize, and exit-code behavior

IAM Roles Anywhere is a global/account-scope service (not multi-region), so
collect_trust_anchors() and collect_profiles() are the two PRIMARY
account-scope collectors -- mirrors the scripts/iam_export.py account-scope
pattern (see scripts/shield_export.py for the same fix applied to a single
account-scope collector, and scripts/lambda_export.py for the finalize
shape). moto's Roles Anywhere support is limited (``list_trust_anchors`` /
``list_profiles`` raise "Not yet implemented" -- see moto 5.1.21), so these
tests drive the module through monkeypatched boto3 clients / module
functions rather than real moto-backed Roles Anywhere state.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import iam_rolesanywhere_export  # noqa: E402
from iam_rolesanywhere_export import collect_profiles, collect_trust_anchors  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture(autouse=True)
def patch_output_dir(tmp_path, monkeypatch):
    """Redirect get_output_dir() to a temp directory for every test."""
    monkeypatch.setattr(iam_rolesanywhere_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_rolesanywhere_client(trust_anchors=None, profiles=None):
    """Build a MagicMock standing in for a boto3 Roles Anywhere client."""
    client = MagicMock()

    def get_paginator(operation):
        paginator = MagicMock()
        if operation == "list_trust_anchors":
            paginator.paginate.return_value = [{"trustAnchors": trust_anchors or []}]
        elif operation == "list_profiles":
            paginator.paginate.return_value = [{"profiles": profiles or []}]
        else:
            paginator.paginate.return_value = [{}]
        return paginator

    client.get_paginator.side_effect = get_paginator
    client.get_trust_anchor.return_value = {"trustAnchor": {}}
    client.get_profile.return_value = {"profile": {}}
    return client


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits, applied to IAM Roles Anywhere: collect_trust_anchors() and
    collect_profiles() -- the two PRIMARY, global/account-scope collectors --
    used to swallow a real API error into an empty list, indistinguishable
    from an account with no trust anchors/profiles configured. main() also
    had no way to signal that failure downstream. These tests cover: (a) a
    malformed trust anchor / profile is skipped, not fatal; (b)
    collect_trust_anchors() and collect_profiles() raise rather than
    swallowing a real API error; (c) that a failure in either primary scope
    surfaces through main() as a non-zero exit plus a
    utils.report_collection_failures() call.
    """

    # -- (a) Per-item guard: trust anchors ----------------------------------

    def test_malformed_trust_anchor_is_skipped_not_fatal(self, monkeypatch):
        """One trust anchor that fails to process must not discard the others."""
        good = {"trustAnchorId": "good-id", "name": "good-anchor"}
        bad = {"trustAnchorId": "bad-id", "name": "bad-anchor"}

        client = _fake_rolesanywhere_client(trust_anchors=[good, bad])
        monkeypatch.setattr(iam_rolesanywhere_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = iam_rolesanywhere_export._build_trust_anchor_row

        def raise_for_bad(client_arg, anchor):
            if anchor.get("trustAnchorId") == "bad-id":
                raise KeyError("SomeUnexpectedField")
            return original(client_arg, anchor)

        monkeypatch.setattr(iam_rolesanywhere_export, "_build_trust_anchor_row", raise_for_bad)

        result = collect_trust_anchors()

        ids = {row["Trust Anchor ID"] for row in result}
        assert "good-id" in ids, "healthy trust anchor was lost when a sibling failed"
        assert "bad-id" not in ids, "malformed trust anchor should have been skipped"

    # -- (a) Per-item guard: profiles ----------------------------------------

    def test_malformed_profile_is_skipped_not_fatal(self, monkeypatch):
        """One profile that fails to process must not discard the others."""
        good = {"profileId": "good-id", "name": "good-profile"}
        bad = {"profileId": "bad-id", "name": "bad-profile"}

        client = _fake_rolesanywhere_client(profiles=[good, bad])
        monkeypatch.setattr(iam_rolesanywhere_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = iam_rolesanywhere_export._build_profile_row

        def raise_for_bad(client_arg, profile):
            if profile.get("profileId") == "bad-id":
                raise KeyError("SomeUnexpectedField")
            return original(client_arg, profile)

        monkeypatch.setattr(iam_rolesanywhere_export, "_build_profile_row", raise_for_bad)

        result = collect_profiles()

        ids = {row["Profile ID"] for row in result}
        assert "good-id" in ids, "healthy profile was lost when a sibling failed"
        assert "bad-id" not in ids, "malformed profile should have been skipped"

    # -- (b) Account-scope failure propagation: trust anchors ---------------

    def test_collect_trust_anchors_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Roles Anywhere API error during trust anchor collection must
        propagate, not collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Something broke"}},
                "ListTrustAnchors",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(iam_rolesanywhere_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_trust_anchors()

    # -- (b) Account-scope failure propagation: profiles ---------------------

    def test_collect_profiles_raises_on_api_error_not_swallowed(self, monkeypatch):
        """A real Roles Anywhere API error during profile collection must
        propagate, not collapse to an empty list."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Something broke"}},
                "ListProfiles",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(iam_rolesanywhere_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_profiles()

    # -- (c) main(): failure surfaced, non-zero exit -------------------------

    def _patch_common_main(self, monkeypatch):
        monkeypatch.setattr(iam_rolesanywhere_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(iam_rolesanywhere_export.utils, "setup_logging", lambda *a, **kw: None)
        monkeypatch.setattr(
            iam_rolesanywhere_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(
            iam_rolesanywhere_export.utils,
            "validate_aws_credentials",
            lambda *a, **kw: (True, "123456789012", None),
        )
        monkeypatch.setattr(iam_rolesanywhere_export, "collect_crls", lambda: [])

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(iam_rolesanywhere_export.utils, "report_collection_failures", fake_report)
        return calls

    def test_main_trust_anchors_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A trust-anchor API failure in main() must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty export."""
        calls = self._patch_common_main(monkeypatch)

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Something broke"}},
                "ListTrustAnchors",
            )

        monkeypatch.setattr(iam_rolesanywhere_export, "collect_trust_anchors", boom)
        monkeypatch.setattr(iam_rolesanywhere_export, "collect_profiles", lambda: [])

        with pytest.raises(SystemExit) as exc_info:
            iam_rolesanywhere_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "iam-rolesanywhere"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "trust_anchors"

    def test_main_profiles_failure_exits_nonzero_and_reports(self, monkeypatch):
        """A profiles API failure in main() must exit non-zero and call
        utils.report_collection_failures -- never silently collapse into an
        empty export."""
        calls = self._patch_common_main(monkeypatch)

        def boom():
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Something broke"}},
                "ListProfiles",
            )

        monkeypatch.setattr(iam_rolesanywhere_export, "collect_trust_anchors", lambda: [])
        monkeypatch.setattr(iam_rolesanywhere_export, "collect_profiles", boom)

        with pytest.raises(SystemExit) as exc_info:
            iam_rolesanywhere_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "iam-rolesanywhere"
        assert calls.get("failed_scopes")
        assert calls["failed_scopes"][0][0] == "profiles"

    def test_main_genuinely_empty_exits_zero_no_marker(self, monkeypatch):
        """Both primary scopes succeeding with no data is a legitimate,
        genuinely-empty state -- exit 0 (implicit), and
        utils.report_collection_failures is never called (no
        *-FAILED-*.txt marker is written)."""
        calls = self._patch_common_main(monkeypatch)

        monkeypatch.setattr(iam_rolesanywhere_export, "collect_trust_anchors", lambda: [])
        monkeypatch.setattr(iam_rolesanywhere_export, "collect_profiles", lambda: [])

        # main() does not sys.exit() on the success path; it simply returns.
        iam_rolesanywhere_export.main()

        assert "failed_scopes" not in calls


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
