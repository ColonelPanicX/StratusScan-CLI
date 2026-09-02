#!/usr/bin/env python3
"""
Moto-based tests for ami_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ami_export  # noqa: E402
from ami_export import collect_amis_in_region  # noqa: E402

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_ami(ec2_client, name):
    """Launch a minimal instance and register/create an AMI named ``name``."""
    reservation = ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    response = ec2_client.create_image(
        InstanceId=instance_id,
        Name=name,
        Description="test AMI",
    )
    return response["ImageId"]


class TestCollectAmisInRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_amis(self):
        client = boto3.client("ec2", region_name=REGION)
        _create_ami(client, "web-ami")

        rows = collect_amis_in_region(REGION, ACCOUNT_ID)

        names = {row["AMI Name"] for row in rows}
        assert "web-ami" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("ec2", region_name=REGION)  # region exists, no AMIs

        rows = collect_amis_in_region(REGION, ACCOUNT_ID)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One AMI that fails to process must not discard the whole region."""
        client = boto3.client("ec2", region_name=REGION)
        _create_ami(client, "good-ami")
        _create_ami(client, "bad-ami")

        original = ami_export._build_ami_row

        def raise_for_bad(ami, region):
            if ami.get("Name") == "bad-ami":
                raise KeyError("SomeUnexpectedField")
            return original(ami, region)

        monkeypatch.setattr(ami_export, "_build_ami_row", raise_for_bad)

        rows = collect_amis_in_region(REGION, ACCOUNT_ID)

        names = {row["AMI Name"] for row in rows}
        assert "good-ami" in names, "healthy AMI was lost when a sibling failed"
        assert "bad-ami" not in names, "malformed AMI should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeImages",
            )

        monkeypatch.setattr(ami_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_amis_in_region(REGION, ACCOUNT_ID)

    @mock_aws
    def test_collect_amis_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region, account_id):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeImages",
            )

        monkeypatch.setattr(ami_export, "collect_amis_in_region", boom)

        amis, failed_regions = ami_export.collect_amis([REGION], ACCOUNT_ID)

        assert amis == []
        assert [r for r, _ in failed_regions] == [REGION]


# ---------------------------------------------------------------------------
# AMI ancestry (Issue #270)
#
# Contractual fields and the value parsed from a snapshot description are kept
# in separate columns, and "AWS reported nothing" stays distinguishable from
# "this client could not ask" — the distinction that made Issue #268 findable.
# ---------------------------------------------------------------------------


class TestCreateImageDescriptionParsing:
    def test_matches_the_aws_convention(self):
        match = ami_export._CREATE_IMAGE_DESCRIPTION.search(
            "Created by CreateImage(i-0abc123def456789a) for ami-0f1e2d3c4b5a69788"
        )

        assert match.group(1) == "i-0abc123def456789a"
        assert match.group(2) == "ami-0f1e2d3c4b5a69788"

    def test_user_edited_description_does_not_match(self):
        """
        The parse is a convention, not a contract. A snapshot whose description
        someone rewrote yields no ancestry rather than a wrong answer.
        """
        assert ami_export._CREATE_IMAGE_DESCRIPTION.search("nightly backup before patching") is None


class TestCopySourceSupportDetection:
    @mock_aws
    def test_detection_matches_the_installed_botocore_model(self):
        """
        SourceImageId postdates the pinned boto3 floor, so the answer differs
        by installed version. Assert against the model itself rather than
        hardcoding an expectation that breaks on one end of the range.
        """
        client = boto3.client("ec2", region_name=REGION)
        image_shape = (
            client.meta.service_model
            .operation_model("DescribeImages")
            .output_shape.members["Images"].member
        )
        expected = "SourceImageId" in image_shape.members

        assert ami_export._copy_source_supported(client) is expected


class TestAncestryColumns:
    def test_contractual_fields_are_reported_when_present(self):
        columns = ami_export._ancestry_columns(
            {
                "SourceInstanceId": "i-0abc123def456789a",
                "SourceImageId": "ami-0aaa1111bbbb2222c",
                "SourceImageRegion": "us-west-2",
                "BlockDeviceMappings": [],
            },
            {},
            copy_source_supported=True,
        )

        assert columns["Source Instance ID"] == "i-0abc123def456789a"
        assert columns["Source Image ID"] == "ami-0aaa1111bbbb2222c"
        assert columns["Source Image Region"] == "us-west-2"

    def test_old_botocore_is_distinguishable_from_a_non_copied_ami(self):
        """
        'This AMI was not copied' and 'this client cannot report copies' are
        different facts. Collapsing them into one blank is what hid #268.
        """
        supported = ami_export._ancestry_columns(
            {"BlockDeviceMappings": []}, {}, copy_source_supported=True
        )
        unsupported = ami_export._ancestry_columns(
            {"BlockDeviceMappings": []}, {}, copy_source_supported=False
        )

        assert supported["Source Image ID"] == "N/A"
        assert unsupported["Source Image ID"] == "Unavailable (boto3 too old)"
        assert unsupported["Source Image Region"] == "Unavailable (boto3 too old)"

    def test_parent_ami_comes_from_the_snapshot_map(self):
        columns = ami_export._ancestry_columns(
            {"BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-111"}}]},
            {"snap-111": {"source_instance": "i-222", "parent_ami": "ami-333"}},
            copy_source_supported=True,
        )

        assert columns["Parent AMI (inferred)"] == "ami-333"

    def test_no_resolvable_ancestor_reports_na(self):
        """
        An imported or third-party AMI has no ancestor. That is a correct
        result, not a failure.
        """
        columns = ami_export._ancestry_columns(
            {"BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-111"}}]},
            {},
            copy_source_supported=True,
        )

        assert columns["Parent AMI (inferred)"] == "N/A"
        assert columns["Source Instance ID"] == "N/A"

    def test_failed_lookup_is_distinguishable_from_no_ancestor(self):
        columns = ami_export._ancestry_columns(
            {"BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-111"}}]},
            {},
            copy_source_supported=True,
            lookup_failed=True,
        )

        assert columns["Parent AMI (inferred)"] == "Unresolved (snapshot lookup failed)"

    def test_failed_lookup_with_no_snapshots_still_reports_na(self):
        """Nothing was there to resolve, so the failure is irrelevant."""
        columns = ami_export._ancestry_columns(
            {"BlockDeviceMappings": []}, {}, copy_source_supported=True, lookup_failed=True
        )

        assert columns["Parent AMI (inferred)"] == "N/A"


class TestResolveSnapshotAncestry:
    @mock_aws
    def test_parses_ancestry_from_real_snapshot_descriptions(self):
        ec2_client = boto3.client("ec2", region_name=REGION)
        base = ec2_client.describe_images()["Images"][0]["ImageId"]
        instance_id = ec2_client.run_instances(
            ImageId=base, MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )["Instances"][0]["InstanceId"]
        image_id = ec2_client.create_image(
            InstanceId=instance_id, Name="built-from-instance"
        )["ImageId"]
        image = ec2_client.describe_images(ImageIds=[image_id])["Images"][0]
        snapshot_ids = [
            bdm["Ebs"]["SnapshotId"]
            for bdm in image["BlockDeviceMappings"]
            if bdm.get("Ebs", {}).get("SnapshotId")
        ]

        ancestry = ami_export._resolve_snapshot_ancestry(ec2_client, snapshot_ids)

        assert ancestry
        resolved = ancestry[snapshot_ids[0]]
        assert resolved["source_instance"] == instance_id
        assert resolved["parent_ami"] == image_id

    @mock_aws
    def test_empty_input_makes_no_api_call(self):
        class ExplodingClient:
            def get_paginator(self, name):
                raise AssertionError("no API call should be made for an empty set")

        assert ami_export._resolve_snapshot_ancestry(ExplodingClient(), []) == {}

    @mock_aws
    def test_more_snapshots_than_one_chunk_all_resolve(self):
        """
        SnapshotIds bounds the request (chunked at 100) while the response pages
        independently. Handling only one of the two silently drops results —
        the shape of Issue #268.
        """
        ec2_client = boto3.client("ec2", region_name=REGION)
        volume = ec2_client.create_volume(AvailabilityZone=f"{REGION}a", Size=1)
        snapshot_ids = []
        for index in range(150):
            snapshot = ec2_client.create_snapshot(
                VolumeId=volume["VolumeId"],
                Description=(
                    f"Created by CreateImage(i-{index:017x}) for ami-{index:017x}"
                ),
            )
            snapshot_ids.append(snapshot["SnapshotId"])

        ancestry = ami_export._resolve_snapshot_ancestry(ec2_client, snapshot_ids)

        assert len(ancestry) == 150, (
            f"resolved {len(ancestry)} of 150 — snapshots past the first chunk "
            "or response page were dropped"
        )


class TestAncestryInRegionScan:
    @mock_aws
    def test_region_scan_populates_ancestry_columns(self):
        ec2_client = boto3.client("ec2", region_name=REGION)
        base = ec2_client.describe_images()["Images"][0]["ImageId"]
        instance_id = ec2_client.run_instances(
            ImageId=base, MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )["Instances"][0]["InstanceId"]
        ec2_client.create_image(InstanceId=instance_id, Name="built-from-instance")

        rows = ami_export.collect_amis_in_region(REGION, "123456789012")

        row = next(r for r in rows if r["AMI Name"] == "built-from-instance")
        assert row["Source Instance ID"] == instance_id
        assert row["Parent AMI (inferred)"].startswith("ami-")

    @mock_aws
    def test_ancestry_failure_does_not_fail_the_region(self, monkeypatch):
        """
        Ancestry is enrichment. A snapshot-lookup failure must not discard AMIs
        that were collected successfully.
        """
        ec2_client = boto3.client("ec2", region_name=REGION)
        base = ec2_client.describe_images()["Images"][0]["ImageId"]
        instance_id = ec2_client.run_instances(
            ImageId=base, MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )["Instances"][0]["InstanceId"]
        ec2_client.create_image(InstanceId=instance_id, Name="built-from-instance")

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeSnapshots",
            )

        monkeypatch.setattr(ami_export, "_resolve_snapshot_ancestry", boom)

        rows = ami_export.collect_amis_in_region(REGION, "123456789012")

        row = next(r for r in rows if r["AMI Name"] == "built-from-instance")
        assert row["Parent AMI (inferred)"] == "Unresolved (snapshot lookup failed)"
        assert row["Source Instance ID"] == instance_id, "contractual field still reported"
