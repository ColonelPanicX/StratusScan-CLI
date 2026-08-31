#!/usr/bin/env python3
"""
Moto-based tests for autoscaling_export.py.

Focus: the silent-collection-failure contract (Tier-2, see
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md) and the
launch-source coverage gap (Issues #257 / #258, see
.collab/audit/08.31.2026-autoscaling-exporter-coverage-gap.md).
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import autoscaling_export  # noqa: E402
from autoscaling_export import _scan_asgs_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_asg(client, name):
    """Create a launch configuration + Auto Scaling Group named ``name``."""
    client.create_launch_configuration(
        LaunchConfigurationName=f"{name}-lc",
        ImageId="ami-12345678",
        InstanceType="t3.micro",
    )
    client.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchConfigurationName=f"{name}-lc",
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[f"{REGION}a"],
    )


class TestScanAsgsRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_asgs(self):
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")

        rows = _scan_asgs_region(REGION)

        names = {row["ASG Name"] for row in rows}
        assert "web-asg" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("autoscaling", region_name=REGION)  # region exists, no ASGs

        rows = _scan_asgs_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One ASG that fails to process must not discard the whole region."""
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "good-asg")
        _create_asg(client, "bad-asg")

        original = autoscaling_export._build_asg_row

        def raise_for_bad(asg, region):
            if asg.get("AutoScalingGroupName") == "bad-asg":
                raise KeyError("SomeUnexpectedField")
            return original(asg, region)

        monkeypatch.setattr(autoscaling_export, "_build_asg_row", raise_for_bad)

        rows = _scan_asgs_region(REGION)

        names = {row["ASG Name"] for row in rows}
        assert "good-asg" in names, "healthy ASG was lost when a sibling failed"
        assert "bad-asg" not in names, "malformed ASG should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeAutoScalingGroups",
            )

        monkeypatch.setattr(autoscaling_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_asgs_region(REGION)

    @mock_aws
    def test_collect_autoscaling_groups_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeAutoScalingGroups",
            )

        monkeypatch.setattr(autoscaling_export, "_scan_launch_data_region", boom)

        asgs, failed_regions = autoscaling_export.collect_autoscaling_groups([REGION])

        assert asgs == []
        assert [r for r, _ in failed_regions] == [REGION]


# ---------------------------------------------------------------------------
# Launch source coverage (Issue #257)
#
# The exporter previously recorded only the *name* of a launch template or
# configuration and never fetched the object, so instance type, AMI, volumes,
# and IMDS posture were absent while the docstring claimed to cover them.
# ---------------------------------------------------------------------------


def _create_launch_template(ec2_client, name, **overrides):
    """
    Create a launch template with a realistic data block.

    The security group is created for real rather than hardcoded: newer moto
    releases validate that an ASG's launch template references an existing
    group, so a literal sg-xxxx id fails at create_auto_scaling_group time.
    """
    security_group_id = ec2_client.create_security_group(
        GroupName=f"{name}-sg", Description=f"test group for {name}"
    )["GroupId"]
    data = {
        "ImageId": "ami-0abcdef1234567890",
        "InstanceType": "m5.xlarge",
        "KeyName": "prod-key",
        "SecurityGroupIds": [security_group_id],
        "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1},
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {"VolumeSize": 50, "VolumeType": "gp3", "Encrypted": True},
            },
            {
                "DeviceName": "/dev/xvdb",
                "Ebs": {"VolumeSize": 100, "VolumeType": "gp3", "Encrypted": True},
            },
        ],
    }
    data.update(overrides)
    return ec2_client.create_launch_template(
        LaunchTemplateName=name, LaunchTemplateData=data
    )["LaunchTemplate"]


class TestLaunchConfigurationResolution:
    """Launch configurations are the majority path in long-lived estates."""

    @mock_aws
    def test_referenced_launch_configuration_is_resolved(self):
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")

        result = autoscaling_export._scan_launch_data_region(REGION)
        configs = result["launch_configurations"]

        assert len(configs) == 1
        row = configs[0]
        assert row["Launch Configuration Name"] == "web-asg-lc"
        assert row["Instance Type"] == "t3.micro"
        assert row["AMI ID"] == "ami-12345678"
        assert row["Used By ASGs"] == "web-asg"

    @mock_aws
    def test_unreferenced_launch_configuration_is_excluded(self):
        """Referenced-only: an LC no ASG uses is out of scope for this export."""
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")
        client.create_launch_configuration(
            LaunchConfigurationName="orphan-lc",
            ImageId="ami-99999999",
            InstanceType="c5.large",
        )

        result = autoscaling_export._scan_launch_data_region(REGION)

        names = {row["Launch Configuration Name"] for row in result["launch_configurations"]}
        assert names == {"web-asg-lc"}, "unreferenced LC leaked into the export"

    @mock_aws
    def test_shared_launch_configuration_lists_every_asg(self):
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")
        client.create_auto_scaling_group(
            AutoScalingGroupName="api-asg",
            LaunchConfigurationName="web-asg-lc",
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            AvailabilityZones=[f"{REGION}a"],
        )

        result = autoscaling_export._scan_launch_data_region(REGION)

        assert result["launch_configurations"][0]["Used By ASGs"] == "api-asg, web-asg"

    @mock_aws
    def test_unresolvable_launch_configurations_raise(self, monkeypatch):
        """
        Referenced configurations that all fail to resolve means a permission
        or API problem, not an empty account. It must fail loud rather than
        export an empty sheet that reads as complete.
        """
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")

        refs = {"web-asg": autoscaling_export._launch_source_ref(
            {"LaunchConfigurationName": "web-asg-lc"}
        )}

        class EmptyPaginator:
            def paginate(self, *args, **kwargs):
                return iter([{"LaunchConfigurations": []}])

        class StubClient:
            def get_paginator(self, name):
                return EmptyPaginator()

        monkeypatch.setattr(
            autoscaling_export.utils, "get_boto3_client", lambda *a, **k: StubClient()
        )

        with pytest.raises(RuntimeError, match="launch configuration"):
            autoscaling_export._collect_launch_configurations(REGION, refs)


class TestLaunchTemplateResolution:
    @mock_aws
    def test_referenced_launch_template_is_resolved(self):
        ec2_client = boto3.client("ec2", region_name=REGION)
        asg_client = boto3.client("autoscaling", region_name=REGION)
        template = _create_launch_template(ec2_client, "web-lt")
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName="web-asg",
            LaunchTemplate={
                "LaunchTemplateId": template["LaunchTemplateId"],
                "Version": "1",
            },
            MinSize=1,
            MaxSize=4,
            DesiredCapacity=2,
            AvailabilityZones=[f"{REGION}a"],
        )

        result = autoscaling_export._scan_launch_data_region(REGION)
        templates = result["launch_templates"]

        assert len(templates) == 1
        row = templates[0]
        assert row["Instance Type"] == "m5.xlarge"
        assert row["AMI ID"] == "ami-0abcdef1234567890"
        assert row["IMDSv2 Required"] == "required"
        assert row["Security Groups"].startswith("sg-")
        assert row["Root Volume Size (GiB)"] == 50
        assert row["Total EBS Size (GiB)"] == 150
        assert row["EBS Encrypted"] is True
        assert row["Used By ASGs"] == "web-asg"

    @mock_aws
    def test_default_version_alias_is_resolved_to_a_number(self):
        """
        An ASG that omits the version means $Default. The export must resolve
        that to the concrete version actually in use.
        """
        ec2_client = boto3.client("ec2", region_name=REGION)
        asg_client = boto3.client("autoscaling", region_name=REGION)
        template = _create_launch_template(ec2_client, "web-lt")
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName="web-asg",
            LaunchTemplate={"LaunchTemplateId": template["LaunchTemplateId"]},
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            AvailabilityZones=[f"{REGION}a"],
        )

        result = autoscaling_export._scan_launch_data_region(REGION)
        row = result["launch_templates"][0]

        assert row["Version In Use"] == "$Default"
        assert row["Resolved Version"] == "1"
        assert row["Instance Type"] == "m5.xlarge"

    @mock_aws
    def test_unreferenced_launch_template_is_excluded(self):
        ec2_client = boto3.client("ec2", region_name=REGION)
        asg_client = boto3.client("autoscaling", region_name=REGION)
        template = _create_launch_template(ec2_client, "web-lt")
        _create_launch_template(ec2_client, "orphan-lt")
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName="web-asg",
            LaunchTemplate={"LaunchTemplateId": template["LaunchTemplateId"], "Version": "1"},
            MinSize=0,
            MaxSize=1,
            DesiredCapacity=0,
            AvailabilityZones=[f"{REGION}a"],
        )

        result = autoscaling_export._scan_launch_data_region(REGION)

        names = {row["Launch Template Name"] for row in result["launch_templates"]}
        assert names == {"web-lt"}, "unreferenced launch template leaked into the export"


class TestCapacityEnvelope:
    """
    Capacity is an envelope, not a scalar: per-instance spec x a capacity
    range. A single number is wrong the moment the group scales.
    """

    @mock_aws
    def test_envelope_spans_min_desired_and_max(self):
        ec2_client = boto3.client("ec2", region_name=REGION)
        asg_client = boto3.client("autoscaling", region_name=REGION)
        template = _create_launch_template(ec2_client, "web-lt")
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName="web-asg",
            LaunchTemplate={"LaunchTemplateId": template["LaunchTemplateId"], "Version": "1"},
            MinSize=1,
            MaxSize=4,
            DesiredCapacity=2,
            AvailabilityZones=[f"{REGION}a"],
        )

        row = autoscaling_export._scan_launch_data_region(REGION)["asgs"][0]

        # m5.xlarge: 4 vCPU / 16 GiB, 150 GiB of EBS per instance
        assert row["Instance Type"] == "m5.xlarge"
        assert row["vCPU per Instance"] == 4
        assert row["vCPU (Min)"] == 4
        assert row["vCPU (Desired)"] == 8
        assert row["vCPU (Max)"] == 16
        assert row["Memory GiB (Desired)"] == 32
        assert row["Memory GiB (Max)"] == 64
        assert row["Storage GiB (Desired)"] == 300
        assert row["AMI ID"] == "ami-0abcdef1234567890"
        assert row["Root Volume Size (GiB)"] == 50

    @mock_aws
    def test_launch_configuration_asg_is_enriched_too(self):
        client = boto3.client("autoscaling", region_name=REGION)
        client.create_launch_configuration(
            LaunchConfigurationName="web-lc",
            ImageId="ami-12345678",
            InstanceType="c5.large",
        )
        client.create_auto_scaling_group(
            AutoScalingGroupName="web-asg",
            LaunchConfigurationName="web-lc",
            MinSize=2,
            MaxSize=6,
            DesiredCapacity=3,
            AvailabilityZones=[f"{REGION}a"],
        )

        row = autoscaling_export._scan_launch_data_region(REGION)["asgs"][0]

        # c5.large: 2 vCPU / 4 GiB
        assert row["Launch Source Type"] == "Launch Configuration"
        assert row["Instance Type"] == "c5.large"
        assert row["vCPU (Min)"] == 4
        assert row["vCPU (Desired)"] == 6
        assert row["vCPU (Max)"] == 12
        assert row["Memory GiB (Desired)"] == 12

    def test_unknown_instance_type_reports_na_not_zero(self):
        """An unresolved spec must read as 'N/A', never as a confident zero."""
        enrichment = autoscaling_export._launch_enrichment(
            {"instance_type": "made.up", "ami_id": "ami-1", "source": "Launch Template"},
            {},
            1, 2, 4,
        )

        assert enrichment["vCPU per Instance"] == "N/A"
        assert enrichment["vCPU (Desired)"] == "N/A"
        assert enrichment["Memory GiB (Max)"] == "N/A"

    def test_mixed_policy_without_single_type_reports_overrides(self):
        """
        A mixed-instances policy with no template-level type has no single
        per-instance spec; the columns must say so rather than pick one.
        """
        enrichment = autoscaling_export._launch_enrichment(
            {
                "instance_type": None,
                "overrides": ["m5.large", "m5a.large"],
                "ami_id": "ami-1",
                "source": "Launch Template",
            },
            {},
            1, 2, 4,
        )

        assert enrichment["Instance Type"] == "Mixed: m5.large, m5a.large"
        assert enrichment["vCPU (Desired)"] == "N/A"


class TestBlockDeviceSummary:
    def test_root_volume_preferred_over_first_mapping(self):
        summary = autoscaling_export._summarize_block_devices([
            {"DeviceName": "/dev/xvdb", "Ebs": {"VolumeSize": 500, "VolumeType": "st1"}},
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 30, "VolumeType": "gp3"}},
        ])

        assert summary["root_size"] == 30
        assert summary["root_type"] == "gp3"
        assert summary["total_size"] == 530

    def test_absent_mappings_report_none_not_zero(self):
        """
        A template that omits block devices inherits the AMI's. That is
        unknown, not zero, and must not be reported as a size.
        """
        summary = autoscaling_export._summarize_block_devices([])

        assert summary["root_size"] is None
        assert summary["total_size"] is None

    def test_partial_encryption_is_not_reported_as_encrypted(self):
        summary = autoscaling_export._summarize_block_devices([
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 30, "Encrypted": True}},
            {"DeviceName": "/dev/xvdb", "Ebs": {"VolumeSize": 30, "Encrypted": False}},
        ])

        assert summary["encrypted"] is False


class TestInstanceSpecResolution:
    def test_reference_data_supplies_true_vcpu_not_core_count(self):
        """
        vCPU must be the thread count. m5.xlarge is 4 vCPU / 2 physical cores;
        sourcing CoreCount would report 2 (see Issue #259).
        """
        specs = autoscaling_export._resolve_instance_specs(REGION, {"m5.xlarge"})

        assert specs["m5.xlarge"]["vcpu"] == 4
        assert specs["m5.xlarge"]["memory_gib"] == 16.0

    def test_empty_input_makes_no_api_call(self, monkeypatch):
        def boom(*args, **kwargs):
            raise AssertionError("no client should be created for an empty type set")

        monkeypatch.setattr(autoscaling_export.utils, "get_boto3_client", boom)

        assert autoscaling_export._resolve_instance_specs(REGION, set()) == {}


# ---------------------------------------------------------------------------
# Scheduled actions (Issue #258)
# ---------------------------------------------------------------------------


class TestScheduledActions:
    @mock_aws
    def test_collects_scheduled_actions(self):
        client = boto3.client("autoscaling", region_name=REGION)
        _create_asg(client, "web-asg")
        client.put_scheduled_update_group_action(
            AutoScalingGroupName="web-asg",
            ScheduledActionName="scale-up-weekday-mornings",
            Recurrence="0 13 * * MON-FRI",
            MinSize=2,
            MaxSize=10,
            DesiredCapacity=4,
        )

        rows = autoscaling_export._scan_scheduled_actions_region(REGION)

        assert len(rows) == 1
        row = rows[0]
        assert row["Action Name"] == "scale-up-weekday-mornings"
        assert row["ASG Name"] == "web-asg"
        assert row["Recurrence"] == "0 13 * * MON-FRI"
        assert row["Min Size"] == 2
        assert row["Max Size"] == 10
        assert row["Desired Capacity"] == 4

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("autoscaling", region_name=REGION)

        assert autoscaling_export._scan_scheduled_actions_region(REGION) == []

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """Same fail-loud contract as the primary ASG scope."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeScheduledActions",
            )

        monkeypatch.setattr(autoscaling_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            autoscaling_export._scan_scheduled_actions_region(REGION)


class TestMixedInstancesPolicy:
    """
    A mixed-instances policy carries its template on a different key and adds
    an override list plus a spot/on-demand split — all of which the exporter
    previously reduced to a display string.
    """

    @mock_aws
    def test_mixed_policy_template_and_distribution_are_captured(self):
        ec2_client = boto3.client("ec2", region_name=REGION)
        asg_client = boto3.client("autoscaling", region_name=REGION)
        template = _create_launch_template(ec2_client, "mix-lt", InstanceType="m5.large")
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName="mix-asg",
            MixedInstancesPolicy={
                "LaunchTemplate": {
                    "LaunchTemplateSpecification": {
                        "LaunchTemplateId": template["LaunchTemplateId"],
                        "Version": "1",
                    },
                    "Overrides": [
                        {"InstanceType": "m5.large"},
                        {"InstanceType": "m5a.large"},
                    ],
                },
                "InstancesDistribution": {
                    "OnDemandBaseCapacity": 1,
                    "OnDemandPercentageAboveBaseCapacity": 50,
                    "SpotAllocationStrategy": "capacity-optimized",
                },
            },
            MinSize=1,
            MaxSize=4,
            DesiredCapacity=2,
            AvailabilityZones=[f"{REGION}a"],
        )

        result = autoscaling_export._scan_launch_data_region(REGION)

        row = result["launch_templates"][0]
        assert row["Instance Type Overrides"] == "m5.large, m5a.large"
        assert row["On-Demand Base Capacity"] == 1
        assert row["On-Demand % Above Base"] == 50
        assert row["Spot Allocation Strategy"] == "capacity-optimized"

        asg_row = result["asgs"][0]
        assert asg_row["Launch Source"] == "Mixed: mix-lt (1)"
        assert asg_row["Instance Type"] == "m5.large"
        assert asg_row["vCPU (Desired)"] == 4
