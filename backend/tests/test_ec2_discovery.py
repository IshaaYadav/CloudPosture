"""Tests for EC2 instance, security group, and region discovery."""

import boto3
import pytest
from app.aws.ec2 import discover_instances, discover_security_groups, get_enabled_regions


def test_get_enabled_regions(mocked_aws) -> None:
    """Test discovering enabled AWS regions."""
    regions = get_enabled_regions()
    assert isinstance(regions, list)
    assert len(regions) > 0
    assert "ap-southeast-2" in regions or "us-east-1" in regions


def test_discover_instances_empty(mocked_aws) -> None:
    """Test discovering instances when none exist."""
    instances = discover_instances(["ap-southeast-2"])
    assert isinstance(instances, list)
    assert len(instances) == 0


def test_discover_instances_with_resources(mocked_aws) -> None:
    """Test discovering EC2 instances created in mock."""
    ec2 = boto3.client("ec2", region_name="ap-southeast-2")
    # Launch mock instance
    resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "TestServer"}],
            }
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    instances = discover_instances(["ap-southeast-2"])
    assert len(instances) >= 1
    found = [i for i in instances if i["instance_id"] == instance_id]
    assert len(found) == 1
    assert found[0]["name"] == "TestServer"
    assert found[0]["state"] == "running"


def test_discover_security_groups(mocked_aws) -> None:
    """Test discovering security groups."""
    ec2 = boto3.client("ec2", region_name="ap-southeast-2")
    resp = ec2.create_security_group(
        GroupName="web-sg",
        Description="Web security group",
    )
    group_id = resp["GroupId"]

    sgs = discover_security_groups(["ap-southeast-2"])
    assert len(sgs) >= 1
    found = [sg for sg in sgs if sg["group_id"] == group_id]
    assert len(found) == 1
    assert found[0]["group_name"] == "web-sg"

