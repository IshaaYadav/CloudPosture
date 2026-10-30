"""EC2 Discovery - discovers instances, security groups, and enabled regions."""

import logging
from typing import Any

from botocore.exceptions import ClientError, NoCredentialsError

from app.aws.session import get_session_manager

logger = logging.getLogger(__name__)


def get_enabled_regions() -> list[str]:
    """Get all enabled AWS regions for the current account.

    Queries EC2 DescribeRegions with filters for regions that are either
    opted-in or do not require opt-in (standard regions).

    Returns:
        List of enabled region name strings (e.g., ['us-east-1', 'eu-west-1']).

    Raises:
        ValueError: If AWS credentials are not configured.
    """
    session_manager = get_session_manager()
    try:
        ec2_client = session_manager.get_client("ec2")
        response = ec2_client.describe_regions(
            Filters=[
                {
                    "Name": "opt-in-status",
                    "Values": ["opted-in", "opt-in-not-required"],
                }
            ]
        )
        regions = [region["RegionName"] for region in response.get("Regions", [])]
        logger.info(f"Discovered {len(regions)} enabled AWS regions")
        return regions
    except NoCredentialsError as e:
        logger.error(f"No AWS credentials found when discovering regions: {e}")
        raise ValueError("No AWS credentials found. Cannot discover regions.") from e
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]
        logger.error(f"Failed to describe regions: {error_code} - {error_msg}")
        raise


def discover_instances(regions: list[str] | None = None) -> list[dict[str, Any]]:
    """Discover all EC2 instances across the specified (or all enabled) regions.

    Uses paginators to handle accounts with large numbers of instances.
    Regions where access is denied are skipped with a warning.

    Args:
        regions: Optional list of region names to scan. If None, all enabled
                 regions are discovered automatically.

    Returns:
        List of instance dicts, each containing:
            instance_id, name, instance_type, region, state, public_ip,
            private_ip, vpc_id, subnet_id, security_group_ids,
            security_group_names.
    """
    session_manager = get_session_manager()
    if regions is None:
        regions = get_enabled_regions()

    all_instances: list[dict[str, Any]] = []

    for region in regions:
        try:
            ec2_client = session_manager.get_client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_instances")

            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        # Extract the Name tag, defaulting to "N/A"
                        name = "N/A"
                        for tag in instance.get("Tags", []):
                            if tag.get("Key") == "Name":
                                name = tag.get("Value", "N/A")
                                break

                        security_groups = instance.get("SecurityGroups", [])

                        instance_data: dict[str, Any] = {
                            "instance_id": instance["InstanceId"],
                            "name": name,
                            "instance_type": instance.get("InstanceType", "unknown"),
                            "region": region,
                            "state": instance.get("State", {}).get("Name", "unknown"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "private_ip": instance.get("PrivateIpAddress"),
                            "vpc_id": instance.get("VpcId"),
                            "subnet_id": instance.get("SubnetId"),
                            "security_group_ids": [
                                sg.get("GroupId", "") for sg in security_groups
                            ],
                            "security_group_names": [
                                sg.get("GroupName", "") for sg in security_groups
                            ],
                        }
                        all_instances.append(instance_data)

            logger.info(f"Region {region}: discovered instances successfully")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("UnauthorizedOperation", "AccessDenied", "AuthFailure"):
                logger.warning(
                    f"Access denied for EC2 instances in region {region}: "
                    f"{e.response['Error']['Message']}. Skipping region."
                )
                continue
            logger.error(
                f"ClientError discovering EC2 instances in {region}: "
                f"{error_code} - {e.response['Error']['Message']}"
            )
            raise
        except NoCredentialsError as e:
            logger.error(f"No AWS credentials found: {e}")
            raise ValueError("No AWS credentials found. Cannot discover EC2 instances.") from e

    logger.info(f"Total EC2 instances discovered across {len(regions)} regions: {len(all_instances)}")
    return all_instances


def discover_security_groups(regions: list[str] | None = None) -> list[dict[str, Any]]:
    """Discover all EC2 security groups across the specified (or all enabled) regions.

    Uses paginators to handle accounts with large numbers of security groups.
    Regions where access is denied are skipped with a warning.

    Args:
        regions: Optional list of region names to scan. If None, all enabled
                 regions are discovered automatically.

    Returns:
        List of security group dicts, each containing:
            group_id, group_name, description, vpc_id, region,
            inbound_rules, outbound_rules.
    """
    session_manager = get_session_manager()
    if regions is None:
        regions = get_enabled_regions()

    all_security_groups: list[dict[str, Any]] = []

    for region in regions:
        try:
            ec2_client = session_manager.get_client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_data: dict[str, Any] = {
                        "group_id": sg["GroupId"],
                        "group_name": sg.get("GroupName", ""),
                        "description": sg.get("Description", ""),
                        "vpc_id": sg.get("VpcId", ""),
                        "region": region,
                        "inbound_rules": _parse_ip_permissions(sg.get("IpPermissions", [])),
                        "outbound_rules": _parse_ip_permissions(sg.get("IpPermissionsEgress", [])),
                    }
                    all_security_groups.append(sg_data)

            logger.info(f"Region {region}: discovered security groups successfully")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("UnauthorizedOperation", "AccessDenied", "AuthFailure"):
                logger.warning(
                    f"Access denied for security groups in region {region}: "
                    f"{e.response['Error']['Message']}. Skipping region."
                )
                continue
            logger.error(
                f"ClientError discovering security groups in {region}: "
                f"{error_code} - {e.response['Error']['Message']}"
            )
            raise
        except NoCredentialsError as e:
            logger.error(f"No AWS credentials found: {e}")
            raise ValueError(
                "No AWS credentials found. Cannot discover security groups."
            ) from e

    logger.info(
        f"Total security groups discovered across {len(regions)} regions: "
        f"{len(all_security_groups)}"
    )
    return all_security_groups


def _parse_ip_permissions(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse AWS IpPermissions (inbound or outbound) into a normalized format.

    Handles the case where FromPort/ToPort may be absent (e.g., protocol '-1'
    which means all traffic).

    Args:
        permissions: List of IpPermission dicts from the AWS API response.

    Returns:
        List of normalized rule dicts with: protocol, from_port, to_port,
        cidr_ranges, ipv6_ranges, description.
    """
    parsed_rules: list[dict[str, Any]] = []

    for perm in permissions:
        protocol = perm.get("IpProtocol", "-1")

        # For protocol -1 (all traffic), ports are not present in the response
        if protocol == "-1":
            from_port = 0
            to_port = 65535
        else:
            from_port = perm.get("FromPort", 0)
            to_port = perm.get("ToPort", 0)

        cidr_ranges = [ip_range["CidrIp"] for ip_range in perm.get("IpRanges", [])]
        ipv6_ranges = [
            ip_range["CidrIpv6"] for ip_range in perm.get("Ipv6Ranges", [])
        ]

        # Collect descriptions from IP ranges
        descriptions: list[str] = []
        for ip_range in perm.get("IpRanges", []):
            if "Description" in ip_range:
                descriptions.append(ip_range["Description"])
        for ip_range in perm.get("Ipv6Ranges", []):
            if "Description" in ip_range:
                descriptions.append(ip_range["Description"])

        description = "; ".join(descriptions) if descriptions else ""

        rule: dict[str, Any] = {
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "cidr_ranges": cidr_ranges,
            "ipv6_ranges": ipv6_ranges,
            "description": description,
        }
        parsed_rules.append(rule)

    return parsed_rules
