"""CIS Check: EC2 Public Instance Exposure - detects running instances with public IPs and exposed management ports."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-EC2-001"
CHECK_NAME = "EC2 Public Instance Exposure"
DESCRIPTION = (
    "Ensure no running EC2 instances with public IP addresses have security groups "
    "that expose management ports (SSH/22, RDP/3389) to the internet"
)
CATEGORY = "Compute"
REMEDIATION = (
    "Remove public IP associations from EC2 instances that do not require them. "
    "Restrict security group rules to limit SSH (port 22) and RDP (port 3389) access "
    "to specific trusted IP ranges. Use AWS Systems Manager Session Manager for "
    "secure remote access without exposing management ports."
)

# Management ports to check for public exposure
MANAGEMENT_PORTS = {22: "SSH", 3389: "RDP"}

# CIDR blocks that represent public/unrestricted access
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _get_exposed_ports(sg_rules: list[dict]) -> list[dict]:
    """Find management ports exposed to the internet in a set of security group rules.

    Args:
        sg_rules: List of inbound rule dicts with protocol, from_port, to_port,
                  cidr_ranges, and ipv6_ranges fields.

    Returns:
        List of dicts describing each exposed management port.
    """
    exposed: list[dict] = []

    for rule in sg_rules:
        protocol = str(rule.get("protocol", "")).lower()

        # Only check TCP or all-traffic rules
        if protocol not in ("tcp", "-1", "6"):
            continue

        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)

        # Collect all public CIDR sources from this rule
        public_sources: list[str] = []
        for cidr in rule.get("cidr_ranges", []):
            if cidr in PUBLIC_CIDRS:
                public_sources.append(cidr)
        for cidr in rule.get("ipv6_ranges", []):
            if cidr in PUBLIC_CIDRS:
                public_sources.append(cidr)

        if not public_sources:
            continue

        # Check each management port
        for port, service in MANAGEMENT_PORTS.items():
            if protocol == "-1" or (from_port <= port <= to_port):
                exposed.append({
                    "port": port,
                    "service": service,
                    "protocol": protocol,
                    "public_sources": public_sources,
                })

    return exposed


def _build_sg_lookup(security_groups: list[dict]) -> dict[str, dict]:
    """Build a lookup dictionary from security group ID to security group data.

    Args:
        security_groups: List of security group dicts.

    Returns:
        Dict mapping group_id to the full security group dict.
    """
    lookup: dict[str, dict] = {}
    for sg in security_groups:
        group_id = sg.get("group_id", "")
        if group_id:
            lookup[group_id] = sg
    return lookup


def run_check(instances: list[dict], security_groups: list[dict]) -> CheckResult:
    """Check for running EC2 instances with public IPs and exposed management ports.

    An instance is flagged only if it is:
    1. In a 'running' state
    2. Has a public IP address
    3. Has at least one security group that exposes management ports (22, 3389)
       to 0.0.0.0/0 or ::/0

    Args:
        instances: List of EC2 instance dicts, each containing:
            - instance_id (str)
            - state (str): e.g. "running", "stopped"
            - public_ip (str | None)
            - security_group_ids (list[str])
        security_groups: List of security group dicts for cross-referencing.

    Returns:
        CheckResult with PASS if no exposed instances found, FAIL if any are exposed,
        ERROR if no data is available.
    """
    if not instances and not security_groups:
        logger.warning("No EC2 instances or security groups provided for exposure check")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.ERROR.value,
            evidence=[
                {"message": "No EC2 instances or security groups data available"}
            ],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    # If no instances exist, that's a pass (no exposure possible)
    if not instances:
        logger.info("EC2 exposure check PASSED: no EC2 instances found")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.PASS.value,
            evidence=[{"message": "No EC2 instances found in the account"}],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    sg_lookup = _build_sg_lookup(security_groups)
    exposed_instances: list[dict] = []
    affected_resources: list[str] = []

    for instance in instances:
        instance_id = instance.get("instance_id", "unknown")
        state = instance.get("state", "unknown")
        public_ip = instance.get("public_ip")
        sg_ids = instance.get("security_group_ids", [])

        # Only check running instances with public IPs
        if state != "running" or not public_ip:
            continue

        # Check each security group attached to this instance
        all_exposed_ports: list[dict] = []
        exposed_sg_ids: list[str] = []

        for sg_id in sg_ids:
            sg = sg_lookup.get(sg_id)
            if not sg:
                logger.debug(
                    "Security group %s for instance %s not found in lookup",
                    sg_id,
                    instance_id,
                )
                continue

            inbound_rules = sg.get("inbound_rules", [])
            ports = _get_exposed_ports(inbound_rules)
            if ports:
                all_exposed_ports.extend(ports)
                exposed_sg_ids.append(sg_id)

        if all_exposed_ports:
            # Deduplicate exposed ports by port number
            seen_ports: set[int] = set()
            unique_exposed: list[dict] = []
            for port_info in all_exposed_ports:
                if port_info["port"] not in seen_ports:
                    seen_ports.add(port_info["port"])
                    unique_exposed.append(port_info)

            exposed_instances.append({
                "instance_id": instance_id,
                "public_ip": public_ip,
                "state": state,
                "exposed_ports": unique_exposed,
                "exposed_security_group_ids": exposed_sg_ids,
                "instance_name": instance.get("name", ""),
            })
            affected_resources.append(instance_id)
            logger.warning(
                "EC2 instance %s (%s) is publicly exposed on management ports: %s",
                instance_id,
                public_ip,
                ", ".join(
                    f"{p['service']}/{p['port']}" for p in unique_exposed
                ),
            )

    if exposed_instances:
        logger.info(
            "EC2 exposure check FAILED: %d instance(s) publicly exposed on management ports",
            len(exposed_instances),
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.FAIL.value,
            evidence=exposed_instances,
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=affected_resources,
        )

    running_with_public = sum(
        1
        for i in instances
        if i.get("state") == "running" and i.get("public_ip")
    )
    logger.info(
        "EC2 exposure check PASSED: no running instances with public IPs expose "
        "management ports (%d instances checked, %d with public IPs)",
        len(instances),
        running_with_public,
    )
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.HIGH.value,
        status=CheckStatus.PASS.value,
        evidence=[
            {
                "message": (
                    "No running EC2 instances with public IPs expose management ports"
                ),
                "total_instances": len(instances),
                "instances_with_public_ip": running_with_public,
            }
        ],
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=[],
    )
