"""Security Group Analysis - checks for exposed SSH, RDP, and arbitrary ports."""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# CIDR ranges that represent unrestricted public access
_PUBLIC_IPV4_CIDR = "0.0.0.0/0"
_PUBLIC_IPV6_CIDR = "::/0"


def analyze_security_groups(security_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze a list of security groups for dangerous inbound exposures.

    Runs SSH (port 22) and RDP (port 3389) checks against each security group
    and produces a list of finding dicts for any that are publicly exposed.

    Args:
        security_groups: List of security group dicts as returned by
                         ec2.discover_security_groups(). Each must have at
                         minimum: group_id, group_name, region, vpc_id,
                         inbound_rules.

    Returns:
        List of finding dicts. Each finding contains:
            finding_type, severity, group_id, group_name, region, vpc_id,
            port, protocol_name, evidence.
    """
    findings: list[dict[str, Any]] = []

    for sg in security_groups:
        group_id = sg.get("group_id", "unknown")
        group_name = sg.get("group_name", "unknown")
        region = sg.get("region", "unknown")
        vpc_id = sg.get("vpc_id", "")

        # Check SSH exposure (port 22)
        ssh_exposed, ssh_evidence = check_ssh_exposure(sg)
        if ssh_exposed:
            findings.append({
                "finding_type": "SECURITY_GROUP_SSH_OPEN",
                "severity": "HIGH",
                "group_id": group_id,
                "group_name": group_name,
                "region": region,
                "vpc_id": vpc_id,
                "port": 22,
                "protocol_name": "SSH",
                "evidence": ssh_evidence,
            })
            logger.warning(
                f"Security group {group_id} ({group_name}) in {region} "
                f"has SSH (port 22) open to the internet"
            )

        # Check RDP exposure (port 3389)
        rdp_exposed, rdp_evidence = check_rdp_exposure(sg)
        if rdp_exposed:
            findings.append({
                "finding_type": "SECURITY_GROUP_RDP_OPEN",
                "severity": "HIGH",
                "group_id": group_id,
                "group_name": group_name,
                "region": region,
                "vpc_id": vpc_id,
                "port": 3389,
                "protocol_name": "RDP",
                "evidence": rdp_evidence,
            })
            logger.warning(
                f"Security group {group_id} ({group_name}) in {region} "
                f"has RDP (port 3389) open to the internet"
            )

    logger.info(
        f"Security group analysis complete: {len(findings)} findings "
        f"from {len(security_groups)} security groups"
    )
    return findings


def check_ssh_exposure(sg: dict[str, Any]) -> tuple[bool, list[str]]:
    """Check if a security group exposes SSH (port 22) to the public internet.

    Args:
        sg: Security group dict with 'inbound_rules' list.

    Returns:
        Tuple of (is_exposed, evidence).
        is_exposed: True if port 22 is reachable from 0.0.0.0/0 or ::/0.
        evidence: List of human-readable evidence strings.
    """
    return check_port_exposure(sg, port=22, port_name="SSH")


def check_rdp_exposure(sg: dict[str, Any]) -> tuple[bool, list[str]]:
    """Check if a security group exposes RDP (port 3389) to the public internet.

    Args:
        sg: Security group dict with 'inbound_rules' list.

    Returns:
        Tuple of (is_exposed, evidence).
        is_exposed: True if port 3389 is reachable from 0.0.0.0/0 or ::/0.
        evidence: List of human-readable evidence strings.
    """
    return check_port_exposure(sg, port=3389, port_name="RDP")


def check_port_exposure(
    sg: dict[str, Any], port: int, port_name: str
) -> tuple[bool, list[str]]:
    """Check if a security group exposes a specific port to the public internet.

    Inspects all inbound rules for rules that:
      - Have protocol 'tcp' or '-1' (all traffic)
      - Have a port range that includes the target port
      - Have a CIDR of 0.0.0.0/0 (IPv4) or ::/0 (IPv6)

    Args:
        sg: Security group dict with 'inbound_rules' list. Each rule should
            have: protocol, from_port, to_port, cidr_ranges, ipv6_ranges.
        port: The port number to check (e.g., 22 for SSH, 3389 for RDP).
        port_name: Human-readable name for the port (e.g., 'SSH', 'RDP').

    Returns:
        Tuple of (is_exposed, evidence).
        is_exposed: True if the port is reachable from any public CIDR.
        evidence: List of human-readable strings describing each exposure.
    """
    is_exposed = False
    evidence: list[str] = []
    group_id = sg.get("group_id", "unknown")

    inbound_rules = sg.get("inbound_rules", [])

    for rule in inbound_rules:
        protocol = rule.get("protocol", "")
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        cidr_ranges = rule.get("cidr_ranges", [])
        ipv6_ranges = rule.get("ipv6_ranges", [])

        # Check if the protocol allows the target port
        # Protocol '-1' means all traffic (all ports, all protocols)
        # Protocol 'tcp' with matching port range
        protocol_matches = protocol == "-1" or (
            protocol.lower() == "tcp" and from_port <= port <= to_port
        )

        if not protocol_matches:
            continue

        # Check IPv4 CIDRs for public access
        for cidr in cidr_ranges:
            if cidr == _PUBLIC_IPV4_CIDR:
                is_exposed = True
                evidence.append(
                    f"Inbound rule in {group_id} allows {port_name} (port {port}) "
                    f"from {_PUBLIC_IPV4_CIDR} via protocol {protocol} "
                    f"(ports {from_port}-{to_port})"
                )

        # Check IPv6 CIDRs for public access
        for cidr in ipv6_ranges:
            if cidr == _PUBLIC_IPV6_CIDR:
                is_exposed = True
                evidence.append(
                    f"Inbound rule in {group_id} allows {port_name} (port {port}) "
                    f"from {_PUBLIC_IPV6_CIDR} via protocol {protocol} "
                    f"(ports {from_port}-{to_port})"
                )

    return is_exposed, evidence
