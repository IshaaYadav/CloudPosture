"""CIS Check: RDP Public Exposure - ensures no security groups expose RDP (port 3389) to the internet."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-NET-002"
CHECK_NAME = "RDP Public Exposure"
DESCRIPTION = "Ensure no security groups allow unrestricted RDP access (port 3389) from the internet"
CATEGORY = "Network"
REMEDIATION = (
    "Restrict RDP access in security groups to specific trusted IP ranges. "
    "Remove rules that allow 0.0.0.0/0 or ::/0 on port 3389. "
    "Use AWS Systems Manager Session Manager or a VPN for remote desktop access. "
    "Use AWS Config rule 'restricted-common-ports' for ongoing monitoring."
)

# CIDR blocks that represent public/unrestricted access
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_rdp_exposed(rule: dict) -> bool:
    """Determine if a single security group inbound rule exposes RDP publicly.

    A rule exposes RDP if:
    - Protocol is TCP (or -1 meaning all traffic)
    - Port range includes port 3389
    - Source CIDR is 0.0.0.0/0 or ::/0

    Args:
        rule: Security group rule dict with protocol, from_port, to_port,
              cidr_ranges, and ipv6_ranges fields.

    Returns:
        True if the rule exposes RDP publicly.
    """
    protocol = str(rule.get("protocol", "")).lower()

    # Protocol -1 means all traffic
    if protocol not in ("tcp", "-1", "6"):
        return False

    from_port = rule.get("from_port", 0)
    to_port = rule.get("to_port", 0)

    # For protocol -1, all ports are included
    if protocol in ("-1",):
        port_match = True
    else:
        # Check if port 3389 falls within the port range
        port_match = from_port <= 3389 <= to_port

    if not port_match:
        return False

    # Check IPv4 CIDR ranges
    cidr_ranges = rule.get("cidr_ranges", [])
    for cidr in cidr_ranges:
        if cidr in PUBLIC_CIDRS:
            return True

    # Check IPv6 CIDR ranges
    ipv6_ranges = rule.get("ipv6_ranges", [])
    for cidr in ipv6_ranges:
        if cidr in PUBLIC_CIDRS:
            return True

    return False


def run_check(security_groups: list[dict]) -> CheckResult:
    """Check all security groups for public RDP exposure.

    Args:
        security_groups: List of security group dicts, each containing:
            - group_id (str): The security group ID
            - group_name (str): The security group name
            - inbound_rules (list[dict]): List of inbound rule dicts with
              protocol, from_port, to_port, cidr_ranges, ipv6_ranges fields

    Returns:
        CheckResult with PASS if no SGs expose RDP publicly, FAIL if any do,
        ERROR if no security groups provided.
    """
    if not security_groups:
        logger.warning("No security groups provided for RDP exposure check")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.ERROR.value,
            evidence=[{"message": "No security groups found or data unavailable"}],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    exposed_groups: list[dict] = []
    affected_resources: list[str] = []

    for sg in security_groups:
        group_id = sg.get("group_id", "unknown")
        group_name = sg.get("group_name", "unknown")
        inbound_rules = sg.get("inbound_rules", [])

        exposed_rules: list[dict] = []
        for rule in inbound_rules:
            if _is_rdp_exposed(rule):
                exposed_rules.append({
                    "protocol": rule.get("protocol", "tcp"),
                    "from_port": rule.get("from_port", 0),
                    "to_port": rule.get("to_port", 0),
                    "cidr_ranges": rule.get("cidr_ranges", []),
                    "ipv6_ranges": rule.get("ipv6_ranges", []),
                })

        if exposed_rules:
            exposed_groups.append({
                "group_id": group_id,
                "group_name": group_name,
                "exposed_port": 3389,
                "service": "RDP",
                "exposed_rules": exposed_rules,
            })
            affected_resources.append(group_id)
            logger.warning(
                "Security group %s (%s) exposes RDP (port 3389) to the internet",
                group_id,
                group_name,
            )

    if exposed_groups:
        logger.info(
            "RDP exposure check FAILED: %d/%d security groups expose RDP publicly",
            len(exposed_groups),
            len(security_groups),
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.FAIL.value,
            evidence=exposed_groups,
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=affected_resources,
        )

    logger.info(
        "RDP exposure check PASSED: no security groups expose RDP publicly (%d checked)",
        len(security_groups),
    )
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.HIGH.value,
        status=CheckStatus.PASS.value,
        evidence=[
            {
                "message": f"No security groups expose RDP (port 3389) publicly",
                "total_security_groups_checked": len(security_groups),
            }
        ],
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=[],
    )
