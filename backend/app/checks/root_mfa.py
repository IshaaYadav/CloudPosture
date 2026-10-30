"""CIS Check: Root Account MFA - ensures MFA is enabled on the root AWS account."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-IAM-001"
CHECK_NAME = "Root Account MFA"
DESCRIPTION = "Ensure MFA is enabled for the root AWS account"
CATEGORY = "Identity"
REMEDIATION = (
    "Enable MFA on the root account. Navigate to IAM > Security Credentials "
    "and activate a virtual or hardware MFA device for the root user. "
    "Use a hardware MFA device for maximum security. "
    "See AWS documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_add-key-or-mfa.html"
)


def run_check(root_mfa_info: dict) -> CheckResult:
    """Check whether MFA is enabled on the root AWS account.

    Args:
        root_mfa_info: Dict from iam.check_root_mfa() containing keys:
            - mfa_enabled (bool | None): Whether MFA is enabled on root
            - evidence (list[dict]): Supporting evidence details
            - account_summary_available (bool): Whether GetAccountSummary succeeded
            - credential_report_available (bool): Whether credential report was available

    Returns:
        CheckResult with PASS if MFA is enabled, FAIL if disabled,
        ERROR if the determination could not be made.
    """
    if not root_mfa_info:
        logger.warning("No root MFA info provided")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.CRITICAL.value,
            status=CheckStatus.ERROR.value,
            evidence=[{"message": "Root MFA information unavailable"}],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=["root-account"],
        )

    mfa_enabled = root_mfa_info.get("mfa_enabled")
    evidence = root_mfa_info.get("evidence", [])
    account_summary_available = root_mfa_info.get("account_summary_available", False)
    credential_report_available = root_mfa_info.get("credential_report_available", False)

    # If neither data source was available, we can't determine MFA status
    if not account_summary_available and not credential_report_available:
        logger.error(
            "Cannot determine root MFA status: neither account summary nor "
            "credential report available"
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.CRITICAL.value,
            status=CheckStatus.ERROR.value,
            evidence=[
                {
                    "message": (
                        "Cannot determine root MFA status - insufficient permissions "
                        "to access IAM account summary or credential report"
                    ),
                    "account_summary_available": False,
                    "credential_report_available": False,
                }
            ],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=["root-account"],
        )

    if mfa_enabled is True:
        logger.info("Root account MFA check PASSED: MFA is enabled")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.CRITICAL.value,
            status=CheckStatus.PASS.value,
            evidence=evidence
            if evidence
            else [{"message": "MFA is enabled on the root account"}],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    # mfa_enabled is False (or None but we had data sources)
    logger.warning("Root account MFA check FAILED: MFA is NOT enabled")
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.CRITICAL.value,
        status=CheckStatus.FAIL.value,
        evidence=evidence
        if evidence
        else [{"message": "MFA is NOT enabled on the root account"}],
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=["root-account"],
    )
