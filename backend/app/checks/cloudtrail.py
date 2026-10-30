"""CIS Check: CloudTrail Multi-Region Logging - ensures CloudTrail is enabled and logging."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-LOG-001"
CHECK_NAME = "CloudTrail Multi-Region Logging"
DESCRIPTION = "Ensure CloudTrail is enabled in all regions with multi-region logging"
CATEGORY = "Logging"
REMEDIATION = (
    "Create a CloudTrail trail with multi-region logging enabled. "
    "Ensure the trail is actively logging to an S3 bucket. "
    "Enable log file validation for integrity verification. "
    "See AWS documentation: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
)


def run_check(trails: list[dict] | None) -> CheckResult:
    """Check whether CloudTrail multi-region logging is enabled.

    Args:
        trails: List of trail dicts from cloudtrail.get_trails(), each containing:
            - trail_name (str): Name of the trail
            - is_multi_region (bool): Whether the trail covers all regions
            - is_logging (bool): Whether the trail is actively logging
            - home_region (str): The home region of the trail
            - s3_bucket_name (str): The S3 bucket for log storage
            None if CloudTrail data couldn't be accessed.

    Returns:
        CheckResult with PASS if at least one trail is multi-region and logging,
        FAIL if no qualifying trail exists, ERROR if data is unavailable.
    """
    # None means we couldn't access CloudTrail at all
    if trails is None:
        logger.error("CloudTrail data unavailable (trails is None)")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.ERROR.value,
            evidence=[
                {
                    "message": "Unable to access CloudTrail data. "
                    "Check IAM permissions for cloudtrail:DescribeTrails "
                    "and cloudtrail:GetTrailStatus."
                }
            ],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    # No trails exist at all
    if not trails:
        logger.warning("No CloudTrail trails found in the account")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.FAIL.value,
            evidence=[
                {"message": "No CloudTrail trails found in the account"}
            ],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=["cloudtrail"],
        )

    # Evaluate each trail
    compliant_trails: list[dict] = []
    non_compliant_trails: list[dict] = []

    for trail in trails:
        trail_name = trail.get("trail_name", "unknown")
        is_multi_region = trail.get("is_multi_region", False)
        is_logging = trail.get("is_logging", False)
        home_region = trail.get("home_region", "unknown")
        s3_bucket = trail.get("s3_bucket_name", "unknown")

        trail_info = {
            "trail_name": trail_name,
            "is_multi_region": is_multi_region,
            "is_logging": is_logging,
            "home_region": home_region,
            "s3_bucket_name": s3_bucket,
        }

        if is_multi_region and is_logging:
            compliant_trails.append(trail_info)
            logger.info(
                "Compliant CloudTrail trail found: %s (multi-region, logging)",
                trail_name,
            )
        else:
            reasons: list[str] = []
            if not is_multi_region:
                reasons.append("not multi-region")
            if not is_logging:
                reasons.append("not actively logging")
            trail_info["issues"] = reasons
            non_compliant_trails.append(trail_info)
            logger.warning(
                "Non-compliant CloudTrail trail: %s - %s",
                trail_name,
                ", ".join(reasons),
            )

    if compliant_trails:
        logger.info(
            "CloudTrail check PASSED: %d compliant trail(s) found",
            len(compliant_trails),
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.PASS.value,
            evidence=compliant_trails + non_compliant_trails,
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    # No compliant trails found
    affected = [t.get("trail_name", "unknown") for t in non_compliant_trails]
    logger.warning(
        "CloudTrail check FAILED: no multi-region logging trail found among %d trail(s)",
        len(trails),
    )
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.HIGH.value,
        status=CheckStatus.FAIL.value,
        evidence=non_compliant_trails,
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=affected,
    )
