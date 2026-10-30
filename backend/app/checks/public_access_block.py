"""CIS Check: S3 Public Access Block Configuration - ensures all 4 block settings are enabled."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-S3-003"
CHECK_NAME = "S3 Public Access Block Configuration"
DESCRIPTION = (
    "Ensure all S3 buckets have all four Public Access Block settings enabled: "
    "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets"
)
CATEGORY = "Storage"
REMEDIATION = (
    "Enable all four S3 Public Access Block settings on each bucket: "
    "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets. "
    "Use the PutPublicAccessBlock API or the AWS Console to configure these settings. "
    "Consider also enabling the account-level Public Access Block."
)

# The four settings that must all be True
REQUIRED_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def run_check(buckets: list[dict]) -> CheckResult:
    """Check all S3 buckets for complete Public Access Block configuration.

    Args:
        buckets: List of bucket dicts from S3 discovery. Each dict should contain
                 'name' and 'public_access_block' (dict with the 4 boolean settings).

    Returns:
        CheckResult with PASS if all buckets have all 4 settings True,
        FAIL if any bucket is missing any setting, ERROR if no buckets provided.
    """
    if not buckets:
        logger.warning("No S3 buckets provided for public access block check")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.MEDIUM.value,
            status=CheckStatus.ERROR.value,
            evidence=[{"message": "No S3 buckets found or bucket data unavailable"}],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    non_compliant_buckets: list[dict] = []
    affected_resources: list[str] = []

    for bucket in buckets:
        bucket_name = bucket.get("name", "unknown")
        public_access_block = bucket.get("public_access_block")

        # If no public access block configuration exists at all
        if public_access_block is None or not isinstance(public_access_block, dict):
            non_compliant_buckets.append({
                "bucket_name": bucket_name,
                "public_access_block_configured": False,
                "missing_settings": REQUIRED_SETTINGS.copy(),
                "current_settings": None,
            })
            affected_resources.append(bucket_name)
            logger.warning(
                "S3 bucket %s has no Public Access Block configuration", bucket_name
            )
            continue

        # Check each of the 4 required settings
        missing_settings: list[str] = []
        false_settings: list[str] = []
        current_settings: dict[str, bool] = {}

        for setting in REQUIRED_SETTINGS:
            value = public_access_block.get(setting, False)
            current_settings[setting] = bool(value)
            if not value:
                if setting in public_access_block:
                    false_settings.append(setting)
                else:
                    missing_settings.append(setting)

        all_disabled = missing_settings + false_settings
        if all_disabled:
            evidence_entry: dict = {
                "bucket_name": bucket_name,
                "public_access_block_configured": True,
                "current_settings": current_settings,
            }
            if missing_settings:
                evidence_entry["missing_settings"] = missing_settings
            if false_settings:
                evidence_entry["disabled_settings"] = false_settings
            non_compliant_buckets.append(evidence_entry)
            affected_resources.append(bucket_name)
            logger.warning(
                "S3 bucket %s has incomplete Public Access Block: missing/disabled=%s",
                bucket_name,
                ", ".join(all_disabled),
            )

    if non_compliant_buckets:
        logger.info(
            "S3 Public Access Block check FAILED: %d/%d buckets non-compliant",
            len(non_compliant_buckets),
            len(buckets),
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.MEDIUM.value,
            status=CheckStatus.FAIL.value,
            evidence=non_compliant_buckets,
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=affected_resources,
        )

    logger.info(
        "S3 Public Access Block check PASSED: all %d buckets have full configuration",
        len(buckets),
    )
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.MEDIUM.value,
        status=CheckStatus.PASS.value,
        evidence=[
            {
                "message": (
                    f"All {len(buckets)} S3 buckets have all 4 Public Access Block "
                    "settings enabled"
                ),
                "total_buckets": len(buckets),
            }
        ],
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=[],
    )
