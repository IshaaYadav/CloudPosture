"""CIS Check: S3 Default Encryption - ensures all S3 buckets have default encryption enabled."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-S3-002"
CHECK_NAME = "S3 Default Encryption"
DESCRIPTION = "Ensure all S3 buckets have default encryption enabled"
CATEGORY = "Storage"
REMEDIATION = (
    "Enable default encryption on all S3 buckets using either SSE-S3 (AES-256) or SSE-KMS. "
    "Use the PutBucketEncryption API or the AWS Console to configure default encryption. "
    "Use AWS Config rule 's3-bucket-server-side-encryption-enabled' for ongoing monitoring."
)


def run_check(buckets: list[dict]) -> CheckResult:
    """Check all discovered S3 buckets for default encryption.

    Args:
        buckets: List of bucket dicts from S3 discovery. Each dict should contain
                 at minimum 'name' and 'encryption_enabled' fields.

    Returns:
        CheckResult with PASS if all buckets have encryption enabled,
        FAIL if any bucket lacks encryption, ERROR if no buckets found.
    """
    if not buckets:
        logger.warning("No S3 buckets provided for encryption check")
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.ERROR.value,
            evidence=[{"message": "No S3 buckets found or bucket data unavailable"}],
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=[],
        )

    unencrypted_buckets: list[dict] = []
    affected_resources: list[str] = []

    for bucket in buckets:
        bucket_name = bucket.get("name", "unknown")
        encryption_enabled = bucket.get("encryption_enabled", False)
        encryption_type = bucket.get("encryption_type", None)

        if not encryption_enabled:
            evidence_entry = {
                "bucket_name": bucket_name,
                "encryption_enabled": False,
                "encryption_type": encryption_type or "None",
            }
            unencrypted_buckets.append(evidence_entry)
            affected_resources.append(bucket_name)
            logger.warning(
                "S3 bucket without default encryption: %s", bucket_name
            )

    if unencrypted_buckets:
        logger.info(
            "S3 encryption check FAILED: %d/%d buckets lack default encryption",
            len(unencrypted_buckets),
            len(buckets),
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.FAIL.value,
            evidence=unencrypted_buckets,
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=affected_resources,
        )

    logger.info(
        "S3 encryption check PASSED: all %d buckets have default encryption",
        len(buckets),
    )
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.HIGH.value,
        status=CheckStatus.PASS.value,
        evidence=[
            {
                "message": f"All {len(buckets)} S3 buckets have default encryption enabled",
                "total_buckets": len(buckets),
            }
        ],
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=[],
    )
