"""CIS Check: S3 Public Access - ensures no S3 buckets are publicly accessible."""

import logging
from datetime import datetime, timezone

from app.checks.base import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID = "CIS-S3-001"
CHECK_NAME = "S3 Bucket Public Access"
DESCRIPTION = "Ensure no S3 buckets allow public access"
CATEGORY = "Storage"
REMEDIATION = (
    "Enable S3 Block Public Access settings on all buckets. "
    "Review and restrict bucket policies and ACLs that grant public access. "
    "Use AWS Config rule 's3-bucket-public-read-prohibited' for ongoing monitoring."
)


def run_check(buckets: list[dict]) -> CheckResult:
    """Check all discovered S3 buckets for public access.

    Args:
        buckets: List of bucket dicts from S3 discovery (each has name, is_public,
                 policy_status, acl_grants, public_access_block fields).

    Returns:
        CheckResult with PASS if all buckets are private, FAIL if any are public,
        ERROR if no buckets found or data unavailable.
    """
    if not buckets:
        logger.warning("No S3 buckets provided for public access check")
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

    public_buckets: list[dict] = []
    affected_resources: list[str] = []

    for bucket in buckets:
        bucket_name = bucket.get("name", "unknown")
        is_public = bucket.get("is_public", False)

        if is_public:
            # Build a detailed reason string based on why the bucket is public
            reasons: list[str] = []

            policy_status = bucket.get("policy_status")
            if isinstance(policy_status, dict) and policy_status.get("IsPublic", False):
                reasons.append("bucket policy allows public access")

            acl_grants = bucket.get("acl_grants", [])
            for grant in acl_grants:
                grantee = grant.get("Grantee", {})
                grantee_uri = grantee.get("URI", "")
                if "AllUsers" in grantee_uri or "AuthenticatedUsers" in grantee_uri:
                    permission = grant.get("Permission", "unknown")
                    reasons.append(
                        f"ACL grants '{permission}' to '{grantee_uri.split('/')[-1]}'"
                    )

            public_access_block = bucket.get("public_access_block")
            if public_access_block is None:
                reasons.append("no Public Access Block configuration found")
            elif isinstance(public_access_block, dict):
                missing_blocks = [
                    setting
                    for setting in [
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    ]
                    if not public_access_block.get(setting, False)
                ]
                if missing_blocks:
                    reasons.append(
                        f"Public Access Block missing/disabled: {', '.join(missing_blocks)}"
                    )

            reason = "; ".join(reasons) if reasons else "flagged as public"

            public_buckets.append(
                {
                    "bucket_name": bucket_name,
                    "is_public": True,
                    "reason": reason,
                }
            )
            affected_resources.append(bucket_name)
            logger.warning("Public S3 bucket detected: %s - %s", bucket_name, reason)

    if public_buckets:
        logger.info(
            "S3 public access check FAILED: %d/%d buckets are public",
            len(public_buckets),
            len(buckets),
        )
        return CheckResult(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            description=DESCRIPTION,
            severity=Severity.HIGH.value,
            status=CheckStatus.FAIL.value,
            evidence=public_buckets,
            remediation=REMEDIATION,
            category=CATEGORY,
            affected_resources=affected_resources,
        )

    logger.info("S3 public access check PASSED: all %d buckets are private", len(buckets))
    return CheckResult(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        description=DESCRIPTION,
        severity=Severity.HIGH.value,
        status=CheckStatus.PASS.value,
        evidence=[
            {
                "message": f"All {len(buckets)} S3 buckets are private",
                "total_buckets": len(buckets),
            }
        ],
        remediation=REMEDIATION,
        category=CATEGORY,
        affected_resources=[],
    )
