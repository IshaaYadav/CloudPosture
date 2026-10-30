"""S3 Discovery - discovers buckets and their security configurations."""

import logging
from typing import Any

from botocore.exceptions import ClientError, NoCredentialsError

from app.aws.session import get_session_manager

logger = logging.getLogger(__name__)

# URIs that indicate public access in S3 ACLs
_PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def discover_buckets() -> list[dict[str, Any]]:
    """Discover all S3 buckets and their security configurations.

    For each bucket, individually queries:
      - GetBucketLocation (region)
      - GetBucketEncryption (encryption settings)
      - GetPublicAccessBlock (public access block configuration)
      - GetBucketPolicyStatus (policy publicity)
      - GetBucketAcl (ACL grants and public URI detection)
      - GetBucketVersioning (versioning status)

    Each sub-query is wrapped in its own try/except so a failure on one
    attribute does not prevent collection of the others.

    Returns:
        List of bucket dicts, each containing:
            name, region, encryption_enabled, encryption_type,
            public_access_block, is_public, versioning_enabled,
            policy_status, acl_grants.
    """
    session_manager = get_session_manager()
    try:
        s3_client = session_manager.get_client("s3")
    except (NoCredentialsError, ValueError) as e:
        logger.error(f"Cannot create S3 client: {e}")
        raise

    try:
        response = s3_client.list_buckets()
    except NoCredentialsError as e:
        logger.error(f"No AWS credentials when listing buckets: {e}")
        raise ValueError("No AWS credentials found. Cannot list S3 buckets.") from e
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]
        logger.error(f"Failed to list S3 buckets: {error_code} - {error_msg}")
        raise

    buckets_raw = response.get("Buckets", [])
    logger.info(f"Found {len(buckets_raw)} S3 buckets")

    all_buckets: list[dict[str, Any]] = []

    for bucket in buckets_raw:
        bucket_name = bucket["Name"]
        logger.debug(f"Inspecting bucket: {bucket_name}")

        # --- Region ---
        region = _get_bucket_region(s3_client, bucket_name)

        # --- Encryption ---
        encryption_enabled, encryption_type = _get_bucket_encryption(
            s3_client, bucket_name
        )

        # --- Public Access Block ---
        public_access_block = _get_public_access_block(s3_client, bucket_name)

        # --- Policy Status ---
        policy_status = _get_policy_status(s3_client, bucket_name)

        # --- ACL ---
        acl_grants, acl_has_public = _get_bucket_acl(s3_client, bucket_name)

        # --- Versioning ---
        versioning_enabled = _get_bucket_versioning(s3_client, bucket_name)

        # --- Determine is_public ---
        # A bucket is considered public if:
        #   (policy says public OR ACL has public grants)
        #   AND public_access_block doesn't fully block public access
        policy_is_public = policy_status.get("IsPublic", False) if policy_status else False
        block_fully_enabled = _is_public_access_fully_blocked(public_access_block)

        is_public = (policy_is_public or acl_has_public) and not block_fully_enabled

        bucket_data: dict[str, Any] = {
            "name": bucket_name,
            "region": region,
            "encryption_enabled": encryption_enabled,
            "encryption_type": encryption_type,
            "public_access_block": public_access_block,
            "is_public": is_public,
            "versioning_enabled": versioning_enabled,
            "policy_status": policy_status,
            "acl_grants": acl_grants,
        }
        all_buckets.append(bucket_data)

    logger.info(f"Completed S3 bucket discovery: {len(all_buckets)} buckets processed")
    return all_buckets


def _get_bucket_region(s3_client: Any, bucket_name: str) -> str:
    """Get the region of a bucket via GetBucketLocation.

    AWS returns None for us-east-1 (the original S3 region).

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of the S3 bucket.

    Returns:
        Region string (defaults to 'us-east-1' if LocationConstraint is None).
    """
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response.get("LocationConstraint")
        return location if location else "us-east-1"
    except ClientError as e:
        logger.warning(
            f"Could not get location for bucket '{bucket_name}': "
            f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
        )
        return "unknown"


def _get_bucket_encryption(
    s3_client: Any, bucket_name: str
) -> tuple[bool, str | None]:
    """Get the encryption configuration of a bucket.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of the S3 bucket.

    Returns:
        Tuple of (encryption_enabled, encryption_type).
        encryption_type is e.g. 'AES256', 'aws:kms', or None.
    """
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            sse_algorithm = (
                rules[0]
                .get("ApplyServerSideEncryptionByDefault", {})
                .get("SSEAlgorithm", None)
            )
            return True, sse_algorithm
        return False, None
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            logger.debug(f"No encryption configured for bucket '{bucket_name}'")
            return False, None
        logger.warning(
            f"Could not get encryption for bucket '{bucket_name}': "
            f"{error_code} - {e.response['Error']['Message']}"
        )
        return False, None


def _get_public_access_block(
    s3_client: Any, bucket_name: str
) -> dict[str, bool] | None:
    """Get the Public Access Block configuration of a bucket.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of the S3 bucket.

    Returns:
        Dict with the four public access block settings, or None if not set.
    """
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})
        return {
            "BlockPublicAcls": config.get("BlockPublicAcls", False),
            "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
            "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            logger.debug(
                f"No public access block configuration for bucket '{bucket_name}'"
            )
            return None
        logger.warning(
            f"Could not get public access block for bucket '{bucket_name}': "
            f"{error_code} - {e.response['Error']['Message']}"
        )
        return None


def _get_policy_status(s3_client: Any, bucket_name: str) -> dict[str, bool] | None:
    """Get the policy status (public or not) of a bucket.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of the S3 bucket.

    Returns:
        Dict with 'IsPublic' key, or None if no policy exists.
    """
    try:
        response = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        policy_status = response.get("PolicyStatus", {})
        return {"IsPublic": policy_status.get("IsPublic", False)}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchBucketPolicy":
            logger.debug(f"No bucket policy for bucket '{bucket_name}'")
            return None
        logger.warning(
            f"Could not get policy status for bucket '{bucket_name}': "
            f"{error_code} - {e.response['Error']['Message']}"
        )
        return None


def _get_bucket_acl(
    s3_client: Any, bucket_name: str
) -> tuple[list[dict[str, Any]], bool]:
    """Get the ACL grants for a bucket and check for public access URIs.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of the S3 bucket.

    Returns:
        Tuple of (acl_grants list, has_public_access bool).
        Each grant dict contains 'grantee' and 'permission'.
    """
    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = response.get("Grants", [])
        acl_grants: list[dict[str, Any]] = []
        has_public = False

        for grant in grants:
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")

            grant_info: dict[str, Any] = {
                "grantee": {
                    "type": grantee.get("Type", ""),
                    "display_name": grantee.get("DisplayName", ""),
                    "uri": grantee.get("URI", ""),
                    "id": grantee.get("ID", ""),
                },
                "permission": permission,
            }
            acl_grants.append(grant_info)

            # Check for public access URIs
            grantee_uri = grantee.get("URI", "")
            if grantee_uri in _PUBLIC_ACL_URIS:
                has_public = True
                logger.warning(
                    f"Bucket '{bucket_name}' has public ACL grant: "
                    f"URI={grantee_uri}, Permission={permission}"
                )

        return acl_grants, has_public
    except ClientError as e:
        logger.warning(
            f"Could not get ACL for bucket '{bucket_name}': "
            f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
        )
        return [], False


def _get_bucket_versioning(s3_client: Any, bucket_name: str) -> bool:
    """Check if versioning is enabled for a bucket.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of the S3 bucket.

    Returns:
        True if versioning status is 'Enabled', False otherwise.
    """
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return response.get("Status") == "Enabled"
    except ClientError as e:
        logger.warning(
            f"Could not get versioning for bucket '{bucket_name}': "
            f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
        )
        return False


def _is_public_access_fully_blocked(
    public_access_block: dict[str, bool] | None,
) -> bool:
    """Check if a public access block configuration fully blocks public access.

    All four settings must be True for public access to be fully blocked.

    Args:
        public_access_block: The public access block config dict, or None.

    Returns:
        True if all four block settings are enabled.
    """
    if public_access_block is None:
        return False
    return all(
        [
            public_access_block.get("BlockPublicAcls", False),
            public_access_block.get("IgnorePublicAcls", False),
            public_access_block.get("BlockPublicPolicy", False),
            public_access_block.get("RestrictPublicBuckets", False),
        ]
    )
