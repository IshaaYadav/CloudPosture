"""CloudTrail - discovers trails and their logging status. Never creates trails."""

import logging
from typing import Any

from botocore.exceptions import ClientError, NoCredentialsError

from app.aws.session import get_session_manager

logger = logging.getLogger(__name__)


def get_trails() -> list[dict[str, Any]]:
    """Discover all CloudTrail trails and their current logging status.

    Calls cloudtrail:DescribeTrails to list all trails, then for each trail
    calls cloudtrail:GetTrailStatus to determine if logging is currently
    active.

    This function NEVER creates or modifies trails.

    Returns:
        List of trail dicts, each containing:
            trail_name, trail_arn, is_multi_region, is_logging,
            home_region, s3_bucket_name.
        Returns an empty list if access is denied.

    Raises:
        ValueError: If AWS credentials are not configured.
    """
    session_manager = get_session_manager()
    try:
        ct_client = session_manager.get_client("cloudtrail")
    except (NoCredentialsError, ValueError) as e:
        logger.error(f"Cannot create CloudTrail client: {e}")
        raise

    # Describe all trails
    try:
        response = ct_client.describe_trails()
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("AccessDeniedException", "AccessDenied"):
            logger.warning(
                "Access denied when describing CloudTrail trails. "
                "Returning empty list."
            )
            return []
        error_msg = e.response["Error"]["Message"]
        logger.error(f"Failed to describe trails: {error_code} - {error_msg}")
        raise
    except NoCredentialsError as e:
        logger.error(f"No AWS credentials found: {e}")
        raise ValueError(
            "No AWS credentials found. Cannot discover CloudTrail trails."
        ) from e

    trails_raw = response.get("trailList", [])
    logger.info(f"Found {len(trails_raw)} CloudTrail trails")

    all_trails: list[dict[str, Any]] = []

    for trail in trails_raw:
        trail_name = trail.get("Name", "")
        trail_arn = trail.get("TrailARN", "")

        # Get logging status for this trail
        is_logging = _get_trail_logging_status(ct_client, trail_arn or trail_name)

        trail_data: dict[str, Any] = {
            "trail_name": trail_name,
            "trail_arn": trail_arn,
            "is_multi_region": trail.get("IsMultiRegionTrail", False),
            "is_logging": is_logging,
            "home_region": trail.get("HomeRegion", ""),
            "s3_bucket_name": trail.get("S3BucketName", ""),
        }
        all_trails.append(trail_data)

    logger.info(
        f"CloudTrail discovery complete: {len(all_trails)} trails processed"
    )
    return all_trails


def _get_trail_logging_status(ct_client: Any, trail_identifier: str) -> bool:
    """Get the logging status of a specific CloudTrail trail.

    Args:
        ct_client: Boto3 CloudTrail client.
        trail_identifier: Trail ARN or name to query.

    Returns:
        True if the trail is actively logging, False otherwise or on error.
    """
    try:
        status_response = ct_client.get_trail_status(Name=trail_identifier)
        is_logging = status_response.get("IsLogging", False)
        logger.debug(f"Trail '{trail_identifier}' logging status: {is_logging}")
        return is_logging
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("AccessDeniedException", "AccessDenied"):
            logger.warning(
                f"Access denied when getting trail status for "
                f"'{trail_identifier}'. Assuming not logging."
            )
            return False
        if error_code == "TrailNotFoundException":
            logger.warning(f"Trail not found: '{trail_identifier}'")
            return False
        logger.error(
            f"Error getting trail status for '{trail_identifier}': "
            f"{error_code} - {e.response['Error']['Message']}"
        )
        return False
    except NoCredentialsError:
        logger.error("No AWS credentials when getting trail status")
        return False
