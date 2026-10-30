"""AWS Session Manager - handles boto3 session creation and identity verification."""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from app.config import get_settings

logger = logging.getLogger(__name__)


class AWSSessionManager:
    """Manages AWS boto3 sessions and client creation."""

    def __init__(self) -> None:
        self._session: Optional[boto3.Session] = None
        self._settings = get_settings()

    def get_session(self) -> boto3.Session:
        """Create or return cached boto3 session.

        Uses AWS_PROFILE if set, otherwise falls back to standard credential chain
        (env vars, instance profile, etc).
        """
        if self._session is None:
            try:
                session_kwargs: dict[str, Any] = {
                    "region_name": self._settings.AWS_REGION,
                }
                if self._settings.AWS_PROFILE:
                    session_kwargs["profile_name"] = self._settings.AWS_PROFILE
                    logger.info(f"Creating boto3 session with profile: {self._settings.AWS_PROFILE}")
                else:
                    logger.info("Creating boto3 session with default credential chain")

                self._session = boto3.Session(**session_kwargs)
            except ProfileNotFound as e:
                logger.error(f"AWS profile not found: {e}")
                raise ValueError(
                    f"AWS profile '{self._settings.AWS_PROFILE}' not found. "
                    f"Available profiles: {boto3.Session().available_profiles}"
                ) from e
        return self._session

    def get_client(self, service_name: str, region_name: str | None = None) -> Any:
        """Get a boto3 client for the specified AWS service.

        Args:
            service_name: AWS service name (e.g., 's3', 'ec2', 'iam')
            region_name: Optional region override

        Returns:
            boto3 client for the specified service
        """
        session = self.get_session()
        kwargs: dict[str, Any] = {}
        if region_name:
            kwargs["region_name"] = region_name
        try:
            return session.client(service_name, **kwargs)
        except NoCredentialsError as e:
            logger.error(f"No AWS credentials found: {e}")
            raise ValueError(
                "No AWS credentials found. Please configure credentials via:\n"
                "  1. AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables\n"
                "  2. AWS_PROFILE environment variable pointing to a configured profile\n"
                "  3. IAM instance profile (when running on EC2)\n"
                "  4. AWS SSO login (run 'aws sso login')"
            ) from e

    def verify_identity(self) -> dict[str, Any]:
        """Verify AWS credentials by calling STS GetCallerIdentity.

        Returns:
            Dict with account_id, arn, user_id, region, status, timestamp
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            sts_client = self.get_client("sts")
            response = sts_client.get_caller_identity()
            identity = {
                "account_id": response["Account"],
                "arn": response["Arn"],
                "user_id": response["UserId"],
                "region": self._settings.AWS_REGION,
                "status": "connected",
                "timestamp": timestamp,
            }
            logger.info(f"AWS identity verified: {identity['arn']}")
            return identity
        except NoCredentialsError:
            logger.error("No AWS credentials available")
            return {
                "account_id": "",
                "arn": "",
                "user_id": "",
                "region": self._settings.AWS_REGION,
                "status": "no-credentials",
                "timestamp": timestamp,
                "error": "No AWS credentials found. Please configure AWS credentials.",
            }
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_msg = e.response["Error"]["Message"]
            logger.error(f"AWS identity verification failed: {error_code} - {error_msg}")
            return {
                "account_id": "",
                "arn": "",
                "user_id": "",
                "region": self._settings.AWS_REGION,
                "status": "error",
                "timestamp": timestamp,
                "error": f"{error_code}: {error_msg}",
            }
        except Exception as e:
            logger.error(f"Unexpected error during identity verification: {e}")
            return {
                "account_id": "",
                "arn": "",
                "user_id": "",
                "region": self._settings.AWS_REGION,
                "status": "error",
                "timestamp": timestamp,
                "error": str(e),
            }

    def reset_session(self) -> None:
        """Reset the cached session (useful for credential rotation)."""
        self._session = None
        logger.info("AWS session reset")


# Module-level singleton
_session_manager: Optional[AWSSessionManager] = None


def get_session_manager() -> AWSSessionManager:
    """Get or create the singleton AWSSessionManager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = AWSSessionManager()
    return _session_manager
