"""AWS connection and identity routes."""

from datetime import datetime, timezone
import logging
from fastapi import APIRouter, HTTPException

from app.aws.session import get_session_manager
from app.schemas.aws import AWSStatus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/aws", tags=["AWS Connection"])


def _build_status_response(identity: dict) -> AWSStatus:
    status_str = identity.get("status", "error")
    connected = (status_str == "connected")
    ts = identity.get("timestamp") or datetime.now(timezone.utc).isoformat()
    return AWSStatus(
        account_id=identity.get("account_id", ""),
        arn=identity.get("arn", ""),
        user_id=identity.get("user_id", ""),
        region=identity.get("region", ""),
        status=status_str,
        connected=connected,
        timestamp=ts,
        last_verified=ts,
        error=identity.get("error"),
    )


@router.get("/status", response_model=AWSStatus)
def get_aws_status() -> AWSStatus:
    """Retrieve the cached or current AWS connection identity and status."""
    session_manager = get_session_manager()
    identity = session_manager.verify_identity()
    return _build_status_response(identity)


@router.post("/verify", response_model=AWSStatus)
def verify_aws_connection() -> AWSStatus:
    """Force re-verification of AWS credentials against STS GetCallerIdentity."""
    session_manager = get_session_manager()
    session_manager.reset_session()
    identity = session_manager.verify_identity()
    return _build_status_response(identity)

