"""Health check endpoint."""

from datetime import datetime, timezone
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
def get_health() -> dict[str, str]:
    """Health check endpoint to verify backend service status."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "Cloud Posture Scanner",
    }

