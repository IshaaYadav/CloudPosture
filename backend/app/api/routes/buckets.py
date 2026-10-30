"""S3 Buckets inventory routes."""

import logging
from typing import Optional
from fastapi import APIRouter, Query

from app.schemas.aws import S3Bucket
from app.services.scan_state import get_scan_state
from app.services.report_storage import get_report_storage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["S3 Inventory"])


def _fetch_buckets() -> list[S3Bucket]:
    """Retrieve buckets from scan state or latest S3 scan report."""
    state = get_scan_state()
    buckets = state.get_buckets()
    if buckets:
        return buckets

    try:
        storage = get_report_storage()
        latest = storage.get_latest_scan()
        if latest and "buckets" in latest:
            return [S3Bucket(**item) for item in latest["buckets"]]
    except Exception as e:
        logger.debug(f"Could not load buckets from S3 latest scan: {e}")

    return []


@router.get("/buckets", response_model=list[S3Bucket])
@router.get("/inventory/buckets", response_model=list[S3Bucket])
def list_buckets(
    is_public: Optional[bool] = Query(None, description="Filter by public visibility"),
    encryption_enabled: Optional[bool] = Query(None, description="Filter by default encryption enabled"),
) -> list[S3Bucket]:
    """Retrieve discovered S3 buckets with optional filters."""
    buckets = _fetch_buckets()

    if is_public is not None:
        buckets = [b for b in buckets if b.is_public == is_public]
    if encryption_enabled is not None:
        buckets = [b for b in buckets if b.encryption_enabled == encryption_enabled]

    return buckets

