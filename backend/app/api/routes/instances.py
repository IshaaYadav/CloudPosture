"""EC2 Instances inventory routes."""

import logging
from typing import Optional
from fastapi import APIRouter, Query

from app.schemas.aws import EC2Instance
from app.services.scan_state import get_scan_state
from app.services.report_storage import get_report_storage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["EC2 Inventory"])


def _fetch_instances() -> list[EC2Instance]:
    """Retrieve instances from scan state or latest S3 scan report."""
    state = get_scan_state()
    instances = state.get_instances()
    if instances:
        return instances

    # Try loading from S3 latest scan if in-memory state is empty
    try:
        storage = get_report_storage()
        latest = storage.get_latest_scan()
        if latest and "instances" in latest:
            parsed = [EC2Instance(**item) for item in latest["instances"]]
            return parsed
    except Exception as e:
        logger.debug(f"Could not load instances from S3 latest scan: {e}")

    return []


@router.get("/instances", response_model=list[EC2Instance])
@router.get("/inventory/instances", response_model=list[EC2Instance])
def list_instances(
    region: Optional[str] = Query(None, description="Filter by AWS region"),
    state: Optional[str] = Query(None, description="Filter by instance state (running, stopped, etc.)"),
) -> list[EC2Instance]:
    """Retrieve discovered EC2 instances with optional region and state filters."""
    instances = _fetch_instances()

    if region:
        instances = [i for i in instances if i.region.lower() == region.lower()]
    if state:
        instances = [i for i in instances if i.state.lower() == state.lower()]

    return instances

