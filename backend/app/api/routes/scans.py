"""Scan orchestration, history, and report routes."""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from app.schemas.aws import ScanHistoryItem, ScanReport, ScanSummary
from app.services.report_storage import get_report_storage
from app.services.scan_state import get_scan_state
from app.services.scanner import get_scanner

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Scans"])


@router.post("/scan", response_model=ScanReport)
def trigger_full_scan() -> ScanReport:
    """Run a complete end-to-end security scan, upload to S3, and return the report."""
    scanner = get_scanner()
    try:
        report = scanner.run_full_scan()
        return report
    except Exception as e:
        logger.error(f"Scan orchestration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@router.get("/scan/latest", response_model=ScanReport)
def get_latest_scan() -> ScanReport:
    """Retrieve the latest completed scan report from S3 or active in-memory state."""
    # First check state
    state = get_scan_state()
    latest_memory = state.get_latest_report()
    if latest_memory:
        return latest_memory

    # Otherwise fetch from S3
    storage = get_report_storage()
    try:
        latest_s3 = storage.get_latest_scan()
        if latest_s3:
            return ScanReport(**latest_s3)
    except Exception as e:
        logger.error(f"Error fetching latest scan from S3: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch latest scan: {str(e)}")

    raise HTTPException(status_code=404, detail="No scan report found. Run a scan first.")


@router.get("/scans", response_model=list[ScanHistoryItem])
@router.get("/scan/history", response_model=list[ScanHistoryItem])
def get_scan_history(
    limit: int = Query(20, ge=1, le=100, description="Max history items to retrieve")
) -> list[ScanHistoryItem]:
    """Retrieve historical scan records from S3."""
    storage = get_report_storage()
    try:
        history_raw = storage.list_scan_history(limit=limit)
        items: list[ScanHistoryItem] = []
        for h in history_raw:
            items.append(
                ScanHistoryItem(
                    scan_id=h.get("scan_id", ""),
                    timestamp=h.get("timestamp", ""),
                    account_id=h.get("account_id", ""),
                    total_resources=h.get("total_resources", 0),
                    total_checks=h.get("total_checks", 0),
                    passed=h.get("passed", 0),
                    failed=h.get("failed", 0),
                    errors=h.get("errors", 0),
                    score=h.get("score"),
                    score_display=h.get("score_display", "N/A"),
                    storage_key=h.get("storage_key", ""),
                    s3_key=h.get("s3_key", ""),
                )
            )
        return items
    except Exception as e:
        logger.error(f"Error listing scan history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(e)}")


@router.get("/summary", response_model=ScanSummary)
@router.get("/scan/summary", response_model=ScanSummary)
def get_posture_summary() -> ScanSummary:
    """Retrieve the high-level security posture summary for the account."""
    state = get_scan_state()
    summary = state.get_summary()
    if summary:
        return summary

    # Fallback to S3 latest report summary
    storage = get_report_storage()
    try:
        latest = storage.get_latest_scan()
        if latest and "summary" in latest:
            return ScanSummary(**latest["summary"])
    except Exception as e:
        logger.debug(f"Could not load summary from S3: {e}")

    # If no scans exist yet, return an empty initialized summary
    return ScanSummary(
        scan_id="",
        timestamp="",
        account_id="",
        regions_scanned=[],
        total_resources=0,
        total_instances=0,
        total_buckets=0,
        total_security_groups=0,
        total_checks=0,
        passed=0,
        failed=0,
        errors=0,
        score=None,
        score_display="N/A",
        storage_status="none",
    )


@router.get("/scans/{scan_id}", response_model=ScanReport)
@router.get("/scan/{scan_id}", response_model=ScanReport)
def get_scan_by_id(scan_id: str) -> ScanReport:
    """Retrieve an individual scan report by ID from S3."""
    state = get_scan_state()
    current = state.get_latest_report()
    if current and current.scan_id == scan_id:
        return current

    storage = get_report_storage()
    try:
        report_dict = storage.get_scan_by_id(scan_id)
        if report_dict:
            return ScanReport(**report_dict)
    except Exception as e:
        logger.error(f"Error fetching scan {scan_id} from S3: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan report: {str(e)}")

    raise HTTPException(status_code=404, detail=f"Scan report with ID '{scan_id}' not found in S3.")

