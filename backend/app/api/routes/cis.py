"""CIS Security Benchmark Findings routes."""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from app.schemas.aws import CheckResult
from app.services.scan_state import get_scan_state
from app.services.report_storage import get_report_storage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["CIS Security Checks"])


def _fetch_check_results() -> list[CheckResult]:
    """Retrieve check results from scan state or latest S3 scan report."""
    state = get_scan_state()
    checks = state.get_check_results()
    if checks:
        return checks

    try:
        storage = get_report_storage()
        latest = storage.get_latest_scan()
        if latest and "check_results" in latest:
            return [CheckResult(**item) for item in latest["check_results"]]
    except Exception as e:
        logger.debug(f"Could not load check results from S3 latest scan: {e}")

    return []


@router.get("/cis-results", response_model=list[CheckResult])
@router.get("/cis/results", response_model=list[CheckResult])
def list_cis_results(
    status: Optional[str] = Query(None, description="Filter by status (PASS, FAIL, ERROR)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    category: Optional[str] = Query(None, description="Filter by category (Storage, Identity, Network, etc.)"),
) -> list[CheckResult]:
    """Retrieve all CIS-inspired security check findings."""
    results = _fetch_check_results()

    if status:
        results = [r for r in results if r.status.upper() == status.upper()]
    if severity:
        results = [r for r in results if r.severity.upper() == severity.upper()]
    if category:
        results = [r for r in results if r.category.lower() == category.lower()]

    return results


@router.get("/cis-results/{check_id}", response_model=CheckResult)
@router.get("/cis/results/{check_id}", response_model=CheckResult)
def get_cis_result(check_id: str) -> CheckResult:
    """Retrieve an individual CIS security check by its ID (e.g. CIS-S3-001)."""
    results = _fetch_check_results()
    for res in results:
        if res.check_id.lower() == check_id.lower():
            return res

    raise HTTPException(status_code=404, detail=f"Check with ID '{check_id}' not found.")

