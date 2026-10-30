"""In-memory scan state manager for caching the latest scan data."""

import threading
from typing import Any, Optional

from app.schemas.aws import (
    CheckResult,
    EC2Instance,
    PostureScore,
    S3Bucket,
    ScanReport,
    ScanSummary,
    SecurityGroup,
)


class ScanStateManager:
    """Thread-safe in-memory cache for recent scan results."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._latest_report: Optional[ScanReport] = None
        self._instances: list[EC2Instance] = []
        self._buckets: list[S3Bucket] = []
        self._security_groups: list[SecurityGroup] = []
        self._check_results: list[CheckResult] = []
        self._posture_score: Optional[PostureScore] = None
        self._summary: Optional[ScanSummary] = None

    def update(self, report: ScanReport) -> None:
        """Update current in-memory state with a newly completed scan report."""
        with self._lock:
            self._latest_report = report
            self._instances = report.instances
            self._buckets = report.buckets
            self._security_groups = report.security_groups
            self._check_results = report.check_results
            self._posture_score = report.posture_score
            self._summary = report.summary

    def get_latest_report(self) -> Optional[ScanReport]:
        """Get the latest in-memory scan report."""
        with self._lock:
            return self._latest_report

    def get_instances(self) -> list[EC2Instance]:
        """Get discovered EC2 instances from the last scan."""
        with self._lock:
            return list(self._instances)

    def get_buckets(self) -> list[S3Bucket]:
        """Get discovered S3 buckets from the last scan."""
        with self._lock:
            return list(self._buckets)

    def get_security_groups(self) -> list[SecurityGroup]:
        """Get discovered security groups from the last scan."""
        with self._lock:
            return list(self._security_groups)

    def get_check_results(self) -> list[CheckResult]:
        """Get CIS check results from the last scan."""
        with self._lock:
            return list(self._check_results)

    def get_check_result_by_id(self, check_id: str) -> Optional[CheckResult]:
        """Get a single CIS check result by ID."""
        with self._lock:
            for check in self._check_results:
                if check.check_id.lower() == check_id.lower():
                    return check
            return None

    def get_posture_score(self) -> Optional[PostureScore]:
        """Get posture score from the last scan."""
        with self._lock:
            return self._posture_score

    def get_summary(self) -> Optional[ScanSummary]:
        """Get summary from the last scan."""
        with self._lock:
            return self._summary

    def clear(self) -> None:
        """Reset in-memory state."""
        with self._lock:
            self._latest_report = None
            self._instances = []
            self._buckets = []
            self._security_groups = []
            self._check_results = []
            self._posture_score = None
            self._summary = None


# Global singleton instance
_scan_state = ScanStateManager()


def get_scan_state() -> ScanStateManager:
    """Return the global in-memory ScanStateManager."""
    return _scan_state

