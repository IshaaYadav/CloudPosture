"""Tests for Scan Orchestrator and posture score calculation."""

import pytest
from app.services.posture_score import calculate_posture_score
from app.services.scanner import ScanOrchestrator
from app.checks.base import CheckResult, CheckStatus


def test_posture_score_formula() -> None:
    """Test score = PASS / (PASS + FAIL) * 100 with ERROR exclusion."""
    checks = [
        CheckResult("1", "C1", "", "HIGH", CheckStatus.PASS.value),
        CheckResult("2", "C2", "", "HIGH", CheckStatus.PASS.value),
        CheckResult("3", "C3", "", "HIGH", CheckStatus.PASS.value),
        CheckResult("4", "C4", "", "HIGH", CheckStatus.FAIL.value),
        CheckResult("5", "C5", "", "HIGH", CheckStatus.ERROR.value),
    ]
    # Evaluated: 3 PASS + 1 FAIL = 4
    # Score: 3 / 4 * 100 = 75.0%
    score = calculate_posture_score(checks)
    assert score.passed == 3
    assert score.failed == 1
    assert score.errors == 1
    assert score.score == 75.0
    assert score.rating == "Good"


def test_posture_score_all_errors() -> None:
    """Test score when no checks evaluate cleanly."""
    checks = [
        CheckResult("1", "C1", "", "HIGH", CheckStatus.ERROR.value),
    ]
    score = calculate_posture_score(checks)
    assert score.score is None
    assert score.rating == "N/A"


def test_scanner_run_full_scan(mocked_aws) -> None:
    """Test full scan orchestration in mock AWS."""
    scanner = ScanOrchestrator()
    report = scanner.run_full_scan()

    assert report.scan_id != ""
    assert report.account_id != ""
    assert len(report.check_results) == 8
    assert report.posture_score is not None
    assert report.storage_status == "stored"
    assert report.storage_key is not None

