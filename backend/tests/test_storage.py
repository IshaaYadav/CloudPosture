"""Tests for S3 report storage, retrieval, and verification."""

import json
import pytest
from app.services.report_storage import S3ReportStorage


def test_upload_and_retrieve_scan(mocked_aws) -> None:
    """Test uploading a scan report and retrieving it."""
    storage = S3ReportStorage()
    sample_report = {
        "scan_id": "test-scan-123",
        "timestamp": "2026-10-31T00:00:00+00:00",
        "account_id": "123456789012",
        "instances": [],
        "buckets": [],
        "check_results": [],
        "posture_score": {"passed": 5, "failed": 3, "errors": 0, "score": 62.5},
    }

    key = storage.upload_scan_report(sample_report)
    assert key.startswith("cloud-posture-scanner/scans/")
    assert "test-scan-123" in key

    # Test get_latest_scan
    latest = storage.get_latest_scan()
    assert latest is not None
    assert latest["scan_id"] == "test-scan-123"

    # Test get_scan_by_id
    by_id = storage.get_scan_by_id("test-scan-123")
    assert by_id is not None
    assert by_id["scan_id"] == "test-scan-123"


def test_list_scan_history(mocked_aws) -> None:
    """Test listing historical scans from S3."""
    storage = S3ReportStorage()
    sample_report = {
        "scan_id": "hist-scan-001",
        "timestamp": "2026-10-31T01:00:00+00:00",
        "account_id": "123456789012",
        "instances": [],
        "buckets": [],
        "check_results": [],
        "posture_score": {"passed": 8, "failed": 0, "errors": 0, "score": 100.0},
    }
    storage.upload_scan_report(sample_report)

    history = storage.list_scan_history()
    assert len(history) >= 1
    found = [h for h in history if h["scan_id"] == "hist-scan-001"]
    assert len(found) == 1
    assert found[0]["score"] == 100.0


def test_verify_s3_storage(mocked_aws) -> None:
    """Test dedicated storage verification flow."""
    storage = S3ReportStorage()
    verification = storage.verify_s3_storage()

    assert verification.status == "PASSED"
    assert verification.write_access is True
    assert verification.read_access is True
    assert verification.delete_access is True
    assert verification.bucket_name == "test-posture-reports-bucket"

