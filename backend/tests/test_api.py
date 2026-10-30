"""Tests for all FastAPI API endpoints."""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client(mocked_aws) -> TestClient:
    """FastAPI TestClient fixture with mocked AWS."""
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    """Test health check."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_aws_status_and_verify(client: TestClient) -> None:
    """Test AWS identity and status routes."""
    status_resp = client.get("/aws/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "connected"

    verify_resp = client.post("/aws/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["connected"] is True


def test_storage_verify_endpoint(client: TestClient) -> None:
    """Test S3 storage verification route."""
    resp = client.post("/storage/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PASSED"
    assert data["write_access"] is True


def test_scan_and_retrieval_endpoints(client: TestClient) -> None:
    """Test full scan trigger and following retrieval endpoints."""
    # Run scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    report = scan_resp.json()
    scan_id = report["scan_id"]
    assert scan_id != ""
    assert len(report["check_results"]) == 8

    # Instances
    inst_resp1 = client.get("/instances")
    assert inst_resp1.status_code == 200
    inst_resp2 = client.get("/inventory/instances")
    assert inst_resp2.status_code == 200

    # Buckets
    b_resp1 = client.get("/buckets")
    assert b_resp1.status_code == 200
    b_resp2 = client.get("/inventory/buckets")
    assert b_resp2.status_code == 200

    # CIS Findings
    cis_resp1 = client.get("/cis-results")
    assert cis_resp1.status_code == 200
    assert len(cis_resp1.json()) == 8
    cis_resp2 = client.get("/cis/results")
    assert cis_resp2.status_code == 200

    # Single CIS Finding
    check1 = client.get("/cis-results/CIS-S3-001")
    assert check1.status_code == 200
    assert check1.json()["check_id"] == "CIS-S3-001"

    # Latest scan
    latest_resp = client.get("/scan/latest")
    assert latest_resp.status_code == 200
    assert latest_resp.json()["scan_id"] == scan_id

    # Scan history
    hist_resp1 = client.get("/scans")
    assert hist_resp1.status_code == 200
    assert len(hist_resp1.json()) >= 1
    hist_resp2 = client.get("/scan/history")
    assert hist_resp2.status_code == 200

    # Single scan by ID
    single_resp = client.get(f"/scans/{scan_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["scan_id"] == scan_id

    # Summary
    summary_resp1 = client.get("/summary")
    assert summary_resp1.status_code == 200
    summary_resp2 = client.get("/scan/summary")
    assert summary_resp2.status_code == 200

