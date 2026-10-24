"""
Enterprise and Client SDK tests for AegisFlow-DPI.
Validates Pillar 1 (Enterprise Middleware & Metrics), Pillar 2 (Threat Intel Sync & Forensic Export), and Pillar 3 (Client SDK).
"""

import pytest
from starlette.testclient import TestClient

from aegisflow import server
from aegisflow.client import AegisFlowClient


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(server.app)


def test_prometheus_metrics_endpoint(test_client: TestClient):
    resp = test_client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "aegisflow_packets_inspected_total" in text
    assert "aegisflow_threat_alerts_total" in text
    assert "aegisflow_active_signatures_total" in text


def test_intel_sync_endpoint(test_client: TestClient):
    payload = {
        "indicators": [
            {"pattern": "MALICIOUS_C2_HEX_0xDEADBEEF", "signature_name": "Test_APT_Signature"}
        ]
    }
    resp = test_client.post("/v1/intel/sync", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SYNCED"
    assert data["indicators_added"] == 1


def test_forensics_export_endpoint(test_client: TestClient):
    resp = test_client.post("/v1/forensics/export")
    assert resp.status_code == 200
    data = resp.json()
    assert "incident_id" in data
    assert "integrity_seal" in data
    assert "severity_breakdown" in data
    assert "timeline" in data


def test_aegisflow_python_client_sdk(test_client: TestClient):
    client = AegisFlowClient(http_client=test_client)

    # 1. Entropy Audit
    res = client.audit_entropy("aW5zdGl0dXRpb25hbF9leGZpbHRyYXRpb25fZGF0YQ.tunnel.attacker.com")
    assert res["is_tunneling_detected"] is True

    # 2. Threat Intel Sync via SDK
    sync_res = client.sync_threat_intel([
        {"pattern": "COBALT_STRIKE_PIPE", "signature_name": "CobaltStrike_NamedPipe"}
    ])
    assert sync_res["status"] == "SYNCED"

    # 3. Export Forensics via SDK
    forensics = client.export_forensics()
    assert "integrity_seal" in forensics
    client.close()
