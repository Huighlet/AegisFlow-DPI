"""
Unit & Integration Tests for AegisFlow-DPI REST Forensics Service.
"""

import pytest
from starlette.testclient import TestClient
from aegisflow.server import app, engine


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "telemetry" in data


def test_dashboard_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "AegisFlow-DPI Threat Forensics" in response.text


def test_entropy_audit_endpoint(client):
    # 1. Normal domain
    norm_resp = client.post("/v1/audit/entropy", json={"domain": "www.google.com"})
    assert norm_resp.status_code == 200
    assert norm_resp.json()["is_tunneling_detected"] is False

    # 2. Suspicious high-entropy tunneling domain
    tun_domain = "4f8a9b2c3d1e5f7a0b8c6d4e2f1a3b5c7d9e.exfil.attacker.com"
    tun_resp = client.post("/v1/audit/entropy", json={"domain": tun_domain, "threshold": 3.8})
    assert tun_resp.status_code == 200
    assert tun_resp.json()["is_tunneling_detected"] is True
    assert tun_resp.json()["subdomain_entropy"] > 3.8


def _build_test_packet(payload: bytes) -> bytes:
    import socket, struct
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp_hdr = b"\xad\x21\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x18\x72\x10\x00\x00\x00\x00"
    ip_tot_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_tot_len, 0x1234, 0x4000, 64, 6, 0, socket.inet_aton("192.168.1.5"), socket.inet_aton("10.0.0.1"))
    return eth_hdr + ip_hdr + tcp_hdr + payload


def test_inspect_packet_with_c2_signature(client):
    # Construct Ethernet + IPv4 + TCP packet containing webshell pattern "cmd.exe"
    raw_packet = _build_test_packet(b"POST /upload.php HTTP/1.1\r\n\r\ncmd.exe /c whoami")

    resp = client.post("/v1/inspect/packet", json={"packet_hex": raw_packet.hex()})
    assert resp.status_code == 200
    data = resp.json()
    assert data["bytes_inspected"] == len(raw_packet)
    assert data["alerts_count"] >= 1
    alert_descs = [a["description"] for a in data["alerts"]]
    assert any("WebShell" in d or "Reconnaissance" in d for d in alert_descs)


def test_custom_signature_endpoint(client):
    # 1. Register signature
    sig_resp = client.post("/v1/signatures", json={
        "pattern": "ATTACK_SIGNATURE_XYZ",
        "signature_name": "ZeroDay.ProofOfConcept",
    })
    assert sig_resp.status_code == 201
    assert sig_resp.json()["registered"] is True

    # 2. Inspect packet matching custom signature
    raw_packet = _build_test_packet(b"PAYLOAD WITH ATTACK_SIGNATURE_XYZ INSIDE")

    resp = client.post("/v1/inspect/packet", json={"packet_hex": raw_packet.hex()})
    assert resp.status_code == 200
    data = resp.json()
    assert data["alerts_count"] >= 1
    alert_descs = [a["description"] for a in data["alerts"]]
    assert any("ZeroDay.ProofOfConcept" in d for d in alert_descs)
