"""
Unit tests for PCAP reader/writer and end-to-end DPI anomaly engine.
"""

from pathlib import Path
import pytest

from aegisflow.engine import AegisFlowEngine
from aegisflow.pcap import PCAPReader, PCAPWriter
from aegisflow.types import AnomalyType


def test_pcap_roundtrip_write_read(tmp_path: Path):
    """Verify writing raw packets to PCAP and reading them back."""
    pcap_file = tmp_path / "test_capture.pcap"
    writer = PCAPWriter(pcap_file)

    pkt1 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00PACKET_ONE"
    pkt2 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00PACKET_TWO"

    writer.write_packet(pkt1, 1700000000.123456)
    writer.write_packet(pkt2, 1700000001.654321)
    writer.close()

    reader = PCAPReader(pcap_file)
    packets = list(reader.packets())
    assert len(packets) == 2

    assert packets[0][1] == pkt1
    assert abs(packets[0][0] - 1700000000.123456) < 0.00001

    assert packets[1][1] == pkt2
    assert abs(packets[1][0] - 1700000001.654321) < 0.00001


def test_engine_detects_port_scans():
    """Verify detection of NULL and XMAS port scans."""
    engine = AegisFlowEngine()

    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_hdr = b"\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x05\x0a\x00\x00\x01"

    # 1. NULL Scan packet: TCP flags = 0x00
    tcp_null = b"\xad\x21\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x00\x72\x10\x00\x00\x00\x00"
    alerts_null = engine.inspect_raw_packet(eth_hdr + ip_hdr + tcp_null)
    assert len(alerts_null) == 1
    assert alerts_null[0].anomaly_type == AnomalyType.TCP_NULL_SCAN

    # 2. XMAS Scan packet: TCP flags = FIN(0x01) | PSH(0x08) | URG(0x20) == 0x29
    tcp_xmas = b"\xad\x21\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x29\x72\x10\x00\x00\x00\x00"
    alerts_xmas = engine.inspect_raw_packet(eth_hdr + ip_hdr + tcp_xmas)
    assert len(alerts_xmas) == 1
    assert alerts_xmas[0].anomaly_type == AnomalyType.TCP_XMAS_SCAN


def test_engine_detects_c2_payload_signature():
    """Verify detection of C2 stager in TCP payload."""
    engine = AegisFlowEngine()

    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_hdr = b"\x45\x00\x00\x50\x12\x34\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x05\x0a\x00\x00\x01"
    tcp_hdr = b"\xad\x21\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x18\x72\x10\x00\x00\x00\x00"

    # Malicious payload containing Linux password extraction
    payload = b"GET /download?file=/etc/passwd HTTP/1.1\r\n\r\n"

    alerts = engine.inspect_raw_packet(eth_hdr + ip_hdr + tcp_hdr + payload)
    assert len(alerts) == 1
    assert alerts[0].anomaly_type == AnomalyType.C2_BEACON_MATCH
    assert "Credential Harvesting" in alerts[0].description
