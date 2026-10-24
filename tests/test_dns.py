"""
Unit tests for DNS packet parsing and Shannon Entropy exfiltration tunneling detection.
"""

import pytest

from aegisflow.dns import DNSPacket, analyze_dns_tunneling, calculate_shannon_entropy


def test_shannon_entropy_calculation():
    """Verify Shannon entropy mathematical properties."""
    # Repetitive single character has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0

    # Normal domain has moderate entropy
    benign_ent = calculate_shannon_entropy("google")
    assert 1.5 <= benign_ent <= 2.8

    # Random hex/base64 string has high entropy
    high_ent = calculate_shannon_entropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
    assert high_ent >= 4.0


def test_dns_wire_unpack():
    """Verify unpacking of DNS query packet for 'example.com'."""
    # DNS Header: ID=0x1234, Flags=0x0100 (Standard query), QDCOUNT=1
    hdr = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    # QNAME: 7'example' 3'com' 0 + QTYPE=1 (A) + QCLASS=1 (IN)
    qname = b"\x07example\x03com\x00\x00\x01\x00\x01"
    raw_dns = hdr + qname

    dns = DNSPacket.unpack(raw_dns)
    assert dns.tx_id == 0x1234
    assert dns.is_response is False
    assert dns.qd_count == 1
    assert len(dns.questions) == 1
    assert dns.questions[0].qname == "example.com"
    assert dns.questions[0].qtype == 1


def test_dns_tunneling_detection_alert():
    """Verify that an exfiltration subdomain triggers DNS tunneling alerts."""
    # High entropy base64 exfiltration label
    exfil_domain = "VGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZAo.c2.attacker.net"
    is_suspicious, ent, reason = analyze_dns_tunneling(exfil_domain, entropy_threshold=3.8)

    assert is_suspicious is True
    assert ent >= 3.8
    assert "Shannon entropy" in reason or "subdomain length" in reason


def test_benign_dns_query_clean():
    """Verify standard legitimate domain passes as clean."""
    is_suspicious, ent, reason = analyze_dns_tunneling("api.github.com")
    assert is_suspicious is False
    assert "Benign" in reason or "Normal" in reason
