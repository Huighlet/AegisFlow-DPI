"""
Unit tests for TLS Client Hello disassembler and JA3/JA4 cryptographic fingerprinting.
"""

import struct
from aegisflow.tls import KNOWN_MALICIOUS_JA3, TLSClientHello, TLSParser


def test_tls_client_hello_ja3_extraction():
    """Verify parsing of synthetic TLS Client Hello and deterministic JA3 MD5 computation."""
    # Build minimal valid TLS Client Hello
    # TLS Record Header: Type=0x16, Ver=0x0301, Len=...
    # Handshake Header: Type=0x01, Len=...
    # Version: 0x0303 (TLS 1.2, 771)
    # Random: 32 bytes
    # Session ID: 0
    # Cipher suites: 2 ciphers (0xC02F, 0xC030: 49199, 49200)
    # Compression: 1 (0x00)
    # Extensions: Supported Groups (0x000A: 29), EC Point Formats (0x000B: 0)

    client_version = 0x0303
    random_bytes = b"\x00" * 32
    session_id = b"\x00"  # length 0
    ciphers = struct.pack("!HHH", 4, 49199, 49200)
    compression = b"\x01\x00"  # length 1, null

    # Extension 0x000A (Supported Groups: curve 29)
    ext_curves = struct.pack("!HHH", 0x000A, 4, 2) + struct.pack("!H", 29)
    # Extension 0x000B (Point formats: 0)
    ext_points = struct.pack("!HHBB", 0x000B, 2, 1, 0)
    extensions_payload = ext_curves + ext_points
    extensions_total = struct.pack("!H", len(extensions_payload)) + extensions_payload

    handshake_body = (
        struct.pack("!H", client_version)
        + random_bytes
        + session_id
        + ciphers
        + compression
        + extensions_total
    )

    handshake_hdr = struct.pack("!BBH", 0x01, 0, len(handshake_body))
    record_payload = handshake_hdr + handshake_body
    record_hdr = struct.pack("!BBBH", 0x16, 0x03, 0x01, len(record_payload))

    full_tls = record_hdr + record_payload

    parsed = TLSParser.extract_client_hello(full_tls)
    assert parsed is not None
    assert parsed.version == 771
    assert parsed.cipher_suites == [49199, 49200]
    assert parsed.elliptic_curves == [29]
    assert parsed.ec_point_formats == [0]

    # Verify JA3 format
    assert parsed.raw_ja3_string == "771,49199-49200,10-11,29,0"
    assert len(parsed.ja3_hash) == 32  # MD5 hex length
    assert len(parsed.ja3_sha256) == 64  # SHA256 hex length


def test_non_tls_returns_none():
    """Verify non-TLS payloads are ignored cleanly without error."""
    assert TLSParser.extract_client_hello(b"GET /index.html HTTP/1.1\r\n") is None
    assert TLSParser.extract_client_hello(b"\x00\x01\x02\x03") is None
