"""
AegisFlow-DPI: TLS Client Hello Disassembler & JA3/JA4 Cryptographic Fingerprinting.
Extracts TLS Client Hello handshake parameters and produces deterministic JA3 MD5/SHA256 hashes
to identify malware, C2 agents, and bot clients without payload decryption.
"""

from __future__ import annotations

import dataclasses
import hashlib
import struct
from typing import List, Optional, Tuple

from aegisflow.types import PacketDecodeError

# GREASE (Generate Random Extensions And Sustain Extensibility - RFC 8701) values to exclude
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


@dataclasses.dataclass(slots=True, frozen=True)
class TLSClientHello:
    """Parsed TLS Client Hello parameters for cryptographic fingerprinting."""
    version: int
    cipher_suites: List[int]
    extensions: List[int]
    elliptic_curves: List[int]
    ec_point_formats: List[int]
    sni: Optional[str]
    raw_ja3_string: str
    ja3_hash: str
    ja3_sha256: str


class TLSParser:
    """
    Parser for TLS Handshake Client Hello records.
    """
    @staticmethod
    def extract_client_hello(payload: bytes) -> Optional[TLSClientHello]:
        """
        Parse raw TCP payload for TLS Client Hello (Content Type 0x16, Handshake Type 0x01).
        Returns populated TLSClientHello or None if not a valid Client Hello packet.
        """
        # TLS Record Header (5 bytes)
        if len(payload) < 5:
            return None
        content_type, rec_ver_maj, rec_ver_min, rec_len = struct.unpack("!BBBH", payload[:5])
        if content_type != 0x16:  # 0x16 == Handshake
            return None

        offset = 5
        # Handshake Header (4 bytes)
        if len(payload) < offset + 4:
            return None
        handshake_type, length_high, length_low = struct.unpack("!BBH", payload[offset : offset + 4])
        if handshake_type != 0x01:  # 0x01 == Client Hello
            return None
        offset += 4

        # Client Version (2 bytes)
        if len(payload) < offset + 2:
            return None
        (client_version,) = struct.unpack("!H", payload[offset : offset + 2])
        offset += 2

        # Client Random (32 bytes)
        offset += 32
        if len(payload) < offset + 1:
            return None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if len(payload) < offset + 2:
            return None

        # Cipher Suites
        (cipher_len,) = struct.unpack("!H", payload[offset : offset + 2])
        offset += 2
        if len(payload) < offset + cipher_len:
            return None

        cipher_suites: List[int] = []
        for i in range(0, cipher_len, 2):
            (cipher,) = struct.unpack("!H", payload[offset + i : offset + i + 2])
            if cipher not in GREASE_VALUES:
                cipher_suites.append(cipher)
        offset += cipher_len

        # Compression Methods
        if len(payload) < offset + 1:
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        extensions: List[int] = []
        elliptic_curves: List[int] = []
        ec_point_formats: List[int] = []
        sni: Optional[str] = None

        if len(payload) >= offset + 2:
            (ext_total_len,) = struct.unpack("!H", payload[offset : offset + 2])
            offset += 2
            ext_end = min(len(payload), offset + ext_total_len)

            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[offset : offset + 4])
                offset += 4

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                ext_data = payload[offset : offset + ext_len]

                # Extension 0x0000: Server Name Indication (SNI)
                if ext_type == 0x0000 and len(ext_data) >= 5:
                    sni_list_len = struct.unpack("!H", ext_data[:2])[0]
                    name_type = ext_data[2]
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        sni = ext_data[5 : 5 + name_len].decode("ascii", errors="replace")

                # Extension 0x000A: Supported Groups (Elliptic Curves)
                elif ext_type == 0x000A and len(ext_data) >= 2:
                    (curves_len,) = struct.unpack("!H", ext_data[:2])
                    for ci in range(2, min(len(ext_data), 2 + curves_len), 2):
                        (curve,) = struct.unpack("!H", ext_data[ci : ci + 2])
                        if curve not in GREASE_VALUES:
                            elliptic_curves.append(curve)

                # Extension 0x000B: EC Point Formats
                elif ext_type == 0x000B and len(ext_data) >= 1:
                    ec_len = ext_data[0]
                    for pi in range(1, min(len(ext_data), 1 + ec_len)):
                        ec_point_formats.append(ext_data[pi])

                offset += ext_len

        # Format Canonical JA3 string:
        # SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        ciphers_str = "-".join(str(c) for c in cipher_suites)
        extensions_str = "-".join(str(e) for e in extensions)
        curves_str = "-".join(str(c) for c in elliptic_curves)
        points_str = "-".join(str(p) for p in ec_point_formats)

        raw_ja3 = f"{client_version},{ciphers_str},{extensions_str},{curves_str},{points_str}"
        ja3_md5 = hashlib.md5(raw_ja3.encode("ascii")).hexdigest()
        ja3_sha256 = hashlib.sha256(raw_ja3.encode("ascii")).hexdigest()

        return TLSClientHello(
            version=client_version,
            cipher_suites=cipher_suites,
            extensions=extensions,
            elliptic_curves=elliptic_curves,
            ec_point_formats=ec_point_formats,
            sni=sni,
            raw_ja3_string=raw_ja3,
            ja3_hash=ja3_md5,
            ja3_sha256=ja3_sha256,
        )


# -------------------------------------------------------------------------
# Known Threat JA3 Signatures (Cobalt Strike, Malware, C2 Stagers)
# -------------------------------------------------------------------------

KNOWN_MALICIOUS_JA3: dict[str, str] = {
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit / Meterpreter Reverse HTTPS",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon Default TLS Profile",
    "6734f37431670ce653332a48b3b4008a": "TrickBot Banking Trojan",
    "51c64c77e60f3980eea90869b68c58a8": "Dridex C2 Agent",
    "b32309a26951912be7dba376398abc3b": "Emotet Malware HTTPS Spreader",
}
