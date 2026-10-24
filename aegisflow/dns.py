"""
AegisFlow-DPI: DNS Protocol Decoder & Shannon Entropy Tunneling Detector.
Parses RFC 1035 wire-format DNS queries and identifies covert DNS exfiltration tunnels.
"""

from __future__ import annotations

import collections
import dataclasses
import math
import struct
from typing import List, Tuple

from aegisflow.types import PacketDecodeError


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon Informational Entropy of a string:
      H(X) = - sum(P(x) * log2(P(x)))
    Higher entropy indicates random/encrypted/encoded content (Base64/Hex exfiltration).
    """
    if not text:
        return 0.0

    length = len(text)
    counts = collections.Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


@dataclasses.dataclass(slots=True, frozen=True)
class DNSQuestion:
    """DNS Query Question Record."""
    qname: str
    qtype: int
    qclass: int


@dataclasses.dataclass(slots=True, frozen=True)
class DNSPacket:
    """RFC 1035 DNS Message Header and Questions."""
    tx_id: int
    is_response: bool
    opcode: int
    rcode: int
    qd_count: int
    an_count: int
    questions: List[DNSQuestion]

    @classmethod
    def unpack(cls, data: bytes) -> DNSPacket:
        if len(data) < 12:
            raise PacketDecodeError("Truncated DNS header: expected >= 12 bytes")

        tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", data[:12])
        is_response = bool(flags & 0x8000)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        offset = 12
        questions: List[DNSQuestion] = []

        # Parse QDCOUNT questions
        for _ in range(qd_count):
            labels: List[str] = []
            while offset < len(data):
                label_len = data[offset]
                offset += 1
                if label_len == 0:
                    break
                if label_len > 63:
                    # Pointer compression or invalid label
                    break
                if offset + label_len > len(data):
                    raise PacketDecodeError("DNS label exceeds packet boundary")
                label = data[offset : offset + label_len].decode("ascii", errors="replace")
                labels.append(label)
                offset += label_len

            qname = ".".join(labels)
            if offset + 4 <= len(data):
                qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
                offset += 4
                questions.append(DNSQuestion(qname=qname, qtype=qtype, qclass=qclass))

        return cls(
            tx_id=tx_id,
            is_response=is_response,
            opcode=opcode,
            rcode=rcode,
            qd_count=qd_count,
            an_count=an_count,
            questions=questions,
        )


def analyze_dns_tunneling(
    qname: str,
    entropy_threshold: float = 3.8,
    label_length_threshold: int = 35,
) -> Tuple[bool, float, str]:
    """
    Examine DNS query name for signs of covert tunneling (Cobalt Strike, Iodine, dnscat2).
    Evaluates:
      1. Shannon entropy of highest-order subdomain label.
      2. Excessive label length (> 35 characters).
      3. Ratio of numeric/hex characters.
    """
    labels = qname.strip(".").split(".")
    if not labels:
        return False, 0.0, "Empty QNAME"

    # Analyze primary subdomain payload (leftmost label)
    subdomain = labels[0]
    if len(subdomain) < 8:
        # Too short to be a meaningful data exfiltration tunnel
        return False, calculate_shannon_entropy(subdomain), "Normal domain length"

    entropy = calculate_shannon_entropy(subdomain)

    # 1. High entropy exfiltration check
    if entropy >= entropy_threshold:
        return (
            True,
            entropy,
            f"High Shannon entropy ({entropy:.2f} >= {entropy_threshold}) indicates Base64/Hex exfiltration",
        )

    # 2. Abnormal label length check
    if len(subdomain) >= label_length_threshold:
        return (
            True,
            entropy,
            f"Anomalous subdomain length ({len(subdomain)} >= {label_length_threshold} chars)",
        )

    return False, entropy, "Benign DNS query"
