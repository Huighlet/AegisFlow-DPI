"""
AegisFlow-DPI: Network Protocol Enums, Security Classifications, and Exceptions.
"""

from __future__ import annotations

import enum


class Protocol(enum.IntEnum):
    """IANA Layer 4 IP Protocol Numbers."""
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50


class EtherType(enum.IntEnum):
    """Ethernet Frame Type Codes."""
    IPV4 = 0x0800
    ARP = 0x0806
    IPV6 = 0x86DD
    VLAN = 0x8100


class TCPFlags(enum.IntFlag):
    """Standard TCP Control Bit Flags."""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class AlertSeverity(enum.IntEnum):
    """Threat Alert Severity Levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AnomalyType(enum.StrEnum):
    """Classification of detected network anomalies and attack vectors."""
    DNS_TUNNELING = "DNS_TUNNELING"
    SUSPICIOUS_JA3 = "SUSPICIOUS_JA3_FINGERPRINT"
    C2_BEACON_MATCH = "C2_BEACON_MATCH"
    TCP_XMAS_SCAN = "TCP_XMAS_SCAN"
    TCP_NULL_SCAN = "TCP_NULL_SCAN"
    TCP_SYN_FLOOD = "TCP_SYN_FLOOD"
    PROTOCOL_SMUGGLING = "PROTOCOL_SMUGGLING"
    MALFORMED_PACKET = "MALFORMED_PACKET"


# -------------------------------------------------------------------------
# Exceptions
# -------------------------------------------------------------------------

class AegisFlowError(Exception):
    """Base exception for AegisFlow DPI operations."""


class PacketDecodeError(AegisFlowError):
    """Raised when raw packet bytes cannot be parsed into protocol frames."""


class PCAPCorruptError(AegisFlowError):
    """Raised when a PCAP file header or frame structure is invalid."""
