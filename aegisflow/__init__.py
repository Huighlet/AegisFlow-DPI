"""
AegisFlow-DPI: High-Throughput Deep Packet Inspection & Protocol Anomaly Detection Engine.
"""

from aegisflow.dns import DNSPacket, analyze_dns_tunneling, calculate_shannon_entropy
from aegisflow.engine import AegisFlowEngine, NetworkFlow, ThreatAlert
from aegisflow.framing import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from aegisflow.matcher import AhoCorasickMatcher
from aegisflow.pcap import PCAPReader, PCAPWriter
from aegisflow.tls import KNOWN_MALICIOUS_JA3, TLSClientHello, TLSParser
from aegisflow.types import (
    AegisFlowError,
    AlertSeverity,
    AnomalyType,
    EtherType,
    PacketDecodeError,
    PCAPCorruptError,
    Protocol,
    TCPFlags,
)

__version__ = "1.0.0"

__all__ = [
    "AegisFlowEngine",
    "ThreatAlert",
    "NetworkFlow",
    "EthernetFrame",
    "IPv4Packet",
    "TCPPacket",
    "UDPPacket",
    "DNSPacket",
    "analyze_dns_tunneling",
    "calculate_shannon_entropy",
    "TLSParser",
    "TLSClientHello",
    "KNOWN_MALICIOUS_JA3",
    "AhoCorasickMatcher",
    "PCAPReader",
    "PCAPWriter",
    "Protocol",
    "EtherType",
    "TCPFlags",
    "AlertSeverity",
    "AnomalyType",
    "AegisFlowError",
    "PacketDecodeError",
    "PCAPCorruptError",
]
