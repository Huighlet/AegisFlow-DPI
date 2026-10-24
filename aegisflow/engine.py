"""
AegisFlow-DPI: Deep Packet Inspection & Multi-Layer Threat Anomaly Engine.
Unites zero-copy protocol decoders, Shannon entropy analysis, JA3 TLS fingerprinting,
TCP flag anomaly detection, and streaming Aho-Corasick signature matching.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any, Dict, List, Optional, Tuple

from aegisflow.dns import DNSPacket, analyze_dns_tunneling
from aegisflow.framing import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from aegisflow.matcher import AhoCorasickMatcher
from aegisflow.tls import KNOWN_MALICIOUS_JA3, TLSClientHello, TLSParser
from aegisflow.types import AlertSeverity, AnomalyType, EtherType, Protocol, TCPFlags


@dataclasses.dataclass(slots=True, frozen=True)
class ThreatAlert:
    """Security alert emitted when malicious or anomalous traffic is discovered."""
    alert_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    severity: AlertSeverity
    anomaly_type: AnomalyType
    description: str
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(slots=True)
class NetworkFlow:
    """5-Tuple Conversation Flow State."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    packets_count: int = 0
    bytes_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    start_time: float = dataclasses.field(default_factory=time.time)
    last_seen: float = dataclasses.field(default_factory=time.time)


class AegisFlowEngine:
    """
    High-Throughput Deep Packet Inspection Engine.
    """
    def __init__(self, dns_entropy_threshold: float = 3.8) -> None:
        self.dns_entropy_threshold = dns_entropy_threshold
        self.matcher = AhoCorasickMatcher()
        self._load_default_signatures()
        self.matcher.build_automaton()

        self._flows: Dict[str, NetworkFlow] = {}
        self._alerts: List[ThreatAlert] = []

        # Telemetry
        self.packets_inspected: int = 0
        self.bytes_processed: int = 0
        self._alert_counter: int = 0

    def _load_default_signatures(self) -> None:
        """Load standard C2 beacons, webshell headers, and exfiltration patterns."""
        signatures = [
            (b"/etc/passwd", "Linux Credential Harvesting Indicator"),
            (b"cmd.exe", "Windows Command Execution WebShell"),
            (b"whoami", "Privilege Reconnaissance Indicator"),
            (b"powershell -nop -w hidden", "Cobalt Strike / PowerShell Stager"),
            (b"eval(base64_decode", "PHP WebShell Generic Evaluator"),
            (b"c99shell", "C99 PHP WebShell Header"),
            (b"r57shell", "R57 PHP WebShell Header"),
        ]
        for pattern, sig_name in signatures:
            self.matcher.add_pattern(pattern, sig_name)

    def register_custom_signature(self, pattern: str | bytes, signature_name: str) -> None:
        """Add user-defined pattern to Aho-Corasick automaton."""
        self.matcher.add_pattern(pattern, signature_name)
        self.matcher.build_automaton()

    def inspect_raw_packet(self, data: bytes, timestamp: Optional[float] = None) -> List[ThreatAlert]:
        """
        Ingest raw Layer 2/3 packet bytes, execute multi-layer DPI, and return any detected alerts.
        """
        ts = timestamp if timestamp is not None else time.time()
        self.packets_inspected += 1
        self.bytes_processed += len(data)
        alerts: List[ThreatAlert] = []

        # 1. Parse Layer 2 (Ethernet)
        try:
            eth = EthernetFrame.unpack(data)
        except Exception:
            return alerts

        # Only process IPv4 in this layer
        if eth.ethertype != EtherType.IPV4:
            return alerts

        # 2. Parse Layer 3 (IPv4)
        try:
            ip = IPv4Packet.unpack(eth.payload)
        except Exception:
            return alerts

        # 3. Layer 4 Transport Processing
        if ip.protocol == Protocol.UDP:
            alerts.extend(self._inspect_udp(ip, ts))
        elif ip.protocol == Protocol.TCP:
            alerts.extend(self._inspect_tcp(ip, ts))

        for a in alerts:
            self._alerts.append(a)

        return alerts

    def _inspect_udp(self, ip: IPv4Packet, ts: float) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        try:
            udp = UDPPacket.unpack(ip.payload)
        except Exception:
            return alerts

        # Port 53: DNS Deep Inspection
        if udp.dst_port == 53 or udp.src_port == 53:
            try:
                dns = DNSPacket.unpack(udp.payload)
                for q in dns.questions:
                    is_suspicious, entropy, reason = analyze_dns_tunneling(
                        q.qname, entropy_threshold=self.dns_entropy_threshold
                    )
                    if is_suspicious:
                        self._alert_counter += 1
                        alert = ThreatAlert(
                            alert_id=f"ALT_DNS_{self._alert_counter:06d}",
                            timestamp=ts,
                            src_ip=ip.src_ip,
                            dst_ip=ip.dst_ip,
                            src_port=udp.src_port,
                            dst_port=udp.dst_port,
                            protocol="UDP/DNS",
                            severity=AlertSeverity.HIGH,
                            anomaly_type=AnomalyType.DNS_TUNNELING,
                            description=f"Covert DNS exfiltration tunnel detected: {reason}",
                            metadata={"qname": q.qname, "entropy": round(entropy, 3)},
                        )
                        alerts.append(alert)
            except Exception:
                pass

        return alerts

    def _inspect_tcp(self, ip: IPv4Packet, ts: float) -> List[ThreatAlert]:
        alerts: List[ThreatAlert] = []
        try:
            tcp = TCPPacket.unpack(ip.payload)
        except Exception:
            return alerts

        # A. TCP Flag Port Scan Anomaly Detection
        # 1. NULL Scan: No flags set
        if int(tcp.flags) == 0:
            self._alert_counter += 1
            alerts.append(
                ThreatAlert(
                    alert_id=f"ALT_SCAN_{self._alert_counter:06d}",
                    timestamp=ts,
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                    protocol="TCP",
                    severity=AlertSeverity.MEDIUM,
                    anomaly_type=AnomalyType.TCP_NULL_SCAN,
                    description="Stealth NULL Port Scan: TCP packet received with 0 flags set.",
                )
            )

        # 2. XMAS Scan: FIN + PSH + URG
        elif (tcp.flags & (TCPFlags.FIN | TCPFlags.PSH | TCPFlags.URG)) == (TCPFlags.FIN | TCPFlags.PSH | TCPFlags.URG):
            self._alert_counter += 1
            alerts.append(
                ThreatAlert(
                    alert_id=f"ALT_SCAN_{self._alert_counter:06d}",
                    timestamp=ts,
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                    protocol="TCP",
                    severity=AlertSeverity.MEDIUM,
                    anomaly_type=AnomalyType.TCP_XMAS_SCAN,
                    description="Stealth XMAS Port Scan: TCP packet received with FIN, PSH, and URG flags set.",
                )
            )

        # B. TLS Handshake & JA3 Cryptographic Fingerprinting (Port 443 or any TLS packet)
        if tcp.dst_port == 443 or tcp.src_port == 443 or len(tcp.payload) > 5:
            client_hello = TLSParser.extract_client_hello(tcp.payload)
            if client_hello is not None:
                # Check against known threat signatures
                if client_hello.ja3_hash in KNOWN_MALICIOUS_JA3:
                    malware_name = KNOWN_MALICIOUS_JA3[client_hello.ja3_hash]
                    self._alert_counter += 1
                    alerts.append(
                        ThreatAlert(
                            alert_id=f"ALT_JA3_{self._alert_counter:06d}",
                            timestamp=ts,
                            src_ip=ip.src_ip,
                            dst_ip=ip.dst_ip,
                            src_port=tcp.src_port,
                            dst_port=tcp.dst_port,
                            protocol="TCP/TLS",
                            severity=AlertSeverity.CRITICAL,
                            anomaly_type=AnomalyType.SUSPICIOUS_JA3,
                            description=f"Malicious C2/Malware TLS Handshake: {malware_name}",
                            metadata={
                                "ja3_hash": client_hello.ja3_hash,
                                "sni": client_hello.sni or "UNKNOWN",
                                "raw_ja3": client_hello.raw_ja3_string,
                            },
                        )
                    )

        # C. Streaming Aho-Corasick Signature Matching on TCP Payload
        if tcp.payload:
            matches = self.matcher.search(tcp.payload)
            for offset, sig_name in matches:
                self._alert_counter += 1
                alerts.append(
                    ThreatAlert(
                        alert_id=f"ALT_SIG_{self._alert_counter:06d}",
                        timestamp=ts,
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                        protocol="TCP",
                        severity=AlertSeverity.HIGH,
                        anomaly_type=AnomalyType.C2_BEACON_MATCH,
                        description=f"Payload signature match: {sig_name} at byte offset {offset}",
                        metadata={"offset": offset, "signature": sig_name},
                    )
                )

        return alerts

    def get_all_alerts(self) -> List[ThreatAlert]:
        return list(self._alerts)

    def get_telemetry(self) -> dict:
        return {
            "packets_inspected": self.packets_inspected,
            "bytes_processed": self.bytes_processed,
            "total_alerts": len(self._alerts),
        }
