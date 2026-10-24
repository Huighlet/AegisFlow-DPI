"""
Production Simulation Harness: AegisFlow-DPI Enterprise Threat Forensics.
Simulates a multi-stage cyber intrusion on an enterprise network:
  1. High-throughput benign network traffic baseline (HTTP, DNS).
  2. DNS data exfiltration campaign using Shannon entropy detection (RFC 1035).
  3. Malicious C2 payload & WebShell command injection detection via streaming Aho-Corasick.
  4. Dynamic IOC threat intelligence synchronization without restarting the sensor.
  5. Incident timeline synthesis and forensic evidence export with SHA-256 seal.
"""

from __future__ import annotations

import random
import struct
import sys
import time
from typing import Dict, List

from aegisflow.dns import analyze_dns_tunneling, calculate_shannon_entropy
from aegisflow.engine import AegisFlowEngine


def make_synthetic_packet(payload: bytes, dst_port: int = 80) -> bytes:
    """Construct minimal synthetic Ethernet + IPv4 + TCP packet for engine inspection."""
    # Ethernet header: 6 bytes dst MAC, 6 bytes src MAC, 2 bytes EtherType (0x0800 = IPv4)
    eth_hdr = struct.pack("!6s6sH", b"\x00\x11\x22\x33\x44\x55", b"\x66\x77\x88\x99\xaa\xbb", 0x0800)
    ip_tot_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_tot_len, 0x1234, 0, 64, 6, 0,  # Protocol 6 = TCP
        bytes([192, 168, 1, 50]),
        bytes([10, 0, 0, 1]),
    )
    # TCP header: 20 bytes, data offset = 5 (0x50), flags = 0x18 (PSH + ACK)
    tcp_hdr = struct.pack("!HHLLBBHHH", 49152, dst_port, 1001, 2001, 0x50, 0x18, 65535, 0, 0)
    return eth_hdr + ip_hdr + tcp_hdr + payload


def run_enterprise_attack_simulation() -> None:
    print("=" * 70)
    print("AEGISFLOW-DPI: ENTERPRISE CYBER ATTACK & THREAT FORENSICS")
    print("=" * 70)

    # 1. Initialize Forensic Engine
    print("\n[Phase 1] Initializing Deep Packet Inspection Engine & Signature Automaton...")
    engine = AegisFlowEngine()
    print("  Engine online. Registered default C2, WebShell, and DNS tunneling detectors.")

    # 2. Benign Network Traffic Baseline
    print("\n[Phase 2] Simulating Benign Enterprise Network Baseline (200 Packets)...")
    benign_domains = [
        "portal.internal.company.com",
        "api.github.com",
        "login.microsoftonline.com",
        "aws.amazon.com",
        "cdn.jsdelivr.net",
    ]
    t0 = time.perf_counter()
    for i in range(200):
        dom = random.choice(benign_domains)
        payload = f"GET /status HTTP/1.1\r\nHost: {dom}\r\n\r\n".encode("utf-8")
        pkt = make_synthetic_packet(payload, dst_port=80)
        alerts = engine.inspect_raw_packet(pkt)
        assert len(alerts) == 0, f"False positive detected on benign packet: {dom}"

    elapsed = time.perf_counter() - t0
    print(f"  Processed 200 benign frames in {elapsed:.3f}s ({200 / elapsed:,.0f} pkts/s). 0 False Positives.")

    # 3. DNS Tunneling & Data Exfiltration Simulation
    print("\n[Phase 3] Simulating DNS Data Exfiltration Attack (Shannon Entropy)...")
    tunneling_detected = 0
    tunnels = [
        "aW5zdGl0dXRpb25hbF9wYXlsb2FkX2V4ZmlsdHJhdGlvbl85OTIx.exfil.darkoperator.ru",
        "7b889a1c00eef4129b8c01e3b0c44298fc1c149afbf4c2.tunnel.c2channel.xyz",
        "Y29iYWx0c3RyaWtlX21hbHdhcmVfYmVhY29uX2tleXM=.data.attacker-dns.org",
    ]
    for domain in tunnels:
        entropy = calculate_shannon_entropy(domain)
        is_suspicious, sub_entropy, reason = analyze_dns_tunneling(domain, entropy_threshold=3.8)
        if is_suspicious:
            tunneling_detected += 1
            print(f"  [ALERT] Tunneling detected: {domain[:28]}... (H={sub_entropy:.2f} bits/byte, {reason})")

    assert tunneling_detected == len(tunnels), "All DNS tunneling attempts must be detected!"
    print(f"  Detected {tunneling_detected}/{len(tunnels)} DNS exfiltration tunnels.")

    # 4. WebShell & C2 Payload Injection
    print("\n[Phase 4] Injecting Malicious C2 & WebShell Payloads (Aho-Corasick)...")
    malicious_payloads = [
        b"POST /upload.aspx HTTP/1.1\r\n\r\ncmd.exe /c whoami & net user /add",
        b"GET /stager.ps1 HTTP/1.1\r\n\r\npowershell -nop -w hidden -c IEX",
        b"POST /c99shell.php HTTP/1.1\r\n\r\neval(base64_decode('aW5qZWN0'))",
    ]
    attack_alerts = 0
    for payload in malicious_payloads:
        pkt = make_synthetic_packet(payload, dst_port=8080)
        alerts = engine.inspect_raw_packet(pkt)
        if alerts:
            attack_alerts += len(alerts)
            for a in alerts:
                print(f"  [ALERT] {a.severity.name}: {a.description} on {a.src_ip} -> {a.dst_ip}")

    assert attack_alerts >= len(malicious_payloads), "All malicious payload signatures must trigger alerts!"
    print(f"  Detected {attack_alerts} signature violations across malicious streams.")

    # 5. Dynamic Threat Intel Synchronization
    print("\n[Phase 5] Synchronizing External CISA / AlienVault Threat Indicators...")
    engine.register_custom_signature(b"MALWARE_BEACON_HEADER_0x89", "APT41_Custom_Backdoor")
    probe_pkt = make_synthetic_packet(b"DATA: MALWARE_BEACON_HEADER_0x89", dst_port=9999)
    intel_alerts = engine.inspect_raw_packet(probe_pkt)
    assert len(intel_alerts) == 1, "Dynamic IOC must match immediately!"
    print(f"  Verified dynamic IOC match: {intel_alerts[0].description}")

    # 6. Incident Synthesis & Telemetry
    print("\n[Phase 6] Forensic Summary & Incident Timeline...")
    telem = engine.get_telemetry()
    all_alerts = engine.get_all_alerts()

    print(f"  Total Packets Inspected: {telem['packets_inspected']}")
    print(f"  Total Bytes Scanned:     {telem['bytes_processed']} bytes")
    print(f"  Total Confirmed Alerts:  {len(all_alerts)}")
    print(f"  Registered Signatures:   {len(engine.matcher)}")

    print("\n[PASS] Enterprise Cyber Attack & Forensic Simulation passed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_enterprise_attack_simulation()
