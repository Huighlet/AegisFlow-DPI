"""
AegisFlow-DPI CLI: Command-Line Utilities for PCAP Forensics, Entropy Auditing, and DPI Benchmarks.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from aegisflow.dns import analyze_dns_tunneling, calculate_shannon_entropy
from aegisflow.engine import AegisFlowEngine
from aegisflow.pcap import PCAPReader, PCAPWriter
from aegisflow.tls import TLSParser


def cmd_analyze(pcap_path: str) -> None:
    """Analyze a PCAP file and output detected threat alerts."""
    reader = PCAPReader(pcap_path)
    engine = AegisFlowEngine()

    print(f"Analyzing PCAP capture: {pcap_path} ...")
    t0 = time.perf_counter()

    for ts, pkt_bytes in reader.packets():
        engine.inspect_raw_packet(pkt_bytes, timestamp=ts)

    elapsed = time.perf_counter() - t0
    alerts = engine.get_all_alerts()
    telemetry = engine.get_telemetry()

    print("=" * 65)
    print("AEGISFLOW-DPI FORENSIC ANALYSIS SUMMARY")
    print("=" * 65)
    print(f"Packets Inspected:      {telemetry['packets_inspected']:,}")
    print(f"Bytes Processed:        {telemetry['bytes_processed']:,} bytes")
    print(f"Elapsed Processing Time:{elapsed:.3f} seconds")
    if elapsed > 0:
        print(f"Processing Throughput:  {telemetry['packets_inspected'] / elapsed:,.1f} packets/sec")
    print(f"Threat Alerts Generated:{len(alerts)}")
    print("-" * 65)

    if not alerts:
        print("[CLEAN] No threat signatures or protocol anomalies detected.")
    else:
        print("Detected Threat Alerts:")
        for idx, alt in enumerate(alerts, 1):
            print(f"\n[{idx}] {alt.severity.name} | {alt.anomaly_type.name} ({alt.protocol})")
            print(f"    Flow:   {alt.src_ip}:{alt.src_port} -> {alt.dst_ip}:{alt.dst_port}")
            print(f"    Detail: {alt.description}")
            if alt.metadata:
                print(f"    Meta:   {alt.metadata}")
    print("=" * 65)


def cmd_entropy(domain: str) -> None:
    """Analyze Shannon entropy and exfiltration risk of a domain query."""
    full_entropy = calculate_shannon_entropy(domain)
    is_suspicious, sub_ent, reason = analyze_dns_tunneling(domain)

    print("=" * 65)
    print(f"DNS SHANNON ENTROPY AUDIT: {domain}")
    print("=" * 65)
    print(f"Full Domain Entropy:    {full_entropy:.4f} bits/symbol")
    print(f"Subdomain Payload Ent:  {sub_ent:.4f} bits/symbol")
    print(f"Tunneling Detected:     {is_suspicious}")
    print(f"Diagnosis:              {reason}")
    print("=" * 65)


def cmd_bench(count: int = 50_000) -> None:
    """Execute high-load micro-benchmarks on packet decoding and DPI signature matching."""
    print("=" * 65)
    print(f"AEGISFLOW-DPI BENCHMARK: {count:,} PACKETS")
    print("=" * 65)

    # Synthetic Ethernet + IPv4 + TCP packet with payload
    # Ethernet Header (14 bytes)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    # IPv4 Header (20 bytes: 192.168.1.5 -> 10.0.0.1, Protocol 6 TCP)
    ip_hdr = b"\x45\x00\x00\x3c\x12\x34\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x05\x0a\x00\x00\x01"
    # TCP Header (20 bytes: port 44321 -> 80, SYN/ACK flags 0x12)
    tcp_hdr = b"\xad\x21\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x12\x72\x10\x00\x00\x00\x00"
    # Payload
    payload = b"GET /index.php HTTP/1.1\r\nHost: target.corp\r\nUser-Agent: Mozilla\r\n\r\n"
    raw_packet = eth_hdr + ip_hdr + tcp_hdr + payload

    engine = AegisFlowEngine()

    t0 = time.perf_counter()
    for _ in range(count):
        engine.inspect_raw_packet(raw_packet)
    elapsed = time.perf_counter() - t0
    pps = count / elapsed

    print(f"Packet Frame Size:      {len(raw_packet)} bytes")
    print(f"Total Inspection Time:  {elapsed:.3f} seconds")
    print(f"Inspection Throughput:  {pps:,.1f} packets / second")
    print("=" * 65)


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegisflow", description="AegisFlow-DPI Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Analyze
    analyze_p = subparsers.add_parser("analyze", help="Analyze PCAP capture file")
    analyze_p.add_argument("--pcap", required=True, help="Path to .pcap file")

    # Entropy
    entropy_p = subparsers.add_parser("entropy", help="Compute Shannon entropy of domain")
    entropy_p.add_argument("--domain", required=True, help="Domain name or FQDN")

    # Bench
    bench_p = subparsers.add_parser("bench", help="Run packet inspection benchmarks")
    bench_p.add_argument("-n", "--count", type=int, default=30000, help="Packet count")

    # Serve
    serve_p = subparsers.add_parser("serve", help="Launch FastAPI Threat Forensics REST service")
    serve_p.add_argument("--host", default="0.0.0.0", help="Binding host address")
    serve_p.add_argument("--port", type=int, default=8080, help="Binding port (default: 8080)")

    args = parser.parse_args()
    if args.command == "serve":
        from aegisflow.server import serve
        serve(host=args.host, port=args.port)
    elif args.command == "analyze":
        cmd_analyze(args.pcap)
    elif args.command == "entropy":
        cmd_entropy(args.domain)
    elif args.command == "bench":
        cmd_bench(args.count)


if __name__ == "__main__":
    main()
