# AegisFlow-DPI

High-Throughput Deep Packet Inspection (DPI) and Protocol Anomaly Detection Engine.

Designed for Critical Information Infrastructure (CII) protection, national telecommunications monitoring, and Security Operations Centers (SOCs) under cybersecurity regulatory standards (such as Ghana Cyber Security Authority Act 1038 / Critical Information Infrastructure Directives). Built from first principles to provide zero-copy protocol disassembly, Shannon entropy covert channel detection, and cryptographic TLS JA3 fingerprinting without SSL decryption.

---

## 1. Problem Statement: Modern Network Evasion Vectors

Conventional L3/L4 firewalls and stateful packet inspection (SPI) engines inspect only IP addresses and port numbers. Modern threat actors bypass perimeter security using stealth evasion techniques:

```
+----------------------------------------------------------------------------------------------------+
|                               NETWORK EVASION THREAT MATRIX                                        |
+----------------------------------------------------------------------------------------------------+
| Threat Vector             | Attack Mechanism                       | Defense in AegisFlow-DPI      |
+---------------------------+----------------------------------------+-------------------------------+
| Covert DNS Tunneling      | Exfiltrates stolen databases/credentials| Real-time Shannon Entropy     |
| (Iodine, Cobalt Strike)   | via Base64/Hex subdomain labels on 53  | calculation on RFC 1035 QNAMEs|
+---------------------------+----------------------------------------+-------------------------------+
| Encrypted C2 Handshakes   | Reverse HTTPS shells using Cobalt      | Deterministic JA3/JA4 MD5 and |
| (Meterpreter, TrickBot)   | Strike or Metasploit stagers           | SHA-256 Client Hello hashing  |
+---------------------------+----------------------------------------+-------------------------------+
| Stealth TCP Scans         | Evasive port reconnaissance using NULL | Control bit flag evaluation   |
| (Nmap -sN, -sX)           | (no flags) or XMAS (FIN+PSH+URG) flags | against RFC 793 invariants    |
+---------------------------+----------------------------------------+-------------------------------+
| Multi-Signature WebShells | WebShell execution and Linux password  | Streaming Aho-Corasick trie   |
| (r57, c99, command exec)  | file extraction over unencrypted HTTP  | multi-pattern search in O(n)  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Core Security Primitives

### 1. Shannon Entropy DNS Tunneling Detection

DNS exfiltration encodes high-entropy encrypted or compressed data into subdomain labels:
`VGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZAo.c2.attacker.net`

AegisFlow evaluates the informational entropy of the leftmost subdomain label:

$$H(X) = -\sum_{i=1}^{k} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the probability of character $x_i$ occurring in the label string.
* **Benign Domains:** Standard phonetic domains (`google.com`, `ghana.gov.gh`) exhibit $H \approx 1.8 - 3.2$ bits/symbol.
* **Covert Tunneling:** Base64 or Hex encoded payloads exhibit $H \ge 3.8$ bits/symbol, triggering an immediate `HIGH` severity `DNS_TUNNELING` alert.

### 2. TLS Client Hello Cryptographic Fingerprinting (JA3 / JA4)

Malware and C2 frameworks use specific SSL/TLS libraries that reveal a deterministic fingerprint during the initial unencrypted TLS Client Hello handshake:

$$\text{JA3\_String} = \text{SSLVersion},\text{Ciphers},\text{Extensions},\text{EllipticCurves},\text{PointFormats}$$

$$\text{JA3\_MD5} = \text{MD5}(\text{JA3\_String})$$

AegisFlow parses the Client Hello, filters out RFC 8701 GREASE values, and checks the resulting digest against known malware and C2 signatures (e.g. Cobalt Strike, TrickBot, Metasploit reverse HTTPS) without requiring private SSL decryption keys.

### 3. Streaming Aho-Corasick Multi-Pattern Search

Rather than iterating sequentially through thousands of byte patterns in $O(n \times m)$, AegisFlow compiles signatures into an Aho-Corasick Trie with Breadth-First Search (BFS) suffix failure links, scanning raw packet byte streams in linear $O(n)$ time.

---

## 3. Architecture & Data Flow

```
                      RAW PCAP / NETWORK WIRE INGRESS
                                     |
                                     v
                 +---------------------------------------+
                 |    Layer 2: Ethernet Frame Decoder    |
                 |  - MAC Unpack & EtherType Filtering   |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |     Layer 3: IPv4 Packet Decoder      |
                 |  - Version, IHL, TTL, Protocol Check  |
                 +---------------------------------------+
                                     |
                    +----------------+----------------+
                    |                                 |
                    v (Protocol = 17)                 v (Protocol = 6)
   +---------------------------------+   +---------------------------------+
   |      Layer 4: UDP Datagram      |   |       Layer 4: TCP Segment      |
   +---------------------------------+   +---------------------------------+
                    |                                     |
                    v (Port = 53)                         +-----------------+
   +---------------------------------+                    |                 |
   |      RFC 1035 DNS Decoder       |                    v                 v
   |  - QNAME extraction             |          +------------------+ +-----------------+
   |  - Shannon Entropy Audit        |          | TCP Flags Audit  | | TLS JA3 Codec   |
   +---------------------------------+          | - NULL Scan      | | - Client Hello  |
                    |                           | - XMAS Scan      | | - MD5/SHA256    |
                    |                           +------------------+ +-----------------+
                    |                                     |                 |
                    +------------------+------------------+-----------------+
                                       |
                                       v
                     +-----------------------------------+
                     |   Streaming Aho-Corasick Matcher  |
                     |  - Multi-pattern payload scan     |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |       Threat Alert Generator      |
                     |  - Severity, 5-Tuple, Metadata    |
                     +-----------------------------------+
```

---

## 4. Performance Benchmarks

Micro-benchmarks executed on commodity 64-bit hardware (Python 3.13):

```text
=================================================================
AEGISFLOW-DPI BENCHMARK: 50,000 PACKETS
=================================================================
Packet Frame Size:      121 bytes
Total Inspection Time:  2.767 seconds
Inspection Throughput:  18,070.0 packets / second
=================================================================
```

* **Multi-Layer Zero-Copy Processing:** Disassembles Ethernet, IPv4, and TCP headers and evaluates Aho-Corasick signatures at **18,070 packets per second**.

---

## 5. Project Map

```
AegisFlow-DPI/
|-- aegisflow/
|   |-- __init__.py         # Public exports and API surface
|   |-- types.py            # Protocol enums, AlertSeverity, AnomalyType
|   |-- framing.py          # Zero-copy Ethernet, IPv4, TCP, UDP decoders
|   |-- dns.py              # DNS RFC 1035 parser and Shannon entropy tunneling detector
|   |-- tls.py              # TLS Client Hello parser and JA3/JA4 fingerprinting
|   |-- matcher.py          # Streaming Aho-Corasick multi-pattern search engine
|   |-- pcap.py             # Binary libpcap file reader and writer
|   |-- engine.py           # AegisFlowEngine multi-layer coordinator and flow tracker
|   |-- cli.py              # CLI for PCAP forensic analysis, entropy audit, bench
|-- tests/
|   |-- test_framing.py     # Layer 2/3/4 unpack and truncated buffer handling
|   |-- test_dns.py         # DNS unpacking and Shannon entropy verification
|   |-- test_tls.py         # TLS Client Hello unpacking and JA3 calculation
|   |-- test_matcher.py     # Aho-Corasick multi-pattern search in O(n)
|   |-- test_pcap_and_engine.py # PCAP I/O and end-to-end anomaly engine detection
|-- pyproject.toml          # Package metadata and CLI hook
|-- requirements.txt        # Frozen dependencies
|-- LICENSE                 # MIT License (Huighlet Eyram Zowonu)
|-- README.md               # Technical specification and documentation
```

---

## 6. Installation & Quickstart

### Setup Environment

```bash
git clone https://github.com/Huighlet/AegisFlow-DPI.git
cd AegisFlow-DPI

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\Activate.ps1

pip install -e .
```

### Python API Example

```python
from aegisflow import AegisFlowEngine, PCAPReader

# 1. Initialize DPI engine
engine = AegisFlowEngine(dns_entropy_threshold=3.8)

# 2. Ingest packets from PCAP capture
reader = PCAPReader("network_capture.pcap")
for ts, packet_bytes in reader.packets():
    alerts = engine.inspect_raw_packet(packet_bytes, timestamp=ts)
    for alert in alerts:
        print(f"[{alert.severity.name}] {alert.anomaly_type.name}: {alert.description}")

# 3. Query telemetry
telemetry = engine.get_telemetry()
print(f"Inspected {telemetry['packets_inspected']} packets with {telemetry['total_alerts']} alerts.")
```

---

## 7. Turnkey REST Threat Forensics Server & Docker Deployment

AegisFlow-DPI includes a production-grade FastAPI REST inspection daemon and interactive Cyber Threat Forensics dashboard.

### 1. Launch Server via CLI

```bash
# Start standalone forensics service on port 8080
aegisflow serve --host 0.0.0.0 --port 8080
```

Once initialized:
- **Interactive Threat Forensics UI:** [`http://localhost:8080/`](http://localhost:8080/)
- **Interactive Swagger / OpenAPI Docs:** [`http://localhost:8080/docs`](http://localhost:8080/docs)
- **Engine Health & Inspection Telemetry:** [`http://localhost:8080/health`](http://localhost:8080/health)
- **Threat Alerts Query:** [`http://localhost:8080/v1/alerts`](http://localhost:8080/v1/alerts)
- **Active 5-Tuple Network Flows:** [`http://localhost:8080/v1/flows`](http://localhost:8080/v1/flows)

### 2. Standalone Container Execution (Docker)

```bash
# Build production image
docker build -t aegisflow-dpi:latest .

# Run standalone container
docker run -d --name aegisflow-daemon -p 8080:8080 aegisflow-dpi:latest

# Verify service health
curl -s http://localhost:8080/health
```

### 3. REST API Forensics Usage Examples

**Inspect Raw Packet Wire Bytes (Hex):**
```bash
curl -X POST http://localhost:8080/v1/inspect/packet \
  -H "Content-Type: application/json" \
  -d '{
    "packet_hex": "00112233445566778899aabb08004500004b1234400040060000c0a801050a000001ad21005000000001000000005018721000000000504f5354202f20485454502f312e310d0a0d0a636d642e657865202f632077686f616d69"
  }'
```

**Audit Domain for DNS Covert Tunneling (Shannon Entropy):**
```bash
curl -X POST http://localhost:8080/v1/audit/entropy \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "VGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZAo.c2.attacker.net",
    "threshold": 3.8
  }'
```

**Upload PCAP Capture File for Automated Forensics:**
```bash
curl -X POST http://localhost:8080/v1/inspect/pcap \
  -F "file=@incident_traffic.pcap"
```

---

## 8. CLI Usage

### 1. Forensic PCAP Analysis

```bash
aegisflow analyze --pcap incident_traffic.pcap
```

Output:
```text
Analyzing PCAP capture: incident_traffic.pcap ...
=================================================================
AEGISFLOW-DPI FORENSIC ANALYSIS SUMMARY
=================================================================
Packets Inspected:      4
Bytes Processed:        353 bytes
Elapsed Processing Time:0.016 seconds
Threat Alerts Generated:4
-----------------------------------------------------------------
Detected Threat Alerts:

[1] HIGH | C2_BEACON_MATCH (TCP)
    Flow:   192.168.1.5:44321 -> 10.0.0.1:80
    Detail: Payload signature match: Windows Command Execution WebShell at byte offset 22

[2] HIGH | C2_BEACON_MATCH (TCP)
    Flow:   192.168.1.5:44321 -> 10.0.0.1:80
    Detail: Payload signature match: Privilege Reconnaissance Indicator at byte offset 36

[3] MEDIUM | TCP_XMAS_SCAN (TCP)
    Flow:   192.168.1.5:44321 -> 10.0.0.1:80
    Detail: Stealth XMAS Port Scan: TCP packet received with FIN, PSH, and URG flags set.

[4] HIGH | DNS_TUNNELING (UDP/DNS)
    Flow:   192.168.1.5:5000 -> 8.8.8.8:53
    Detail: Covert DNS exfiltration tunnel detected: High Shannon entropy (4.33 >= 3.8) indicates Base64/Hex exfiltration
=================================================================
```

### 2. Shannon Entropy Audit of Domain Queries

```bash
aegisflow entropy --domain "VGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZAo.c2.attacker.net"
```

Output:
```text
=================================================================
DNS SHANNON ENTROPY AUDIT: VGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZAo.c2.attacker.net
=================================================================
Full Domain Entropy:    4.6599 bits/symbol
Subdomain Payload Ent:  4.3328 bits/symbol
Tunneling Detected:     True
Diagnosis:              High Shannon entropy (4.33 >= 3.8) indicates Base64/Hex exfiltration
=================================================================
```

### 3. Run Throughput Benchmarks

```bash
aegisflow bench -n 50000
```

---

## 9. Test Suite Execution

Run the complete 22-case test suite covering protocol decoders, Shannon entropy math, JA3 hashing, Aho-Corasick matching, and REST forensics endpoints:

```bash
pytest -v
```

All 22 test scenarios pass deterministically:
```text
tests/test_dns.py::test_shannon_entropy_calculation PASSED
tests/test_dns.py::test_dns_wire_unpack PASSED
tests/test_dns.py::test_dns_tunneling_detection_alert PASSED
tests/test_dns.py::test_benign_dns_query_clean PASSED
tests/test_framing.py::test_ethernet_unpack PASSED
tests/test_framing.py::test_ipv4_unpack PASSED
tests/test_framing.py::test_tcp_unpack_flags PASSED
tests/test_framing.py::test_udp_unpack PASSED
tests/test_framing.py::test_truncated_buffer_raises PASSED
tests/test_matcher.py::test_aho_corasick_single_and_multiple_matches PASSED
tests/test_matcher.py::test_aho_corasick_overlapping_patterns PASSED
tests/test_matcher.py::test_no_matches_clean PASSED
tests/test_pcap_and_engine.py::test_pcap_roundtrip_write_read PASSED
tests/test_pcap_and_engine.py::test_engine_detects_port_scans PASSED
tests/test_pcap_and_engine.py::test_engine_detects_c2_payload_signature PASSED
tests/test_server.py::test_health_check PASSED
tests/test_server.py::test_dashboard_ui PASSED
tests/test_server.py::test_entropy_audit_endpoint PASSED
tests/test_server.py::test_inspect_packet_with_c2_signature PASSED
tests/test_server.py::test_custom_signature_endpoint PASSED
tests/test_tls.py::test_tls_client_hello_ja3_extraction PASSED
tests/test_tls.py::test_non_tls_returns_none PASSED
```

---

## 10. License

MIT License. Copyright (c) 2026 Huighlet Eyram Zowonu.
