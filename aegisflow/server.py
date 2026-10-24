"""
AegisFlow-DPI: Production Deep Packet Inspection & Threat Forensics Server.
Provides real-time packet inspection, PCAP capture forensic processing,
DNS tunneling entropy auditing, TLS JA3 fingerprinting, and an interactive developer UI.
"""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from aegisflow.dns import analyze_dns_tunneling, calculate_shannon_entropy
from aegisflow.engine import AegisFlowEngine, ThreatAlert
from aegisflow.pcap import PCAPReader


# ---------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------

class PacketInspectRequest(BaseModel):
    packet_hex: str = Field(..., description="Raw hex-encoded Layer 2 (Ethernet) or Layer 3 packet bytes")
    timestamp: Optional[float] = Field(None, description="Capture timestamp in epoch seconds")


class EntropyAuditRequest(BaseModel):
    domain: str = Field(..., description="Fully Qualified Domain Name (FQDN) or DNS query label")
    threshold: float = Field(3.8, description="Shannon entropy threshold (bits/symbol)")


class CustomSignatureRequest(BaseModel):
    pattern: str = Field(..., description="Malicious byte sequence or text pattern")
    signature_name: str = Field(..., description="Rule or malware family classification name")


class IntelIndicator(BaseModel):
    pattern: str = Field(..., description="Malicious IOC pattern")
    signature_name: str = Field(..., description="Threat classification name")


class IntelSyncRequest(BaseModel):
    indicators: List[IntelIndicator] = Field(..., description="List of threat indicators to ingest")


# ---------------------------------------------------------
# Engine Initialization
# ---------------------------------------------------------

app = FastAPI(
    title="AegisFlow-DPI Threat Forensics Engine",
    description="Zero-copy Deep Packet Inspection microservice with TLS JA3/JA4 fingerprinting, DNS Shannon entropy tunneling detection, and streaming Aho-Corasick signature matching.",
    version="1.0.0",
)

engine = AegisFlowEngine()


class DPIRateLimiter:
    """Token bucket rate limiter for packet ingestion."""
    def __init__(self, capacity: int = 2000, refill_rate: float = 500.0) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self.last_ts = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> Tuple[bool, int]:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_ts
            self.last_ts = now
            self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, int(self.tokens)
            return False, 0


_limiter = DPIRateLimiter(capacity=2000, refill_rate=500.0)


@app.middleware("http")
async def enterprise_middleware(request: Request, call_next):
    allowed, remaining = _limiter.consume()
    if not allowed:
        return Response(
            content='{"detail": "Rate limit exceeded. Sensor saturated."}',
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={"Retry-After": "1"},
        )

    configured_key = os.environ.get("AEGISFLOW_API_KEY")
    if configured_key and request.url.path.startswith("/v1/"):
        req_key = request.headers.get("X-API-Key")
        if req_key != configured_key:
            return Response(
                content='{"detail": "Unauthorized: Invalid or missing X-API-Key header"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )

    response = await call_next(request)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


@app.get("/metrics", response_class=PlainTextResponse, tags=["Observability"])
def get_metrics() -> PlainTextResponse:
    """Prometheus metrics endpoint for packet processing and detected anomalies."""
    telem = engine.get_telemetry()
    lines = [
        "# HELP aegisflow_packets_inspected_total Total network frames analyzed",
        "# TYPE aegisflow_packets_inspected_total counter",
        f"aegisflow_packets_inspected_total {telem['packets_inspected']}",
        "# HELP aegisflow_bytes_inspected_total Total payload bytes processed",
        "# TYPE aegisflow_bytes_inspected_total counter",
        f"aegisflow_bytes_inspected_total {telem['bytes_processed']}",
        "# HELP aegisflow_threat_alerts_total Total security alerts triggered",
        "# TYPE aegisflow_threat_alerts_total counter",
        f"aegisflow_threat_alerts_total {telem['total_alerts']}",
        "# HELP aegisflow_active_signatures_total Number of registered detection patterns",
        "# TYPE aegisflow_active_signatures_total gauge",
        f"aegisflow_active_signatures_total {len(engine.matcher)}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")


# ---------------------------------------------------------
# Developer UI Dashboard
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def forensics_dashboard():
    """Interactive Cyber Threat Forensics & DPI Dashboard."""
    telem = engine.get_telemetry()
    recent_alerts = engine.get_all_alerts()[-5:]

    alerts_rows = "".join(
        f"<tr><td><code>{a.alert_id}</code></td><td><strong>{a.severity.name}</strong></td><td>{a.anomaly_type.name}</td><td>{a.src_ip}:{a.src_port} &rarr; {a.dst_ip}:{a.dst_port}</td><td>{a.description}</td></tr>"
        for a in recent_alerts
    )
    if not alerts_rows:
        alerts_rows = "<tr><td colspan='5' style='text-align:center;color:#9ca3af;'>No alerts recorded yet. Submit a packet below to begin analysis.</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AegisFlow-DPI Threat Forensics</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 32px; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            h1 {{ color: #ef4444; margin-top: 0; font-size: 24px; font-weight: 600; }}
            p {{ color: #9ca3af; font-size: 14px; line-height: 1.5; }}
            .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }}
            .card {{ background: #1f2937; padding: 14px; border-radius: 6px; border-left: 3px solid #ef4444; }}
            .card-label {{ font-size: 11px; text-transform: uppercase; color: #9ca3af; }}
            .card-val {{ font-size: 22px; font-weight: 700; color: #f9fafb; margin-top: 4px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
            th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #374151; }}
            th {{ background: #1f2937; color: #9ca3af; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
            .btn {{ display: inline-block; padding: 9px 16px; border-radius: 6px; background: #dc2626; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 600; margin-right: 8px; }}
            .btn:hover {{ background: #b91c1c; }}
            code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; color: #fca5a5; }}
            pre {{ background: #030712; padding: 14px; border-radius: 6px; color: #fca5a5; font-size: 12px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AegisFlow-DPI Threat Forensics & Deep Packet Inspection</h1>
            <p>Institutional network security telemetry microservice providing zero-copy protocol decoding, JA3 C2 detection, DNS entropy tunneling alerts, and streaming Aho-Corasick matching.</p>

            <div class="metrics">
                <div class="card">
                    <div class="card-label">Packets Inspected</div>
                    <div class="card-val">{telem['packets_inspected']:,}</div>
                </div>
                <div class="card">
                    <div class="card-label">Bytes Processed</div>
                    <div class="card-val">{telem['bytes_processed']:,} B</div>
                </div>
                <div class="card">
                    <div class="card-label">Threat Alerts</div>
                    <div class="card-val">{telem['total_alerts']:,}</div>
                </div>
            </div>

            <p>
                <a href="/docs" class="btn">Explore OpenAPI / Swagger &rarr;</a>
                <a href="/v1/alerts" class="btn" style="background: #374151;">All Threat Alerts</a>
            </p>

            <h3>Recent Threat Detections</h3>
            <table>
                <thead>
                    <tr><th>Alert ID</th><th>Severity</th><th>Anomaly Type</th><th>Flow (Src &rarr; Dst)</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {alerts_rows}
                </tbody>
            </table>

            <h3>Quick Packet Analysis Example</h3>
            <pre># Submit raw Ethernet + IPv4 + TCP packet hex
curl -X POST http://localhost:8080/v1/inspect/packet \\
  -H "Content-Type: application/json" \\
  -d '{{"packet_hex": "00112233445566778899aabb08004500003c1234400040060000c0a801050a000001ad21005000000001000000005012721000000000"}}'</pre>
        </div>
    </body>
    </html>
    """


# ---------------------------------------------------------
# Health & Telemetry Endpoints
# ---------------------------------------------------------

@app.get("/health")
def health():
    """Liveness probe and engine telemetry counters."""
    return {
        "status": "HEALTHY",
        "timestamp_ns": time.time_ns(),
        "telemetry": engine.get_telemetry(),
        "active_flows_count": len(engine._flows),
    }


@app.get("/v1/alerts")
def get_alerts():
    """Retrieve all detected threat alerts."""
    alerts = engine.get_all_alerts()
    return {
        "count": len(alerts),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
                "protocol": a.protocol,
                "severity": a.severity.name,
                "anomaly_type": a.anomaly_type.name,
                "description": a.description,
                "metadata": a.metadata,
            }
            for a in alerts
        ],
    }


@app.get("/v1/flows")
def get_flows():
    """Inspect active 5-tuple conversations and telemetry."""
    flows = [
        {
            "flow_id": f.flow_id,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol.name,
            "packets_count": f.packets_count,
            "bytes_count": f.bytes_count,
            "syn_count": f.syn_count,
            "ack_count": f.ack_count,
            "start_time": f.start_time,
            "last_seen": f.last_seen,
        }
        for f in engine._flows.values()
    ]
    return {"count": len(flows), "flows": flows}


# ---------------------------------------------------------
# Inspection & Forensics Endpoints
# ---------------------------------------------------------

@app.post("/v1/inspect/packet")
def inspect_packet(req: PacketInspectRequest):
    """
    Ingest a raw hex packet frame, execute zero-copy decoding and DPI signatures,
    and return forensic analysis with any triggered threat alerts.
    """
    clean_hex = req.packet_hex.strip().replace(" ", "").replace("\n", "")
    try:
        raw_bytes = bytes.fromhex(clean_hex)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}")

    alerts = engine.inspect_raw_packet(raw_bytes, timestamp=req.timestamp)

    return {
        "bytes_inspected": len(raw_bytes),
        "alerts_count": len(alerts),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "severity": a.severity.name,
                "anomaly_type": a.anomaly_type.name,
                "protocol": a.protocol,
                "src": f"{a.src_ip}:{a.src_port}",
                "dst": f"{a.dst_ip}:{a.dst_port}",
                "description": a.description,
                "metadata": a.metadata,
            }
            for a in alerts
        ],
    }


@app.post("/v1/inspect/pcap")
async def inspect_pcap_upload(file: UploadFile = File(...)):
    """
    Upload a PCAP capture file for automated forensic inspection and threat timeline extraction.
    """
    content = await file.read()
    if len(content) < 24:
        raise HTTPException(status_code=400, detail="Invalid PCAP file: header too short.")

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        reader = PCAPReader(tmp_path)
        pcap_alerts = []
        packet_count = 0
        t0 = time.perf_counter()

        for ts, pkt_bytes in reader.packets():
            packet_count += 1
            new_alerts = engine.inspect_raw_packet(pkt_bytes, timestamp=ts)
            pcap_alerts.extend(new_alerts)

        elapsed = time.perf_counter() - t0

        return {
            "filename": file.filename,
            "packets_inspected": packet_count,
            "elapsed_seconds": round(elapsed, 4),
            "threat_alerts_detected": len(pcap_alerts),
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity.name,
                    "anomaly_type": a.anomaly_type.name,
                    "protocol": a.protocol,
                    "src": f"{a.src_ip}:{a.src_port}",
                    "dst": f"{a.dst_ip}:{a.dst_port}",
                    "description": a.description,
                }
                for a in pcap_alerts
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"PCAP parsing error: {e}")


@app.post("/v1/audit/entropy")
def audit_dns_entropy(req: EntropyAuditRequest):
    """
    Calculate Shannon entropy of a domain name to detect DNS data exfiltration and tunneling.
    """
    full_entropy = calculate_shannon_entropy(req.domain)
    is_suspicious, sub_entropy, reason = analyze_dns_tunneling(
        req.domain, entropy_threshold=req.threshold
    )

    return {
        "domain": req.domain,
        "full_entropy": round(full_entropy, 4),
        "subdomain_entropy": round(sub_entropy, 4),
        "threshold": req.threshold,
        "is_tunneling_detected": is_suspicious,
        "diagnosis": reason,
    }


@app.post("/v1/signatures", status_code=status.HTTP_201_CREATED)
def add_custom_signature(req: CustomSignatureRequest):
    """Register custom signature into streaming Aho-Corasick matching automaton."""
    engine.register_custom_signature(req.pattern.encode("utf-8"), req.signature_name)
    return {"registered": True, "signature_name": req.signature_name}


@app.post("/v1/intel/sync", status_code=status.HTTP_200_OK, tags=["Threat Intelligence"])
def sync_threat_intel(req: IntelSyncRequest) -> Dict[str, Any]:
    """Ingest external IOC threat intelligence indicators into the matching automaton."""
    added = 0
    for ind in req.indicators:
        engine.register_custom_signature(ind.pattern.encode("utf-8"), ind.signature_name)
        added += 1
    return {
        "status": "SYNCED",
        "indicators_added": added,
        "total_signatures": len(engine.matcher),
    }


@app.post("/v1/forensics/export", tags=["Forensics"])
def export_forensic_incident_report() -> Dict[str, Any]:
    """Export complete incident report with threat timeline, IOC attribution, and cryptographic seal."""
    alerts = engine.get_all_alerts()
    incident_id = f"INCIDENT_{time.strftime('%Y%m%d_%H%M%S')}"

    severities: Dict[str, int] = {}
    for a in alerts:
        sev = a.severity.name
        severities[sev] = severities.get(sev, 0) + 1

    seal = hashlib.sha256(f"{incident_id}:{len(alerts)}:{severities}".encode("utf-8")).hexdigest()

    return {
        "incident_id": incident_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "integrity_seal": seal,
        "total_threat_alerts": len(alerts),
        "severity_breakdown": severities,
        "timeline": [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp,
                "severity": a.severity.name,
                "anomaly_type": a.anomaly_type.name,
                "src": f"{a.src_ip}:{a.src_port}",
                "dst": f"{a.dst_ip}:{a.dst_port}",
                "description": a.description,
            }
            for a in alerts[-50:]  # Recent 50
        ],
    }


def serve(host: str = "0.0.0.0", port: int = 8080):
    """Launch AegisFlow REST Forensics service."""
    import uvicorn
    uvicorn.run("aegisflow.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    serve()
