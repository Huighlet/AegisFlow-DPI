"""
AegisFlow Client SDK: Idiomatic high-performance client for the AegisFlow-DPI Threat Forensics Server.
Supports raw packet submission, DNS tunneling entropy audits, dynamic IOC threat intel synchronization, and forensic incident export.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Union

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


class AegisFlowClient:
    """
    Client for interacting with a live AegisFlow-DPI forensic sensor node.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout_seconds: float = 10.0,
        http_client: Optional[Any] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        if http_client is not None:
            self._client = http_client
        elif httpx is not None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        else:
            self._client = None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> AegisFlowClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def inspect_packet(self, packet_bytes_or_hex: Union[bytes, str], timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Submit a raw network frame (Layer 2 Ethernet or Layer 3 IP) for deep packet inspection."""
        hex_str = packet_bytes_or_hex.hex() if isinstance(packet_bytes_or_hex, bytes) else packet_bytes_or_hex
        payload = {"packet_hex": hex_str, "timestamp": timestamp}
        resp = self._client.post("/v1/inspect/packet", json=payload)
        resp.raise_for_status()
        return resp.json()

    def audit_entropy(self, domain: str, threshold: float = 3.8) -> Dict[str, Any]:
        """Perform Shannon entropy audit on a domain name to detect DNS tunneling."""
        resp = self._client.post("/v1/audit/entropy", json={"domain": domain, "threshold": threshold})
        resp.raise_for_status()
        return resp.json()

    def register_signature(self, pattern: str, signature_name: str) -> Dict[str, Any]:
        """Add custom detection rule into streaming Aho-Corasick automaton."""
        resp = self._client.post("/v1/signatures", json={"pattern": pattern, "signature_name": signature_name})
        resp.raise_for_status()
        return resp.json()

    def sync_threat_intel(self, indicators: List[Dict[str, str]]) -> Dict[str, Any]:
        """Dynamically synchronize IOC threat intelligence feeds."""
        resp = self._client.post("/v1/intel/sync", json={"indicators": indicators})
        resp.raise_for_status()
        return resp.json()

    def get_alerts(self) -> Dict[str, Any]:
        """Retrieve detected threat alerts."""
        resp = self._client.get("/v1/alerts")
        resp.raise_for_status()
        return resp.json()

    def export_forensics(self) -> Dict[str, Any]:
        """Export comprehensive forensic incident timeline with integrity signature."""
        resp = self._client.post("/v1/forensics/export")
        resp.raise_for_status()
        return resp.json()

    def get_metrics(self) -> str:
        """Fetch Prometheus metrics."""
        resp = self._client.get("/metrics")
        resp.raise_for_status()
        return resp.text
