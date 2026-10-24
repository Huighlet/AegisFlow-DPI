"""
AegisFlow-DPI: Binary PCAP Capture File Parser and Serializer.
Reads and generates standard libpcap capture traces for forensic analysis.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import BinaryIO, Generator, Tuple

from aegisflow.types import PCAPCorruptError

PCAP_MAGIC_MICROSEC: int = 0xA1B2C3D4
PCAP_MAGIC_NANOSEC: int = 0xA1B23C4D
GLOBAL_HEADER_STRUCT = struct.Struct("=IHHiIII")  # 24 bytes
PACKET_HEADER_STRUCT = struct.Struct("=IIII")     # 16 bytes


class PCAPReader:
    """Parser for reading raw network packets from standard libpcap files."""
    def __init__(self, filepath: str | Path) -> None:
        self.filepath = Path(filepath)

    def packets(self) -> Generator[Tuple[float, bytes], None, None]:
        """
        Iterate through all packets in PCAP file.
        Yields (timestamp_float, raw_ethernet_bytes).
        """
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            header_bytes = f.read(GLOBAL_HEADER_STRUCT.size)
            if len(header_bytes) < GLOBAL_HEADER_STRUCT.size:
                raise PCAPCorruptError("Truncated PCAP global header")

            magic, v_maj, v_min, thiszone, sigfigs, snaplen, linktype = GLOBAL_HEADER_STRUCT.unpack(header_bytes)

            is_nanosec = False
            if magic == PCAP_MAGIC_MICROSEC:
                is_nanosec = False
            elif magic == PCAP_MAGIC_NANOSEC:
                is_nanosec = True
            elif magic == 0xD4C3B2A1:  # Big-endian swapped
                raise PCAPCorruptError("Big-endian byte swapped PCAPs not supported")
            else:
                raise PCAPCorruptError(f"Invalid PCAP magic number: 0x{magic:08x}")

            while True:
                pkt_hdr_bytes = f.read(PACKET_HEADER_STRUCT.size)
                if not pkt_hdr_bytes or len(pkt_hdr_bytes) < PACKET_HEADER_STRUCT.size:
                    break

                ts_sec, ts_sub, incl_len, orig_len = PACKET_HEADER_STRUCT.unpack(pkt_hdr_bytes)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break  # Truncated trailing packet at crash boundary

                divisor = 1_000_000_000.0 if is_nanosec else 1_000_000.0
                timestamp = float(ts_sec) + (float(ts_sub) / divisor)

                yield timestamp, pkt_data


class PCAPWriter:
    """Serializer for writing synthetic or captured packets into standard libpcap format."""
    def __init__(self, filepath: str | Path, snaplen: int = 65535, linktype: int = 1) -> None:
        self.filepath = Path(filepath)
        self.snaplen = snaplen
        self.linktype = linktype
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self._file: BinaryIO = open(self.filepath, "wb")
        self._write_global_header()

    def _write_global_header(self) -> None:
        hdr = GLOBAL_HEADER_STRUCT.pack(
            PCAP_MAGIC_MICROSEC,
            2,  # Major 2
            4,  # Minor 4
            0,  # Thiszone
            0,  # Sigfigs
            self.snaplen,
            self.linktype,  # 1 = Ethernet
        )
        self._file.write(hdr)
        self._file.flush()

    def write_packet(self, data: bytes, timestamp: float) -> None:
        """Append packet with timestamp."""
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        incl_len = min(len(data), self.snaplen)
        orig_len = len(data)

        hdr = PACKET_HEADER_STRUCT.pack(ts_sec, ts_usec, incl_len, orig_len)
        self._file.write(hdr)
        self._file.write(data[:incl_len])

    def close(self) -> None:
        try:
            self._file.flush()
            self._file.close()
        except Exception:
            pass
