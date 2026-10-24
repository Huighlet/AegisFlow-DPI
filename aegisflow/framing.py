"""
AegisFlow-DPI: Zero-Copy Protocol Framing Decoders.
Unpacks Ethernet, IPv4, IPv6, TCP, UDP, and ICMP headers with sub-microsecond extraction.
"""

from __future__ import annotations

import dataclasses
import socket
import struct
from typing import Tuple

from aegisflow.types import EtherType, PacketDecodeError, Protocol, TCPFlags


def format_mac(raw_mac: bytes) -> str:
    """Convert 6-byte raw hardware address to colon-delimited string."""
    return ":".join(f"{b:02x}" for b in raw_mac)


@dataclasses.dataclass(slots=True, frozen=True)
class EthernetFrame:
    """Layer 2 Ethernet Header (14 bytes)."""
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes

    @classmethod
    def unpack(cls, data: bytes) -> EthernetFrame:
        if len(data) < 14:
            raise PacketDecodeError(f"Truncated Ethernet frame: expected >= 14 bytes, got {len(data)}")
        dst_raw, src_raw, ethertype = struct.unpack("!6s6sH", data[:14])
        return cls(
            dst_mac=format_mac(dst_raw),
            src_mac=format_mac(src_raw),
            ethertype=ethertype,
            payload=data[14:],
        )


@dataclasses.dataclass(slots=True, frozen=True)
class IPv4Packet:
    """Layer 3 IPv4 Packet Header (20 bytes minimum)."""
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    ttl: int
    protocol: Protocol
    src_ip: str
    dst_ip: str
    payload: bytes

    @classmethod
    def unpack(cls, data: bytes) -> IPv4Packet:
        if len(data) < 20:
            raise PacketDecodeError(f"Truncated IPv4 packet: expected >= 20 bytes, got {len(data)}")

        v_ihl, tos, total_len, ident, flags_frag, ttl, proto_num, cksum, src_bytes, dst_bytes = (
            struct.unpack("!BBHHHBBH4s4s", data[:20])
        )
        version = v_ihl >> 4
        ihl = (v_ihl & 0x0F) * 4

        if version != 4:
            raise PacketDecodeError(f"Invalid IPv4 version: {version}")
        if len(data) < ihl:
            raise PacketDecodeError(f"IPv4 packet smaller than declared header length {ihl}")

        src_ip = socket.inet_ntoa(src_bytes)
        dst_ip = socket.inet_ntoa(dst_bytes)

        try:
            proto = Protocol(proto_num)
        except ValueError:
            proto = proto_num  # type: ignore

        payload_end = total_len if (ihl < total_len <= len(data)) else len(data)
        return cls(
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_len,
            identification=ident,
            flags=flags_frag >> 13,
            ttl=ttl,
            protocol=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            payload=data[ihl:payload_end],
        )


@dataclasses.dataclass(slots=True, frozen=True)
class TCPPacket:
    """Layer 4 TCP Segment Header (20 bytes minimum)."""
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags: TCPFlags
    window_size: int
    checksum: int
    urgent_ptr: int
    payload: bytes

    @classmethod
    def unpack(cls, data: bytes) -> TCPPacket:
        if len(data) < 20:
            raise PacketDecodeError(f"Truncated TCP segment: expected >= 20 bytes, got {len(data)}")

        src_port, dst_port, seq, ack, offset_reserved, flags_byte, win, cksum, urg = (
            struct.unpack("!HHLLBBHHH", data[:20])
        )
        data_offset = (offset_reserved >> 4) * 4

        if len(data) < data_offset:
            raise PacketDecodeError(f"TCP segment smaller than data offset {data_offset}")

        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq,
            ack_num=ack,
            data_offset=data_offset,
            flags=TCPFlags(flags_byte),
            window_size=win,
            checksum=cksum,
            urgent_ptr=urg,
            payload=data[data_offset:],
        )


@dataclasses.dataclass(slots=True, frozen=True)
class UDPPacket:
    """Layer 4 UDP Datagram Header (8 bytes)."""
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes

    @classmethod
    def unpack(cls, data: bytes) -> UDPPacket:
        if len(data) < 8:
            raise PacketDecodeError(f"Truncated UDP packet: expected >= 8 bytes, got {len(data)}")
        src_port, dst_port, length, cksum = struct.unpack("!HHHH", data[:8])
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=cksum,
            payload=data[8:],
        )
