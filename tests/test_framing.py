"""
Unit tests for Layer 2/3/4 protocol decoders.
"""

import pytest

from aegisflow.framing import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket
from aegisflow.types import EtherType, PacketDecodeError, Protocol, TCPFlags


def test_ethernet_unpack():
    """Verify Ethernet frame parsing and MAC formatting."""
    raw = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00" + b"TEST_PAYLOAD"
    eth = EthernetFrame.unpack(raw)

    assert eth.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert eth.src_mac == "11:22:33:44:55:66"
    assert eth.ethertype == EtherType.IPV4
    assert eth.payload == b"TEST_PAYLOAD"


def test_ipv4_unpack():
    """Verify IPv4 header unpacking, version checking, and IP string conversion."""
    # 20 bytes standard IPv4: 192.168.1.100 -> 10.0.0.1, TCP
    raw_ip = (
        b"\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x00\x00"
        b"\xc0\xa8\x01\x64\x0a\x00\x00\x01" + b"TCP_PAYLOAD"
    )
    ip = IPv4Packet.unpack(raw_ip)

    assert ip.version == 4
    assert ip.ihl == 20
    assert ip.protocol == Protocol.TCP
    assert ip.src_ip == "192.168.1.100"
    assert ip.dst_ip == "10.0.0.1"
    assert ip.payload == b"TCP_PAYLOAD"


def test_tcp_unpack_flags():
    """Verify TCP flags unpacking (SYN + ACK)."""
    # 20 bytes TCP: Port 44321 -> 80, flags 0x12 (SYN | ACK)
    raw_tcp = (
        b"\xad\x21\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00"
        b"\x50\x12\x72\x10\x00\x00\x00\x00" + b"HTTP_DATA"
    )
    tcp = TCPPacket.unpack(raw_tcp)

    assert tcp.src_port == 44321
    assert tcp.dst_port == 80
    assert tcp.flags == (TCPFlags.SYN | TCPFlags.ACK)
    assert tcp.payload == b"HTTP_DATA"


def test_udp_unpack():
    """Verify UDP header unpacking."""
    raw_udp = b"\x13\x88\x00\x35\x00\x10\x00\x00" + b"DNS_DATA_HERE!!"
    udp = UDPPacket.unpack(raw_udp)

    assert udp.src_port == 5000
    assert udp.dst_port == 53
    assert udp.length == 16
    assert udp.payload == b"DNS_DATA_HERE!!"


def test_truncated_buffer_raises():
    """Verify truncated packet throws PacketDecodeError."""
    with pytest.raises(PacketDecodeError):
        EthernetFrame.unpack(b"\x00\x01\x02")
