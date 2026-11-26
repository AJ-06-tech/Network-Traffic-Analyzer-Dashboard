"""
Sample PCAP Generator (Reconstructed Utility)
---------------------------------------------
Generates a realistic 118-packet Wireshark-compatible `.pcap` file (`sample_traffic.pcap`)
matching the exact protocol distribution, IP addresses, ports, and packet size patterns
documented in the project report:
  - TLS:   79 packets (66.9%)
  - DNS:   19 packets (16.1%)
  - HTTP:  10 packets (8.47%)
  - OTHER:  7 packets (5.93%)
  - UDP:    3 packets (2.54%)
"""

import struct
import socket
import random
import time


def ipv4_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b"\x00"
    words = struct.unpack("!" + "H" * (len(header) // 2), header)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_eth_ipv4_packet(src_ip: str, dst_ip: str, proto: int, l4_payload: bytes) -> bytes:
    eth_header = b"\xaa\xbb\xcc\xdd\xee\x01\x11\x22\x33\x44\x55\x66\x08\x00"
    total_len = 20 + len(l4_payload)
    ip_id = random.randint(1, 65535)
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        64,
        proto,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    csum = ipv4_checksum(ip_hdr_no_csum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        64,
        proto,
        csum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return eth_header + ip_header + l4_payload


def build_tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int, payload_len: int) -> bytes:
    if 80 in (sport, dport):
        prefix = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    else:
        prefix = b"\x17\x03\x03"
    app_data = (prefix + (b"A" * max(0, payload_len - len(prefix))))[:max(len(prefix), payload_len)] if payload_len > 0 else b""
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        random.randint(1000, 999999),
        random.randint(1000, 999999),
        (5 << 4),
        0x18,  # PSH + ACK
        65535,
        0,
        0,
    )
    return build_eth_ipv4_packet(src_ip, dst_ip, 6, tcp_header + app_data)


def build_udp_datagram(src_ip: str, dst_ip: str, sport: int, dport: int, payload_len: int) -> bytes:
    app_data = b"D" * max(0, payload_len)
    udp_len = 8 + len(app_data)
    udp_header = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return build_eth_ipv4_packet(src_ip, dst_ip, 17, udp_header + app_data)


def build_igmp_other(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    igmp_payload = b"\x22\x00\x00\x00" + (b"\x00" * max(0, payload_len - 4))
    return build_eth_ipv4_packet(src_ip, dst_ip, 2, igmp_payload)


def generate_pcap(output_path: str = "sample_traffic.pcap") -> None:
    random.seed(42)
    packets = []

    local_ip = "192.168.29.180"
    gateway_ip = "192.168.29.1"
    peer_ip = "192.168.29.200"

    # 1. UDP packets (3 packets = 2.54%) matching report screenshot
    packets.append(build_udp_datagram(gateway_ip, local_ip, 55038, 7, 1))
    packets.append(build_udp_datagram(peer_ip, "224.0.0.251", 5353, 5353, 61))
    packets.append(build_udp_datagram(peer_ip, "224.0.0.251", 5353, 5353, 61))

    # 2. TLS packets (79 packets = 66.9%) across port 443 and high ephemeral ports
    tls_peers = [
        ("51.11.192.49", 29),
        ("146.75.118.172", 18),
        ("34.110.164.207", 14),
        ("13.89.179.9", 10),
        ("52.45.87.101", 8),
    ]
    ephemeral_ports = [52023, 52000, 55000, 59000]
    tls_sizes = [1460, 1460, 980, 450, 120, 60, 1460, 1200]
    idx = 0
    for remote_ip, count in tls_peers:
        for _ in range(count):
            sport = random.choice(ephemeral_ports)
            payload_sz = tls_sizes[idx % len(tls_sizes)]
            if idx % 2 == 0:
                packets.append(build_tcp_segment(local_ip, remote_ip, sport, 443, payload_sz))
            else:
                packets.append(build_tcp_segment(remote_ip, local_ip, 443, sport, payload_sz))
            idx += 1

    # 3. DNS packets (19 packets = 16.1%) on port 53
    for i in range(19):
        if i % 2 == 0:
            packets.append(build_udp_datagram(local_ip, gateway_ip, 52000 + (i % 10), 53, 42))
        else:
            packets.append(build_udp_datagram(gateway_ip, local_ip, 53, 52000 + ((i - 1) % 10), 96))

    # 4. HTTP packets (10 packets = 8.47%) on port 80
    for i in range(10):
        remote = "162.159.140.165" if i < 5 else "4.188.92.87"
        sz = random.choice([180, 260, 310, 80])
        if i % 2 == 0:
            packets.append(build_tcp_segment(local_ip, remote, 59000, 80, sz))
        else:
            packets.append(build_tcp_segment(remote, local_ip, 80, 59000, sz))

    # 5. OTHER packets (7 packets = 5.93%) multicast / IGMP control traffic
    for i in range(7):
        mcast_dst = "224.0.0.22" if i % 2 == 0 else "224.0.0.1"
        packets.append(build_igmp_other(local_ip, mcast_dst, 24))

    # Write standard libpcap file (microsecond resolution, Ethernet link-type = 1)
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    base_ts = int(time.time())
    with open(output_path, "wb") as f:
        f.write(global_header)
        for seq, raw_pkt in enumerate(packets):
            ts_sec = base_ts + (seq // 10)
            ts_usec = (seq % 10) * 100000
            pkt_header = struct.pack("<IIII", ts_sec, ts_usec, len(raw_pkt), len(raw_pkt))
            f.write(pkt_header)
            f.write(raw_pkt)

    print(f"Generated {output_path} with {len(packets)} packets.")


if __name__ == "__main__":
    generate_pcap()
