"""
Packet Analyzer & Anomaly Detection Engine (Reconstructed Implementation)
-------------------------------------------------------------------------
Implements Stages 1–3 and Stage 6 of the Network Traffic Analyzer Dashboard
described in the Computer Communication Networks (ECC 602) project report:
  1. Reads `.pcap` files (via Scapy `rdpcap`, with a built-in PCAP fallback parser)
     or captures live packets from a network interface (via Scapy `sniff`).
  2. Extracts Source IP, Destination IP, Source Port, Destination Port,
     Packet Size, Packet Number, and classifies protocols (`TLS`, `DNS`,
     `HTTP`, `UDP`, `TCP`, `ICMP`, `OTHER`).
  3. Enriches IP addresses via reverse DNS / known service mapping and evaluates
     rule-based statistical thresholds for network anomaly detection and alerts.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from functools import lru_cache
from typing import Dict, List, Tuple

import pandas as pd

try:
    from scapy.all import DNS, ICMP, IP, TCP, UDP, rdpcap, sniff  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


KNOWN_IP_LABELS: Dict[str, str] = {
    "224.0.0.1": "mcast.net",
    "224.0.0.22": "mcast.net",
    "224.0.0.251": "mcast.net",
    "34.110.164.207": "googleusercontent.com",
    "52.45.87.101": "amazonaws.com",
}


def classify_protocol(
    ip_proto: int,
    sport: int | None,
    dport: int | None,
    has_dns: bool = False,
    payload: bytes = b"",
) -> str:
    """Classify packet into TLS, DNS, HTTP, ICMP, UDP, TCP, or OTHER."""
    if ip_proto == 1:
        return "ICMP"

    ports = {p for p in (sport, dport) if p is not None}

    # DNS (Port 53)
    if has_dns or 53 in ports:
        return "DNS"

    # TCP-based application protocols
    if ip_proto == 6:
        if 443 in ports or (len(payload) >= 3 and payload[:2] == b"\x16\x03" or payload[:2] == b"\x17\x03"):
            return "TLS"
        if 80 in ports or 8080 in ports or payload.startswith((b"GET ", b"POST ", b"HTTP/")):
            return "HTTP"
        return "TCP"

    # UDP transport protocol (including mDNS 5353 & Echo 7 as shown in report)
    if ip_proto == 17:
        return "UDP"

    return "OTHER"


@lru_cache(maxsize=256)
def resolve_hostname(ip_str: str) -> str:
    """Resolve an IP address to a human-readable domain or device category."""
    if ip_str in KNOWN_IP_LABELS:
        return KNOWN_IP_LABELS[ip_str]

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "Local Device"
        if ip_obj.is_multicast:
            return "mcast.net"
    except ValueError:
        return "Unknown"

    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return "Unknown"


def _parse_with_scapy(packets) -> List[Dict]:
    rows: List[Dict] = []
    for idx, pkt in enumerate(packets):
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_proto = int(ip_layer.proto)
        pkt_size = len(pkt)

        sport = None
        dport = None
        payload_bytes = b""

        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            payload_bytes = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            payload_bytes = bytes(pkt[UDP].payload)

        has_dns = DNS in pkt
        protocol = classify_protocol(ip_proto, sport, dport, has_dns=has_dns, payload=payload_bytes)

        rows.append(
            {
                "Packet Number": idx,
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": protocol,
                "Source Port": sport if sport is not None else 0,
                "Destination Port": dport if dport is not None else 0,
                "Packet Size": pkt_size,
            }
        )
    return rows


def _parse_raw_pcap_fallback(pcap_path: str) -> List[Dict]:
    """Fallback Ethernet/IPv4 PCAP reader if Scapy/Npcap is unavailable."""
    rows: List[Dict] = []
    with open(pcap_path, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return rows
        magic = struct.unpack("<I", global_hdr[:4])[0]
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"

        idx = 0
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            _, _, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_hdr)
            frame = f.read(incl_len)
            if len(frame) < 34:
                idx += 1
                continue

            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type != 0x0800:
                idx += 1
                continue

            ip_start = 14
            ihl = (frame[ip_start] & 0x0F) * 4
            ip_proto = frame[ip_start + 9]
            src_ip = socket.inet_ntoa(frame[ip_start + 12 : ip_start + 16])
            dst_ip = socket.inet_ntoa(frame[ip_start + 16 : ip_start + 20])

            l4_start = ip_start + ihl
            sport = None
            dport = None
            payload = b""
            if ip_proto in (6, 17) and len(frame) >= l4_start + 4:
                sport, dport = struct.unpack("!HH", frame[l4_start : l4_start + 4])
                hdr_len = ((frame[l4_start + 12] >> 4) * 4) if ip_proto == 6 and len(frame) > l4_start + 12 else 8
                payload = frame[l4_start + hdr_len :]

            protocol = classify_protocol(ip_proto, sport, dport, payload=payload)
            rows.append(
                {
                    "Packet Number": idx,
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Protocol": protocol,
                    "Source Port": sport if sport is not None else 0,
                    "Destination Port": dport if dport is not None else 0,
                    "Packet Size": orig_len,
                }
            )
            idx += 1
    return rows


def load_pcap_to_dataframe(pcap_path: str) -> pd.DataFrame:
    """Parse a `.pcap` file into a structured Pandas DataFrame."""
    if SCAPY_AVAILABLE:
        packets = rdpcap(pcap_path)
        rows = _parse_with_scapy(packets)
    else:
        rows = _parse_raw_pcap_fallback(pcap_path)

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(
            columns=[
                "Packet Number",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Source Port",
                "Destination Port",
                "Packet Size",
                "Website",
            ]
        )

    df["Website"] = df["Source IP"].apply(resolve_hostname)
    return df


def capture_live_to_dataframe(interface: str | None = None, packet_count: int = 100, timeout: int = 15) -> pd.DataFrame:
    """Capture live network packets using Scapy `sniff()`."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is required for live packet capture. Install scapy and Npcap/libpcap.")

    kwargs = {"count": packet_count, "timeout": timeout}
    if interface and interface.strip():
        kwargs["iface"] = interface.strip()

    packets = sniff(**kwargs)
    rows = _parse_with_scapy(packets)
    df = pd.DataFrame(rows)
    if not df.empty:
        df["Website"] = df["Source IP"].apply(resolve_hostname)
    return df


def detect_anomalies_and_alerts(df: pd.DataFrame) -> Tuple[List[str], List[str]]:
    """
    Rule-based anomaly detection and informational network alerts (Stage 6):
      - Checks for port-scan behavior (many distinct destination ports from one source IP)
      - Checks for volumetric / flood spikes from a single IP
      - Checks for high encrypted TLS traffic share
    """
    anomalies: List[str] = []
    alerts: List[str] = []

    if df.empty:
        return anomalies, alerts

    total_packets = len(df)

    # 1. Port scan check (> 20 unique destination ports from a single source IP)
    unique_ports_per_src = df.groupby("Source IP")["Destination Port"].nunique()
    scanners = unique_ports_per_src[unique_ports_per_src > 20]
    for src_ip, port_cnt in scanners.items():
        anomalies.append(f"Potential port scanning detected from {src_ip} ({port_cnt} unique destination ports).")

    # 2. High-frequency flood check (> 85% of total traffic from one IP when >= 200 packets)
    if total_packets >= 200:
        src_counts = df["Source IP"].value_counts()
        top_ip = src_counts.index[0]
        share = src_counts.iloc[0] / total_packets
        if share > 0.85:
            anomalies.append(f"Abnormal traffic spike from {top_ip} ({share * 100:.1f}% of captured packets).")

    # 3. Informational network alerts
    tls_count = int((df["Protocol"] == "TLS").sum())
    if total_packets > 0 and (tls_count / total_packets) >= 0.50:
        alerts.append("Large amount of encrypted TLS traffic detected.")

    icmp_count = int((df["Protocol"] == "ICMP").sum())
    if icmp_count >= 15:
        alerts.append(f"Elevated ICMP ping traffic observed ({icmp_count} packets).")

    return anomalies, alerts
