# Network Traffic Analyzer Dashboard using Python

An interactive web-based network traffic monitoring, protocol classification, and anomaly detection dashboard built with **Python**, **Scapy**, **Streamlit**, and **Plotly**. Developed as an academic project for the **Computer Communication Networks (ECC 602)** course in Semester VI of the Electronics & Telecommunication Engineering (EXTC) program at Don Bosco Institute of Technology (DBIT), Mumbai.

---

## 1. Project Overview

While packet sniffers such as Wireshark capture raw network frames in detail, interpreting traffic trends, bandwidth consumers, and suspicious port activity requires manual filtering and protocol expertise. **Network Traffic Analyzer Dashboard** bridges this gap by combining packet capture (`.pcap` file ingestion or live interface sniffing via Scapy) with automated Pandas aggregation, reverse-DNS enrichment, rule-based anomaly detection, and interactive Plotly visualizations inside a dark-themed Streamlit dashboard.

---

## 2. Objectives

- Capture and inspect live or recorded (`.pcap`) network traffic from a local Wi-Fi interface.
- Parse packet headers using **Scapy** to extract Source/Destination IP addresses, Source/Destination ports, packet sizes, and sequence numbers.
- Classify network packets across core protocols: **TLS**, **DNS**, **HTTP**, **TCP**, **UDP**, **ICMP**, and **OTHER**.
- Perform reverse-DNS lookups and traffic categorization (`Local Device`, external cloud/web domains, and multicast traffic).
- Visualize protocol distribution, active IP hosts, bandwidth usage, port frequency, and traffic timelines in real time using **Streamlit** and **Plotly**.
- Implement rule-based statistical checks to flag potential network anomalies (such as port scanning or volumetric spikes) and surface automated alerts.

---

## 3. Technologies, Tools & Protocols

| Category | Tools / Technologies | Purpose |
| :--- | :--- | :--- |
| **Packet Capture & Generation** | Wireshark, Scapy (`sniff` / `rdpcap`), Terminal (`ping`), Cisco Packet Tracer | Live Wi-Fi packet capture into `.pcap`, ICMP traffic generation, and topology simulation |
| **Backend & Packet Parsing** | Python 3, Scapy, Pandas, `socket`, `ipaddress` | Layer-2/3/4 header dissection, protocol classification, tabular structuring, and DNS enrichment |
| **Frontend & Visualization** | Streamlit, Plotly Express | Interactive web dashboard with donut charts, bar graphs, line/area timelines, and filterable packet tables |
| **Protocols Analyzed** | `TLS`, `DNS`, `HTTP`, `TCP`, `UDP`, `ICMP`, `OTHER` (Multicast/IGMP) | Transport and application-layer traffic classification and port-level analysis |

---

## 4. System Architecture (9-Stage Pipeline)

![System Architecture](./images/System_Architecture.png)

1. **Traffic Capture:** Intercept packets from the active network interface via Wireshark or Scapy and store/read them in `.pcap` format.
2. **Packet Processing:** Dissect Ethernet/IPv4/TCP/UDP/ICMP headers to identify protocols and session endpoints.
3. **Data Extraction & Enrichment:** Extract Source/Destination IPs, ports, packet sizes, and sequence indices; resolve domain names via DNS lookup and categorize traffic (`Local Device`, `External`, `Multicast`, `Encrypted`).
4. **Traffic Analysis:** Compute protocol counts, top active source IPs, bandwidth consumption per website/host, port frequency (`0–1000` system ports vs. ephemeral ports), and packet size variations.
5. **Visualization (Dashboard):** Render interactive dark-mode Plotly charts and structured Pandas tables in Streamlit.
6. **Anomaly Detection:** Evaluate statistical thresholds for unusual port activity, traffic floods, and high encrypted (`TLS`) traffic share.
7. **Protocol Filtering:** Dynamically filter captured packets by protocol (`TLS`, `DNS`, `HTTP`, `UDP`, `TCP`, `ICMP`, `OTHER`).
8. **Insights & Reporting:** Summarize protocol statistics and highlight actionable network conditions.
9. **Output:** Real-time visibility, traffic insights, and automated security/status banners.

---

## 5. Dashboard Modules & Experimental Results

### 5.1 Protocol Distribution
Displays packet counts and percentage shares across detected protocols. In the report's benchmark capture (118 packets), encrypted **TLS** accounted for **66.9%** (79 packets), followed by **DNS** at **16.1%** (19 packets), **HTTP** at **8.47%** (10 packets), **OTHER** at **5.93%** (7 packets), and **UDP** at **2.54%** (3 packets).

![Protocol Distribution](./images/Protocol_Distribution.png)

### 5.2 Top Active Source IPs & Bandwidth-Consuming Websites
Ranks the most active IP endpoints by packet count and aggregates total bytes transferred by resolved domain/device category (`Local Device` at `192.168.29.180`, external endpoints such as `amazonaws.com` and `googleusercontent.com`, and multicast `mcast.net`).

| Top Active Source IPs | Top Bandwidth Consuming Websites |
| :---: | :---: |
| ![Top Active Source IPs](./images/Top_Active_IPs.png) | ![Top Bandwidth Consuming Websites](./images/Top_Bandwidth_Websites.png) |

![Website Bandwidth Table](./images/Website_Bandwidth_Table.png)

### 5.3 Port Analysis
Identifies the most frequently accessed TCP/UDP port numbers, distinguishing well-known system ports (`0–1000`, such as ports `80`, `443`, and `53`) from high-numbered dynamic/ephemeral client ports (`52000`, `55000`, `59000`).

![Port Analysis](./images/Port_Analysis.png)

### 5.4 Packet Size Analysis & Traffic Timeline
Tracks packet payload/frame sizes (up to the `1514`-byte Ethernet MTU) across packet sequence numbers, highlighting burst transmissions versus smaller control/DNS exchanges.

| Packet Size Variation Over Time | Network Traffic Timeline |
| :---: | :---: |
| ![Packet Size Analysis](./images/Packet_Size_Analysis.png) | ![Traffic Timeline](./images/Traffic_Timeline.png) |

### 5.5 Network Anomaly Detection, Smart Alerts & Packet Inspection
Evaluates traffic against rule-based thresholds to display clear anomaly status banners (`No network anomaly detected.`) alongside informational alerts (`Large amount of encrypted TLS traffic detected.`), followed by an interactive protocol filter and full packet-level inspection table.

| Anomaly Detection & Smart Alerts | Protocol Filter (`UDP`) |
| :---: | :---: |
| ![Anomaly Detection Alerts](./images/Anomaly_Detection_Alerts.png) | ![Protocol Filter](./images/Protocol_Filter.png) |

![Captured Packet Data](./images/Captured_Packet_Data.png)

---

## 6. Repository Structure

```text
Network-Traffic-Analyzer-Dashboard/
├── app.py                        # Streamlit web application & Plotly visualizations (reconstructed)
├── packet_analyzer.py            # Scapy PCAP/live packet parser, DNS resolver & anomaly detector (reconstructed)
├── generate_sample_pcap.py       # Utility script to generate sample_traffic.pcap (reconstructed)
├── sample_traffic.pcap           # 118-packet sample capture matching report statistics (reconstructed)
├── requirements.txt              # Python package dependencies
├── CCN_project_report.pdf        # Original academic project report
├── README.md                     # Project documentation
└── images/                       # Original architecture diagram & dashboard screenshots from report
    ├── System_Architecture.png
    ├── Protocol_Distribution.png
    ├── Top_Active_IPs.png
    ├── Top_Bandwidth_Websites.png
    ├── Website_Bandwidth_Table.png
    ├── Port_Analysis.png
    ├── Packet_Size_Analysis.png
    ├── Traffic_Timeline.png
    ├── Anomaly_Detection_Alerts.png
    ├── Protocol_Filter.png
    └── Captured_Packet_Data.png
