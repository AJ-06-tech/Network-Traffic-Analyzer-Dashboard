"""
Network Traffic Analyzer Dashboard using Python (Reconstructed Implementation)
------------------------------------------------------------------------------
Interactive web dashboard built with Streamlit and Plotly for visualizing
packet-level network traffic captured via Wireshark (.pcap) or Scapy live sniff.

Academic Project: Computer Communication Networks (ECC 602)
Institution: Don Bosco Institute of Technology (DBIT), Mumbai
"""

import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from packet_analyzer import (
    SCAPY_AVAILABLE,
    capture_live_to_dataframe,
    detect_anomalies_and_alerts,
    load_pcap_to_dataframe,
)

st.set_page_config(
    page_title="Network Traffic Analyzer Dashboard",
    page_icon="📡",
    layout="wide",
)

# Dark-mode styling matching the report dashboard UI
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("📡 Network Traffic Analyzer Dashboard")
st.caption(
    "Real-time & PCAP packet inspection, protocol classification, bandwidth analysis, "
    "and rule-based anomaly detection using Python, Scapy, Streamlit, and Plotly."
)

# Sidebar: Data Source Selection
st.sidebar.header("⚙️ Traffic Source Settings")
source_mode = st.sidebar.radio(
    "Select Packet Input Mode:",
    options=["Sample Capture (Report Dataset)", "Upload Wireshark .pcap File", "Live Interface Capture (Scapy)"],
)

df = pd.DataFrame()

if source_mode == "Sample Capture (Report Dataset)":
    sample_path = os.path.join(os.path.dirname(__file__), "sample_traffic.pcap")
    if os.path.exists(sample_path):
        df = load_pcap_to_dataframe(sample_path)
        st.sidebar.success(f"Loaded sample_traffic.pcap ({len(df)} packets)")
    else:
        st.sidebar.error("sample_traffic.pcap not found. Run `python generate_sample_pcap.py` first.")

elif source_mode == "Upload Wireshark .pcap File":
    uploaded_file = st.sidebar.file_uploader("Upload a .pcap or .pcapng capture file", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name
        try:
            df = load_pcap_to_dataframe(tmp_path)
            st.sidebar.success(f"Parsed {len(df)} IPv4 packets from {uploaded_file.name}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
    else:
        st.info("👈 Upload a `.pcap` file from Wireshark in the sidebar to begin analysis.")

elif source_mode == "Live Interface Capture (Scapy)":
    iface_name = st.sidebar.text_input("Network Interface (leave blank for default Wi-Fi)", value="")
    pkt_limit = st.sidebar.slider("Packets to Capture", min_value=20, max_value=500, value=100, step=20)
    if st.sidebar.button("Start Live Capture"):
        if not SCAPY_AVAILABLE:
            st.sidebar.error("Scapy is not installed in this environment.")
        else:
            with st.spinner(f"Capturing up to {pkt_limit} live packets..."):
                try:
                    df = capture_live_to_dataframe(interface=iface_name, packet_count=pkt_limit)
                    st.session_state["live_df"] = df
                except Exception as exc:
                    st.sidebar.error(f"Live capture error (run with admin/root privileges): {exc}")
    if "live_df" in st.session_state and df.empty:
        df = st.session_state["live_df"]

if df.empty:
    st.stop()

# Top KPI Summary Metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Captured Packets", f"{len(df):,}")
col2.metric("Total Traffic Volume", f"{df['Packet Size'].sum():,} Bytes")
col3.metric("Unique Source IPs", f"{df['Source IP'].nunique()}")
col4.metric("Active Protocols", f"{df['Protocol'].nunique()}")

st.divider()

# -------------------------------------------------------------------------
# 1. Protocol Distribution
# -------------------------------------------------------------------------
st.subheader("📊 Protocol Distribution")
st.caption("Shows how network traffic is distributed across different protocols.")

proto_counts = df["Protocol"].value_counts().reset_index()
proto_counts.columns = ["Protocols", "Count"]

left_col, right_col = st.columns([1, 2])
with left_col:
    st.markdown("**PROTOCOL STATISTICS:**")
    st.dataframe(proto_counts, use_container_width=True, hide_index=True)

with right_col:
    fig_proto = px.pie(
        proto_counts,
        names="Protocols",
        values="Count",
        hole=0.4,
        title="Protocol Usage Distribution",
        template="plotly_dark",
    )
    fig_proto.update_traces(textposition="inside", textinfo="percent")
    st.plotly_chart(fig_proto, use_container_width=True)

st.divider()

# -------------------------------------------------------------------------
# 2. Top Active Source IPs
# -------------------------------------------------------------------------
st.subheader("🌐 Top Active Source IPs")
st.caption("Devices generating the highest amount of network traffic.")

ip_counts = df["Source IP"].value_counts().head(10).reset_index()
ip_counts.columns = ["IP Address", "Packets"]

fig_ips = px.bar(
    ip_counts,
    x="IP Address",
    y="Packets",
    text="Packets",
    title="Top Active IP Addresses",
    template="plotly_dark",
)
fig_ips.update_traces(marker_color="#7cc4fa", textposition="inside")
st.plotly_chart(fig_ips, use_container_width=True)

st.divider()

# -------------------------------------------------------------------------
# 3. Top Bandwidth Consuming Websites
# -------------------------------------------------------------------------
st.subheader("📶 Top Bandwidth Consuming Websites")
st.caption("Shows which websites and network sources are consuming the most bandwidth.")

bw_by_site = df.groupby("Website", as_index=False)["Packet Size"].sum().sort_values("Packet Size", ascending=False)
bw_by_site.columns = ["Website", "Bandwidth"]

fig_bw = px.bar(
    bw_by_site.head(10),
    x="Website",
    y="Bandwidth",
    text="Bandwidth",
    title="Top Bandwidth Consuming Websites",
    template="plotly_dark",
)
fig_bw.update_traces(marker_color="#7cc4fa", textposition="auto")
st.plotly_chart(fig_bw, use_container_width=True)

bw_table = (
    df.groupby(["Website", "Source IP"], as_index=False)["Packet Size"]
    .sum()
    .sort_values("Packet Size", ascending=False)
    .rename(columns={"Source IP": "IP Address", "Packet Size": "Bandwidth"})
)
st.dataframe(bw_table, use_container_width=True, hide_index=True)

st.divider()

# -------------------------------------------------------------------------
# 4. Port Analysis
# -------------------------------------------------------------------------
st.subheader("🔌 Port Analysis")
st.caption("Displays the most frequently used network service ports.")

port_series = pd.concat([df["Source Port"], df["Destination Port"]])
port_series = port_series[port_series > 0]
port_counts = port_series.value_counts().head(15).reset_index()
port_counts.columns = ["Port", "Count"]

fig_ports = px.bar(
    port_counts,
    x="Port",
    y="Count",
    title="Most Frequently Used Ports",
    template="plotly_dark",
)
fig_ports.update_traces(marker_color="#7cc4fa")
st.plotly_chart(fig_ports, use_container_width=True)

st.divider()

# -------------------------------------------------------------------------
# 5. Packet Size Analysis & 6. Traffic Timeline
# -------------------------------------------------------------------------
st.subheader("📈 Packet Size Analysis")
st.caption("Visualizes variation in packet sizes over network traffic.")

fig_size = px.line(
    df,
    x="Packet Number",
    y="Packet Size",
    color="Protocol",
    title="Packet Size Variation Over Time",
    template="plotly_dark",
)
st.plotly_chart(fig_size, use_container_width=True)

st.subheader("🛰️ Traffic Timeline")
st.caption("Shows network traffic behaviour across captured packets.")

fig_timeline = px.area(
    df,
    x="Packet Number",
    y="Packet Size",
    color="Protocol",
    title="Network Traffic Timeline",
    template="plotly_dark",
)
st.plotly_chart(fig_timeline, use_container_width=True)

st.divider()

# -------------------------------------------------------------------------
# 7. Network Anomaly Detection & Network Alerts
# -------------------------------------------------------------------------
st.subheader("⚠️ Network Anomaly Detection")
st.caption("Detects unusual traffic behaviour based on abnormal port activity and traffic patterns.")

anomalies, alerts = detect_anomalies_and_alerts(df)
if not anomalies:
    st.success("No network anomaly detected.")
else:
    for item in anomalies:
        st.error(item)

st.subheader("🔔 Network Alerts")
st.caption("Highlights important network conditions observed during traffic analysis.")

if not alerts:
    st.info("No active network alerts.")
else:
    for alert in alerts:
        st.info(alert)

st.divider()

# -------------------------------------------------------------------------
# 8. Filter Traffic By Protocol & Captured Packet Data
# -------------------------------------------------------------------------
st.subheader("🔍 Filter Traffic By Protocol")
protocols_available = ["ALL"] + sorted(df["Protocol"].unique().tolist())
default_idx = protocols_available.index("UDP") if "UDP" in protocols_available else 0
selected_proto = st.selectbox("Select Protocol", options=protocols_available, index=default_idx)

filtered_df = df if selected_proto == "ALL" else df[df["Protocol"] == selected_proto]
display_cols = ["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Size", "Packet Number"]
st.dataframe(filtered_df[display_cols], use_container_width=True, hide_index=True)

st.subheader("📋 Captured Packet Data")
st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
