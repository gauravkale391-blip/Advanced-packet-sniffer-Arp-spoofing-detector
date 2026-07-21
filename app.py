import streamlit as st
import threading
import time
import pandas as pd
import plotly.express as px
from sniffer import start_sniffing
from streamlit_autorefresh import st_autorefresh
from mitre_mapping import get_mitre_info
from report_generator import generate_incident_report
from ai_investigation import generate_investigation_summary
from email_alert import send_alert_email
from threat_intel import check_ip_reputation
from auth import verify_login
from database import init_db, get_recent_packets, get_recent_arp_events
DATA_FILE = "captured_packets.jsonl"

def build_ip_mac_table(arp_packets):
    ip_to_macs = {}
    for entry in arp_packets:
        ip = entry["ip"]
        mac = entry["mac"]
        if ip not in ip_to_macs:
            ip_to_macs[ip] = set()
        ip_to_macs[ip].add(mac)

    table_rows = []
    for ip, macs in ip_to_macs.items():
        table_rows.append({
            "IP Address": ip,
            "MAC Address(es)": ", ".join(macs),
            "MAC Count": len(macs),
            "Status": "⚠️ Suspicious" if len(macs) > 1 else "✅ Normal"
        })
    return table_rows

def get_protocol_counts(packets):
    protocol_counts = {}
    for p in packets:
        proto = p.get("protocol", "Unknown")
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    return protocol_counts

def count_unique_devices(arp_packets):
    unique_macs = set()
    for entry in arp_packets:
        mac = entry.get("mac")
        if mac:
            unique_macs.add(mac)
    return len(unique_macs)

def get_top_ips(packets, key, top_n=5):
    ip_counts = {}
    for p in packets:
        ip = p.get(key, "Unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    top_ips = sorted_ips[:top_n]

    return [{"IP Address": ip, "Packet Count": count} for ip, count in top_ips]

def get_threat_intel_table(packets, max_ips=5):
    unique_ips = set()
    for p in packets:
        unique_ips.add(p.get("source"))
        unique_ips.add(p.get("destination"))

    unique_ips = list(unique_ips)[:max_ips]

    results = []
    for ip in unique_ips:
        if ip is None:
            continue
        intel = check_ip_reputation(ip)
        results.append({
            "IP Address": ip,
            "Malicious Reports": intel["malicious_count"],
            "Harmless Reports": intel["harmless_count"],
            "Country": intel["country"]
        })
    return results
ISO2_TO_ISO3 = {
    "US": "USA", "IN": "IND", "GB": "GBR", "DE": "DEU", "FR": "FRA",
    "CN": "CHN", "RU": "RUS", "JP": "JPN", "BR": "BRA", "CA": "CAN",
    "AU": "AUS", "NL": "NLD", "SG": "SGP", "IE": "IRL", "KR": "KOR",
    "IT": "ITA", "ES": "ESP", "SE": "SWE", "CH": "CHE", "ZA": "ZAF"
}
def get_country_traffic_counts(threat_table):
    country_counts = {}
    for row in threat_table:
        country = row.get("Country", "Unknown")
        if country in ("Unknown", "Private/Local"):
            continue
        iso3 = ISO2_TO_ISO3.get(country)
        if iso3:
            country_counts[iso3] = country_counts.get(iso3, 0) + 1
    return country_counts

def get_packets_per_second(packets, window_seconds=30):
    now = time.time()
    buckets = {}

    for p in packets:
        ts = p.get("timestamp")
        if ts is None:
            continue
        if now - ts > window_seconds:
            continue
        second_bucket = int(ts)
        buckets[second_bucket] = buckets.get(second_bucket, 0) + 1

    sorted_buckets = sorted(buckets.items())
    readable_buckets = [
        (time.strftime("%H:%M:%S", time.localtime(sec)), count)
        for sec, count in sorted_buckets
    ]
    return readable_buckets

if "sniffer_running" not in st.session_state:
    st.session_state.sniffer_running = False

if "email_last_sent" not in st.session_state:
    st.session_state.email_last_sent = {}
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_role" not in st.session_state:
    st.session_state.user_role = None

st.set_page_config(page_title="Advanced Packet Sniffer", page_icon="🛡️", layout="wide")
with open('style.css') as f:
    st.markdown('<style>' + f.read() + '</style>', unsafe_allow_html=True)
if not st.session_state.logged_in:
    st.title("🔐 SOC Dashboard Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        role = verify_login(username, password)
        if role:
            st.session_state.logged_in = True
            st.session_state.user_role = role
            st.rerun()
        else:
            st.error("Invalid username or password")
    st.stop()
st_autorefresh(interval=1000, key="packet_refresh")
with st.sidebar:
    st.markdown(f"**Logged in as:** {st.session_state.user_role}")
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.user_role = None
        st.rerun()

st.title("🛡️ Advanced Packet Sniffer & ARP Spoofing Detector")
st.markdown("### Real-Time Network Monitoring Dashboard")
st.divider()

col1, col2, col3, col4 = st.columns(4)
init_db()
packets = get_recent_packets(limit=200)
arp_packets = get_recent_arp_events(limit=500)
ip_mac_table = build_ip_mac_table(arp_packets)
suspicious_entries = [row for row in ip_mac_table if row["MAC Count"] > 1]
col1.metric("📦 Total Packets", str(len(packets)))
col2.metric("🌐 ARP Packets", str(len(arp_packets)))
col3.metric("💻 Devices", str(count_unique_devices(arp_packets)))
col4.metric("🚨 Alerts", str(len(suspicious_entries)))
st.divider()

st.subheader("📈 Packets per Second (last 30s)")
pps_data = get_packets_per_second(packets)

if pps_data:
    df_pps = pd.DataFrame(pps_data, columns=["Second", "Packet Count"])
    fig2 = px.line(df_pps, x="Second", y="Packet Count", markers=True)
    fig2.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        xaxis=dict(gridcolor="rgba(255,255,255,0.1)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.1)")
    )
    st.plotly_chart(fig2, use_container_width=True)
else:
    st.info("Collecting traffic data...")
st.divider()
st.subheader("📡 Live Packet Capture")
if packets:
   display_packets = []
   for p in packets[-20:]:
       p_copy = p.copy()
       if "timestamp" in p_copy:
           p_copy["timestamp"] = time.strftime("%H:%M:%S", time.localtime(p_copy["timestamp"]))
       display_packets.append(p_copy)
   df = pd.DataFrame(display_packets)
   st.dataframe(df, use_container_width=True)
else:
   st.info("Waiting for packets...")
st.divider()
st.subheader("📊 Protocol Distribution")
protocol_counts = get_protocol_counts(packets)

if protocol_counts:
    fig = px.pie(
        names=list(protocol_counts.keys()),
        values=list(protocol_counts.values()),
        hole=0.4
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        legend=dict(font=dict(color="#e2e8f0"))
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No packet data yet for protocol distribution.")
st.divider()
st.subheader("🎯 Top Source & Destination IPs")
top_col1, top_col2 = st.columns(2)

with top_col1:
    st.markdown("**Top Source IPs**")
    top_sources = get_top_ips(packets, "source")
    if top_sources:
        st.dataframe(pd.DataFrame(top_sources), use_container_width=True, hide_index=True)
    else:
        st.info("No data yet.")

with top_col2:
    st.markdown("**Top Destination IPs**")
    top_destinations = get_top_ips(packets, "destination")
    if top_destinations:
        st.dataframe(pd.DataFrame(top_destinations), use_container_width=True, hide_index=True)
    else:
        st.info("No data yet.")

st.divider()

st.subheader("🌍 Threat Intelligence")
with st.spinner("Checking IP reputation..."):
    threat_table = get_threat_intel_table(packets)

if threat_table:
    df_threat = pd.DataFrame(threat_table)
    st.dataframe(df_threat, use_container_width=True, hide_index=True)
else:
    st.info("No external IPs to check yet.")
st.divider()
st.subheader("🗺️ Traffic Origin Map")
country_counts = get_country_traffic_counts(threat_table)

if country_counts:
    df_geo = pd.DataFrame(list(country_counts.items()), columns=["Country", "Count"])
    fig3 = px.choropleth(
        df_geo,
        locations="Country",
        locationmode="ISO-3",
        color="Count",
        color_continuous_scale="Tealgrn"
    )
    fig3.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        geo=dict(bgcolor="rgba(0,0,0,0)", showframe=False)
    )
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.info("Not enough external IP data yet for the map.")
st.divider()
st.subheader("🔗 IP - MAC Address Table")

if ip_mac_table:
    df_arp = pd.DataFrame(ip_mac_table)
    st.dataframe(df_arp, use_container_width=True)
else:
    st.info("No ARP packets captured yet.")
st.divider()
st.subheader("🚨 Security Alerts")
if suspicious_entries:
    mitre = get_mitre_info()
    for entry in suspicious_entries:
        st.error(f"⚠️ Possible ARP Spoofing: IP {entry['IP Address']} has multiple MACs — {entry['MAC Address(es)']}")
        with st.expander(f"🔍 MITRE ATT&CK Details for {entry['IP Address']}"):
            st.markdown(f"**Technique:** {mitre['technique']} — {mitre['name']}")
            st.markdown(f"**Tactic:** {mitre['tactic']}")
            st.markdown(f"**Description:** {mitre['description']}")
            st.markdown(f"**Mitigation:** {mitre['mitigation']}")
            st.divider()
            st.markdown("**🤖 AI Investigation Summary**")
            ai_summary = generate_investigation_summary(entry, mitre)
            st.markdown(ai_summary)
        ip_key = entry['IP Address']
        last_sent_time = st.session_state.email_last_sent.get(ip_key, 0)
        if time.time() - last_sent_time > 300:
            email_sent = send_alert_email(ip_key, entry['MAC Address(es)'], mitre)
            if email_sent:
                st.session_state.email_last_sent[ip_key] = time.time()
                st.info(f"📧 Alert email sent for {ip_key}")
        else:
            st.caption(f"📧 Email already sent recently for {ip_key} (cooldown active)")
else:
    st.success("✅ No ARP Spoofing Detected")
if suspicious_entries:
    mitre_for_report = get_mitre_info()
    pdf_buffer = generate_incident_report(suspicious_entries, mitre_for_report)
    st.download_button(
        label="📄 Generate Incident Report (PDF)",
        data=pdf_buffer,
        file_name=f"incident_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
        mime="application/pdf"
    )

st.divider()

col1, col2 = st.columns(2)
with col1:
    if st.button("▶ Start Monitoring", disabled=st.session_state.sniffer_running, use_container_width=True):
        st.session_state.sniffer_running = True
        thread = threading.Thread(target=start_sniffing, daemon=True)
        thread.start()
        st.success("Sniffer Started")
with col2:
    if st.button("■ Stop Monitoring", use_container_width=True):
        st.session_state.sniffer_running = False
        st.warning("Sniffer Stopped")
