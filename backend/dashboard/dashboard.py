"""
dashboard.py
============
RESPONSIBILITY: The main Streamlit application. Lays out the sidebar
navigation and every page, and wires already-fetched backend data
into the chart/component/topology builders.

This file NEVER calculates risk, NEVER matches vulnerability rules,
and NEVER writes to MongoDB directly. It only:
    1. Calls the existing Flask API (via api_client.ApiClient) to
       READ data, or to trigger the existing POST /scan endpoint.
    2. Hands that data to charts.py / topology.py / components.py to
       render it.

Run with:
    streamlit run backend/dashboard/dashboard.py
(or use run_dashboard.py from the project root, which does this for you)
"""

import time
from pathlib import Path

import pandas as pd
import streamlit as st

from backend.dashboard.api_client import ApiClient, check_mongo_status, DEFAULT_API_URL, DEFAULT_MONGO_URI
from backend.dashboard.charts import (
    build_risk_gauge,
    build_risk_level_pie,
    build_vulnerability_breakdown,
    build_risk_histogram,
    build_ports_per_device_bar,
    build_os_distribution_pie,
    build_discovery_timeline,
)
from backend.dashboard.topology import render_topology_figure, render_knowledge_graph_figure
from backend.dashboard.components import (
    metric_card,
    status_badge,
    risk_badge,
    severity_badge,
    page_header,
    section_header,
    backend_status_pill,
    empty_state,
    current_datetime_display,
    service_card,
)

NAV_PAGES = ["Dashboard", "Assets", "Services", "Ports", "Risk", "Topology", "Logs", "Settings"]
NAV_ICONS = {
    "Dashboard": "🏠", "Assets": "🖥️", "Services": "🧩", "Ports": "🔌",
    "Risk": "⚠️", "Topology": "🕸️", "Logs": "📜", "Settings": "⚙️",
}


# ----------------------------------------------------------------------
# SETUP
# ----------------------------------------------------------------------
def load_css() -> None:
    """
    Load the Module 5 dashboard CSS.

    First look beside dashboard.py.
    Then fall back to the project-level assets/styles.css.
    """

    dashboard_css = Path(__file__).resolve().parent / "styles.css"

    project_css = (
        Path(__file__).resolve().parents[2]
        / "assets"
        / "styles.css"
    )

    if dashboard_css.exists():
        css_path = dashboard_css

    elif project_css.exists():
        css_path = project_css

    else:
        st.warning(
            "CyberTwinAI CSS file not found. "
            "Expected backend/dashboard/styles.css "
            "or assets/styles.css."
        )
        return

    css = css_path.read_text(
        encoding="utf-8"
    )

    st.markdown(
        f"<style>{css}</style>",
        unsafe_allow_html=True
    )

def init_session_state() -> None:
    """Set every session_state default exactly once per session."""
    defaults = {
        "api_base_url": DEFAULT_API_URL,
        "mongo_uri": DEFAULT_MONGO_URI,
        "nav_page": "Dashboard",
        "scan_log": [],           # list of {timestamp, target, devices_found, status}
        "auto_refresh": False,
        "refresh_interval": 10,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get_client() -> ApiClient:
    return ApiClient(base_url=st.session_state["api_base_url"])


# ----------------------------------------------------------------------
# DATA HELPERS (shape data for display only -- no analysis)
# ----------------------------------------------------------------------
def assets_to_dataframe(assets: list) -> pd.DataFrame:
    rows = []
    for asset in assets:
        rows.append({
            "asset_id": asset.get("asset_id"),
            "IP": asset.get("ip_address"),
            "Hostname": asset.get("hostname") or "—",
            "Operating System": asset.get("operating_system") or "Unknown",
            "Status": asset.get("status", "unknown"),
            "Risk Score": asset.get("risk_score", 0),
            "Risk Level": asset.get("risk_level") or "Unassessed",
            "Open Ports": len(asset.get("ports", [])),
            "Last Updated": asset.get("last_updated", ""),
        })
    return pd.DataFrame(rows)


def build_ports_table(assets: list) -> pd.DataFrame:
    rows = []
    for asset in assets:
        device_label = asset.get("hostname") or asset.get("ip_address")
        for service in asset.get("services", []):
            rows.append({
                "Device": device_label,
                "Service": service.get("service_name", "unknown"),
                "Version": service.get("version") or "Unknown",
                "Port": service.get("port"),
                "Protocol": service.get("protocol", "tcp"),
                "State": service.get("state", "open"),
            })
    return pd.DataFrame(rows)


def total_services(assets: list) -> int:
    return sum(len(asset.get("services", [])) for asset in assets)


def total_open_ports(assets: list) -> int:
    return sum(len(asset.get("ports", [])) for asset in assets)


def average_risk(assets: list) -> float:
    if not assets:
        return 0.0
    return sum(asset.get("risk_score", 0) for asset in assets) / len(assets)


# ----------------------------------------------------------------------
# SIDEBAR
# ----------------------------------------------------------------------
def render_sidebar(client: ApiClient) -> None:
    st.sidebar.markdown(
        """
        <div style="text-align:center; padding: 10px 0 20px 0;">
            <div style="font-size:2rem;">🛡️</div>
            <div style="font-weight:800; font-size:1.2rem; color:#e6f1ff;">CyberTwinAI</div>
            <div style="font-size:0.75rem; color:#8ea3bd;">Digital Twin Console</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    selected = st.sidebar.radio(
        "Navigation",
        NAV_PAGES,
        format_func=lambda page: f"{NAV_ICONS[page]}  {page}",
        index=NAV_PAGES.index(st.session_state["nav_page"]),
        label_visibility="collapsed",
    )
    st.session_state["nav_page"] = selected

    st.sidebar.markdown("---")
    st.sidebar.markdown("**Discovery Scan**")
    scan_target = st.sidebar.text_input(
        "Target (IP / CIDR)", placeholder="192.168.56.101", key="scan_target_input"
    )
    if st.sidebar.button("🔄 Refresh Scan", use_container_width=True):
        if not scan_target:
            st.sidebar.error("Enter a target IP or CIDR range first.")
        else:
            with st.spinner(f"Scanning {scan_target} ..."):
                result = client.trigger_scan(scan_target)

            log_entry = {
                "timestamp": current_datetime_display(),
                "target": scan_target,
            }
            if "error" in result:
                log_entry["status"] = "failed"
                log_entry["devices_found"] = 0
                st.session_state["scan_log"].insert(0, log_entry)
                st.sidebar.error(f"Scan failed: {result['error']}")
            else:
                log_entry["status"] = "success"
                log_entry["devices_found"] = result.get("devices_found", 0)
                st.session_state["scan_log"].insert(0, log_entry)
                st.sidebar.success(f"Found {result.get('devices_found', 0)} device(s).")
                st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.markdown("**Live View**")
    st.session_state["auto_refresh"] = st.sidebar.checkbox(
        "Auto Refresh (10s)", value=st.session_state["auto_refresh"]
    )
    if st.sidebar.button("↻ Refresh Now", use_container_width=True):
        st.rerun()

    st.sidebar.markdown("---")
    backend_status_pill(client.check_health(), "Flask API")


# ----------------------------------------------------------------------
# PAGE: DASHBOARD (HOME)
# ----------------------------------------------------------------------
def page_dashboard(assets: list) -> None:
    page_header("CyberTwinAI", "AI-Powered Cybersecurity Digital Twin")
    st.caption(f"🕒 {current_datetime_display()}")

    if not assets:
        empty_state("🛰️", "No assets discovered yet. Run a scan from the sidebar to populate the twin.")
        return

    online = [a for a in assets if a.get("status") == "online"]
    offline = [a for a in assets if a.get("status") != "online"]

    cols = st.columns(6)
    with cols[0]:
        metric_card("🖥️", "Total Devices", len(assets), "#3b82f6")
    with cols[1]:
        metric_card("🟢", "Online", len(online), "#22c55e")
    with cols[2]:
        metric_card("🔴", "Offline", len(offline), "#ef4444")
    with cols[3]:
        metric_card("📊", "Average Risk", f"{average_risk(assets):.1f}", "#eab308")
    with cols[4]:
        metric_card("🧩", "Total Services", total_services(assets), "#22d3ee")
    with cols[5]:
        metric_card("🔌", "Open Ports", total_open_ports(assets), "#f97316")

    section_header("📈", "Risk Overview")
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(build_risk_gauge(average_risk(assets)), use_container_width=True)
    with col2:
        st.plotly_chart(build_risk_level_pie(assets), use_container_width=True)

    section_header("📊", "Network Charts")
    col3, col4 = st.columns(2)
    with col3:
        st.plotly_chart(build_ports_per_device_bar(assets), use_container_width=True)
    with col4:
        st.plotly_chart(build_os_distribution_pie(assets), use_container_width=True)

    col5, col6 = st.columns(2)
    with col5:
        st.plotly_chart(build_discovery_timeline(assets), use_container_width=True)
    with col6:
        st.plotly_chart(build_risk_histogram(assets), use_container_width=True)

    section_header("🖥️", "Recent Assets")
    df = assets_to_dataframe(assets).drop(columns=["asset_id"]).head(5)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ----------------------------------------------------------------------
# PAGE: ASSETS
# ----------------------------------------------------------------------
def page_assets(assets: list) -> None:
    page_header("Assets", "Every device currently known to the Digital Twin")

    if not assets:
        empty_state("🖥️", "No assets discovered yet.")
        return

    df = assets_to_dataframe(assets)

    col_search, col_status, col_risk = st.columns([2, 1, 1])
    with col_search:
        search = st.text_input("🔍 Search by IP or hostname", "")
    with col_status:
        status_filter = st.selectbox("Status", ["All", "online", "offline"])
    with col_risk:
        risk_filter = st.selectbox("Risk Level", ["All", "Critical", "High", "Medium", "Low", "Unassessed"])

    filtered = df.copy()
    if search:
        mask = filtered["IP"].str.contains(search, case=False, na=False) | \
            filtered["Hostname"].str.contains(search, case=False, na=False)
        filtered = filtered[mask]
    if status_filter != "All":
        filtered = filtered[filtered["Status"] == status_filter]
    if risk_filter != "All":
        filtered = filtered[filtered["Risk Level"] == risk_filter]

    section_header("📋", f"Asset Inventory ({len(filtered)} of {len(df)})")
    st.dataframe(
        filtered.drop(columns=["asset_id"]),
        use_container_width=True,
        hide_index=True,
    )

    section_header("🔎", "Asset Details")
    if filtered.empty:
        empty_state("🔍", "No assets match your filters.")
        return

    options = {
        f"{row['Hostname']}  ({row['IP']})": row["asset_id"] for _, row in filtered.iterrows()
    }
    chosen_label = st.selectbox("Select an asset to inspect", list(options.keys()))
    chosen_id = options[chosen_label]
    asset = next((a for a in assets if a.get("asset_id") == chosen_id), None)

    if asset is None:
        return

    st.markdown('<div class="twin-panel">', unsafe_allow_html=True)
    detail_cols = st.columns(4)
    with detail_cols[0]:
        st.markdown(f"**Hostname**<br>{asset.get('hostname') or '—'}", unsafe_allow_html=True)
        st.markdown(f"**IP Address**<br>{asset.get('ip_address')}", unsafe_allow_html=True)
    with detail_cols[1]:
        st.markdown(f"**Operating System**<br>{asset.get('operating_system') or 'Unknown'}", unsafe_allow_html=True)
        st.markdown(f"**MAC Address**<br>{asset.get('mac_address') or '—'}", unsafe_allow_html=True)
    with detail_cols[2]:
        st.markdown(f"**Status**<br>{status_badge(asset.get('status'))}", unsafe_allow_html=True)
        st.markdown(f"**Risk Level**<br>{risk_badge(asset.get('risk_level'))}", unsafe_allow_html=True)
    with detail_cols[3]:
        st.markdown(f"**Risk Score**<br>{asset.get('risk_score', 0)} / 100", unsafe_allow_html=True)
        st.markdown(f"**Last Updated**<br>{asset.get('last_updated', '—')}", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    section_header("🔌", "Open Ports & Services")
    services = asset.get("services", [])
    if services:
        service_df = pd.DataFrame([{
            "Service": s.get("service_name", "unknown"),
            "Version": s.get("version") or "Unknown",
            "Port": s.get("port"),
            "Protocol": s.get("protocol", "tcp"),
        } for s in services])
        st.dataframe(service_df, use_container_width=True, hide_index=True)
    else:
        empty_state("🔌", "No open ports recorded for this asset.")

    section_header("🛡️", "Vulnerabilities")
    vulnerabilities = asset.get("vulnerabilities", [])
    if vulnerabilities:
        for vuln in vulnerabilities:
            st.markdown(
                f"""
                <div class="twin-panel">
                    <strong>{vuln.get('id', '')} — {vuln.get('name', 'Unknown')}</strong>
                    &nbsp;&nbsp;{severity_badge(vuln.get('severity'))}
                    <p style="color:#8ea3bd; margin:6px 0;">{vuln.get('description', '')}</p>
                    <p style="color:#22d3ee; margin:0;">💡 {vuln.get('recommendation', '')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        empty_state("✅", "No vulnerabilities recorded for this asset.")


# ----------------------------------------------------------------------
# PAGE: SERVICES
# ----------------------------------------------------------------------
def page_services(assets: list) -> None:
    page_header("Services", "Every network service discovered across the twin")

    if not assets:
        empty_state("🧩", "No services discovered yet.")
        return

    for asset in assets:
        services = asset.get("services", [])
        label = asset.get("hostname") or asset.get("ip_address")
        with st.expander(f"🖥️  {label}  —  {len(services)} service(s)", expanded=False):
            if not services:
                empty_state("🧩", "No services detected on this device.")
                continue
            columns = st.columns(2)
            for index, service in enumerate(services):
                with columns[index % 2]:
                    service_card(
                        service.get("service_name", "unknown"),
                        service.get("port"),
                        service.get("protocol", "tcp"),
                        service.get("version"),
                    )


# ----------------------------------------------------------------------
# PAGE: PORTS
# ----------------------------------------------------------------------
def page_ports(assets: list) -> None:
    page_header("Ports", "Open ports across every discovered device")

    if not assets:
        empty_state("🔌", "No open ports discovered yet.")
        return

    df = build_ports_table(assets)
    if df.empty:
        empty_state("🔌", "No open ports discovered yet.")
        return

    search = st.text_input("🔍 Filter by port number or service name", "")
    filtered = df.copy()
    if search:
        mask = filtered["Port"].astype(str).str.contains(search, case=False, na=False) | \
            filtered["Service"].str.contains(search, case=False, na=False)
        filtered = filtered[mask]

    section_header("🔌", f"Open Ports ({len(filtered)} of {len(df)})")
    st.dataframe(filtered, use_container_width=True, hide_index=True)

    section_header("📊", "Open Ports per Device")
    st.plotly_chart(build_ports_per_device_bar(assets), use_container_width=True)


# ----------------------------------------------------------------------
# PAGE: RISK
# ----------------------------------------------------------------------
def page_risk(assets: list) -> None:
    page_header("Risk", "Network-wide risk assessment, as calculated by the Risk Engine")

    if not assets:
        empty_state("⚠️", "No risk data available yet.")
        return

    avg_risk = average_risk(assets)
    col1, col2 = st.columns([1, 1])
    with col1:
        st.plotly_chart(build_risk_gauge(avg_risk), use_container_width=True)
        st.progress(min(int(avg_risk), 100) / 100, text=f"Average Network Risk: {avg_risk:.1f} / 100")
    with col2:
        st.plotly_chart(build_risk_level_pie(assets), use_container_width=True)

    section_header("🛡️", "Vulnerability Severity Breakdown")
    st.plotly_chart(build_vulnerability_breakdown(assets), use_container_width=True)

    section_header("📊", "Risk Score Distribution")
    st.plotly_chart(build_risk_histogram(assets), use_container_width=True)

    section_header("🚨", "Highest Risk Assets")
    df = assets_to_dataframe(assets).sort_values("Risk Score", ascending=False).head(5)
    st.dataframe(df.drop(columns=["asset_id"]), use_container_width=True, hide_index=True)


# ----------------------------------------------------------------------
# PAGE: TOPOLOGY
# ----------------------------------------------------------------------
def page_topology(assets: list, client: ApiClient) -> None:
    page_header("Topology", "Network views built from discovered assets")

    if not assets:
        empty_state("🕸️", "No assets discovered yet.")
        return

    view = st.radio(
        "View",
        ["Logical Hub View (Module 5)", "Knowledge Graph — Asset Relationships (Module 6)"],
        horizontal=True,
        label_visibility="collapsed",
    )

    if view == "Logical Hub View (Module 5)":
        st.caption(
            "ℹ️ Real device-to-device connections are not yet discovered by the backend "
            "(see backend/twin/connection.py). This view shows a logical hub topology "
            "so you can still see every asset at a glance -- it is NOT physical network topology."
        )
        st.plotly_chart(render_topology_figure(assets), use_container_width=True)
    else:
        st.caption(
            "ℹ️ This graph represents relationships between assets, IPs, operating systems, "
            "ports, services, vulnerabilities, and risk -- as already computed by Modules 1-4. "
            "It does NOT represent physical network topology or attacker paths (that is a "
            "future module). Device-to-device edges only appear if the backend has real "
            "connection data; none are fabricated."
        )
        with st.spinner("Building Knowledge Graph..."):
            graph_data = client.get_knowledge_graph()

        if graph_data is None:
            empty_state("🕸️", "Knowledge Graph endpoint is unavailable. Make sure the backend "
                              "includes Module 6 (GET /knowledge-graph).")
            return

        st.plotly_chart(render_knowledge_graph_figure(graph_data), use_container_width=True)


# ----------------------------------------------------------------------
# PAGE: LOGS
# ----------------------------------------------------------------------
def page_logs(assets: list) -> None:
    page_header("Logs", "Scan activity and Digital Twin update history")

    section_header("🛰️", "Last Scan (this session)")
    scan_log = st.session_state.get("scan_log", [])
    if scan_log:
        latest = scan_log[0]
        status_color = "#22c55e" if latest["status"] == "success" else "#ef4444"
        st.markdown(
            f"""
            <div class="twin-panel">
                <strong>Target:</strong> {latest['target']} &nbsp;|&nbsp;
                <strong>Time:</strong> {latest['timestamp']} &nbsp;|&nbsp;
                <strong>Status:</strong> <span style="color:{status_color};">{latest['status']}</span>
                &nbsp;|&nbsp; <strong>Devices Found:</strong> {latest['devices_found']}
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        empty_state("🛰️", "No scans triggered yet in this session.")

    section_header("📜", "Discovery Scan Log (newest first)")
    if scan_log:
        log_df = pd.DataFrame(scan_log)
        st.dataframe(log_df, use_container_width=True, hide_index=True)
    else:
        empty_state("📜", "Scan history will appear here once you run a scan.")

    section_header("🔄", "Digital Twin Updates (newest first)")
    if assets:
        updates_df = assets_to_dataframe(assets)[["Hostname", "IP", "Status", "Last Updated"]]
        updates_df = updates_df.sort_values("Last Updated", ascending=False)
        st.dataframe(updates_df, use_container_width=True, hide_index=True)
    else:
        empty_state("🔄", "No twin updates recorded yet.")


# ----------------------------------------------------------------------
# PAGE: SETTINGS
# ----------------------------------------------------------------------
def page_settings(client: ApiClient) -> None:
    page_header("Settings", "Backend connection and dashboard preferences")

    section_header("🌐", "Backend Connection")
    new_url = st.text_input("Flask API Base URL", value=st.session_state["api_base_url"])
    new_mongo_uri = st.text_input("MongoDB URI (read-only status check)", value=st.session_state["mongo_uri"])

    if st.button("💾 Apply Settings"):
        st.session_state["api_base_url"] = new_url
        st.session_state["mongo_uri"] = new_mongo_uri
        st.success("Settings updated.")
        st.rerun()

    section_header("📡", "Connection Status")
    col1, col2 = st.columns(2)
    with col1:
        backend_status_pill(client.check_health(), "Flask API")
    with col2:
        backend_status_pill(check_mongo_status(st.session_state["mongo_uri"]), "MongoDB")

    section_header("⏱️", "Auto Refresh")
    st.session_state["refresh_interval"] = st.number_input(
        "Refresh interval (seconds)", min_value=5, max_value=120,
        value=st.session_state["refresh_interval"], step=5,
    )


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main() -> None:
    st.set_page_config(
        page_title="CyberTwinAI Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    load_css()
    init_session_state()

    client = get_client()
    render_sidebar(client)

    with st.spinner("Loading Digital Twin state..."):
        assets = client.get_all_assets()

    page = st.session_state["nav_page"]
    if page == "Dashboard":
        page_dashboard(assets)
    elif page == "Assets":
        page_assets(assets)
    elif page == "Services":
        page_services(assets)
    elif page == "Ports":
        page_ports(assets)
    elif page == "Risk":
        page_risk(assets)
    elif page == "Topology":
        page_topology(assets, client)
    elif page == "Logs":
        page_logs(assets)
    elif page == "Settings":
        page_settings(client)

    # Best-effort auto-refresh: Streamlit has no built-in polling, so a
    # short sleep + rerun is the standard lightweight approach without
    # adding a JS-based dependency.
    if st.session_state.get("auto_refresh"):
        time.sleep(st.session_state["refresh_interval"])
        st.rerun()


if __name__ == "__main__":
    main()
