"""
CyberTwinAI Dashboard
=====================

Main Streamlit dashboard.

Run from project root:

    streamlit run backend/dashboard/dashboard.py

This file:
    - Reads data through the existing Flask API
    - Triggers the existing scan endpoint
    - Displays assets, services, ports, risk and topology
    - Uses the existing charts.py, components.py and topology.py
    - Does NOT calculate risk
    - Does NOT match vulnerabilities
    - Does NOT write directly to MongoDB
"""

import time
from pathlib import Path

import pandas as pd
import streamlit as st

from backend.dashboard.api_client import (
    ApiClient,
    check_mongo_status,
    DEFAULT_API_URL,
    DEFAULT_MONGO_URI,
)

from backend.dashboard.charts import (
    build_risk_gauge,
    build_risk_level_pie,
    build_vulnerability_breakdown,
    build_risk_histogram,
    build_ports_per_device_bar,
    build_os_distribution_pie,
    build_discovery_timeline,
)

from backend.dashboard.topology import (
    render_topology_figure,
    render_knowledge_graph_figure,
)

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


# ======================================================================
# NAVIGATION
# ======================================================================

NAV_PAGES = [
    "Dashboard",
    "Assets",
    "Services",
    "Ports",
    "Risk",
    "Topology",
    "Logs",
    "Settings",
]

NAV_ICONS = {
    "Dashboard": "🏠",
    "Assets": "🖥️",
    "Services": "🧩",
    "Ports": "🔌",
    "Risk": "⚠️",
    "Topology": "🕸️",
    "Logs": "📜",
    "Settings": "⚙️",
}


# ======================================================================
# BUILT-IN CSS
#
# This is intentionally inside dashboard.py as a safety net.
# Your styles.css is still loaded first if it exists.
# ======================================================================

DASHBOARD_CSS = r"""
<style>

/* ================================================================
   GLOBAL
   ================================================================ */

html,
body,
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(
            circle at 20% 0%,
            #0d1b2d 0%,
            #07101b 42%,
            #050b13 100%
        ) !important;

    color: #e6f1ff !important;
}

[data-testid="stAppViewContainer"] > .main {
    background: transparent !important;
}

.main .block-container {
    max-width: 1500px !important;

    padding-top: 2.0rem !important;
    padding-right: 2.4rem !important;
    padding-bottom: 3rem !important;
    padding-left: 2.4rem !important;
}


/* ================================================================
   STREAMLIT HEADER
   ================================================================ */

[data-testid="stHeader"] {
    background: rgba(5, 11, 19, 0.75) !important;
    border-bottom: 1px solid rgba(36, 54, 80, 0.55) !important;
}

[data-testid="stToolbar"] {
    visibility: hidden !important;
}


/* ================================================================
   SIDEBAR
   ================================================================ */

section[data-testid="stSidebar"] {

    min-width: 255px !important;
    max-width: 255px !important;

    background:
        linear-gradient(
            180deg,
            #0b1625 0%,
            #08111d 55%,
            #060d16 100%
        ) !important;

    border-right: 1px solid #203149 !important;
}

section[data-testid="stSidebar"] > div {
    padding: 1rem 0.85rem 1.2rem !important;
}


/* Sidebar title */

section[data-testid="stSidebar"] h3 {
    color: #eaf7ff !important;
    text-align: center !important;

    font-size: 1.18rem !important;
    font-weight: 800 !important;

    margin-top: 0.2rem !important;
    margin-bottom: 0.15rem !important;
}


/* Sidebar subtitle */

section[data-testid="stSidebar"]
[data-testid="stCaptionContainer"] {

    color: #7890aa !important;
    text-align: center !important;

    font-size: 0.72rem !important;
}


/* Sidebar separators */

section[data-testid="stSidebar"] hr {
    border-color: #1d2b3e !important;
    margin: 0.75rem 0 !important;
}


/* ================================================================
   SIDEBAR RADIO NAVIGATION
   ================================================================ */

section[data-testid="stSidebar"]
div[data-testid="stRadio"] > label {

    display: none !important;
}

section[data-testid="stSidebar"]
div[data-testid="stRadio"]
div[role="radiogroup"] {

    gap: 4px !important;
}

section[data-testid="stSidebar"]
div[data-testid="stRadio"]
div[role="radiogroup"] label {

    min-height: 38px !important;

    padding: 0.45rem 0.65rem !important;

    margin: 0 !important;

    border-radius: 9px !important;

    border: 1px solid transparent !important;

    color: #a9bbcf !important;

    background: transparent !important;

    transition:
        background 0.15s ease,
        color 0.15s ease,
        border 0.15s ease !important;
}

section[data-testid="stSidebar"]
div[data-testid="stRadio"]
div[role="radiogroup"] label:hover {

    background: rgba(34, 211, 238, 0.07) !important;

    color: #e6f1ff !important;

    border-color: rgba(34, 211, 238, 0.15) !important;
}


/* Selected navigation item */

section[data-testid="stSidebar"]
div[data-testid="stRadio"]
div[role="radiogroup"]
label:has(input:checked) {

    background:
        linear-gradient(
            90deg,
            rgba(34, 211, 238, 0.15),
            rgba(59, 130, 246, 0.10)
        ) !important;

    border-color:
        rgba(34, 211, 238, 0.25) !important;

    color: #eafcff !important;

    box-shadow:
        inset 3px 0 0 #22d3ee !important;
}

section[data-testid="stSidebar"]
div[data-testid="stRadio"]
div[role="radiogroup"]
label p {

    color: inherit !important;

    font-size: 0.88rem !important;

    font-weight: 600 !important;
}


/* ================================================================
   SIDEBAR INPUTS
   ================================================================ */

section[data-testid="stSidebar"]
div[data-baseweb="input"] {

    background: #0c1726 !important;

    border-color: #30435e !important;

    border-radius: 8px !important;
}

section[data-testid="stSidebar"]
div[data-baseweb="input"] input {

    color: #dcecff !important;
}

section[data-testid="stSidebar"] button {

    border-radius: 8px !important;
}


/* ================================================================
   MAIN HEADINGS
   ================================================================ */

h1,
h2,
h3 {

    color: #eaf7ff !important;
}


/* ================================================================
   METRIC CARDS
   ================================================================ */

[data-testid="stMetric"] {

    background:
        linear-gradient(
            145deg,
            #111d2e,
            #0d1726
        ) !important;

    border: 1px solid #22344d !important;

    border-radius: 12px !important;

    padding: 0.9rem !important;
}


/* ================================================================
   DATA TABLES
   ================================================================ */

[data-testid="stDataFrame"] {

    border: 1px solid #22344d !important;

    border-radius: 10px !important;

    overflow: hidden !important;
}


/* ================================================================
   EXPANDERS
   ================================================================ */

div[data-testid="stExpander"] {

    background: #0f1a2b !important;

    border: 1px solid #243650 !important;

    border-radius: 10px !important;
}


/* ================================================================
   INPUTS / SELECTBOXES
   ================================================================ */

div[data-baseweb="select"] > div,
div[data-baseweb="input"] {

    background: #0d1827 !important;

    border-color: #2a3d58 !important;
}

div[data-baseweb="select"] * {

    color: #dcecff !important;
}


/* ================================================================
   BUTTONS
   ================================================================ */

button[kind="primary"] {

    background:
        linear-gradient(
            90deg,
            #2563eb,
            #06b6d4
        ) !important;

    border: 0 !important;

    color: white !important;
}


/* ================================================================
   PROGRESS
   ================================================================ */

.stProgress > div > div {

    background: #22d3ee !important;
}


/* ================================================================
   ALERTS
   ================================================================ */

div[data-testid="stAlert"] {

    border-radius: 9px !important;
}


/* ================================================================
   CUSTOM PANELS
   ================================================================ */

.twin-panel {

    background:
        linear-gradient(
            145deg,
            #111d2e,
            #0c1625
        );

    border: 1px solid #263a55;

    border-radius: 12px;

    padding: 18px;

    margin: 8px 0;

    color: #e6f1ff;

    box-shadow:
        0 8px 30px rgba(0, 0, 0, 0.15);
}


/* ================================================================
   SCROLLBAR
   ================================================================ */

::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: #07101b;
}

::-webkit-scrollbar-thumb {

    background: #263b56;

    border-radius: 8px;
}

::-webkit-scrollbar-thumb:hover {

    background: #355474;
}

</style>
"""


# ======================================================================
# CSS LOADER
# ======================================================================

def load_css() -> None:
    """
    Load backend/dashboard/styles.css if it exists.

    Then apply the built-in dashboard CSS.

    The built-in CSS guarantees that the dashboard still has
    a professional appearance even if styles.css is incomplete
    or contains old selectors.
    """

    css_path = Path(__file__).resolve().parent / "styles.css"

    if css_path.exists():

        try:

            css = css_path.read_text(
                encoding="utf-8"
            )

            st.markdown(
                f"<style>{css}</style>",
                unsafe_allow_html=True,
            )

        except OSError:
            pass

    st.markdown(
        DASHBOARD_CSS,
        unsafe_allow_html=True,
    )


# ======================================================================
# SESSION STATE
# ======================================================================

def init_session_state() -> None:
    """Initialize dashboard session variables."""

    defaults = {

        "api_base_url":
            DEFAULT_API_URL,

        "mongo_uri":
            DEFAULT_MONGO_URI,

        "nav_page":
            "Dashboard",

        "scan_log":
            [],

        "auto_refresh":
            False,

        "refresh_interval":
            10,
    }

    for key, value in defaults.items():

        if key not in st.session_state:

            st.session_state[key] = value


# ======================================================================
# API CLIENT
# ======================================================================

def get_client() -> ApiClient:

    return ApiClient(
        base_url=st.session_state["api_base_url"]
    )


# ======================================================================
# SAFE DATA HELPERS
# ======================================================================

def safe_assets(value) -> list:
    """
    Ensure the dashboard always receives a list.

    If the API returns an unexpected object or error payload,
    the dashboard shows an empty state instead of crashing.
    """

    if isinstance(value, list):
        return value

    return []


def numeric_risk(asset: dict) -> float:
    """
    Safely convert risk score to float.
    """

    try:

        return float(
            asset.get(
                "risk_score",
                0
            ) or 0
        )

    except (
        TypeError,
        ValueError,
    ):

        return 0.0


# ======================================================================
# DATAFRAME HELPERS
# ======================================================================

def assets_to_dataframe(
    assets: list,
) -> pd.DataFrame:

    rows = []

    for asset in safe_assets(assets):

        rows.append(
            {
                "asset_id":
                    asset.get("asset_id"),

                "IP":
                    asset.get("ip_address")
                    or "—",

                "Hostname":
                    asset.get("hostname")
                    or "—",

                "Operating System":
                    asset.get("operating_system")
                    or "Unknown",

                "Status":
                    asset.get(
                        "status",
                        "unknown",
                    ),

                "Risk Score":
                    numeric_risk(asset),

                "Risk Level":
                    asset.get("risk_level")
                    or "Unassessed",

                "Open Ports":
                    len(
                        asset.get(
                            "ports",
                            []
                        )
                        or []
                    ),

                "Last Updated":
                    asset.get(
                        "last_updated",
                        "",
                    ),
            }
        )

    return pd.DataFrame(rows)


def build_ports_table(
    assets: list,
) -> pd.DataFrame:

    rows = []

    for asset in safe_assets(assets):

        device_label = (
            asset.get("hostname")
            or asset.get("ip_address")
            or "Unknown device"
        )

        services = (
            asset.get("services", [])
            or []
        )

        for service in services:

            rows.append(
                {
                    "Device":
                        device_label,

                    "Service":
                        service.get(
                            "service_name",
                            "unknown",
                        ),

                    "Version":
                        service.get(
                            "version"
                        )
                        or "Unknown",

                    "Port":
                        service.get("port"),

                    "Protocol":
                        service.get(
                            "protocol",
                            "tcp",
                        ),

                    "State":
                        service.get(
                            "state",
                            "open",
                        ),
                }
            )

    return pd.DataFrame(rows)


def total_services(
    assets: list,
) -> int:

    return sum(
        len(
            asset.get(
                "services",
                []
            )
            or []
        )
        for asset in safe_assets(assets)
    )


def total_open_ports(
    assets: list,
) -> int:

    return sum(
        len(
            asset.get(
                "ports",
                []
            )
            or []
        )
        for asset in safe_assets(assets)
    )


def average_risk(
    assets: list,
) -> float:

    items = safe_assets(assets)

    if not items:
        return 0.0

    return (
        sum(
            numeric_risk(asset)
            for asset in items
        )
        / len(items)
    )


# ======================================================================
# SIDEBAR
# ======================================================================

def render_sidebar(
    client: ApiClient,
) -> None:

    # --------------------------------------------------------------
    # BRAND
    #
    # IMPORTANT:
    # No custom HTML here.
    # This avoids the raw <div class="ct-sidebar..."> problem.
    # --------------------------------------------------------------

    st.sidebar.markdown(
        "### 🛡️ CyberTwinAI"
    )

    st.sidebar.caption(
        "Digital Twin Console"
    )

    # --------------------------------------------------------------
    # NAVIGATION
    # --------------------------------------------------------------

    selected = st.sidebar.radio(
        "Navigation",
        NAV_PAGES,
        format_func=lambda page:
            f"{NAV_ICONS[page]}  {page}",
        index=NAV_PAGES.index(
            st.session_state["nav_page"]
        ),
        label_visibility="collapsed",
    )

    st.session_state["nav_page"] = selected

    # --------------------------------------------------------------
    # DISCOVERY SCAN
    # --------------------------------------------------------------

    st.sidebar.markdown("---")

    st.sidebar.markdown(
        "**DISCOVERY SCAN**"
    )

    scan_target = st.sidebar.text_input(
        "Target (IP / CIDR)",
        placeholder="192.168.56.101",
        key="scan_target_input",
    )

    if st.sidebar.button(
        "🔄 Refresh Scan",
        use_container_width=True,
    ):

        if not scan_target.strip():

            st.sidebar.error(
                "Enter a target IP or CIDR range first."
            )

        else:

            with st.spinner(
                f"Scanning {scan_target} ..."
            ):

                result = client.trigger_scan(
                    scan_target.strip()
                )

            log_entry = {

                "timestamp":
                    current_datetime_display(),

                "target":
                    scan_target.strip(),

                "status":
                    (
                        "failed"
                        if "error" in result
                        else "success"
                    ),

                "devices_found":
                    result.get(
                        "devices_found",
                        0,
                    ),
            }

            st.session_state[
                "scan_log"
            ].insert(
                0,
                log_entry,
            )

            if "error" in result:

                st.sidebar.error(
                    f"Scan failed: "
                    f"{result['error']}"
                )

            else:

                st.sidebar.success(
                    "Found "
                    f"{result.get('devices_found', 0)} "
                    "device(s)."
                )

                st.rerun()

    # --------------------------------------------------------------
    # LIVE VIEW
    # --------------------------------------------------------------

    st.sidebar.markdown("---")

    st.sidebar.markdown(
        "**LIVE VIEW**"
    )

    st.session_state[
        "auto_refresh"
    ] = st.sidebar.checkbox(
        "Auto Refresh",
        value=st.session_state[
            "auto_refresh"
        ],
    )

    if st.sidebar.button(
        "↻ Refresh Now",
        use_container_width=True,
    ):

        st.rerun()

    # --------------------------------------------------------------
    # BACKEND STATUS
    # --------------------------------------------------------------

    st.sidebar.markdown("---")

    backend_status_pill(
        client.check_health(),
        "Flask API",
    )


# ======================================================================
# PAGE: DASHBOARD
# ======================================================================

def page_dashboard(
    assets: list,
) -> None:

    page_header(
        "CyberTwinAI",
        "AI-Powered Cybersecurity Digital Twin",
    )

    st.caption(
        f"🕒 {current_datetime_display()}"
    )

    if not assets:

        empty_state(
            "🛰️",
            "No assets discovered yet. "
            "Run a scan from the sidebar "
            "to populate the twin.",
        )

        return

    online = [
        asset
        for asset in assets
        if asset.get("status") == "online"
    ]

    offline = [
        asset
        for asset in assets
        if asset.get("status") != "online"
    ]

    # --------------------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------------------

    cols = st.columns(6)

    cards = [

        (
            "🖥️",
            "Total Devices",
            len(assets),
            "#3b82f6",
        ),

        (
            "🟢",
            "Online",
            len(online),
            "#22c55e",
        ),

        (
            "🔴",
            "Offline",
            len(offline),
            "#ef4444",
        ),

        (
            "📊",
            "Average Risk",
            f"{average_risk(assets):.1f}",
            "#eab308",
        ),

        (
            "🧩",
            "Total Services",
            total_services(assets),
            "#22d3ee",
        ),

        (
            "🔌",
            "Open Ports",
            total_open_ports(assets),
            "#f97316",
        ),
    ]

    for col, card in zip(
        cols,
        cards,
    ):

        with col:

            metric_card(
                *card
            )

    # --------------------------------------------------------------
    # RISK OVERVIEW
    # --------------------------------------------------------------

    section_header(
        "📈",
        "Risk Overview",
    )

    col1, col2 = st.columns(2)

    with col1:

        st.plotly_chart(
            build_risk_gauge(
                average_risk(assets)
            ),
            use_container_width=True,
        )

    with col2:

        st.plotly_chart(
            build_risk_level_pie(
                assets
            ),
            use_container_width=True,
        )

    # --------------------------------------------------------------
    # NETWORK CHARTS
    # --------------------------------------------------------------

    section_header(
        "📊",
        "Network Charts",
    )

    col3, col4 = st.columns(2)

    with col3:

        st.plotly_chart(
            build_ports_per_device_bar(
                assets
            ),
            use_container_width=True,
        )

    with col4:

        st.plotly_chart(
            build_os_distribution_pie(
                assets
            ),
            use_container_width=True,
        )

    col5, col6 = st.columns(2)

    with col5:

        st.plotly_chart(
            build_discovery_timeline(
                assets
            ),
            use_container_width=True,
        )

    with col6:

        st.plotly_chart(
            build_risk_histogram(
                assets
            ),
            use_container_width=True,
        )

    # --------------------------------------------------------------
    # RECENT ASSETS
    # --------------------------------------------------------------

    section_header(
        "🖥️",
        "Recent Assets",
    )

    df = assets_to_dataframe(
        assets
    )

    if not df.empty:

        st.dataframe(
            df
            .drop(
                columns=["asset_id"]
            )
            .head(5),
            use_container_width=True,
            hide_index=True,
        )


# ======================================================================
# PAGE: ASSETS
# ======================================================================

def page_assets(
    assets: list,
) -> None:

    page_header(
        "Assets",
        "Every device currently known to the Digital Twin",
    )

    if not assets:

        empty_state(
            "🖥️",
            "No assets discovered yet.",
        )

        return

    df = assets_to_dataframe(
        assets
    )

    col_search, col_status, col_risk = st.columns(
        [2, 1, 1]
    )

    with col_search:

        search = st.text_input(
            "🔍 Search by IP or hostname",
            "",
        )

    with col_status:

        status_filter = st.selectbox(
            "Status",
            [
                "All",
                "online",
                "offline",
            ],
        )

    with col_risk:

        risk_filter = st.selectbox(
            "Risk Level",
            [
                "All",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Unassessed",
            ],
        )

    filtered = df.copy()

    if search:

        needle = search.strip()

        mask = (
            filtered["IP"]
            .astype(str)
            .str.contains(
                needle,
                case=False,
                na=False,
            )
            |
            filtered["Hostname"]
            .astype(str)
            .str.contains(
                needle,
                case=False,
                na=False,
            )
        )

        filtered = filtered[mask]

    if status_filter != "All":

        filtered = filtered[
            filtered["Status"]
            == status_filter
        ]

    if risk_filter != "All":

        filtered = filtered[
            filtered["Risk Level"]
            == risk_filter
        ]

    section_header(
        "📋",
        f"Asset Inventory "
        f"({len(filtered)} of {len(df)})",
    )

    st.dataframe(
        filtered.drop(
            columns=["asset_id"]
        ),
        use_container_width=True,
        hide_index=True,
    )

    section_header(
        "🔎",
        "Asset Details",
    )

    if filtered.empty:

        empty_state(
            "🔍",
            "No assets match your filters.",
        )

        return

    options = {

        f"{row['Hostname']} "
        f"({row['IP']})":

            row["asset_id"]

        for _, row
        in filtered.iterrows()
    }

    chosen_label = st.selectbox(
        "Select an asset to inspect",
        list(options),
    )

    chosen_id = options[
        chosen_label
    ]

    asset = next(
        (
            item
            for item in assets
            if item.get(
                "asset_id"
            ) == chosen_id
        ),
        None,
    )

    if asset is None:
        return

    # --------------------------------------------------------------
    # ASSET DETAIL
    # --------------------------------------------------------------

    st.markdown(
        '<div class="twin-panel">',
        unsafe_allow_html=True,
    )

    detail_cols = st.columns(4)

    with detail_cols[0]:

        st.markdown(
            f"**Hostname**<br>"
            f"{asset.get('hostname') or '—'}",
            unsafe_allow_html=True,
        )

        st.markdown(
            f"**IP Address**<br>"
            f"{asset.get('ip_address') or '—'}",
            unsafe_allow_html=True,
        )

    with detail_cols[1]:

        st.markdown(
            f"**Operating System**<br>"
            f"{asset.get('operating_system') or 'Unknown'}",
            unsafe_allow_html=True,
        )

        st.markdown(
            f"**MAC Address**<br>"
            f"{asset.get('mac_address') or '—'}",
            unsafe_allow_html=True,
        )

    with detail_cols[2]:

        st.markdown(
            f"**Status**<br>"
            f"{status_badge(asset.get('status'))}",
            unsafe_allow_html=True,
        )

        st.markdown(
            f"**Risk Level**<br>"
            f"{risk_badge(asset.get('risk_level'))}",
            unsafe_allow_html=True,
        )

    with detail_cols[3]:

        st.markdown(
            f"**Risk Score**<br>"
            f"{numeric_risk(asset):.0f} / 100",
            unsafe_allow_html=True,
        )

        st.markdown(
            f"**Last Updated**<br>"
            f"{asset.get('last_updated') or '—'}",
            unsafe_allow_html=True,
        )

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------------
    # SERVICES
    # --------------------------------------------------------------

    section_header(
        "🔌",
        "Open Ports & Services",
    )

    services = (
        asset.get(
            "services",
            []
        )
        or []
    )

    if services:

        service_df = pd.DataFrame(
            [
                {
                    "Service":
                        service.get(
                            "service_name",
                            "unknown",
                        ),

                    "Version":
                        service.get(
                            "version"
                        )
                        or "Unknown",

                    "Port":
                        service.get(
                            "port"
                        ),

                    "Protocol":
                        service.get(
                            "protocol",
                            "tcp",
                        ),
                }

                for service
                in services
            ]
        )

        st.dataframe(
            service_df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        empty_state(
            "🔌",
            "No open ports recorded for this asset.",
        )

    # --------------------------------------------------------------
    # VULNERABILITIES
    # --------------------------------------------------------------

    section_header(
        "🛡️",
        "Vulnerabilities",
    )

    vulnerabilities = (
        asset.get(
            "vulnerabilities",
            []
        )
        or []
    )

    if vulnerabilities:

        for vuln in vulnerabilities:

            st.markdown(
                f"""
                <div class="twin-panel">

                    <strong>
                        {vuln.get('id', '')}
                        —
                        {vuln.get('name', 'Unknown')}
                    </strong>

                    &nbsp;&nbsp;

                    {severity_badge(
                        vuln.get('severity')
                    )}

                    <p style="
                        color:#8ea3bd;
                        margin:6px 0;
                    ">
                        {vuln.get(
                            'description',
                            ''
                        )}
                    </p>

                    <p style="
                        color:#22d3ee;
                        margin:0;
                    ">
                        💡
                        {vuln.get(
                            'recommendation',
                            ''
                        )}
                    </p>

                </div>
                """,
                unsafe_allow_html=True,
            )

    else:

        empty_state(
            "✅",
            "No vulnerabilities recorded for this asset.",
        )


# ======================================================================
# PAGE: SERVICES
# ======================================================================

def page_services(
    assets: list,
) -> None:

    page_header(
        "Services",
        "Every network service discovered across the twin",
    )

    if not assets:

        empty_state(
            "🧩",
            "No services discovered yet.",
        )

        return

    for asset in assets:

        services = (
            asset.get(
                "services",
                []
            )
            or []
        )

        label = (
            asset.get("hostname")
            or asset.get("ip_address")
            or "Unknown device"
        )

        with st.expander(
            f"🖥️ {label} — "
            f"{len(services)} service(s)",
            expanded=False,
        ):

            if not services:

                empty_state(
                    "🧩",
                    "No services detected on this device.",
                )

                continue

            columns = st.columns(2)

            for index, service in enumerate(
                services
            ):

                with columns[
                    index % 2
                ]:

                    service_card(
                        service.get(
                            "service_name",
                            "unknown",
                        ),
                        service.get(
                            "port"
                        ),
                        service.get(
                            "protocol",
                            "tcp",
                        ),
                        service.get(
                            "version"
                        ),
                    )


# ======================================================================
# PAGE: PORTS
# ======================================================================

def page_ports(
    assets: list,
) -> None:

    page_header(
        "Ports",
        "Open ports across every discovered device",
    )

    if not assets:

        empty_state(
            "🔌",
            "No open ports discovered yet.",
        )

        return

    df = build_ports_table(
        assets
    )

    if df.empty:

        empty_state(
            "🔌",
            "No open ports discovered yet.",
        )

        return

    search = st.text_input(
        "🔍 Filter by port number or service name",
        "",
    )

    filtered = df.copy()

    if search:

        needle = search.strip()

        mask = (
            filtered["Port"]
            .astype(str)
            .str.contains(
                needle,
                case=False,
                na=False,
            )
            |
            filtered["Service"]
            .astype(str)
            .str.contains(
                needle,
                case=False,
                na=False,
            )
        )

        filtered = filtered[mask]

    section_header(
        "🔌",
        f"Open Ports "
        f"({len(filtered)} of {len(df)})",
    )

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

    section_header(
        "📊",
        "Open Ports per Device",
    )

    st.plotly_chart(
        build_ports_per_device_bar(
            assets
        ),
        use_container_width=True,
    )


# ======================================================================
# PAGE: RISK
# ======================================================================

def page_risk(
    assets: list,
) -> None:

    page_header(
        "Risk",
        "Network-wide risk assessment, "
        "as calculated by the Risk Engine",
    )

    if not assets:

        empty_state(
            "⚠️",
            "No risk data available yet.",
        )

        return

    avg_risk = average_risk(
        assets
    )

    col1, col2 = st.columns(2)

    with col1:

        st.plotly_chart(
            build_risk_gauge(
                avg_risk
            ),
            use_container_width=True,
        )

        st.progress(
            max(
                0.0,
                min(
                    avg_risk,
                    100.0,
                ),
            ) / 100.0,

            text=(
                f"Average Network Risk: "
                f"{avg_risk:.1f} / 100"
            ),
        )

    with col2:

        st.plotly_chart(
            build_risk_level_pie(
                assets
            ),
            use_container_width=True,
        )

    section_header(
        "🛡️",
        "Vulnerability Severity Breakdown",
    )

    st.plotly_chart(
        build_vulnerability_breakdown(
            assets
        ),
        use_container_width=True,
    )

    section_header(
        "📊",
        "Risk Score Distribution",
    )

    st.plotly_chart(
        build_risk_histogram(
            assets
        ),
        use_container_width=True,
    )

    section_header(
        "🚨",
        "Highest Risk Assets",
    )

    df = assets_to_dataframe(
        assets
    )

    if not df.empty:

        df = (
            df
            .sort_values(
                "Risk Score",
                ascending=False,
            )
            .head(5)
        )

        st.dataframe(
            df.drop(
                columns=["asset_id"]
            ),
            use_container_width=True,
            hide_index=True,
        )


# ======================================================================
# PAGE: TOPOLOGY
# ======================================================================

def page_topology(
    assets: list,
    client: ApiClient,
) -> None:

    page_header(
        "Topology",
        "Network views built from discovered assets",
    )

    if not assets:

        empty_state(
            "🕸️",
            "No assets discovered yet.",
        )

        return

    view = st.radio(
        "View",

        [
            "Logical Hub View (Module 5)",
            "Knowledge Graph — Asset Relationships (Module 6)",
        ],

        horizontal=True,

        label_visibility="collapsed",
    )

    # --------------------------------------------------------------
    # LOGICAL HUB VIEW
    # --------------------------------------------------------------

    if view == "Logical Hub View (Module 5)":

        st.caption(
            "ℹ️ Real device-to-device connections "
            "are not yet discovered by the backend "
            "(see backend/twin/connection.py). "
            "This view shows a logical hub topology "
            "so you can still see every asset at a glance "
            "— it is NOT physical network topology."
        )

        st.plotly_chart(
            render_topology_figure(
                assets
            ),
            use_container_width=True,
        )

    # --------------------------------------------------------------
    # KNOWLEDGE GRAPH
    # --------------------------------------------------------------

    else:

        st.caption(
            "ℹ️ This graph represents relationships "
            "between assets, IPs, operating systems, "
            "ports, services, vulnerabilities, and risk "
            "as already computed by Modules 1–4. "
            "It does NOT represent physical network "
            "topology or attacker paths."
        )

        with st.spinner(
            "Building Knowledge Graph..."
        ):

            graph_data = (
                client.get_knowledge_graph()
            )

        if graph_data is None:

            empty_state(
                "🕸️",
                "Knowledge Graph endpoint is unavailable. "
                "Make sure the backend includes Module 6 "
                "(GET /knowledge-graph).",
            )

            return

        st.plotly_chart(
            render_knowledge_graph_figure(
                graph_data
            ),
            use_container_width=True,
        )


# ======================================================================
# PAGE: LOGS
# ======================================================================

def page_logs(
    assets: list,
) -> None:

    page_header(
        "Logs",
        "Scan activity and Digital Twin update history",
    )

    # --------------------------------------------------------------
    # LAST SCAN
    # --------------------------------------------------------------

    section_header(
        "🛰️",
        "Last Scan (this session)",
    )

    scan_log = st.session_state.get(
        "scan_log",
        [],
    )

    if scan_log:

        latest = scan_log[0]

        status_color = (
            "#22c55e"
            if latest["status"] == "success"
            else "#ef4444"
        )

        st.markdown(
            f"""
            <div class="twin-panel">

                <strong>Target:</strong>
                {latest['target']}

                &nbsp;|&nbsp;

                <strong>Time:</strong>
                {latest['timestamp']}

                &nbsp;|&nbsp;

                <strong>Status:</strong>

                <span style="
                    color:{status_color};
                ">
                    {latest['status']}
                </span>

                &nbsp;|&nbsp;

                <strong>Devices Found:</strong>
                {latest['devices_found']}

            </div>
            """,
            unsafe_allow_html=True,
        )

    else:

        empty_state(
            "🛰️",
            "No scans triggered yet in this session.",
        )

    # --------------------------------------------------------------
    # SCAN LOG
    # --------------------------------------------------------------

    section_header(
        "📜",
        "Discovery Scan Log (newest first)",
    )

    if scan_log:

        st.dataframe(
            pd.DataFrame(
                scan_log
            ),
            use_container_width=True,
            hide_index=True,
        )

    else:

        empty_state(
            "📜",
            "Scan history will appear here "
            "once you run a scan.",
        )

    # --------------------------------------------------------------
    # DIGITAL TWIN UPDATES
    # --------------------------------------------------------------

    section_header(
        "🔄",
        "Digital Twin Updates (newest first)",
    )

    if assets:

        updates_df = (
            assets_to_dataframe(
                assets
            )[
                [
                    "Hostname",
                    "IP",
                    "Status",
                    "Last Updated",
                ]
            ]
            .copy()
        )

        if not updates_df.empty:

            updates_df = (
                updates_df
                .sort_values(
                    "Last Updated",
                    ascending=False,
                )
            )

            st.dataframe(
                updates_df,
                use_container_width=True,
                hide_index=True,
            )

    else:

        empty_state(
            "🔄",
            "No twin updates recorded yet.",
        )


# ======================================================================
# PAGE: SETTINGS
# ======================================================================

def page_settings(
    client: ApiClient,
) -> None:

    page_header(
        "Settings",
        "Backend connection and dashboard preferences",
    )

    # --------------------------------------------------------------
    # BACKEND CONNECTION
    # --------------------------------------------------------------

    section_header(
        "🌐",
        "Backend Connection",
    )

    new_url = st.text_input(
        "Flask API Base URL",
        value=st.session_state[
            "api_base_url"
        ],
    )

    new_mongo_uri = st.text_input(
        "MongoDB URI (read-only status check)",
        value=st.session_state[
            "mongo_uri"
        ],
    )

    if st.button(
        "💾 Apply Settings"
    ):

        st.session_state[
            "api_base_url"
        ] = new_url.strip()

        st.session_state[
            "mongo_uri"
        ] = new_mongo_uri.strip()

        st.success(
            "Settings updated."
        )

        st.rerun()

    # --------------------------------------------------------------
    # CONNECTION STATUS
    # --------------------------------------------------------------

    section_header(
        "📡",
        "Connection Status",
    )

    col1, col2 = st.columns(2)

    with col1:

        backend_status_pill(
            client.check_health(),
            "Flask API",
        )

    with col2:

        backend_status_pill(
            check_mongo_status(
                st.session_state[
                    "mongo_uri"
                ]
            ),
            "MongoDB",
        )

    # --------------------------------------------------------------
    # AUTO REFRESH
    # --------------------------------------------------------------

    section_header(
        "⏱️",
        "Auto Refresh",
    )

    st.session_state[
        "refresh_interval"
    ] = st.number_input(

        "Refresh interval (seconds)",

        min_value=5,

        max_value=120,

        value=st.session_state[
            "refresh_interval"
        ],

        step=5,
    )


# ======================================================================
# MAIN
# ======================================================================

def main() -> None:

    st.set_page_config(

        page_title=
            "CyberTwinAI Dashboard",

        page_icon=
            "🛡️",

        layout=
            "wide",

        initial_sidebar_state=
            "expanded",
    )

    # CSS first
    load_css()

    # Session state
    init_session_state()

    # API client
    client = get_client()

    # Sidebar
    render_sidebar(
        client
    )

    # --------------------------------------------------------------
    # LOAD ASSETS
    # --------------------------------------------------------------

    with st.spinner(
        "Loading Digital Twin state..."
    ):

        assets = safe_assets(
            client.get_all_assets()
        )

    # --------------------------------------------------------------
    # ROUTING
    # --------------------------------------------------------------

    page = st.session_state[
        "nav_page"
    ]

    if page == "Dashboard":

        page_dashboard(
            assets
        )

    elif page == "Assets":

        page_assets(
            assets
        )

    elif page == "Services":

        page_services(
            assets
        )

    elif page == "Ports":

        page_ports(
            assets
        )

    elif page == "Risk":

        page_risk(
            assets
        )

    elif page == "Topology":

        page_topology(
            assets,
            client,
        )

    elif page == "Logs":

        page_logs(
            assets
        )

    elif page == "Settings":

        page_settings(
            client
        )

    # --------------------------------------------------------------
    # AUTO REFRESH
    # --------------------------------------------------------------

    if st.session_state.get(
        "auto_refresh"
    ):

        time.sleep(
            st.session_state[
                "refresh_interval"
            ]
        )

        st.rerun()


# ======================================================================
# ENTRY POINT
# ======================================================================

if __name__ == "__main__":

    main()