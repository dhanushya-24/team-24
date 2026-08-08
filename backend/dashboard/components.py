"""
components.py
==============
RESPONSIBILITY: Reusable, presentation-only UI building blocks
(metric cards, badges, headers, empty states). Every function here
takes already-fetched values and renders HTML/Streamlit widgets --
none of them fetch data, call the API, or make any decision. That
separation keeps dashboard.py focused on page layout and flow, while
this file owns "what things look like."
"""

from datetime import datetime
from typing import Optional

import streamlit as st

RISK_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#22c55e",
    "": "#64748b",
    "Unassessed": "#64748b",
}

STATUS_COLORS = {
    "online": "#22c55e",
    "offline": "#ef4444",
}


def metric_card(icon: str, label: str, value, accent: str = "#22d3ee") -> None:
    """Render one top-row KPI card (Total Devices, Average Risk, etc.)."""
    st.markdown(
        f"""
        <div class="metric-card" style="border-top: 3px solid {accent};">
            <div class="metric-icon">{icon}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-label">{label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def status_badge(status: Optional[str]) -> str:
    """Return an inline HTML badge for a device's online/offline status."""
    normalized = (status or "unknown").lower()
    color = STATUS_COLORS.get(normalized, "#64748b")
    label = normalized.capitalize()
    return (
        f'<span class="badge" style="color:{color};'
        f'background:{color}22;border:1px solid {color};">{label}</span>'
    )


def risk_badge(risk_level: Optional[str]) -> str:
    """Return an inline HTML badge for a risk_level string."""
    label = risk_level or "Unassessed"
    color = RISK_COLORS.get(label, "#64748b")
    return (
        f'<span class="badge" style="color:{color};'
        f'background:{color}22;border:1px solid {color};">{label}</span>'
    )


def severity_badge(severity: Optional[str]) -> str:
    """Return an inline HTML badge for a vulnerability severity string."""
    label = severity or "Unknown"
    color = RISK_COLORS.get(label, "#64748b")
    return (
        f'<span class="badge" style="color:{color};'
        f'background:{color}22;border:1px solid {color};">{label}</span>'
    )


def page_header(title: str, subtitle: str = "") -> None:
    """Large page title block used at the top of every page."""
    subtitle_html = f'<p class="page-subtitle">{subtitle}</p>' if subtitle else ""
    st.markdown(
        f"""
        <div class="page-header">
            <h1>{title}</h1>
            {subtitle_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(icon: str, title: str) -> None:
    """Smaller header used to separate sections within a page."""
    st.markdown(f'<div class="section-header">{icon}&nbsp;&nbsp;{title}</div>', unsafe_allow_html=True)


def backend_status_pill(is_online: bool, label: str) -> None:
    """Small colored pill shown in the sidebar/settings for backend health."""
    color = "#22c55e" if is_online else "#ef4444"
    text = "Online" if is_online else "Offline"
    st.markdown(
        f"""
        <div class="status-pill" style="border-color:{color};">
            <span class="status-dot" style="background:{color};"></span>
            {label}: <strong style="color:{color};">{text}</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )


def empty_state(icon: str, message: str) -> None:
    """Friendly placeholder shown when there is no data to display yet."""
    st.markdown(
        f"""
        <div class="empty-state">
            <div class="empty-state-icon">{icon}</div>
            <div class="empty-state-message">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def current_datetime_display() -> str:
    """Human-readable current date/time, shown on the Home page."""
    return datetime.now().strftime("%A, %d %B %Y — %H:%M:%S")


def service_card(service_name: str, port: int, protocol: str, version: Optional[str]) -> None:
    """Small colored card representing one running service, used on the Services page."""
    icon = _service_icon(service_name)
    version_text = version or "Unknown version"
    st.markdown(
        f"""
        <div class="service-card">
            <div class="service-card-icon">{icon}</div>
            <div class="service-card-body">
                <div class="service-card-title">{service_name.upper()}</div>
                <div class="service-card-meta">Port {port}/{protocol}</div>
                <div class="service-card-version">{version_text}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _service_icon(service_name: str) -> str:
    """Map a service name to a representative icon (best-effort, cosmetic only)."""
    name = (service_name or "").lower()
    icon_map = {
        "http": "🌐", "https": "🔒", "ftp": "📁", "ssh": "🔑",
        "telnet": "⚠️", "smb": "🗂️", "mysql": "🗄️", "rdp": "🖥️",
        "dns": "📡", "smtp": "✉️",
    }
    for key, icon in icon_map.items():
        if key in name:
            return icon
    return "🔧"
