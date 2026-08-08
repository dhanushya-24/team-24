"""
charts.py
=========
RESPONSIBILITY: Build Plotly figures from asset data already returned
by the Flask API (via api_client.py). Every function here is a pure
function: dictionaries/lists in, a Plotly Figure out. No network
calls, no MongoDB access, no Streamlit calls -- that separation keeps
these charts trivially reusable and testable on their own.

Color palette matches assets/styles.css (dark cyber theme, blue/cyan
accents, semantic red/orange/yellow/green for severity).
"""

from collections import Counter
from typing import List

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

# Shared color palette -- kept in one place so every chart looks
# consistent with the CSS theme in assets/styles.css.
COLOR_BG = "#0e1420"
COLOR_PANEL = "#141c2b"
COLOR_TEXT = "#c9d6e3"
COLOR_CYAN = "#22d3ee"
COLOR_BLUE = "#3b82f6"
COLOR_GREEN = "#22c55e"
COLOR_YELLOW = "#eab308"
COLOR_ORANGE = "#f97316"
COLOR_RED = "#ef4444"

SEVERITY_COLORS = {
    "Critical": COLOR_RED,
    "High": COLOR_ORANGE,
    "Medium": COLOR_YELLOW,
    "Low": COLOR_GREEN,
}

RISK_LEVEL_COLORS = {
    "Critical": COLOR_RED,
    "High": COLOR_ORANGE,
    "Medium": COLOR_YELLOW,
    "Low": COLOR_GREEN,
    "": "#64748b",
}


def _base_layout(fig: go.Figure, title: str, height: int = 360) -> go.Figure:
    """Apply the shared dark theme to any figure produced in this file."""
    fig.update_layout(
        title=dict(text=title, font=dict(size=16, color=COLOR_TEXT, family="Inter, sans-serif")),
        paper_bgcolor=COLOR_PANEL,
        plot_bgcolor=COLOR_PANEL,
        font=dict(color=COLOR_TEXT, family="Inter, sans-serif"),
        height=height,
        margin=dict(l=30, r=30, t=60, b=30),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor="#1f2937", zerolinecolor="#1f2937")
    fig.update_yaxes(gridcolor="#1f2937", zerolinecolor="#1f2937")
    return fig


# ----------------------------------------------------------------------
# RISK PAGE
# ----------------------------------------------------------------------
def build_risk_gauge(average_risk: float) -> go.Figure:
    """Gauge chart showing the average risk score (0-100) across all assets."""
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=round(average_risk, 1),
            number={"suffix": " / 100", "font": {"color": COLOR_TEXT, "size": 36}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": COLOR_TEXT},
                "bar": {"color": COLOR_CYAN},
                "bgcolor": COLOR_PANEL,
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 20], "color": COLOR_GREEN},
                    {"range": [21, 50], "color": COLOR_YELLOW},
                    {"range": [51, 80], "color": COLOR_ORANGE},
                    {"range": [81, 100], "color": COLOR_RED},
                ],
            },
        )
    )
    return _base_layout(fig, "Average Network Risk", height=320)


def build_risk_level_pie(assets: List[dict]) -> go.Figure:
    """Pie chart of assets grouped by risk_level (Low/Medium/High/Critical)."""
    counts = Counter(asset.get("risk_level") or "Unassessed" for asset in assets)
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [RISK_LEVEL_COLORS.get(label, "#64748b") for label in labels]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.55,
            marker=dict(colors=colors, line=dict(color=COLOR_BG, width=2)),
            textfont=dict(color="#ffffff"),
        )
    )
    return _base_layout(fig, "Assets by Risk Level", height=360)


def build_vulnerability_breakdown(assets: List[dict]) -> go.Figure:
    """Bar chart counting every vulnerability finding across all assets, by severity."""
    severity_counter = Counter()
    for asset in assets:
        for vuln in asset.get("vulnerabilities", []):
            severity = vuln.get("severity", "Unknown")
            severity_counter[severity] += 1

    order = ["Critical", "High", "Medium", "Low"]
    labels = [s for s in order if s in severity_counter] + \
        [s for s in severity_counter if s not in order]
    values = [severity_counter[s] for s in labels]
    colors = [SEVERITY_COLORS.get(s, "#64748b") for s in labels]

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color=colors))
    return _base_layout(fig, "Vulnerability Breakdown by Severity", height=360)


def build_risk_histogram(assets: List[dict]) -> go.Figure:
    """Histogram of risk_score distribution across all assets."""
    scores = [asset.get("risk_score", 0) for asset in assets]
    fig = px.histogram(x=scores, nbins=10, color_discrete_sequence=[COLOR_CYAN])
    fig.update_traces(marker_line_color=COLOR_BG, marker_line_width=1)
    fig.update_layout(xaxis_title="Risk Score", yaxis_title="Number of Assets")
    return _base_layout(fig, "Risk Score Distribution", height=360)


# ----------------------------------------------------------------------
# OVERVIEW / CHARTS PAGE
# ----------------------------------------------------------------------
def build_ports_per_device_bar(assets: List[dict]) -> go.Figure:
    """Bar chart of open port count per device (by hostname or IP)."""
    labels = [asset.get("hostname") or asset.get("ip_address", "unknown") for asset in assets]
    values = [len(asset.get("ports", [])) for asset in assets]

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color=COLOR_BLUE))
    fig.update_layout(xaxis_title="Device", yaxis_title="Open Ports")
    return _base_layout(fig, "Open Ports per Device", height=380)


def build_os_distribution_pie(assets: List[dict]) -> go.Figure:
    """Pie chart of detected operating systems across all assets."""
    counts = Counter(asset.get("operating_system") or "Unknown" for asset in assets)
    fig = go.Figure(
        go.Pie(
            labels=list(counts.keys()),
            values=list(counts.values()),
            hole=0.4,
            marker=dict(
                colors=px.colors.sequential.Blues_r[: len(counts)] or [COLOR_BLUE],
                line=dict(color=COLOR_BG, width=2),
            ),
            textfont=dict(color="#ffffff"),
        )
    )
    return _base_layout(fig, "Operating System Distribution", height=380)


def build_discovery_timeline(assets: List[dict]) -> go.Figure:
    """Line chart: number of assets last updated per day (discovery activity over time)."""
    if not assets:
        fig = go.Figure()
        return _base_layout(fig, "Discovery Timeline", height=340)

    dates = []
    for asset in assets:
        timestamp = asset.get("last_updated")
        if timestamp:
            dates.append(pd.to_datetime(timestamp).date())

    if not dates:
        fig = go.Figure()
        return _base_layout(fig, "Discovery Timeline", height=340)

    series = pd.Series(dates).value_counts().sort_index()
    fig = go.Figure(
        go.Scatter(
            x=series.index.astype(str),
            y=series.values,
            mode="lines+markers",
            line=dict(color=COLOR_CYAN, width=3),
            marker=dict(size=8, color=COLOR_CYAN),
        )
    )
    fig.update_layout(xaxis_title="Date", yaxis_title="Assets Updated")
    return _base_layout(fig, "Discovery Timeline", height=340)
