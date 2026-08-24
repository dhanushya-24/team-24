"""
topology.py
===========
RESPONSIBILITY: Build interactive network visualizations from
existing asset data, using NetworkX for graph structure and Plotly
for rendering. Two distinct views are provided:

1. render_topology_figure() -- the original Module 5 LOGICAL HUB view
   (one central hub connected to every asset). This is NOT real
   network topology -- see its docstring below.

2. render_knowledge_graph_figure() -- renders the real Module 6
   Knowledge Graph (backend/knowledge_graph), which shows actual
   relationships between assets, ports, services, vulnerabilities,
   and risk levels, as already computed by Modules 1-4. This is
   clearly labeled "Knowledge Graph -- Asset Relationships" and is
   NOT physical network topology either -- it has no notion of
   cables, switches, or routing, only data relationships.

Neither function performs any analysis -- both only render graphs
that were already built elsewhere (topology.py never computes risk,
never matches vulnerabilities, never invents connections).
"""

from typing import Any, Dict, List

import networkx as nx
import plotly.graph_objects as go

NODE_COLORS = {
    "router": "#22d3ee",
    "server": "#3b82f6",
    "workstation": "#22c55e",
    "unknown": "#64748b",
    "hub": "#eab308",
}

NODE_SYMBOLS = {
    "router": "diamond",
    "server": "square",
    "workstation": "circle",
    "unknown": "circle",
    "hub": "diamond",
}

# Colors for the Module 6 Knowledge Graph's typed nodes -- a separate
# palette from NODE_COLORS above, since these represent DATA types
# (asset/ip/os/port/service/vulnerability/risk), not device types.
KG_NODE_COLORS = {
    "asset": "#3b82f6",
    "ip": "#64748b",
    "operating_system": "#a855f7",
    "port": "#22d3ee",
    "service": "#22c55e",
    "vulnerability": "#ef4444",
    "risk": "#f97316",
}

KG_NODE_SYMBOLS = {
    "asset": "square",
    "ip": "circle",
    "operating_system": "diamond",
    "port": "circle",
    "service": "circle",
    "vulnerability": "triangle-up",
    "risk": "star",
}


def build_topology_graph(assets: List[dict]) -> nx.Graph:
    """
    Build a NetworkX graph: one hub node connected to every asset.

    The hub is the first asset found with device_type == "router". If
    no router was discovered, a virtual "Network" hub node is used
    instead, clearly distinguishable in the UI (device_type "hub").
    """
    graph = nx.Graph()

    router = next((a for a in assets if a.get("device_type") == "router"), None)
    hub_id = router["asset_id"] if router else "network-hub"
    hub_label = router.get("hostname") or router.get("ip_address") if router else "Network"
    hub_type = "router" if router else "hub"

    graph.add_node(hub_id, label=hub_label, device_type=hub_type, risk_score=0)

    for asset in assets:
        if router and asset["asset_id"] == router["asset_id"]:
            continue  # the router is already the hub, don't link it to itself
        node_id = asset["asset_id"]
        label = asset.get("hostname") or asset.get("ip_address", node_id)
        graph.add_node(
            node_id,
            label=label,
            device_type=asset.get("device_type", "unknown"),
            risk_score=asset.get("risk_score", 0),
        )
        graph.add_edge(hub_id, node_id)

    return graph


def render_topology_figure(assets: List[dict]) -> go.Figure:
    """
    Convert the NetworkX graph above into an interactive Plotly
    scatter figure (draggable/zoomable in the browser via Plotly's
    built-in controls -- no extra JS framework required).
    """
    graph = build_topology_graph(assets)

    if graph.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#141c2b",
            plot_bgcolor="#141c2b",
            height=520,
            annotations=[dict(text="No assets discovered yet", showarrow=False,
                               font=dict(color="#c9d6e3", size=16))],
        )
        return fig

    layout_positions = nx.spring_layout(graph, seed=42, k=0.9)

    # --- Edges ---
    edge_x, edge_y = [], []
    for source, target in graph.edges():
        x0, y0 = layout_positions[source]
        x1, y1 = layout_positions[target]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(color="#334155", width=2),
        hoverinfo="none",
    )

    # --- Nodes ---
    node_x, node_y, node_labels, node_colors, node_symbols, hover_text = [], [], [], [], [], []
    for node_id, data in graph.nodes(data=True):
        x, y = layout_positions[node_id]
        node_x.append(x)
        node_y.append(y)
        node_labels.append(data["label"])
        device_type = data.get("device_type", "unknown")
        node_colors.append(NODE_COLORS.get(device_type, NODE_COLORS["unknown"]))
        node_symbols.append(NODE_SYMBOLS.get(device_type, "circle"))
        hover_text.append(
            f"{data['label']}<br>Type: {device_type}<br>Risk Score: {data.get('risk_score', 0)}"
        )

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=node_labels,
        textposition="bottom center",
        textfont=dict(color="#c9d6e3", size=11),
        hovertext=hover_text,
        hoverinfo="text",
        marker=dict(
            size=26,
            color=node_colors,
            symbol=node_symbols,
            line=dict(color="#0e1420", width=2),
        ),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title=dict(text="Network Topology (Logical View)", font=dict(color="#c9d6e3", size=16)),
        paper_bgcolor="#141c2b",
        plot_bgcolor="#141c2b",
        showlegend=False,
        height=560,
        margin=dict(l=10, r=10, t=50, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    return fig


def render_knowledge_graph_figure(graph_data: Dict[str, List[Dict[str, Any]]]) -> go.Figure:
    """
    Render the real Module 6 Knowledge Graph, as returned by
    GET /knowledge-graph ({"nodes": [...], "edges": [...]}).

    IMPORTANT: this is "Knowledge Graph -- Asset Relationships", NOT
    physical network topology. It shows how assets relate to their
    IPs, operating systems, ports, services, vulnerabilities, and
    risk levels (as already computed by Modules 1-4) -- it does not
    represent cables, switches, or routing paths. Device-to-device
    edges (ASSET_CONNECTED_TO_ASSET) only appear here if the backend
    actually has real connection data; none are fabricated.
    """
    if not graph_data or not graph_data.get("nodes"):
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#141c2b",
            plot_bgcolor="#141c2b",
            height=560,
            annotations=[dict(text="No knowledge graph data available yet", showarrow=False,
                               font=dict(color="#c9d6e3", size=16))],
        )
        return fig

    # Rebuild a NetworkX graph locally from the plain dict so we can
    # reuse nx.spring_layout() for positioning -- this local import
    # avoids a hard dependency on backend.knowledge_graph for callers
    # who only want to render pre-fetched graph data.
    graph = nx.DiGraph()
    for node in graph_data.get("nodes", []):
        node = dict(node)
        node_id = node.pop("id")
        graph.add_node(node_id, **node)
    for edge in graph_data.get("edges", []):
        edge = dict(edge)
        source = edge.pop("source")
        target = edge.pop("target")
        graph.add_edge(source, target, **edge)

    if graph.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#141c2b", plot_bgcolor="#141c2b", height=560,
            annotations=[dict(text="No knowledge graph data available yet", showarrow=False,
                               font=dict(color="#c9d6e3", size=16))],
        )
        return fig

    layout_positions = nx.spring_layout(graph, seed=42, k=0.6)

    # --- Edges ---
    edge_x, edge_y = [], []
    for source, target in graph.edges():
        x0, y0 = layout_positions[source]
        x1, y1 = layout_positions[target]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(color="#334155", width=1.5),
        hoverinfo="none",
    )

    # --- Nodes ---
    node_x, node_y, node_labels, node_colors, node_symbols, node_sizes, hover_text = [], [], [], [], [], [], []
    for node_id, data in graph.nodes(data=True):
        x, y = layout_positions[node_id]
        node_x.append(x)
        node_y.append(y)
        node_type = data.get("node_type", "unknown")
        label = data.get("label", node_id)
        node_labels.append(label if node_type == "asset" else "")  # keep non-asset labels off by default (hover shows them)
        node_colors.append(KG_NODE_COLORS.get(node_type, "#64748b"))
        node_symbols.append(KG_NODE_SYMBOLS.get(node_type, "circle"))
        node_sizes.append(30 if node_type == "asset" else 16)
        hover_text.append(f"{label}<br>Type: {node_type}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=node_labels,
        textposition="bottom center",
        textfont=dict(color="#c9d6e3", size=11),
        hovertext=hover_text,
        hoverinfo="text",
        marker=dict(
            size=node_sizes,
            color=node_colors,
            symbol=node_symbols,
            line=dict(color="#0e1420", width=1.5),
        ),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title=dict(text="Knowledge Graph — Asset Relationships", font=dict(color="#c9d6e3", size=16)),
        paper_bgcolor="#141c2b",
        plot_bgcolor="#141c2b",
        showlegend=False,
        height=600,
        margin=dict(l=10, r=10, t=50, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    return fig
