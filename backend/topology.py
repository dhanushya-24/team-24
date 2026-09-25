import networkx as nx
import plotly.graph_objects as go

class TopologyVisualizer:
    """
    Module 7: Topology & Relationship View visualizer.
    Generates interactive Plotly graph figures for:
    1. Logical Network Topology (Router -> Hosts)
    2. Knowledge Graph Relationship Map
    """

    @staticmethod
    def create_logical_topology_figure(twin_state):
        """
        Creates a clear Logical Network Topology layout.
        Central Gateway Router at root connecting to Server, Workstations, and Laptops.
        """
        assets = twin_state.get("assets", [])
        if not assets:
            return go.Figure().add_annotation(text="No Digital Twin assets discovered", showarrow=False)

        # Build Logical Network Graph
        G = nx.DiGraph()
        router_node = "Gateway Router (192.168.1.1)"
        G.add_node(router_node, device_type="Router", status="Online", color="#38bdf8")

        for asset in assets:
            ip = asset.get("ip_address", "0.0.0.0")
            host = asset.get("hostname", "Device")
            dev_type = asset.get("device_type", "Host")
            status = asset.get("status", "Online")
            node_label = f"{host}\n({ip})"

            if dev_type.lower() != "router":
                color = "#4ade80" if status == "Online" else "#f87171"
                G.add_node(node_label, device_type=dev_type, status=status, color=color)
                G.add_edge(router_node, node_label, relation="CONNECTS_TO")

        pos = nx.spring_layout(G, k=1.5, seed=42)

        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=2, color='#475569'),
            hoverinfo='none',
            mode='lines'
        )

        node_x, node_y, node_text, node_color = [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            attr = G.nodes[node]
            node_text.append(f"<b>{node}</b><br>Type: {attr.get('device_type')}<br>Status: {attr.get('status')}")
            node_color.append(attr.get('color', '#38bdf8'))

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=[n.split('\n')[0] for n in G.nodes()],
            textposition="bottom center",
            textfont=dict(color='#cbd5e1', size=11),
            hovertext=node_text,
            marker=dict(
                color=node_color,
                size=26,
                line=dict(width=2, color='#0f172a')
            )
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title=dict(text="Logical Network Topology View", font=dict(color="#38bdf8", size=16)),
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=10, r=10, t=50),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)'
            )
        )
        return fig

    @staticmethod
    def create_knowledge_graph_figure(nx_graph):
        """
        Creates an interactive Plotly visualization for the NetworkX Knowledge Graph (Module 6).
        """
        if nx_graph.number_of_nodes() == 0:
            return go.Figure().add_annotation(text="Knowledge Graph is empty", showarrow=False)

        pos = nx.spring_layout(nx_graph, k=0.8, seed=42)

        edge_x, edge_y, edge_text = [], [], []
        for edge in nx_graph.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color='#334155'),
            hoverinfo='none',
            mode='lines'
        )

        node_x, node_y, node_hover, node_text, node_color, node_size = [], [], [], [], [], []
        for node in nx_graph.nodes(data=True):
            node_id = node[0]
            attrs = node[1]
            x, y = pos[node_id]
            node_x.append(x)
            node_y.append(y)

            label = attrs.get('label', node_id)
            node_type = attrs.get('node_type', 'Entity')
            details = attrs.get('details', '')

            node_text.append(label)
            node_hover.append(f"<b>[{node_type}] {label}</b><br>{details}")
            node_color.append(attrs.get('color', '#38bdf8'))
            node_size.append(attrs.get('size', 20))

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            hovertext=node_hover,
            text=node_text,
            textposition="top center",
            textfont=dict(color='#e2e8f0', size=10),
            marker=dict(
                color=node_color,
                size=node_size,
                line=dict(width=1.5, color='#0f172a')
            )
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title=dict(text="CyberTwinAI - Digital Twin Knowledge Graph", font=dict(color="#38bdf8", size=16)),
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=10, r=10, t=50),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)'
            )
        )
        return fig
