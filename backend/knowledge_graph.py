import networkx as nx

class DigitalTwinKnowledgeGraph:
    """
    Module 6: Knowledge Graph Construction using NetworkX.
    Generates a graph strictly from the central Digital Twin state.
    Uses safe, non-null node IDs and standard relationship types.
    """

    NODE_COLORS = {
        "Asset": "#38bdf8",         # Light Blue
        "IP": "#a855f7",            # Purple
        "OS": "#64748b",            # Slate Gray
        "Port": "#f59e0b",          # Amber
        "Service": "#10b981",       # Emerald Green
        "Vulnerability": "#ef4444",  # Bright Red
        "Risk": "#f97316"           # Orange
    }

    def __init__(self, twin_state):
        self.twin_state = twin_state or {"assets": [], "services": [], "vulnerabilities": [], "risks": []}
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        """Constructs NetworkX DiGraph safely."""
        self.graph.clear()

        assets = self.twin_state.get("assets", [])
        services = self.twin_state.get("services", [])
        vulnerabilities = self.twin_state.get("vulnerabilities", [])

        # Index vulnerabilities by asset_id + service for fast lookup
        vuln_map = {}
        for v in vulnerabilities:
            key = (str(v.get("asset_id", "")), str(v.get("affected_service", "")))
            if key not in vuln_map:
                vuln_map[key] = []
            vuln_map[key].append(v)

        for asset in assets:
            asset_id = str(asset.get("asset_id") or "AST-UNKNOWN")
            hostname = str(asset.get("hostname") or "Unknown Host")
            ip = str(asset.get("ip_address") or "0.0.0.0")
            os_name = str(asset.get("os") or "Unknown OS")
            risk_level = str(asset.get("risk_level") or "Low")
            risk_score = float(asset.get("risk_score", 0.0))

            # 1. Asset Node
            asset_node_id = f"asset:{asset_id}"
            self.graph.add_node(
                asset_node_id,
                label=hostname,
                node_type="Asset",
                color=self.NODE_COLORS["Asset"],
                size=28,
                details=f"Asset ID: {asset_id}<br>Status: {asset.get('status')}<br>Type: {asset.get('device_type')}"
            )

            # 2. IP Relationship: Asset -> HAS_IP -> IP
            if ip and ip != "0.0.0.0":
                ip_node_id = f"ip:{ip}"
                if not self.graph.has_node(ip_node_id):
                    self.graph.add_node(
                        ip_node_id,
                        label=ip,
                        node_type="IP",
                        color=self.NODE_COLORS["IP"],
                        size=20,
                        details=f"IP Address: {ip}"
                    )
                self.graph.add_edge(asset_node_id, ip_node_id, relation="HAS_IP")

            # 3. OS Relationship: Asset -> RUNS -> Operating System
            if os_name and os_name != "Unknown OS":
                os_node_id = f"os:{os_name}"
                if not self.graph.has_node(os_node_id):
                    self.graph.add_node(
                        os_node_id,
                        label=os_name,
                        node_type="OS",
                        color=self.NODE_COLORS["OS"],
                        size=20,
                        details=f"Operating System: {os_name}"
                    )
                self.graph.add_edge(asset_node_id, os_node_id, relation="RUNS")

            # 4. Risk Relationship: Asset -> HAS_RISK -> Risk
            risk_node_id = f"risk:{asset_id}"
            self.graph.add_node(
                risk_node_id,
                label=f"Risk: {risk_level} ({risk_score})",
                node_type="Risk",
                color=self.NODE_COLORS["Risk"],
                size=22,
                details=f"Risk Level: {risk_level}<br>Score: {risk_score}/100"
            )
            self.graph.add_edge(asset_node_id, risk_node_id, relation="HAS_RISK")

        # 5. Port & Service Relationships
        for srv in services:
            asset_id = str(srv.get("asset_id") or "")
            port_num = int(srv.get("port", 0))
            proto = str(srv.get("protocol", "TCP"))
            service_name = str(srv.get("service", "Unknown"))
            version = str(srv.get("version", ""))

            asset_node_id = f"asset:{asset_id}"
            if not self.graph.has_node(asset_node_id):
                continue

            # Asset -> EXPOSES -> Port
            port_node_id = f"port:{asset_id}:{port_num}"
            if not self.graph.has_node(port_node_id):
                self.graph.add_node(
                    port_node_id,
                    label=f"Port {port_num}/{proto}",
                    node_type="Port",
                    color=self.NODE_COLORS["Port"],
                    size=18,
                    details=f"Port: {port_num}/{proto}<br>State: {srv.get('state')}"
                )
            self.graph.add_edge(asset_node_id, port_node_id, relation="EXPOSES")

            # Port -> RUNS_SERVICE -> Service
            service_node_id = f"service:{asset_id}:{service_name}"
            if not self.graph.has_node(service_node_id):
                self.graph.add_node(
                    service_node_id,
                    label=f"{service_name} ({version})",
                    node_type="Service",
                    color=self.NODE_COLORS["Service"],
                    size=20,
                    details=f"Service: {service_name}<br>Version: {version}"
                )
            self.graph.add_edge(port_node_id, service_node_id, relation="RUNS_SERVICE")

            # 6. Service -> HAS_VULNERABILITY -> Vulnerability
            matched_v = vuln_map.get((asset_id, service_name), [])
            for v in matched_v:
                cve_id = str(v.get("cve_id", "CVE-UNKNOWN"))
                vuln_node_id = f"vuln:{asset_id}:{cve_id}"
                if not self.graph.has_node(vuln_node_id):
                    self.graph.add_node(
                        vuln_node_id,
                        label=cve_id,
                        node_type="Vulnerability",
                        color=self.NODE_COLORS["Vulnerability"],
                        size=24,
                        details=f"CVE: {cve_id}<br>Title: {v.get('title')}<br>Severity: {v.get('severity')}<br>CVSS: {v.get('cvss')}"
                    )
                self.graph.add_edge(service_node_id, vuln_node_id, relation="HAS_VULNERABILITY")

    def get_graph(self):
        """Returns the built NetworkX graph."""
        return self.graph

    def get_summary_stats(self):
        """Returns node and edge summary statistics."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges()
        }
