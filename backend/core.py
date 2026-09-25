import os
import json
from datetime import datetime
from mongodb import MongoManager
from backend.nmap_parser import NmapXMLParser

class DigitalTwinEngine:
    """
    Central Digital Twin Core Engine covering Modules 1 to 14.
    Maintains a single source of truth state dictionary:
    {
       "assets": [...],
       "services": [...],
       "vulnerabilities": [...],
       "risks": [...]
    }
    Supports continuous monitoring, Nmap XML import, deduplication, dataset filtering,
    change detection, risk simulation, automated security recommendations, alerting, and report generation.
    """

    def __init__(self, data_filepath=None):
        if data_filepath is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_filepath = os.path.join(base_dir, "data", "demo_data.json")
        
        self.data_filepath = data_filepath
        self.db_manager = MongoManager()
        self.raw_data = self._load_data()
        
        self.previous_twin_state = None
        self.twin_state = {"assets": [], "services": [], "vulnerabilities": [], "risks": []}
        self.detected_changes = []
        self.active_alerts = []
        
        self.refresh_digital_twin(initial_run=True)

    def _load_data(self):
        """Safely load initial json data with fallback defaults."""
        if os.path.exists(self.data_filepath):
            try:
                with open(self.data_filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"assets": [], "vulnerability_db": []}

    def import_nmap_scan_xml(self, xml_filepath=None):
        """
        Imports Nmap XML scan (data/scan.xml) into the Digital Twin model.
        Idempotent: updates existing asset by IP/ID without creating duplicate assets.
        """
        imported_assets = NmapXMLParser.parse_scan_xml(xml_filepath)
        if not imported_assets:
            return False

        existing_assets = self.raw_data.get("assets", [])
        existing_vuln_db = self.raw_data.get("vulnerability_db", [])

        # Additional CVE rules for Metasploitable2 / Nmap service findings
        nmap_cve_rules = [
            {
                "cve_id": "CVE-2011-2523",
                "title": "vsftpd 2.3.4 Backdoor Command Execution",
                "description": "vsftpd 2.3.4 contains a malicious backdoor allowing unauthorized shell access.",
                "severity": "Critical",
                "cvss": 9.8,
                "affected_service": "vsftpd",
                "affected_version": "2.3.4"
            },
            {
                "cve_id": "CVE-2008-0166",
                "title": "OpenSSH Debian Predictable PRNG Key Generation",
                "description": "Debian OpenSSH package contains predictable random number generator flaw.",
                "severity": "High",
                "cvss": 8.5,
                "affected_service": "OpenSSH",
                "affected_version": "4.7p1"
            },
            {
                "cve_id": "CVE-2010-4221",
                "title": "ProFTPD Telnet IAC Buffer Overflow",
                "description": "Stack-based buffer overflow in ProFTPD server allows remote code execution.",
                "severity": "Critical",
                "cvss": 10.0,
                "affected_service": "ProFTPD",
                "affected_version": "1.3.1"
            },
            {
                "cve_id": "CVE-2010-2075",
                "title": "UnrealIRCd Backdoor Command Execution",
                "description": "UnrealIRCd contains a trojaned backdoor allowing arbitrary code execution.",
                "severity": "Critical",
                "cvss": 10.0,
                "affected_service": "UnrealIRCd",
                "affected_version": "UnrealIRCd"
            },
            {
                "cve_id": "CVE-2007-2447",
                "title": "Samba MS-RPC Remote Code Execution",
                "description": "Samba 3.x username map script command execution vulnerability.",
                "severity": "Critical",
                "cvss": 9.8,
                "affected_service": "Samba",
                "affected_version": "3.X"
            }
        ]

        # Merge vulnerability DB rules
        existing_cve_ids = {v.get("cve_id") for v in existing_vuln_db}
        for rule in nmap_cve_rules:
            if rule["cve_id"] not in existing_cve_ids:
                existing_vuln_db.append(rule)

        # Deduplicate and merge assets by IP address or asset_id
        existing_map = {a.get("ip_address"): a for a in existing_assets}
        for imp in imported_assets:
            ip = imp["ip_address"]
            imp["data_source"] = "IMPORTED_LAB_SCAN"
            if ip in existing_map:
                # Update existing host record cleanly without duplicating
                existing_map[ip]["ports"] = imp["ports"]
                if imp["os"] != "Unknown OS":
                    existing_map[ip]["os"] = imp["os"]
                existing_map[ip]["status"] = "Online"
                existing_map[ip]["data_source"] = "IMPORTED_LAB_SCAN"
            else:
                existing_assets.append(imp)

        self.raw_data["assets"] = existing_assets
        self.raw_data["vulnerability_db"] = existing_vuln_db

        try:
            with open(self.data_filepath, "w", encoding="utf-8") as f:
                json.dump(self.raw_data, f, indent=2)
        except Exception:
            pass

        self.refresh_digital_twin()
        return True

    def refresh_digital_twin(self, initial_run=False, simulated_scan=False):
        """
        Module 1 - 4 & Module 8: Continuous Scan & State Update Engine.
        """
        if not initial_run and self.twin_state.get("assets"):
            self.previous_twin_state = dict(self.twin_state)

        assets_raw = self.raw_data.get("assets", [])
        vuln_db = self.raw_data.get("vulnerability_db", [])

        if simulated_scan and not initial_run:
            assets_raw = self._inject_simulated_network_event(assets_raw)

        processed_assets = []
        all_services = []
        all_matched_vulns = []
        all_risks = []

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for idx, item in enumerate(assets_raw):
            asset_id = str(item.get("asset_id") or f"AST-DEF-{idx+1}")
            hostname = str(item.get("hostname") or "Unknown-Host")
            ip_address = str(item.get("ip_address") or "0.0.0.0")
            mac_address = str(item.get("mac_address") or "00:00:00:00:00:00")
            device_type = str(item.get("device_type") or "Generic Device")
            os_name = str(item.get("os") or "Unknown OS")
            status = str(item.get("status") or "Online")
            first_seen = str(item.get("first_seen") or now_str)
            last_seen = now_str if status == "Online" else str(item.get("last_seen") or now_str)
            importance = str(item.get("importance") or "Medium")
            data_src = str(item.get("data_source") or ("IMPORTED_LAB_SCAN" if "56.101" in ip_address else "DEMO_NETWORK"))

            # Module 2: Ports & Services
            ports_raw = item.get("ports", [])
            asset_ports = []
            for p in ports_raw:
                if not isinstance(p, dict):
                    continue
                port_num = int(p.get("port", 0))
                protocol = str(p.get("protocol", "TCP")).upper()
                state = str(p.get("state", "Open")).capitalize()
                service_name = str(p.get("service", "Unknown Service"))
                service_ver = str(p.get("version", "1.0"))

                port_record = {
                    "asset_id": asset_id,
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": service_ver,
                    "data_source": data_src
                }
                asset_ports.append(port_record)
                all_services.append(port_record)

            # Module 3: Vulnerability Assessment (Flexible Matching)
            matched_vulns = []
            for port_obj in asset_ports:
                srv = port_obj["service"]
                ver = port_obj["version"]
                combined_str = f"{srv} {ver}".lower()

                for v in vuln_db:
                    aff_srv = str(v.get("affected_service", "")).lower()
                    aff_ver = str(v.get("affected_version", "")).lower()

                    if aff_srv and aff_srv in combined_str:
                        if not aff_ver or aff_ver in combined_str or aff_ver in ver.lower():
                            vuln_record = {
                                "cve_id": str(v.get("cve_id", "CVE-UNKNOWN")),
                                "title": str(v.get("title", "Vulnerability")),
                                "description": str(v.get("description", "")),
                                "severity": str(v.get("severity", "Medium")),
                                "cvss": float(v.get("cvss", 5.0)),
                                "asset_id": asset_id,
                                "hostname": hostname,
                                "ip_address": ip_address,
                                "affected_service": srv,
                                "affected_version": ver,
                                "data_source": data_src
                            }
                            matched_vulns.append(vuln_record)
                            all_matched_vulns.append(vuln_record)

            # Module 4: Risk Analysis
            risk_info = self._calculate_asset_risk(asset_id, hostname, asset_ports, matched_vulns, importance)
            risk_info["data_source"] = data_src
            all_risks.append(risk_info)

            asset_obj = {
                "asset_id": asset_id,
                "hostname": hostname,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "device_type": device_type,
                "os": os_name,
                "status": status,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "importance": importance,
                "data_source": data_src,
                "open_ports_count": len(asset_ports),
                "vuln_count": len(matched_vulns),
                "risk_score": risk_info["risk_score"],
                "risk_level": risk_info["risk_level"],
                "risk_factors": risk_info["risk_factors"]
            }
            processed_assets.append(asset_obj)

        self.twin_state = {
            "assets": processed_assets,
            "services": all_services,
            "vulnerabilities": all_matched_vulns,
            "risks": all_risks
        }

        # Module 9: Delta & Anomaly Detection
        self.detected_changes = self._compute_changes()

        # Module 13: Generate Alerts
        self.active_alerts = self._generate_alerts()

        # Module 8 & 12: Save Scan Snapshot to DB
        self.db_manager.save_scan_snapshot(self.twin_state, self.detected_changes, self.active_alerts)

        return self.twin_state

    def get_filtered_twin_state(self, dataset_filter="ALL"):
        """
        Returns Digital Twin state filtered by dataset:
        - "ALL": All Assets
        - "DEMO": Demo Network Assets Only
        - "IMPORTED_LAB": Imported Lab Scan Assets (192.168.56.101) Only
        """
        if dataset_filter == "DEMO":
            filtered_assets = [a for a in self.twin_state["assets"] if a.get("data_source") == "DEMO_NETWORK"]
        elif dataset_filter == "IMPORTED_LAB":
            filtered_assets = [a for a in self.twin_state["assets"] if a.get("data_source") == "IMPORTED_LAB_SCAN"]
        else:
            return self.twin_state

        asset_ids = {a["asset_id"] for a in filtered_assets}
        return {
            "assets": filtered_assets,
            "services": [s for s in self.twin_state["services"] if s["asset_id"] in asset_ids],
            "vulnerabilities": [v for v in self.twin_state["vulnerabilities"] if v["asset_id"] in asset_ids],
            "risks": [r for r in self.twin_state["risks"] if r["asset_id"] in asset_ids]
        }

    def _inject_simulated_network_event(self, assets_raw):
        """Helper to simulate network changes for testing Module 8 & 9."""
        import copy
        modified = copy.deepcopy(assets_raw)
        if not any(a.get("asset_id") == "AST-006" for a in modified):
            modified.append({
                "asset_id": "AST-006",
                "hostname": "iot-camera-01.local",
                "ip_address": "192.168.1.45",
                "mac_address": "00:1A:2B:99:88:77",
                "device_type": "IoT Camera",
                "os": "Embedded Linux",
                "status": "Online",
                "importance": "High",
                "data_source": "DEMO_NETWORK",
                "ports": [
                    {"port": 554, "protocol": "TCP", "state": "Open", "service": "RTSP", "version": "Real Time Streaming 1.0"},
                    {"port": 80, "protocol": "TCP", "state": "Open", "service": "HTTP", "version": "Apache httpd 2.4.41"}
                ]
            })
        return modified

    def _calculate_asset_risk(self, asset_id, hostname, ports, vulns, importance):
        risk_factors = []
        base_score = 0.0

        if vulns:
            max_cvss = max([v["cvss"] for v in vulns])
            vuln_pts = min(max_cvss * 5.5, 55.0)
            base_score += vuln_pts
            risk_factors.append(f"{len(vulns)} vulnerability matched (Max CVSS: {max_cvss})")
        else:
            risk_factors.append("No active CVE matches found")

        port_count = len(ports)
        if port_count > 0:
            port_pts = min(port_count * 4.0, 15.0)
            base_score += port_pts
            risk_factors.append(f"{port_count} open listening port(s)")

        critical_ports = {22: "SSH", 445: "SMB", 3389: "RDP", 3306: "MySQL", 21: "FTP", 23: "Telnet"}
        exposed_crit = [p["service"] for p in ports if p["port"] in critical_ports]
        if exposed_crit:
            base_score += 15.0
            risk_factors.append(f"Exposed critical service(s): {', '.join(set(exposed_crit))}")

        importance_weights = {"Critical": 1.2, "High": 1.1, "Medium": 1.0, "Low": 0.85}
        weight = importance_weights.get(importance, 1.0)
        final_score = min(max(round(base_score * weight, 1), 0.0), 100.0)
        risk_factors.append(f"Asset criticality level: {importance} (Multiplier: {weight}x)")

        if final_score <= 20.0:
            risk_level = "Low"
        elif final_score <= 40.0:
            risk_level = "Moderate"
        elif final_score <= 60.0:
            risk_level = "Medium"
        elif final_score <= 80.0:
            risk_level = "High"
        else:
            risk_level = "Critical"

        return {
            "asset_id": asset_id,
            "hostname": hostname,
            "risk_score": final_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors
        }

    def _compute_changes(self):
        """
        Module 9: Rule-based Change and Anomaly Detection Engine.
        Compares Previous Twin State vs Current Twin State.
        """
        if not self.previous_twin_state:
            return [{"type": "INFO", "category": "SCAN_INIT", "message": "Initial Digital Twin baseline snapshot established."}]

        changes = []
        prev_assets = {a["asset_id"]: a for a in self.previous_twin_state.get("assets", [])}
        curr_assets = {a["asset_id"]: a for a in self.twin_state.get("assets", [])}

        for aid, asset in curr_assets.items():
            if aid not in prev_assets:
                changes.append({
                    "type": "WARNING",
                    "category": "NEW_ASSET",
                    "message": f"NEW ASSET DETECTED: [{aid}] {asset['hostname']} ({asset['ip_address']}) - OS: {asset['os']}"
                })
            else:
                p_asset = prev_assets[aid]
                if asset["risk_score"] > p_asset["risk_score"]:
                    changes.append({
                        "type": "WARNING",
                        "category": "RISK_INCREASED",
                        "message": f"RISK SCORE INCREASED: {asset['hostname']} increased from {p_asset['risk_score']} to {asset['risk_score']} ({asset['risk_level']})"
                    })

        for aid, asset in prev_assets.items():
            if aid not in curr_assets:
                changes.append({
                    "type": "INFO",
                    "category": "REMOVED_ASSET",
                    "message": f"ASSET REMOVED / DECOMMISSIONED: [{aid}] {asset['hostname']} ({asset['ip_address']})"
                })

        prev_ports = {(s["asset_id"], s["port"]): s for s in self.previous_twin_state.get("services", [])}
        curr_ports = {(s["asset_id"], s["port"]): s for s in self.twin_state.get("services", [])}

        for p_key, port_info in curr_ports.items():
            if p_key not in prev_ports:
                changes.append({
                    "type": "WARNING",
                    "category": "NEW_OPEN_PORT",
                    "message": f"NEW OPEN PORT DETECTED: Port {port_info['port']}/{port_info['protocol']} ({port_info['service']}) opened on {port_info['hostname']}"
                })

        for p_key, port_info in prev_ports.items():
            if p_key not in curr_ports:
                changes.append({
                    "type": "INFO",
                    "category": "CLOSED_PORT",
                    "message": f"PORT CLOSED: Port {port_info['port']} ({port_info['service']}) on {port_info['hostname']} is no longer exposed"
                })

        prev_vulns = {(v["asset_id"], v["cve_id"]) for v in self.previous_twin_state.get("vulnerabilities", [])}
        curr_vulns = {(v["asset_id"], v["cve_id"]): v for v in self.twin_state.get("vulnerabilities", [])}

        for v_key, v_info in curr_vulns.items():
            if v_key not in prev_vulns:
                changes.append({
                    "type": "CRITICAL" if v_info["severity"] in ["Critical", "High"] else "WARNING",
                    "category": "NEW_VULNERABILITY",
                    "message": f"NEW VULNERABILITY DETECTED: [{v_info['cve_id']}] {v_info['title']} (CVSS {v_info['cvss']}) on {v_info['hostname']}"
                })

        if not changes:
            changes.append({"type": "INFO", "category": "NO_CHANGE", "message": "No anomalous state changes detected between scans."})

        return changes

    def _generate_alerts(self):
        """
        Module 13: Alert System based on twin vulnerabilities, high risk, and ports.
        """
        alerts = []
        for asset in self.twin_state.get("assets", []):
            if asset.get("risk_level") == "Critical":
                alerts.append({
                    "severity": "CRITICAL",
                    "asset_id": asset["asset_id"],
                    "hostname": asset["hostname"],
                    "title": "Critical Risk Threshold Exceeded",
                    "message": f"Asset {asset['hostname']} has a CRITICAL risk score of {asset['risk_score']}/100."
                })

        for v in self.twin_state.get("vulnerabilities", []):
            if v.get("severity") == "Critical":
                alerts.append({
                    "severity": "CRITICAL",
                    "asset_id": v["asset_id"],
                    "hostname": v["hostname"],
                    "title": f"Unpatched Critical CVE {v['cve_id']}",
                    "message": f"Vulnerability {v['cve_id']} (CVSS {v['cvss']}) detected on service {v['affected_service']}."
                })

        for srv in self.twin_state.get("services", []):
            if srv["port"] in [445, 3389, 21, 23, 1524, 6667]:
                alerts.append({
                    "severity": "HIGH",
                    "asset_id": srv["asset_id"],
                    "hostname": srv["hostname"],
                    "title": f"Exposed Sensitive Port {srv['port']}",
                    "message": f"Sensitive service {srv['service']} open on port {srv['port']}."
                })

        return alerts

    def simulate_risk_remediation(self, asset_id, fix_cve_ids=None, close_ports=None):
        """
        Module 10: What-If / Risk Remediation Simulation Engine.
        """
        fix_cve_ids = fix_cve_ids or []
        close_ports = close_ports or []

        target_asset = next((a for a in self.twin_state["assets"] if a["asset_id"] == asset_id), None)
        if not target_asset:
            return None

        asset_ports = [p for p in self.twin_state["services"] if p["asset_id"] == asset_id and p["port"] not in close_ports]
        asset_vulns = [v for v in self.twin_state["vulnerabilities"] if v["asset_id"] == asset_id and v["cve_id"] not in fix_cve_ids]

        simulated_risk = self._calculate_asset_risk(
            asset_id=target_asset["asset_id"],
            hostname=target_asset["hostname"],
            ports=asset_ports,
            vulns=asset_vulns,
            importance=target_asset["importance"]
        )

        orig_score = target_asset["risk_score"]
        sim_score = simulated_risk["risk_score"]
        reduction = round(orig_score - sim_score, 1)

        return {
            "asset_id": asset_id,
            "hostname": target_asset["hostname"],
            "original_score": orig_score,
            "original_level": target_asset["risk_level"],
            "simulated_score": sim_score,
            "simulated_level": simulated_risk["risk_level"],
            "risk_reduction": max(reduction, 0.0),
            "simulated_factors": simulated_risk["risk_factors"]
        }

    def get_security_recommendations(self):
        """
        Module 11: Security Recommendations Engine.
        """
        recs = []
        vulns = self.twin_state.get("vulnerabilities", [])
        services = self.twin_state.get("services", [])
        assets = self.twin_state.get("assets", [])

        crit_vulns = [v for v in vulns if v["severity"] == "Critical"]
        if crit_vulns:
            recs.append({
                "priority": "CRITICAL",
                "action": "Immediate Patch Deployment Required",
                "details": f"Apply security patches for {len(crit_vulns)} Critical CVE(s) ({', '.join(set([v['cve_id'] for v in crit_vulns]))}) immediately to prevent remote execution."
            })

        exposed_rdp_smb = [s for s in services if s["port"] in [445, 3389, 21, 23]]
        if exposed_rdp_smb:
            recs.append({
                "priority": "HIGH",
                "action": "Restrict Sensitive Remote Ports",
                "details": f"Restrict public access to SMB (445), RDP (3389), Telnet (23) and FTP (21) ports on {len(exposed_rdp_smb)} host(s) using firewall access rules."
            })

        legacy_services = [s for s in services if "7.6p1" in s["version"] or "v1" in s["version"] or "vsftpd 2.3.4" in s["version"]]
        if legacy_services:
            recs.append({
                "priority": "MEDIUM",
                "action": "Upgrade Outdated Software Services",
                "details": f"Upgrade legacy software versions (e.g., vsftpd 2.3.4 / OpenSSH / Samba) on hosts: {', '.join(set([s['hostname'] for s in legacy_services]))}."
            })

        crit_assets = [a for a in assets if a["risk_level"] in ["Critical", "High"]]
        if crit_assets:
            recs.append({
                "priority": "HIGH",
                "action": "Segment High-Risk Assets",
                "details": f"Isolate high-risk hosts ({', '.join([a['hostname'] for a in crit_assets])}) into an isolated VLAN until remediated."
            })

        return recs

    def generate_assessment_report_html(self):
        """
        Module 14: Cyber Twin Security Assessment HTML Report Generator.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        assets = self.twin_state.get("assets", [])
        vulns = self.twin_state.get("vulnerabilities", [])

        asset_rows = "".join([
            f"<tr><td>{a['asset_id']}</td><td>{a['hostname']}</td><td>{a['ip_address']}</td><td>{a['os']}</td><td>{a['risk_level']}</td><td>{a['risk_score']}</td></tr>"
            for a in assets
        ])

        vuln_rows = "".join([
            f"<tr><td>{v['cve_id']}</td><td>{v['hostname']}</td><td>{v['severity']}</td><td>{v['cvss']}</td><td>{v['title']}</td></tr>"
            for v in vulns
        ])

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CyberTwinAI Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 30px; }}
                h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
                h2 {{ color: #60a5fa; margin-top: 25px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; }}
                th {{ background-color: #1e293b; color: #38bdf8; }}
                tr:nth-child(even) {{ background-color: #0f172a; }}
                .summary {{ background: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #334155; }}
            </style>
        </head>
        <body>
            <h1>🛡️ CyberTwinAI - Digital Twin Security Assessment Report</h1>
            <div class="summary">
                <p><strong>Generated On:</strong> {now}</p>
                <p><strong>Total Assets Monitored:</strong> {len(assets)}</p>
                <p><strong>Total Open Ports Discovered:</strong> {len(self.twin_state.get('services', []))}</p>
                <p><strong>Matched Vulnerabilities:</strong> {len(vulns)}</p>
            </div>

            <h2>🖥️ Monitored Assets</h2>
            <table>
                <tr><th>Asset ID</th><th>Hostname</th><th>IP Address</th><th>OS</th><th>Risk Level</th><th>Risk Score</th></tr>
                {asset_rows}
            </table>

            <h2>⚠️ Discovered Vulnerabilities</h2>
            <table>
                <tr><th>CVE ID</th><th>Affected Host</th><th>Severity</th><th>CVSS</th><th>Title</th></tr>
                {vuln_rows}
            </table>
        </body>
        </html>
        """
        return html_content

    def get_digital_twin_state(self):
        return self.twin_state
