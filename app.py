import os
import time
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from backend.core import DigitalTwinEngine
from backend.knowledge_graph import DigitalTwinKnowledgeGraph
from backend.topology import TopologyVisualizer
from backend.ai.attack_simulator import QAttackAgent, AttackPathAnalyzer, DefensiveDecisionEngine, WhatIfCounterfactualSimulator

# Page Configuration
st.set_page_config(
    page_title="CyberTwin - Cybersecurity Digital Twin",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load Custom CSS Style
def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "backend", "styles.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# Initialize Engine in Session State (with auto-refresh on new engine methods)
if "twin_engine" not in st.session_state or not hasattr(st.session_state.twin_engine, "import_nmap_scan_xml"):
    st.session_state.twin_engine = DigitalTwinEngine()

engine = st.session_state.twin_engine
twin_state = engine.get_digital_twin_state()
assets = twin_state.get("assets", [])
services = twin_state.get("services", [])
vulnerabilities = twin_state.get("vulnerabilities", [])
risks = twin_state.get("risks", [])

def get_risk_pill_html(level):
    level_cls = str(level).lower()
    return f'<span class="risk-pill risk-{level_cls}">{level}</span>'

# Sidebar Navigation
st.sidebar.markdown("""
<div style="text-align: center; padding-bottom: 15px;">
    <h2 style="color: #38bdf8; margin: 0;">🛡️ CYBER TWIN</h2>
    <p style="color: #ffffff; font-size: 0.85rem; margin-top: 4px; font-weight:600;">Network Asset & Risk Digital Twin</p>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    [
        "OVERVIEW",
        "ASSETS",
        "VULNERABILITIES",
        "RISK",
        "CYBER TWIN",
        "KNOWLEDGE GRAPH",
        "AI ATTACK SIMULATION",
        "ATTACK PATHS",
        "DEFENSIVE ENGINE",
        "WHAT-IF ANALYSIS",
        "AI TRAINING",
        "MONITORING",
        "CHANGES & ALERTS",
        "RECOMMENDATIONS",
        "REPORTS"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔌 System Status")
mongo_status_color = "#34d399" if engine.db_manager.use_mongo else "#facc15"
mongo_status_text = "MongoDB Online" if engine.db_manager.use_mongo else "Local Store Active"

st.sidebar.markdown(f"""
- **Backend Engine:** <span style="color:#34d399; font-weight:600;">Online</span>
- **Database:** <span style="color:{mongo_status_color}; font-weight:600;">{mongo_status_text}</span>
- **Target Network:** Enterprise Subnet
""", unsafe_allow_html=True)

# Import Nmap Scan Button
if st.sidebar.button("📥 Import Nmap Scan (data/scan.xml)", use_container_width=True):
    success = st.session_state.twin_engine.import_nmap_scan_xml("data/scan.xml")
    if success:
        st.sidebar.success("Successfully imported Nmap XML scan (192.168.56.101)!")
        st.rerun()
    else:
        st.sidebar.error("Failed to import Nmap XML scan from data/scan.xml")

if st.sidebar.button("🔄 Refresh / Run Scan", use_container_width=True):
    st.session_state.twin_engine.refresh_digital_twin(simulated_scan=True)
    st.sidebar.success("Digital Twin scan refreshed & state snapshot stored!")
    st.rerun()

# Main Header Banner
st.markdown("""
<div class="soc-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <div class="soc-title">🛡️ CyberTwin – Cybersecurity Digital Twin</div>
            <div class="soc-subtitle">Real-Time Network Asset Monitoring, AI Attack Simulation & Nmap XML Import Integration</div>
        </div>
        <div>
            <span class="soc-badge">● System Online</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

total_assets_cnt = len(assets)
online_assets_cnt = len([a for a in assets if a.get("status") == "Online"])
total_open_ports = len(services)
total_vulns_cnt = len(vulnerabilities)
avg_risk_score = round(sum([a.get("risk_score", 0.0) for a in assets]) / max(total_assets_cnt, 1), 1)

# PAGE 1: OVERVIEW
if page == "OVERVIEW":
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Total Assets</div><div class="metric-value">{total_assets_cnt}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Online Assets</div><div class="metric-value" style="color:#4ade80;">{online_assets_cnt}</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Open Ports</div><div class="metric-value" style="color:#facc15;">{total_open_ports}</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Services</div><div class="metric-value" style="color:#60a5fa;">{total_open_ports}</div></div>', unsafe_allow_html=True)
    with c5:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Vulnerabilities</div><div class="metric-value" style="color:#f87171;">{total_vulns_cnt}</div></div>', unsafe_allow_html=True)
    with c6:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Average Risk</div><div class="metric-value" style="color:#fb923c;">{avg_risk_score}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("📊 Asset Risk Score Overview")
        if assets:
            df_assets = pd.DataFrame(assets)
            fig_risk = px.bar(
                df_assets,
                x="hostname",
                y="risk_score",
                color="risk_level",
                color_discrete_map={
                    "Low": "#4ade80",
                    "Moderate": "#60a5fa",
                    "Medium": "#facc15",
                    "High": "#fb923c",
                    "Critical": "#f87171"
                },
                labels={"hostname": "Asset Hostname", "risk_score": "Risk Score (0-100)"},
                title="Asset Risk Scores"
            )
            fig_risk.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#ffffff')
            st.plotly_chart(fig_risk, use_container_width=True)

    with col_b:
        st.subheader("🍩 Vulnerability Severity Distribution")
        if vulnerabilities:
            df_v = pd.DataFrame(vulnerabilities)
            sev_counts = df_v["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            fig_sev = px.pie(
                sev_counts,
                names="Severity",
                values="Count",
                color="Severity",
                color_discrete_map={
                    "Critical": "#ef4444",
                    "High": "#f97316",
                    "Medium": "#eab308",
                    "Low": "#22c55e"
                },
                hole=0.45,
                title="Vulnerabilities by Severity"
            )
            fig_sev.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#ffffff')
            st.plotly_chart(fig_sev, use_container_width=True)

    st.subheader("🖥️ Digital Twin Monitored Assets")
    if assets:
        df_display = pd.DataFrame(assets)[["asset_id", "hostname", "ip_address", "device_type", "os", "status", "risk_level", "risk_score"]]
        st.dataframe(df_display, use_container_width=True)

# PAGE 2: ASSETS
elif page == "ASSETS":
    st.title("Asset, Port & Service Inventory")
    st.markdown("Digital Twin asset discovery module tracking host IP addresses, MAC addresses, device types, operating systems, and open listening services.")

    if st.button("📥 Trigger Nmap XML Scan Import (data/scan.xml)", use_container_width=True):
        res = engine.import_nmap_scan_xml("data/scan.xml")
        if res:
            st.success("Successfully imported Nmap XML scan (192.168.56.101) into Digital Twin!")
            st.rerun()

    if assets:
        for a in assets:
            with st.expander(f"📌 [{a['asset_id']}] {a['hostname']} - {a['ip_address']} ({a['status']})"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**MAC Address:** `{a['mac_address']}`")
                    st.write(f"**Device Type:** {a['device_type']}")
                    st.write(f"**Importance:** {a['importance']}")
                with col2:
                    st.write(f"**Operating System:** {a['os']}")
                    st.write(f"**Status:** {a['status']}")
                    st.write(f"**Open Ports Count:** {a['open_ports_count']}")
                with col3:
                    st.write(f"**First Seen:** {a['first_seen']}")
                    st.write(f"**Last Seen:** {a['last_seen']}")
                    st.write(f"**Risk Level:** {a['risk_level']} ({a['risk_score']}/100)")

# PAGE 3: VULNERABILITIES
elif page == "VULNERABILITIES":
    st.title("Automated Vulnerability Assessment")
    v1, v2, v3, v4 = st.columns(4)
    v1.metric("Total Vulnerabilities", total_vulns_cnt)
    v2.metric("Critical CVEs", len([v for v in vulnerabilities if v['severity'] == 'Critical']))
    v3.metric("High CVEs", len([v for v in vulnerabilities if v['severity'] == 'High']))
    v4.metric("Medium CVEs", len([v for v in vulnerabilities if v['severity'] == 'Medium']))

    st.markdown("<br>", unsafe_allow_html=True)
    if vulnerabilities:
        for v in vulnerabilities:
            st.markdown(f"""
            <div class="soc-callout">
                <strong style="color:#f87171;">[{v['cve_id']}] {v['title']}</strong> | 
                <span style="color:#fb923c;">Severity: {v['severity']} (CVSS {v['cvss']})</span><br>
                <span><b>Affected Host:</b> {v['hostname']} ({v['ip_address']}) via {v['affected_service']} {v['affected_version']}</span><br>
                <small style="color:#cbd5e1;">{v['description']}</small>
            </div>
            """, unsafe_allow_html=True)

# PAGE 4: RISK
elif page == "RISK":
    st.title("Transparent Risk Analysis Engine")
    if assets:
        for a in assets:
            with st.container():
                rc1, rc2 = st.columns([1, 3])
                with rc1:
                    st.markdown(f"### {a['hostname']}")
                    st.markdown(f"Risk Score: **{a['risk_score']} / 100**")
                    st.markdown(f"Level: {get_risk_pill_html(a['risk_level'])}", unsafe_allow_html=True)
                with rc2:
                    st.markdown("**Risk Calculation Factors:**")
                    for factor in a.get("risk_factors", []):
                        st.markdown(f"- {factor}")
                st.markdown("---")

# PAGE 5: CYBER TWIN
elif page == "CYBER TWIN":
    st.title("Integrated Cyber Twin & Topology")
    tab1, tab2 = st.tabs(["🌐 View 1: Logical Network Topology", "🕸️ View 2: Integrated Cyber Twin Model"])
    with tab1:
        fig_logical = TopologyVisualizer.create_logical_topology_figure(twin_state)
        st.plotly_chart(fig_logical, use_container_width=True)
    with tab2:
        kg = DigitalTwinKnowledgeGraph(twin_state)
        fig_kg = TopologyVisualizer.create_knowledge_graph_figure(kg.get_graph())
        st.plotly_chart(fig_kg, use_container_width=True)

# PAGE 6: KNOWLEDGE GRAPH
elif page == "KNOWLEDGE GRAPH":
    st.title("Knowledge Graph Model")
    kg = DigitalTwinKnowledgeGraph(twin_state)
    stats = kg.get_summary_stats()
    m1, m2 = st.columns(2)
    m1.metric("Graph Total Nodes", stats["total_nodes"])
    m2.metric("Graph Total Edges", stats["total_edges"])
    st.markdown("<br>", unsafe_allow_html=True)
    fig_kg = TopologyVisualizer.create_knowledge_graph_figure(kg.get_graph())
    st.plotly_chart(fig_kg, use_container_width=True)

# PAGE 7: AI ATTACK SIMULATION
elif page == "AI ATTACK SIMULATION":
    st.title("Module 8 – Offline AI Attack Simulation")
    st.markdown("Simulated reinforcement learning agent operating strictly on the Digital Twin software model. **No real network packets are transmitted.**")

    if st.button("▶️ Execute AI Attack Simulation", use_container_width=True):
        agent = QAttackAgent(twin_state)
        history = agent.train(episodes=50)
        st.session_state["sim_history"] = history
        st.session_state["sim_agent"] = agent
        st.success("AI Attack Simulation Completed!")

    if "sim_agent" in st.session_state:
        agent = st.session_state["sim_agent"]
        status = agent.get_model_status()
        
        m1, m2, m3 = st.columns(3)
        m1.metric("Entry Node", status["entry_node"])
        m2.metric("Target Node", status["target_node"])
        m3.metric("Learned Q-Table Entries", status["total_state_action_pairs"])

        st.markdown("### AI Attacker State & Policy Matrix")
        df_q = agent.get_q_table_dataframe()
        if not df_q.empty:
            st.dataframe(df_q, use_container_width=True)

# PAGE 8: ATTACK PATHS
elif page == "ATTACK PATHS":
    st.title("Module 9 – Attack Path Analysis")
    analyzer = AttackPathAnalyzer(twin_state)
    paths = analyzer.analyze_paths()

    if paths:
        st.subheader("🔥 Top Dangerous Attack Paths")
        for idx, p in enumerate(paths, 1):
            st.markdown(f"""
            <div class="soc-callout">
                <strong style="color:#38bdf8;">Path #{idx}: {' ➔ '.join(p['path'])}</strong><br>
                <span><b>Entry Point:</b> {p['entry_point']} | <b>Target:</b> {p['target']}</span><br>
                <span><b>Path Risk Score:</b> <strong style="color:#f87171;">{p['path_risk']}/100</strong> | <b>Difficulty:</b> {p['difficulty']} | <b>Impact:</b> {p['impact']}</span>
            </div>
            """, unsafe_allow_html=True)

# PAGE 9: DEFENSIVE ENGINE
elif page == "DEFENSIVE ENGINE":
    st.title("Module 10 – Defensive Decision Engine")
    engine_dec = DefensiveDecisionEngine(twin_state)
    recs = engine_dec.recommend_defenses()

    if recs:
        for r in recs:
            st.markdown(f"""
            <div class="soc-callout" style="border-left-color: #38bdf8;">
                <strong style="color:#38bdf8;">Priority #{r['priority']}: {r['action']}</strong><br>
                <span><b>Action Type:</b> `{r['type']}` on host <b>{r['target_asset']}</b></span><br>
                <span><b>Attack Paths Broken:</b> {r['paths_broken']} | <b>Estimated Risk Reduction:</b> -{r['risk_reduction']} Points</span><br>
                <small style="color:#cbd5e1;">Reason: {r['reason']}</small>
            </div>
            """, unsafe_allow_html=True)

# PAGE 10: WHAT-IF ANALYSIS
elif page == "WHAT-IF ANALYSIS":
    st.title("Module 11 & 12 – Predictive What-If & Counterfactual Simulation")
    if assets:
        asset_options = {f"{a['hostname']} ({a['ip_address']})": a["asset_id"] for a in assets}
        selected_label = st.selectbox("Select Target Asset for Simulation", list(asset_options.keys()))
        selected_aid = asset_options[selected_label]

        action_type = st.selectbox("Select Virtual Defense Action", ["PATCH_VULNERABILITY", "CLOSE_PORT", "ISOLATE_HOST"])
        param = ""
        if action_type == "PATCH_VULNERABILITY":
            asset_vulns = [v for v in vulnerabilities if v["asset_id"] == selected_aid]
            cve_opts = [v["cve_id"] for v in asset_vulns] if asset_vulns else ["CVE-2024-21626"]
            param = st.selectbox("Select Vulnerability CVE to Patch", cve_opts)
        elif action_type == "CLOSE_PORT":
            asset_ports = [s["port"] for s in services if s["asset_id"] == selected_aid]
            param = st.selectbox("Select Port Number to Close", asset_ports if asset_ports else [445, 3389, 22])

        if st.button("🔮 Run Counterfactual Simulation", use_container_width=True):
            sim = WhatIfCounterfactualSimulator(engine)
            res = sim.run_counterfactual_simulation(selected_aid, action_type, param)

            st.markdown("---")
            st.subheader("📊 Before vs. After Remediation Comparison")
            w1, w2, w3, w4 = st.columns(4)
            w1.metric("Before Risk Score", f"{res['before_risk']}")
            w2.metric("After Risk Score", f"{res['after_risk']}")
            w3.metric("Risk Reduction", f"-{res['risk_reduction']}", delta=f"-{res['risk_reduction']}")
            w4.metric("Attack Path Broken", "YES ✓" if res['path_broken'] else "NO ❌")

            col_bp, col_ap = st.columns(2)
            with col_bp:
                st.warning(f"**Attack Path BEFORE:** {' ➔ '.join(res['before_path'])}")
            with col_ap:
                st.success(f"**Attack Path AFTER:** {' ➔ '.join(res['after_path'])}")

# PAGE 11: AI TRAINING
elif page == "AI TRAINING":
    st.title("🤖 AI Agent Training & Q-Learning Dashboard")
    st.subheader("⚙️ Q-Learning Hyperparameter Configuration")
    col_hp1, col_hp2, col_hp3, col_hp4 = st.columns(4)
    with col_hp1:
        episodes_input = st.slider("Training Episodes", min_value=10, max_value=500, value=100, step=10)
    with col_hp2:
        alpha_input = st.slider("Learning Rate (α)", min_value=0.01, max_value=0.50, value=0.10, step=0.01)
    with col_hp3:
        gamma_input = st.slider("Discount Factor (γ)", min_value=0.50, max_value=0.99, value=0.90, step=0.01)
    with col_hp4:
        epsilon_input = st.slider("Exploration Rate (ε)", min_value=0.05, max_value=0.50, value=0.20, step=0.01)

    if st.button("🚀 Start AI Agent Training", use_container_width=True):
        t0 = time.time()
        agent = QAttackAgent(twin_state, alpha=alpha_input, gamma=gamma_input, epsilon=epsilon_input)
        history = agent.train(episodes=episodes_input)
        duration = round(time.time() - t0, 3)

        success_cnt = len([h for h in history if h.get("target_reached")])
        success_rate = round((success_cnt / max(len(history), 1)) * 100, 1)

        st.session_state["train_history"] = history
        st.session_state["train_agent"] = agent
        st.session_state["train_params"] = {
            "episodes": episodes_input,
            "alpha": alpha_input,
            "gamma": gamma_input,
            "epsilon": epsilon_input,
            "success_rate": success_rate,
            "duration": duration
        }

        run_record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "episodes": episodes_input,
            "alpha": alpha_input,
            "gamma": gamma_input,
            "epsilon": epsilon_input,
            "success_rate": success_rate,
            "duration_sec": duration,
            "q_table_size": len(agent.q_table)
        }
        engine.db_manager.save_training_run(run_record)
        st.success(f"AI Q-Learning Training Completed in {duration}s! Success Rate: {success_rate}%")

    if "train_history" in st.session_state:
        history = st.session_state["train_history"]
        agent = st.session_state["train_agent"]
        params = st.session_state["train_params"]

        st.markdown("---")
        st.subheader("📊 Training Metrics & Status")
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Status", "COMPLETED", delta="Ready")
        m2.metric("Duration", f"{params['duration']}s")
        m3.metric("Episodes", f"{params['episodes']}")
        m4.metric("Success Rate", f"{params['success_rate']}%")
        m5.metric("Final Epsilon", f"{max(0.01, round(params['epsilon'] - (params['epsilon']/params['episodes'])*params['episodes'], 3))}")
        m6.metric("Learned Q-Pairs", f"{len(agent.q_table)}")

        st.subheader("📈 Reward-Per-Episode Convergence")
        df_hist = pd.DataFrame(history)
        df_hist["rolling_reward"] = df_hist["reward"].rolling(window=10, min_periods=1).mean()

        fig_train = go.Figure()
        fig_train.add_trace(go.Scatter(
            x=df_hist["episode"], y=df_hist["reward"],
            mode='lines+markers', name='Episode Reward',
            line=dict(color='#60a5fa', width=1.5),
            marker=dict(size=4)
        ))
        fig_train.add_trace(go.Scatter(
            x=df_hist["episode"], y=df_hist["rolling_reward"],
            mode='lines', name='10-Episode Rolling Avg',
            line=dict(color='#34d399', width=3)
        ))
        fig_train.update_layout(
            title="Q-Learning Reward Progression Over Training Episodes",
            xaxis_title="Episode",
            yaxis_title="Total Reward",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#ffffff',
            hovermode='x unified'
        )
        st.plotly_chart(fig_train, use_container_width=True)

        st.subheader("🧠 Learned Q-Table & Model Policy")
        df_q = agent.get_q_table_dataframe()
        if not df_q.empty:
            st.dataframe(df_q, use_container_width=True)

    st.markdown("---")
    st.subheader("📜 Historical AI Training Runs (MongoDB / Local Store)")
    db_history = engine.db_manager.get_training_history()
    if db_history:
        df_db = pd.DataFrame(db_history)[["timestamp", "episodes", "alpha", "gamma", "epsilon", "success_rate", "duration_sec", "q_table_size"]]
        st.dataframe(df_db, use_container_width=True)

# PAGE 12: MONITORING
elif page == "MONITORING":
    st.title("Continuous Cyber Twin Monitoring")
    history = engine.db_manager.get_scan_history()
    if history:
        st.subheader("📜 Recent Scan Snapshots")
        df_hist = pd.DataFrame(history)[["timestamp", "asset_count", "open_ports_count", "vulnerabilities_count", "avg_risk_score", "alerts_count"]]
        st.dataframe(df_hist, use_container_width=True)

# PAGE 13: CHANGES & ALERTS
elif page == "CHANGES & ALERTS":
    st.title("State Change & Anomaly Detection")
    col_ch, col_al = st.columns(2)
    with col_ch:
        st.subheader("🔍 Detected State Changes & Anomalies")
        changes = engine.detected_changes
        if changes:
            for ch in changes:
                st.info(f"**[{ch.get('category', 'CHANGE')}]** {ch.get('message')}")

    with col_al:
        st.subheader("🚨 Real-time Security Alerts")
        alerts = engine.active_alerts
        if alerts:
            for al in alerts:
                sev = al.get("severity", "MEDIUM")
                color = "#ef4444" if sev == "CRITICAL" else "#f97316"
                st.markdown(f"""
                <div style="background:#1e293b; border-left:4px solid {color}; padding:12px 16px; border-radius:6px; margin-bottom:12px;">
                    <strong style="color:{color}; font-size:1.05rem;">[{sev}] {al.get('title')}</strong><br>
                    <span style="color:#ffffff;">{al.get('message')}</span>
                </div>
                """, unsafe_allow_html=True)

# PAGE 14: RECOMMENDATIONS
elif page == "RECOMMENDATIONS":
    st.title("Automated Security Recommendations")
    recs = engine.get_security_recommendations()
    if recs:
        for r in recs:
            prio = r.get("priority", "MEDIUM")
            color = "#ef4444" if prio == "CRITICAL" else ("#f97316" if prio == "HIGH" else "#facc15")
            st.markdown(f"""
            <div class="soc-callout" style="border-left-color: {color};">
                <strong style="color:{color}; font-size:1.05rem;">[{prio}] {r.get('action')}</strong><br>
                <span style="color:#ffffff;">{r.get('details')}</span>
            </div>
            """, unsafe_allow_html=True)

# PAGE 15: REPORTS
elif page == "REPORTS":
    st.title("Historical Risk Trends & Executive Security Reports")
    st.subheader("📈 Historical Risk & Vulnerability Trends")
    risk_history = engine.db_manager.get_risk_history()

    if len(risk_history) > 0:
        df_rh = pd.DataFrame(risk_history)
        fig_trend = px.line(
            df_rh,
            x="timestamp",
            y="avg_risk_score",
            markers=True,
            title="Network Average Risk Score Over Time",
            labels={"timestamp": "Scan Timestamp", "avg_risk_score": "Average Risk Score"}
        )
        fig_trend.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#ffffff')
        st.plotly_chart(fig_trend, use_container_width=True)

    st.markdown("---")
    st.subheader("📥 Download Cyber Twin Assessment Report")

    report_html = engine.generate_assessment_report_html()
    st.download_button(
        label="📄 Download Security Assessment Report (HTML)",
        data=report_html,
        file_name="cybertwin_security_report.html",
        mime="text/html",
        use_container_width=True
    )
