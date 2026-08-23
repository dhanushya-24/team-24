# CyberTwinAI — AI-Powered Autonomous Cybersecurity Digital Twin

## 1. Project Overview

CyberTwinAI builds a live, software-based "digital twin" of a small
network. It discovers real devices on a lab network using Nmap,
represents each device as a structured Python object, checks it
against rule-based vulnerability signatures, calculates a numeric
risk score, visualizes all of it in an interactive Streamlit
dashboard, and represents everything as a Knowledge Graph for future
modules to reason over.

This repository currently implements **Modules 1 through 6** of a
larger planned system. No machine learning, attack-path analysis,
simulation, or autonomous decision-making code exists yet — those are
future modules, listed at the bottom of this file.

## 2. Architecture (full planned system)

```
Network
   |
   v
Discovery Engine        <-- IMPLEMENTED (Module 1)
   |
   v
Digital Twin             <-- IMPLEMENTED (Module 2)
   |
   v
Vulnerability Assessment   <-- IMPLEMENTED (Module 3, rule-based)
   |
   v
Risk Assessment              <-- IMPLEMENTED (Module 4, rule-based)
   |
   v
Dashboard                      <-- IMPLEMENTED (Module 5, visualization only)
   |
   v
Knowledge Graph                  <-- IMPLEMENTED (Module 6, graph foundation only)
   |
   v
Attack Path Analysis               <-- future
   |
   v
Simulation                           <-- future
   |
   v
Decision Engine / AI Agent             <-- future
```

## 3. Folder Structure

```
CyberTwinAI/
│
├── backend/
│   ├── discovery/            # Module 1: finds devices with Nmap
│   │   ├── scanner.py         # runs nmap only
│   │   ├── parser.py          # parses nmap XML only
│   │   ├── database.py        # saves raw scan data only
│   │   └── main.py            # orchestrates scan -> parse -> store
│   │
│   ├── twin/                  # Module 2: builds the Digital Twin
│   │   ├── asset.py            # Asset data model (incl. risk_score, risk_level)
│   │   ├── service.py          # Service data model
│   │   ├── vulnerability.py    # Vulnerability data model
│   │   ├── connection.py       # Connection data model (unused for now)
│   │   └── twin_manager.py     # create/update/offline/save/load logic
│   │
│   ├── vulnerability/          # Module 3: rule-based vulnerability assessment
│   │   ├── rules.py             # VulnerabilityFinding model + port/OS rules
│   │   ├── cve_matcher.py       # version-string based CVE-candidate matching
│   │   └── vulnerability_manager.py  # analyze_asset() / analyze_assets()
│   │
│   ├── risk/                   # Module 4: rule-based risk scoring
│   │   ├── scoring.py           # scoring tables + risk-level thresholds
│   │   └── risk_calculator.py   # calculate_asset_risk() / calculate_all_assets()
│   │
│   ├── dashboard/              # Module 5: Streamlit dashboard (visualization only)
│   │   ├── dashboard.py         # main app: sidebar nav + all pages
│   │   ├── api_client.py        # HTTP client for the existing Flask API
│   │   ├── charts.py            # Plotly figure builders
│   │   ├── components.py        # reusable UI building blocks (cards, badges)
│   │   └── topology.py          # logical hub view + Module 6 knowledge graph rendering
│   │
│   ├── knowledge_graph/         # Module 6: graph foundation (NetworkX)
│   │   ├── graph_builder.py      # Asset data -> typed NetworkX nodes/edges
│   │   ├── graph_manager.py      # build/save/load/clear via MongoDBHandler
│   │   └── graph_queries.py      # read-only lookups (no attack-path analysis)
│   │
│   └── database/
│       └── mongodb.py          # the ONLY file that talks to MongoDB directly
│
├── assets/
│   └── styles.css              # dark cyber-security theme for the dashboard
│
├── docs/
│   └── mongo_schema.md         # full MongoDB collection reference
├── data/                       # raw Nmap XML scan output is saved here
├── tests/
│   └── sample_test.py          # demo/test of the full twin sync logic
│
├── app.py                      # Flask entry point (Modules 1 + 2 API)
├── run_dashboard.py            # convenience launcher for the dashboard
├── requirements.txt
└── README.md
```

## 4. Module 1 — Discovery Engine

**Purpose:** find real devices on a network using Nmap and turn the
result into clean Python dictionaries stored in MongoDB.

- **`scanner.py`** — runs `nmap -oX <file> -sV -O -T4 <target>` via
  `subprocess`, saves raw XML to `data/`. Does not parse or store.
- **`parser.py`** — reads that XML with `xml.etree.ElementTree` and
  returns a list of dictionaries. Does not scan or store.
- **`database.py`** — upserts those dictionaries into the `assets`
  collection as a raw snapshot. Does not scan or parse.
- **`main.py`** — orchestrates: Scan → Parse → Store → Return result.

## 5. Module 2 — Digital Twin

**Purpose:** convert raw discovery dictionaries into structured,
stateful `Asset` objects, and keep that state accurate over repeated
scans.

- **`asset.py` / `service.py` / `vulnerability.py` / `connection.py`**
  — `@dataclass` data models with `to_dict()` / `from_dict()`.
- **`twin_manager.py`** — `create_asset()`, `add_or_update_asset()`,
  `mark_offline_assets()` (never auto-deletes — see its docstring),
  and `sync_from_discovery()`, the single entry point tying a scan's
  results into twin state.

## 6. Module 3 — Vulnerability Assessment

**Purpose:** identify likely vulnerabilities on each asset using
rule-based matching only — no AI, no ML.

- **`rules.py`** — the `VulnerabilityFinding` data shape, plus static
  `PORT_RULES` (FTP/Telnet/HTTP/RDP) and `OS_PORT_COMBO_RULES`
  (Windows + SMB → SMB Exposure).
- **`cve_matcher.py`** — parses service version strings and flags
  known-vulnerable versions (e.g. outdated Apache/OpenSSH, the
  vsftpd 2.3.4 backdoor).
- **`vulnerability_manager.py`** — `analyze_asset(asset)` and
  `analyze_assets(asset_list)` run all rule checks and write the
  results into `asset.vulnerabilities`, persisting via `TwinManager`.

## 7. Module 4 — Risk Assessment

**Purpose:** calculate a 0–100 `risk_score` and a `risk_level` label
for each asset, using the vulnerability findings from Module 3 plus
open ports and OS.

- **`scoring.py`** — severity point values, port bonuses, the
  Windows Server bonus, and the 4-tier risk-level thresholds
  (Low/Medium/High/Critical).
- **`risk_calculator.py`** — `calculate_asset_risk(asset)` and
  `calculate_all_assets(asset_list)` compute and persist
  `risk_score`/`risk_level` back onto each asset via `TwinManager`.

## 8. Module 5 — Dashboard

**Purpose:** visualize everything Modules 1–4 have already computed.
The dashboard performs **no analysis of its own** — it only calls the
existing, unmodified Flask API (`GET /health`, `POST /scan`,
`GET /assets`, `GET /assets/<asset_id>`) and renders what comes back.

- **`api_client.py`** — the only file that talks to the backend. Wraps
  the four existing Flask endpoints, plus a separate read-only
  MongoDB ping (`check_mongo_status`) used solely for the Settings
  page's status indicator — it never reads asset data directly from
  MongoDB.
- **`charts.py`** — pure functions building Plotly figures (risk
  gauge, risk-level pie, vulnerability severity bar, risk histogram,
  ports-per-device bar, OS distribution pie, discovery timeline).
- **`components.py`** — reusable presentation building blocks: metric
  cards, status/risk/severity badges, page headers, service cards.
- **`topology.py`** — builds a NetworkX graph and renders it with
  Plotly. Since the backend's `connections` collection isn't
  populated by any module yet, this draws an honestly-labeled
  **logical hub topology** (one router/hub node connected to every
  asset) rather than fabricating real network paths.
- **`dashboard.py`** — the main app: sidebar navigation (Dashboard,
  Assets, Services, Ports, Risk, Topology, Logs, Settings), the
  "Refresh Scan" control (calls `POST /scan` then reloads), and an
  optional 10-second auto-refresh.

Pages:
| Page | Shows |
|---|---|
| **Dashboard** | KPI cards, risk gauge/pie, ports/OS/timeline/histogram charts, recent assets |
| **Assets** | Searchable/filterable inventory table + full asset detail view (ports, services, vulnerabilities) |
| **Services** | Every asset's services as icon cards, grouped by device |
| **Ports** | A flat, searchable table of every open port across the network |
| **Risk** | Gauge, progress bar, risk-level pie, vulnerability severity breakdown, risk histogram, top-5 riskiest assets |
| **Topology** | Toggle between the Module 5 logical hub view and the Module 6 Knowledge Graph |
| **Logs** | Last scan (this session), scan history, and Digital Twin update history sorted newest-first |
| **Settings** | Backend URL, MongoDB status, Flask status, refresh interval |

## 9. Module 6 — Knowledge Graph

**Purpose:** represent relationships between devices, IPs, operating
systems, ports, services, vulnerabilities, and risk levels using
NetworkX. **Module 6 does not perform attack-path analysis or AI
reasoning. It provides the graph foundation used by later modules**
(7 — Attack Path Analysis, 8 — Simulation, 9 — AI Agent / Decision Engine).

- **`graph_builder.py`** — `KnowledgeGraphBuilder` converts existing
  `Asset` objects/dicts (from Modules 1–4) into typed NetworkX nodes
  (`asset`, `ip`, `operating_system`, `port`, `service`,
  `vulnerability`, `risk`) and relationship edges (`ASSET_HAS_IP`,
  `ASSET_RUNS_OS`, `ASSET_EXPOSES_PORT`, `ASSET_RUNS_SERVICE`,
  `ASSET_HAS_VULNERABILITY`, `ASSET_HAS_RISK`). It never invents
  device-to-device connections — `ASSET_CONNECTED_TO_ASSET` edges are
  only created when real connection records are explicitly supplied.
- **`graph_manager.py`** — `KnowledgeGraphManager` builds the graph
  from the current Digital Twin state (via the existing
  `TwinManager`), and can save/load it through the existing
  `MongoDBHandler` into a dedicated `knowledge_graph` collection, as
  a plain serializable `{"nodes": [...], "edges": [...]}` document —
  never a raw NetworkX object.
- **`graph_queries.py`** — read-only lookups only: `get_asset_neighbors`,
  `get_asset_services`, `get_asset_ports`, `get_asset_vulnerabilities`,
  `get_high_risk_assets`, `get_assets_with_vulnerability`,
  `get_nodes_by_type`, `get_edges_by_relationship`. No attack-path
  finding, no exploitation, no recommendations.
- **Dashboard integration:** the Topology page now offers both the
  original Module 5 logical hub view and the real Module 6 Knowledge
  Graph (fetched via `GET /knowledge-graph`), clearly labeled
  "Knowledge Graph — Asset Relationships" and explicitly not
  presented as physical network topology.
- **Flask integration:** a new read-only `GET /knowledge-graph`
  endpoint builds the graph fresh from the current twin state and
  returns it as `{"nodes": [...], "edges": [...]}`. The four existing
  endpoints are unchanged.

## 10. Installation

### 10.1 Python Environment

```bash
# from the CyberTwinAI project root
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 10.2 MongoDB Setup

1. Install MongoDB Community Server:
   https://www.mongodb.com/try/download/community
2. During setup, choose "Complete" install and tick "Install MongoDB
   as a Service" so it starts automatically.
3. Verify it's running:
   - Windows: open **Services** app → find **MongoDB Server** → status
     should be **Running**.
   - Mac/Linux: `sudo systemctl status mongod`

No manual database/collection creation is needed — `mongodb.py`
creates the `cybertwin` database and its collections automatically the
first time data is written.

### 10.3 Nmap Installation

1. Download Nmap: https://nmap.org/download.html
2. Install it, making sure it's added to your system PATH.
3. Verify: `nmap --version`
4. **Permissions:** OS detection (`-O` flag) requires elevated
   privileges (Windows: run terminal "as Administrator"; Mac/Linux:
   run with `sudo`). Remove `-O` from `backend/discovery/scanner.py`
   if you don't want to run elevated — scans still work, just without
   OS guesses.

### 10.4 Lab Target (what you scan)

Do not scan networks or devices you don't own or have permission to
scan. Use **VirtualBox** with a **Host-Only Network** adapter, a
**Kali Linux** VM, and a **Metasploitable2** VM as your scan target.
Find its IP inside the VM with `ifconfig`.

## 11. How to Run

**Start MongoDB first** (see 10.2), then from the project root:

```bash
# 1. Start the Flask backend
python app.py
```

In a second terminal:

```bash
# 2. Launch the dashboard
python run_dashboard.py
```

This opens the dashboard in your browser (typically
`http://localhost:8501`). From the sidebar, enter a target IP/CIDR
and click **🔄 Refresh Scan** to trigger `POST /scan` and populate the
twin — every page updates automatically afterward. Visit the
**Topology** page and switch to "Knowledge Graph — Asset
Relationships" to see the Module 6 graph.

You can also drive the backend directly without the dashboard:
```bash
curl -X POST http://127.0.0.1:5000/scan \
     -H "Content-Type: application/json" \
     -d "{\"target\": \"192.168.56.101\"}"

curl http://127.0.0.1:5000/assets
curl http://127.0.0.1:5000/assets/192.168.56.101
curl http://127.0.0.1:5000/knowledge-graph
```

### Testing without a live scan

```bash
python -m tests.sample_test
python -m tests.test_knowledge_graph
```

`sample_test.py` simulates a full discovery-to-twin cycle (create two
devices, update one, mark one offline) using fake data, so you can
verify Module 1/2 logic without VirtualBox/Kali set up.
`test_knowledge_graph.py` builds a Knowledge Graph from fake in-memory
assets and asserts the expected nodes/edges exist — it needs no live
scan, no Flask server, and no MongoDB connection.

## 12. Expected Output

`POST /scan` returns JSON like:
```json
{
  "target": "192.168.56.101",
  "devices_found": 1,
  "assets": [
    {
      "asset_id": "192.168.56.101",
      "hostname": null,
      "ip_address": "192.168.56.101",
      "operating_system": "Linux 2.6.X",
      "device_type": "server",
      "status": "online",
      "ports": [21, 22, 80, 3306],
      "vulnerabilities": [],
      "risk_score": 25,
      "risk_level": "Medium",
      "...": "..."
    }
  ]
}
```

`GET /knowledge-graph` returns:
```json
{
  "nodes": [
    {"id": "asset:192.168.56.101", "node_type": "asset", "label": "192.168.56.101", "...": "..."},
    {"id": "port:80", "node_type": "port", "label": "80", "port": 80}
  ],
  "edges": [
    {"source": "asset:192.168.56.101", "target": "port:80", "relationship": "ASSET_EXPOSES_PORT"}
  ]
}
```

The dashboard's **Dashboard** page shows this same data as KPI cards
and charts; the **Assets** page lets you drill into any single asset;
the **Topology** page can render the Knowledge Graph directly.

## 13. Current Progress

- [x] Module 1: Discovery Engine
- [x] Module 2: Digital Twin
- [x] Module 3: Vulnerability Assessment (rule-based)
- [x] Module 4: Risk Assessment (rule-based)
- [x] Module 5: Dashboard (Streamlit, visualization only)
- [x] Module 6: Knowledge Graph (graph foundation only — no attack-path analysis)
- [ ] Module 7: Attack Path Analysis
- [ ] Module 8: Simulation
- [ ] Module 9: Decision Engine / AI Agent

## 14. Future Modules (not implemented — by design, per current scope)

- **Attack Path Analysis** — will use the Module 6 Knowledge Graph +
  known vulnerabilities to find possible attacker routes through the
  network.
- **Simulation** — controlled attack simulation, likely using
  Metasploit against the lab VM, feeding results back into the twin.
- **Decision Engine / AI Agent** — rule-based (and later ML-assisted)
  recommendation logic, built entirely in your own Python — no
  external AI frameworks, per project constraints.
