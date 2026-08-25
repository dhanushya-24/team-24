"""
app.py
======
Root entry point of CyberTwinAI. Exposes the Discovery Engine,
Digital Twin, and Knowledge Graph as a small Flask API.

This file contains NO scanning, parsing, twin, vulnerability, risk,
or graph-construction logic itself -- it only calls into the
existing backend modules, exactly like each module's own main.py /
manager only orchestrates its own sub-steps.
"""

from flask import Flask, jsonify, request

from backend.database.mongodb import MongoDBHandler
from backend.discovery.main import discover
from backend.twin.twin_manager import TwinManager
from backend.knowledge_graph.graph_manager import KnowledgeGraphManager, graph_to_dict
from backend.attack_paths.attack_path_analyzer import AttackPathAnalyzer
from backend.attack_paths.attack_path_queries import get_path_by_id, summarize_paths

app = Flask(__name__)

# One shared MongoDB connection for the whole running app, reused by
# the Discovery Engine, the Twin Manager, and the Knowledge Graph
# Manager (see mongodb.py docstring for why we centralize this).
db_handler = MongoDBHandler()
twin_manager = TwinManager(db_handler)
knowledge_graph_manager = KnowledgeGraphManager(db_handler, twin_manager)


@app.route("/health", methods=["GET"])
def health():
    """Simple check that the server is up."""
    return jsonify({"status": "ok"})


@app.route("/scan", methods=["POST"])
def scan():
    """
    Trigger a full pipeline run:
        Discovery Engine (scan + parse + raw store)
            -> Twin Manager (sync into Digital Twin state)

    Expects JSON body: {"target": "192.168.56.101"}
    (an IP, hostname, or CIDR range on YOUR OWN lab network)

    Returns the list of assets found in this scan, with their
    calculated risk scores.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target")

    if not target:
        return jsonify({"error": "Missing 'target' in request body"}), 400

    raw_devices = discover(target, db_handler=db_handler)
    assets = twin_manager.sync_from_discovery(raw_devices)

    return jsonify({
        "target": target,
        "devices_found": len(assets),
        "assets": [asset.to_dict() for asset in assets],
    })


@app.route("/assets", methods=["GET"])
def get_assets():
    """
    Return the entire current Digital Twin state -- every asset
    currently known, online or offline.
    """
    assets = twin_manager.load_all_assets()
    return jsonify([asset.to_dict() for asset in assets])


@app.route("/assets/<asset_id>", methods=["GET"])
def get_single_asset(asset_id):
    """Return a single asset by its ID (its IP address)."""
    doc = db_handler.find_one("assets", {"asset_id": asset_id})
    if doc is None:
        return jsonify({"error": "Asset not found"}), 404
    return jsonify(doc)


@app.route("/knowledge-graph", methods=["GET"])
def get_knowledge_graph():
    """
    Return the current Knowledge Graph (Module 6), built fresh from
    the current Digital Twin state, as a plain JSON-serializable
    structure:
        {"nodes": [...], "edges": [...]}

    This is READ-ONLY: it builds the graph in memory from existing
    asset data and returns it -- it does not perform attack-path
    analysis, simulation, or AI reasoning, and it does not persist
    anything unless save_graph() is called elsewhere.
    """
    graph = knowledge_graph_manager.build_graph()
    return jsonify(graph_to_dict(graph))


@app.route("/attack-paths", methods=["GET"])
def get_attack_paths():
    """
    Module 7: return potential attack paths through the current
    Knowledge Graph, ranked by risk_score (highest first).

    Optional query parameters:
        entry       - restrict to this entry asset_id only
        target      - restrict to this target asset_id only
        max_length  - maximum hops per path (default 6)
        top_n       - maximum number of paths returned (default 10)

    This is READ-ONLY ANALYSIS: it builds the Knowledge Graph fresh
    from the current Digital Twin state and reasons over it. It never
    performs exploitation and never executes anything on a real
    machine -- see backend/attack_paths for details.
    """
    graph = knowledge_graph_manager.build_graph()
    analyzer = AttackPathAnalyzer(graph)

    paths = analyzer.find_attack_paths(
        entry_asset_id=request.args.get("entry"),
        target_asset_id=request.args.get("target"),
        max_path_length=request.args.get("max_length", default=6, type=int),
        top_n=request.args.get("top_n", default=10, type=int),
    )

    return jsonify({
        "paths": [path.to_dict() for path in paths],
        "summary": summarize_paths(paths),
    })


@app.route("/attack-paths/<path_id>", methods=["GET"])
def get_single_attack_path(path_id):
    """Return a single previously-discoverable attack path by its path_id."""
    graph = knowledge_graph_manager.build_graph()
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths(top_n=50)

    path = get_path_by_id(paths, path_id)
    if path is None:
        return jsonify({"error": "Attack path not found"}), 404
    return jsonify(path.to_dict())


@app.route("/attack-paths/summary", methods=["GET"])
def get_attack_paths_summary():
    """Return only the summary (counts, severity breakdown, highest-risk
    path) without the full path details -- useful for dashboard KPI cards."""
    graph = knowledge_graph_manager.build_graph()
    analyzer = AttackPathAnalyzer(graph)
    paths = analyzer.find_attack_paths()
    return jsonify(summarize_paths(paths))


if __name__ == "__main__":
    # debug=True gives auto-reload + readable error pages while
    # developing. Turn this off before any real deployment.
    app.run(debug=True, port=5000)
