"""
CyberTwinAI Flask Backend

Current modules:
    Module 1 - Discovery
    Module 2 - Digital Twin
    Module 3 - Vulnerability Assessment
    Module 4 - Risk Assessment

Module 5 is the Streamlit dashboard.

Module 6 is NOT connected yet.
"""

from flask import Flask, jsonify, request

from mongodb import MongoDBHandler
from backend.discovery.main import discover
from backend.twin.twin_manager import TwinManager


# ---------------------------------------------------------
# Flask application
# ---------------------------------------------------------

app = Flask(__name__)


# ---------------------------------------------------------
# Shared MongoDB connection
# ---------------------------------------------------------

db_handler = MongoDBHandler()

twin_manager = TwinManager(db_handler)


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Check whether the Flask backend is running."""
    return jsonify({
        "status": "ok"
    })


# ---------------------------------------------------------
# Scan
# ---------------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():
    """
    Run Discovery -> Digital Twin.

    Expected JSON:
        {
            "target": "192.168.56.101"
        }
    """

    data = request.get_json(silent=True) or {}

    target = data.get("target")

    if not target:
        return jsonify({
            "error": "Missing 'target' in request body"
        }), 400

    try:
        # Module 1
        raw_devices = discover(
            target,
            db_handler=db_handler
        )

        # Module 2
        assets = twin_manager.sync_from_discovery(
            raw_devices
        )

        return jsonify({
            "target": target,
            "devices_found": len(assets),
            "assets": [
                asset.to_dict()
                for asset in assets
            ]
        })

    except Exception as exc:
        app.logger.exception("Scan failed")

        return jsonify({
            "error": "Scan failed",
            "details": str(exc)
        }), 500


# ---------------------------------------------------------
# All assets
# ---------------------------------------------------------

@app.route("/assets", methods=["GET"])
def get_assets():
    """Return all Digital Twin assets."""

    try:
        assets = twin_manager.load_all_assets()

        return jsonify([
            asset.to_dict()
            for asset in assets
        ])

    except Exception as exc:
        app.logger.exception("Failed to load assets")

        return jsonify({
            "error": "Failed to load assets",
            "details": str(exc)
        }), 500


# ---------------------------------------------------------
# Single asset
# ---------------------------------------------------------

@app.route("/assets/<asset_id>", methods=["GET"])
def get_single_asset(asset_id):
    """Return a single asset."""

    try:
        doc = db_handler.find_one(
            "assets",
            {
                "asset_id": asset_id
            }
        )

        if doc is None:
            return jsonify({
                "error": "Asset not found"
            }), 404

        return jsonify(doc)

    except Exception as exc:
        app.logger.exception("Failed to load asset")

        return jsonify({
            "error": "Failed to load asset",
            "details": str(exc)
        }), 500


# ---------------------------------------------------------
# Start server
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )