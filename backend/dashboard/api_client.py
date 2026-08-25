"""
api_client.py
=============
RESPONSIBILITY: All HTTP communication with the existing Flask backend
(app.py), plus a single read-only MongoDB connectivity check for the
Settings page.

This file NEVER modifies backend logic, NEVER writes to MongoDB, and
NEVER calls any endpoint other than the ones that already exist:
    GET  /health
    POST /scan
    GET  /assets
    GET  /assets/<asset_id>
    GET  /knowledge-graph
    GET  /attack-paths

Every asset dictionary returned by /assets and /assets/<asset_id>
already contains ports, services, vulnerabilities, risk_score,
risk_level, status, and last_updated (see backend/twin/asset.py
to_dict()). The dashboard builds every page from that single source
of data -- there is no need to query MongoDB directly for services or
vulnerabilities, which keeps this module a pure visualization layer.
"""

import os
from typing import List, Optional

import requests

# Backend Flask URL. Overridable via environment variable so the
# dashboard can point at a different host/port without code changes.
DEFAULT_API_URL = os.environ.get("CYBERTWIN_API_URL", "http://127.0.0.1:5000")

# MongoDB URI, used ONLY for a read-only connectivity ping in the
# Settings page (see check_mongo_status below). No queries are ever
# issued against this connection.
DEFAULT_MONGO_URI = os.environ.get("CYBERTWIN_MONGO_URI", "mongodb://localhost:27017/")

# Default timeout (seconds) for every HTTP request to the Flask API.
REQUEST_TIMEOUT = 10


class ApiClient:
    """
    Thin wrapper around the existing Flask REST API. One instance is
    created per Streamlit session and reused across pages.
    """

    def __init__(self, base_url: str = DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    def check_health(self) -> bool:
        """
        Call GET /health. Returns True if the Flask backend responds
        with a 200 status, False otherwise (backend down, network
        error, timeout, etc.). Never raises -- callers should be able
        to check backend status without a try/except of their own.
        """
        try:
            response = requests.get(f"{self.base_url}/health", timeout=REQUEST_TIMEOUT)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    # ------------------------------------------------------------------
    def trigger_scan(self, target: str) -> dict:
        """
        Call POST /scan with {"target": target}.

        Returns the parsed JSON response on success:
            {"target": ..., "devices_found": ..., "assets": [...]}

        On failure, returns:
            {"error": "<message>"}
        so callers can always safely read result.get("error") without
        an extra try/except at the call site.
        """
        try:
            response = requests.post(
                f"{self.base_url}/scan",
                json={"target": target},
                timeout=180,  # scans can legitimately take a while
            )
            if response.status_code != 200:
                return {"error": response.json().get("error", f"HTTP {response.status_code}")}
            return response.json()
        except requests.exceptions.RequestException as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    def get_all_assets(self) -> List[dict]:
        """
        Call GET /assets. Returns a list of asset dictionaries (each
        matching Asset.to_dict() -- see backend/twin/asset.py), or an
        empty list if the backend is unreachable or returns an error.
        """
        try:
            response = requests.get(f"{self.base_url}/assets", timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                return []
            return response.json()
        except requests.exceptions.RequestException:
            return []

    # ------------------------------------------------------------------
    def get_asset(self, asset_id: str) -> Optional[dict]:
        """
        Call GET /assets/<asset_id>. Returns the asset dictionary, or
        None if it doesn't exist or the backend is unreachable.
        """
        try:
            response = requests.get(f"{self.base_url}/assets/{asset_id}", timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                return None
            return response.json()
        except requests.exceptions.RequestException:
            return None

    # ------------------------------------------------------------------
    def get_knowledge_graph(self) -> Optional[dict]:
        """
        Call GET /knowledge-graph (Module 6). Returns
        {"nodes": [...], "edges": [...]}, or None if the endpoint is
        unreachable or unavailable (e.g. an older backend that
        doesn't have Module 6 yet) -- callers should treat None as
        "graph not available" and fall back gracefully.
        """
        try:
            response = requests.get(f"{self.base_url}/knowledge-graph", timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                return None
            return response.json()
        except requests.exceptions.RequestException:
            return None

    # ------------------------------------------------------------------
    def get_attack_paths(self) -> Optional[dict]:
        """
        Call GET /attack-paths (Module 7). Returns
        {"paths": [...], "summary": {...}}, or None if the endpoint is
        unreachable or unavailable (e.g. an older backend that
        doesn't have Module 7 yet) -- callers should treat None as
        "not available" and fall back gracefully, exactly like
        get_knowledge_graph() above.
        """
        try:
            response = requests.get(f"{self.base_url}/attack-paths", timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                return None
            return response.json()
        except requests.exceptions.RequestException:
            return None


def check_mongo_status(mongo_uri: str = DEFAULT_MONGO_URI) -> bool:
    """
    Read-only MongoDB connectivity ping for the Settings page.

    This does NOT query any collection -- it only asks the MongoDB
    server to confirm it is reachable, using the standard `ping`
    admin command. No data is read or written.

    Returns True if MongoDB responds, False otherwise.
    """
    try:
        # Imported locally so the rest of the dashboard has no hard
        # dependency on pymongo being importable if this check is
        # never used (keeps import errors isolated to this function).
        from pymongo import MongoClient

        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        client.close()
        return True
    except Exception:
        return False
