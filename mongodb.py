import os
import json
from datetime import datetime

try:
    from pymongo import MongoClient
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

class MongoManager:
    """
    MongoDB Integration for CyberTwin with automatic local JSON persistence fallback.
    Collections managed:
    - assets
    - vulnerabilities
    - scan_history
    - risk_history
    - alerts
    - training_history
    """

    def __init__(self, uri="mongodb://localhost:27017/", db_name="cybertwin_db"):
        self.uri = uri
        self.db_name = db_name
        self.use_mongo = False
        self.client = None
        self.db = None

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.fallback_dir = os.path.join(base_dir, "data")
        os.makedirs(self.fallback_dir, exist_ok=True)
        self.fallback_file = os.path.join(self.fallback_dir, "history_store.json")

        if PYMONGO_AVAILABLE:
            try:
                self.client = MongoClient(self.uri, serverSelectionTimeoutMS=1500)
                self.client.admin.command('ping')
                self.db = self.client[self.db_name]
                self.use_mongo = True
            except Exception:
                self.use_mongo = False

        if not self.use_mongo:
            self._init_fallback_store()

    def _init_fallback_store(self):
        """Initializes local JSON store if MongoDB is offline."""
        if not os.path.exists(self.fallback_file):
            default_data = {
                "scan_history": [],
                "risk_history": [],
                "alerts": [],
                "training_history": []
            }
            with open(self.fallback_file, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=2)

    def _load_fallback(self):
        if os.path.exists(self.fallback_file):
            try:
                with open(self.fallback_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "training_history" not in data:
                        data["training_history"] = []
                    return data
            except Exception:
                pass
        return {"scan_history": [], "risk_history": [], "alerts": [], "training_history": []}

    def _save_fallback(self, data):
        try:
            with open(self.fallback_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def save_scan_snapshot(self, twin_state, changes, alerts):
        """Saves a scan snapshot to MongoDB or local fallback JSON."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        avg_risk = round(sum([a.get("risk_score", 0.0) for a in twin_state.get("assets", [])]) / max(len(twin_state.get("assets", [])), 1), 1)

        snapshot = {
            "timestamp": timestamp,
            "asset_count": len(twin_state.get("assets", [])),
            "open_ports_count": len(twin_state.get("services", [])),
            "vulnerabilities_count": len(twin_state.get("vulnerabilities", [])),
            "avg_risk_score": avg_risk,
            "assets": twin_state.get("assets", []),
            "changes": changes,
            "alerts_count": len(alerts)
        }

        risk_entry = {
            "timestamp": timestamp,
            "avg_risk_score": avg_risk,
            "vulnerabilities_count": len(twin_state.get("vulnerabilities", [])),
            "asset_count": len(twin_state.get("assets", [])),
            "critical_assets": len([a for a in twin_state.get("assets", []) if a.get("risk_level") in ["Critical", "High"]])
        }

        if self.use_mongo:
            try:
                self.db["scan_history"].insert_one(snapshot)
                self.db["risk_history"].insert_one(risk_entry)
                if alerts:
                    self.db["alerts"].insert_many([{"timestamp": timestamp, **a} for a in alerts])
                return True
            except Exception:
                pass

        store = self._load_fallback()
        store["scan_history"].append(snapshot)
        store["risk_history"].append(risk_entry)
        for a in alerts:
            store["alerts"].append({"timestamp": timestamp, **a})
        self._save_fallback(store)
        return False

    def save_training_run(self, run_metadata):
        """Saves an AI Q-learning training run result."""
        if self.use_mongo:
            try:
                self.db["training_history"].insert_one(run_metadata)
                return True
            except Exception:
                pass

        store = self._load_fallback()
        store["training_history"].append(run_metadata)
        self._save_fallback(store)
        return False

    def get_scan_history(self):
        """Retrieves past scan snapshots."""
        if self.use_mongo:
            try:
                records = list(self.db["scan_history"].find({}, {"_id": 0}).sort("timestamp", -1))
                if records:
                    return records
            except Exception:
                pass
        store = self._load_fallback()
        return sorted(store.get("scan_history", []), key=lambda x: x.get("timestamp", ""), reverse=True)

    def get_risk_history(self):
        """Retrieves risk trend records."""
        if self.use_mongo:
            try:
                records = list(self.db["risk_history"].find({}, {"_id": 0}).sort("timestamp", 1))
                if records:
                    return records
            except Exception:
                pass
        store = self._load_fallback()
        return sorted(store.get("risk_history", []), key=lambda x: x.get("timestamp", ""))

    def get_alerts(self):
        """Retrieves all generated system alerts."""
        if self.use_mongo:
            try:
                records = list(self.db["alerts"].find({}, {"_id": 0}).sort("timestamp", -1))
                if records:
                    return records
            except Exception:
                pass
        store = self._load_fallback()
        return sorted(store.get("alerts", []), key=lambda x: x.get("timestamp", ""), reverse=True)

    def get_training_history(self):
        """Retrieves past AI agent training runs."""
        if self.use_mongo:
            try:
                records = list(self.db["training_history"].find({}, {"_id": 0}).sort("timestamp", -1))
                if records:
                    return records
            except Exception:
                pass
        store = self._load_fallback()
        return sorted(store.get("training_history", []), key=lambda x: x.get("timestamp", ""), reverse=True)
