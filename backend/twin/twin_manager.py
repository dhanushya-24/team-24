"""
twin_manager.py
================
RESPONSIBILITY: Turn raw discovery data into Digital Twin state, and
keep that state in sync with reality over time.

This is the "brain" of Module 2. It:
    - Creates Asset objects from raw discovery dictionaries
    - Decides whether a discovered device is NEW or EXISTING
    - Updates existing assets when a re-scan shows changes
    - Marks assets OFFLINE if they disappear from a scan
      (never deletes them automatically -- see mark_offline_assets)
    - Calculates a simple, explainable risk score per asset
    - Saves/loads the twin's state to/from MongoDB

Design rule: this file is the ONLY place that decides how raw
discovery dicts become Asset objects. scanner.py, parser.py, and
database.py in the Discovery Engine never know Asset even exists --
that keeps Module 1 and Module 2 cleanly separated.
"""

from typing import List
from backend.twin.asset import Asset
from backend.twin.service import Service
from backend.database.mongodb import MongoDBHandler


class TwinManager:
    """
    Owns the Digital Twin's lifecycle: create, update, mark-offline,
    save, load. One TwinManager per running application is enough --
    it holds no per-scan state itself, it just operates on MongoDB.
    """

    def __init__(self, db_handler: MongoDBHandler = None):
        self.db = db_handler or MongoDBHandler()

    # ------------------------------------------------------------------
    # CREATING ASSETS FROM RAW DISCOVERY DATA
    # ------------------------------------------------------------------
    def create_asset(self, raw_device: dict) -> Asset:
        """
        Build a brand-new Asset object from a raw discovery dictionary
        (the shape returned by backend/discovery/parser.py).

        We use the IP address as the asset_id: on a single lab/home
        network, IPs are unique and stable enough for a student
        prototype, and it keeps lookups simple (no separate ID
        generator needed).
        """
        asset = Asset(
            asset_id=raw_device["ip_address"],
            hostname=raw_device.get("hostname"),
            ip_address=raw_device["ip_address"],
            mac_address=raw_device.get("mac_address"),
            operating_system=raw_device.get("operating_system", "Unknown"),
            device_type=self._guess_device_type(raw_device),
            status="online",
            ports=raw_device.get("ports", []),
            services=raw_device.get("services", []),
            vulnerabilities=[],   # populated later by a future Threat Detection module
        )
        asset.risk_score = self.calculate_risk_score(asset)
        return asset

    def _guess_device_type(self, raw_device: dict) -> str:
        """
        Very simple, explainable heuristic to label a device type
        based on which ports are open. This is NOT machine learning --
        it's a lookup table, kept deliberately simple so you can
        explain every branch in a review.

        This is a best-effort label, not a hard classification --
        later modules can refine it.
        """
        ports = set(raw_device.get("ports", []))

        if {80, 443}.intersection(ports) or {3306, 5432}.intersection(ports):
            return "server"
        if 3389 in ports or 445 in ports:
            return "workstation"
        if {23, 179}.intersection(ports):  # telnet/BGP -> typical on network gear
            return "router"
        return "unknown"

    # ------------------------------------------------------------------
    # RISK SCORING (same simple, explainable approach as Week 1-2)
    # ------------------------------------------------------------------
    def calculate_risk_score(self, asset: Asset) -> int:
        """
        A simple, explainable 0-100 risk score based on what the
        Discovery Engine actually found. No ML -- plain weighted
        rules, so you can defend every point in a review.

        Rules:
            +5   per open port beyond the first 2 (bigger attack surface)
            +15  if operating_system is "Unknown" (can't assess patch level)
            +10  if device_type is "server" (higher-value target)
            +20  if status is "offline" and it previously had open
                 ports -- an unexpectedly vanished device is itself
                 a signal worth flagging, not just "no risk"

        Capped at 100.
        """
        score = 0

        extra_ports = max(0, len(asset.ports) - 2)
        score += extra_ports * 5

        if asset.operating_system == "Unknown":
            score += 15

        if asset.device_type == "server":
            score += 10

        if asset.status == "offline" and len(asset.ports) > 0:
            score += 20

        return min(score, 100)

    # ------------------------------------------------------------------
    # ADD OR UPDATE (the core sync logic you asked for)
    # ------------------------------------------------------------------
    def add_or_update_asset(self, raw_device: dict) -> Asset:
        """
        Core sync rule:
            - If this IP is NOT already in the twin -> create + save it (NEW)
            - If this IP IS already in the twin -> refresh its fields (UPDATE)

        Either way, the asset ends up saved in MongoDB with status="online"
        (because we only call this for devices that WERE found in the
        current scan).
        """
        existing_doc = self.db.find_one("assets", {"asset_id": raw_device["ip_address"]})

        if existing_doc is None:
            # NEW asset
            asset = self.create_asset(raw_device)
            print(f"[twin_manager] NEW asset discovered: {asset.asset_id} ({asset.hostname})")
        else:
            # EXISTING asset -> update its fields with the latest scan data
            asset = Asset.from_dict(existing_doc)
            asset.hostname = raw_device.get("hostname") or asset.hostname
            asset.mac_address = raw_device.get("mac_address") or asset.mac_address
            asset.operating_system = raw_device.get("operating_system", asset.operating_system)
            asset.device_type = self._guess_device_type(raw_device)
            asset.status = "online"
            asset.ports = raw_device.get("ports", [])
            asset.services = raw_device.get("services", [])
            asset.risk_score = self.calculate_risk_score(asset)
            print(f"[twin_manager] UPDATED existing asset: {asset.asset_id}")

        self.save_asset(asset)
        return asset

    # ------------------------------------------------------------------
    # MARKING DISAPPEARED DEVICES OFFLINE (never auto-delete)
    # ------------------------------------------------------------------
    def mark_offline_assets(self, current_scan_ips: List[str]) -> int:
        """
        Any asset currently stored as "online" whose IP did NOT appear
        in the latest scan gets marked status="offline".

        We deliberately do NOT delete these documents. A device that
        didn't respond to this scan might be temporarily powered off,
        on a different subnet right now, or blocking ping -- deleting
        its history would throw away useful security context (e.g.
        "this server went offline right after the port scan we
        detected" is a meaningful correlation for later modules).

        Returns the number of assets marked offline.
        """
        online_assets = self.db.find_many("assets", {"status": "online"})
        marked_count = 0

        for doc in online_assets:
            if doc["ip_address"] not in current_scan_ips:
                asset = Asset.from_dict(doc)
                asset.status = "offline"
                asset.risk_score = self.calculate_risk_score(asset)
                self.save_asset(asset)
                marked_count += 1
                print(f"[twin_manager] Asset marked OFFLINE: {asset.asset_id}")

        return marked_count

    # ------------------------------------------------------------------
    # FULL SYNC (what app.py / discovery.main call after a scan)
    # ------------------------------------------------------------------
    def sync_from_discovery(self, raw_devices: List[dict]) -> List[Asset]:
        """
        The main entry point tying Module 1 output into Module 2 state.

        Steps:
            1. For every device found in this scan -> add_or_update_asset()
            2. For every PREVIOUSLY known device NOT in this scan ->
               mark_offline_assets()

        Returns the list of Asset objects that were found in THIS scan
        (online devices only -- offline ones are updated in the
        database but not returned here, since the caller is usually
        reporting "what did we just find").
        """
        updated_assets = []
        current_ips = []

        for raw_device in raw_devices:
            asset = self.add_or_update_asset(raw_device)
            updated_assets.append(asset)
            current_ips.append(raw_device["ip_address"])

        offline_count = self.mark_offline_assets(current_ips)
        print(f"[twin_manager] Sync complete. "
              f"{len(updated_assets)} online, {offline_count} newly offline.")

        return updated_assets

    # ------------------------------------------------------------------
    # SAVE / LOAD
    # ------------------------------------------------------------------
    def save_asset(self, asset: Asset):
        """
        Persist a single Asset object into the `assets` collection, AND
        mirror its services into the separate `services` collection.

        Why both? The `assets` document keeps services embedded so an
        Asset is self-contained and easy to read in one query (e.g.
        for the dashboard). The standalone `services` collection lets
        future modules (like Threat Detection) query "every device
        running vsftpd 2.3.4 across the whole network" without having
        to scan through every asset document individually.
        """
        self.db.upsert_one("assets", {"asset_id": asset.asset_id}, asset.to_dict())
        self._save_services(asset)

    def _save_services(self, asset: Asset):
        """
        Mirror this asset's services into the `services` collection.
        Each service document is keyed by (asset_id, port, protocol)
        so re-saving the same asset updates existing service records
        instead of duplicating them.
        """
        for service_dict in asset.services:
            service = Service.from_dict(service_dict)
            query = {
                "asset_id": asset.asset_id,
                "port": service.port,
                "protocol": service.protocol,
            }
            document = {**service.to_dict(), "asset_id": asset.asset_id}
            self.db.upsert_one("services", query, document)

    def load_all_assets(self) -> List[Asset]:
        """Load the entire current Digital Twin state from MongoDB."""
        docs = self.db.find_many("assets")
        return [Asset.from_dict(doc) for doc in docs]

    def delete_asset(self, asset_id: str) -> bool:
        """
        Manually remove an asset from the twin.

        This is intentionally NEVER called automatically anywhere in
        this project (see mark_offline_assets docstring). It exists
        only for deliberate manual cleanup, e.g. if you added a test
        device by mistake.
        """
        deleted_count = self.db.delete_one("assets", {"asset_id": asset_id})
        return deleted_count == 1
