"""
digital_twin.py
================
This module IS the Digital Twin.

Design rule for the whole project:
    -> No other file is allowed to talk to the `devices` MongoDB
       collection directly. They must go through this class.
    This keeps the project modular: if you ever swap MongoDB for
    something else, only this file changes.

A "digital twin" here simply means:
    a live, continuously-updated software representation of the
    real (or simulated) network devices.
"""

from datetime import datetime
from pymongo import MongoClient


class DigitalTwin:
    """
    Represents the whole network as a collection of device documents
    stored in MongoDB. Provides CRUD operations + a simple risk score.
    """

    def __init__(self, mongo_uri="mongodb://localhost:27017/", db_name="cybertwin_db"):
        # We connect once when the object is created, and reuse the
        # connection for every operation (this is the recommended
        # pattern for pymongo -- don't reconnect per call).
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.devices = self.db["devices"]

    # ------------------------------------------------------------------
    # CREATE / UPDATE
    # ------------------------------------------------------------------
    def add_device(self, device: dict):
        """
        Add a new device to the twin, OR update it if it already exists.

        We use `update_one(..., upsert=True)` instead of `insert_one`
        on purpose: in a real network, "adding a device" and
        "re-syncing an existing device's state" should behave the
        same way from the twin's perspective.
        """
        device = device.copy()  # never mutate the caller's dict
        device["last_updated"] = datetime.now().isoformat()

        # Risk score is always recalculated on save, so it can never
        # go stale compared to the device's current attributes.
        device["risk_score"] = self.calculate_risk_score(device)

        device_id = device["_id"]
        self.devices.update_one(
            {"_id": device_id},
            {"$set": device},
            upsert=True
        )
        return device

    def update_device(self, device_id: str, updates: dict):
        """
        Partially update a device (e.g. patch_status changed,
        a new open port detected, status went offline, etc.)
        """
        updates = updates.copy()
        updates["last_updated"] = datetime.now().isoformat()

        # Recalculate risk using the MERGED document (old + new fields),
        # not just the partial update, because risk depends on fields
        # that might not be present in `updates`.
        existing = self.devices.find_one({"_id": device_id})
        if existing is None:
            raise ValueError(f"Device '{device_id}' does not exist. Use add_device() first.")

        merged = {**existing, **updates}
        updates["risk_score"] = self.calculate_risk_score(merged)

        self.devices.update_one({"_id": device_id}, {"$set": updates})
        return self.devices.find_one({"_id": device_id})

    # ------------------------------------------------------------------
    # DELETE
    # ------------------------------------------------------------------
    def remove_device(self, device_id: str):
        """Remove a device from the twin entirely (e.g. decommissioned)."""
        result = self.devices.delete_one({"_id": device_id})
        return result.deleted_count == 1

    # ------------------------------------------------------------------
    # READ
    # ------------------------------------------------------------------
    def get_device(self, device_id: str):
        return self.devices.find_one({"_id": device_id})

    def get_all_devices(self):
        return list(self.devices.find())

    # ------------------------------------------------------------------
    # RISK SCORING
    # ------------------------------------------------------------------
    def calculate_risk_score(self, device: dict) -> int:
        """
        A SIMPLE, EXPLAINABLE risk score from 0 to 100.

        This is NOT machine learning -- it's a weighted rule set,
        exactly like a checklist a junior security analyst would use.
        We start here so you (and your reviewers) can see exactly
        WHY a device got a certain score. ML comes later (Week 3+)
        and can be compared against this baseline.

        Rules (weights are intentionally simple round numbers):
            +20  if criticality is "high"
            +10  if criticality is "medium"
            +25  if patch_status is "outdated"
            +5   for every open port beyond the first 2
                 (more open ports = larger attack surface)
            +15  if status is "compromised"
        Score is capped at 100.
        """
        score = 0

        criticality = device.get("criticality", "low")
        if criticality == "high":
            score += 20
        elif criticality == "medium":
            score += 10

        if device.get("patch_status") == "outdated":
            score += 25

        open_ports = device.get("open_ports", [])
        extra_ports = max(0, len(open_ports) - 2)
        score += extra_ports * 5

        if device.get("status") == "compromised":
            score += 15

        return min(score, 100)

    def close(self):
        """Close the MongoDB connection cleanly."""
        self.client.close()
