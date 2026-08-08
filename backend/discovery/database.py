"""
database.py (Discovery Engine)
===============================
RESPONSIBILITY: Save parsed device dictionaries into MongoDB.
Nothing else.

This file does NOT run scans and does NOT parse XML. It receives
already-clean dictionaries (from parser.py) and stores them.

IMPORTANT DESIGN NOTE (read this so the two-stage storage makes sense):
    This file writes RAW discovery snapshots into the `assets`
    collection -- exactly what Nmap found, nothing more.

    Separately, backend/twin/twin_manager.py ALSO writes to the
    `assets` collection, but with the richer Digital Twin schema
    (risk_score, vulnerabilities, last_updated, etc.), built FROM
    these raw dictionaries.

    So the flow is:
        scanner -> parser -> database.py (raw save)
                                  |
                                  v
                          twin_manager.py (converts raw dict -> Asset,
                                            enriches it, re-saves it)

    This file's raw save happens first and is mainly useful for
    debugging / verifying what Nmap actually returned, independent of
    any twin logic. The Twin Manager's save is what your dashboard
    and detection logic will actually read from later.
"""

from typing import List
from backend.database.mongodb import MongoDBHandler


def save_devices(devices: List[dict], db_handler: MongoDBHandler = None) -> int:
    """
    Save a list of parsed device dictionaries into the `assets`
    collection as raw discovery data.

    Args:
        devices: list of dicts, as returned by parser.parse_scan()
        db_handler: an existing MongoDBHandler instance to reuse.
                    If None, a new one is created (useful for quick
                    scripts/tests, but in the main app you should
                    always pass in a shared handler).

    Returns:
        The number of devices saved.

    Uses upsert (update-or-insert) keyed on ip_address, so re-running
    a scan on the same network updates existing records instead of
    creating duplicates.
    """
    handler = db_handler or MongoDBHandler()

    saved_count = 0
    for device in devices:
        query = {"ip_address": device["ip_address"]}
        handler.upsert_one("assets", query, device)
        saved_count += 1

    print(f"[discovery.database] Saved {saved_count} raw device(s) to 'assets' collection.")
    return saved_count
