"""
simulate_events.py
===================
A small helper -- NOT part of the agent itself -- that inserts fake
network events into MongoDB so you can test the agent without needing
Nmap/Hydra wired up yet (that's a later-week integration task).

Run this whenever you want to "trigger" the agent during a demo:
    python simulate_events.py
"""

import uuid
from datetime import datetime
from pymongo import MongoClient


def insert_event(device_id, event_type, source_ip, details, severity):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["cybertwin_db"]
    events = db["network_events"]

    event = {
        "_id": f"evt-{uuid.uuid4().hex[:8]}",
        "device_id": device_id,
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,   # port_scan | brute_force | unusual_traffic | login_attempt | normal
        "source_ip": source_ip,
        "details": details,
        "severity": severity,       # low | medium | high
        "processed": False,
    }
    events.insert_one(event)
    print(f"Inserted event {event['_id']} ({event_type}) for {device_id}")
    client.close()


if __name__ == "__main__":
    # A mix of normal and suspicious events for demo purposes
    insert_event("srv-01", "port_scan", "192.168.1.55", "15 ports scanned in 3 seconds", "high")
    insert_event("pc-02", "brute_force", "192.168.1.60", "12 failed RDP logins in 1 minute", "high")
    insert_event("srv-02", "normal", "192.168.1.20", "Regular HTTPS traffic", "low")
