"""
ai_agent.py
===========
The ORCHESTRATOR of your own AI Security Agent.

This file implements exactly the loop you specified:

    while True:
        collect_network_information()
        analyze()
        if suspicious:
            calculate_risk()
            recommend_defense()
        save_log()
        update_dashboard()

Design rule: this file does NOT contain any "reasoning". All the
if-else decision logic lives in decision_logic.py. This file's only
job is to fetch data, call the brain, and persist results. That
separation is what lets you swap in ML later (Week 3+) by changing
ONLY decision_logic.py, without touching this loop at all.
"""

import time
import uuid
from datetime import datetime
from pymongo import MongoClient

# Make the digital_twin module importable from a sibling folder
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "digital_twin"))
from digital_twin import DigitalTwin

import decision_logic


class AISecurityAgent:
    def __init__(self, mongo_uri="mongodb://localhost:27017/", db_name="cybertwin_db"):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.events = self.db["network_events"]
        self.logs = self.db["agent_logs"]

        # The agent uses the SAME Digital Twin class as everything else --
        # it never queries the `devices` collection directly.
        self.twin = DigitalTwin(mongo_uri, db_name)

    # ------------------------------------------------------------------
    def collect_network_information(self):
        """
        STEP 1 of the loop.

        Fetches the most recent network event that the agent has not
        processed yet. In Week 1-2 this reads from MongoDB, where
        events are inserted either manually (for testing) or by a
        simple simulator script. Later, this function is where a real
        packet sniffer / Nmap scan output would plug in -- the rest
        of the agent would not need to change.
        """
        unprocessed_event = self.events.find_one({"processed": {"$ne": True}})
        return unprocessed_event

    # ------------------------------------------------------------------
    def analyze(self, event):
        """STEP 2: delegate the 'is this suspicious?' judgment to decision_logic."""
        return decision_logic.analyze(event)

    # ------------------------------------------------------------------
    def calculate_risk(self, device, event):
        """STEP 3a: combine device risk + event severity."""
        device_risk = device.get("risk_score", 0) if device else 0
        return decision_logic.calculate_risk(device_risk, event)

    # ------------------------------------------------------------------
    def recommend_defense(self, event, risk_score):
        """STEP 3b: get a human-readable recommendation."""
        return decision_logic.recommend_defense(event, risk_score)

    # ------------------------------------------------------------------
    def save_log(self, event, risk_score, recommendation, suspicious):
        """
        STEP 4: persist the agent's decision.

        This is the single most important function for your project
        review -- it's the proof that "the agent observed, reasoned,
        and recommended", written down, timestamped, and queryable.
        """
        action_taken = decision_logic.decide_action_taken(risk_score)

        log_entry = {
            "_id": f"log-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now().isoformat(),
            "device_id": event.get("device_id"),
            "event_id": event.get("_id"),
            "suspicious": suspicious,
            "risk_score": risk_score,
            "recommendation": recommendation,
            "action_taken": action_taken,
        }
        self.logs.insert_one(log_entry)

        # Mark the event as processed so we don't analyze it again
        self.events.update_one({"_id": event["_id"]}, {"$set": {"processed": True}})

        return log_entry

    # ------------------------------------------------------------------
    def update_dashboard(self, log_entry):
        """
        STEP 5: notify/refresh the dashboard.

        In Week 1-2, Streamlit reads directly from MongoDB on each
        refresh, so this function currently just prints a confirmation.
        It exists as a clear extension point: later you could push a
        websocket event or Flask notification from here instead.
        """
        print(f"[dashboard] New log available: {log_entry['_id']} "
              f"(risk={log_entry['risk_score']}, suspicious={log_entry['suspicious']})")

    # ------------------------------------------------------------------
    def run_once(self):
        """
        Executes exactly ONE cycle of the loop. Useful for testing
        and for calling from Streamlit/Flask without blocking forever.
        Returns the log entry produced, or None if there was nothing
        to process.
        """
        event = self.collect_network_information()
        if event is None:
            return None  # nothing new to analyze

        suspicious = self.analyze(event)

        risk_score = 0
        recommendation = "No action needed -- traffic looks normal."

        if suspicious:
            device = self.twin.get_device(event.get("device_id"))
            risk_score = self.calculate_risk(device, event)
            recommendation = self.recommend_defense(event, risk_score)

        log_entry = self.save_log(event, risk_score, recommendation, suspicious)
        self.update_dashboard(log_entry)
        return log_entry

    # ------------------------------------------------------------------
    def run_forever(self, poll_interval_seconds=5):
        """
        The actual `while True` loop you asked for. Kept separate from
        run_once() so the dashboard/tests can call run_once() without
        starting an infinite loop.
        """
        print("AI Security Agent started. Press Ctrl+C to stop.")
        try:
            while True:
                self.run_once()
                time.sleep(poll_interval_seconds)
        except KeyboardInterrupt:
            print("Agent stopped by user.")
        finally:
            self.client.close()
            self.twin.close()


if __name__ == "__main__":
    agent = AISecurityAgent()
    agent.run_forever(poll_interval_seconds=5)
