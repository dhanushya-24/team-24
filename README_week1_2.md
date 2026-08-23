# CyberTwin AI — Week 1 & 2 Summary

## How to run everything (order matters)

1. Install MongoDB locally and make sure it's running on `localhost:27017`.
2. `pip install -r requirements.txt`
3. Seed the twin:
   ```
   cd digital_twin
   python sample_data.py
   ```
4. Generate some test events:
   ```
   cd ../agent
   python simulate_events.py
   ```
5. Run the agent for a few cycles (or just once):
   ```
   python ai_agent.py
   ```
   (It will pick up the events you just inserted, analyze them, and log recommendations. Ctrl+C to stop.)
6. Launch the dashboard:
   ```
   cd ../dashboard
   streamlit run app.py
   ```

---

## What to demonstrate in your first project review

1. **The Digital Twin concept** — show `devices` collection in MongoDB
   (or via the dashboard table) and explain that this is a *live
   representation* of the network, not a static diagram.

2. **Explainable risk scoring** — pick one device (e.g. `srv-01`,
   outdated + high criticality) and manually walk through
   `calculate_risk_score()` line by line, showing how its score was
   derived. This proves you understand the logic, not just that code runs.

3. **The AI Agent loop, live** — run `simulate_events.py`, then run
   the agent, then show the new row appear in `agent_logs` and on the
   dashboard. Narrate the loop out loud: collect → analyze → risk →
   recommend → log → dashboard.

4. **Why there's no ML yet, on purpose** — be upfront that Weeks 1-2
   deliberately used only rule-based logic so you could design and
   defend the *reasoning* before treating detection as a black box.
   This is a strength to state, not something to hide.

5. **Modularity** — show that `decision_logic.py` is separate from
   `ai_agent.py`, and explain that this is exactly the seam where
   ML will be inserted later without changing the orchestrator.

---

## What is intentionally NOT built yet (future weeks)

- **Machine learning detection** (Step 9 was explicit: rules only for
  now). Coming: train a classifier (e.g. `RandomForestClassifier` from
  scikit-learn) on labeled event data to replace/augment
  `decision_logic.analyze()`.
- **Real data collection** — Nmap/Hydra/Metasploit are in your stack
  but not yet wired in. `collect_network_information()` currently
  reads simulated events from MongoDB; it needs a real capture layer.
- **VirtualBox + Kali Linux lab** — no actual attack simulation
  environment has been built yet; Week 1-2 used synthetic events only.
- **Flask API layer** — Flask is installed but unused so far. Future
  weeks will expose the agent/twin over REST endpoints so the
  dashboard (and potentially other tools) don't need direct Mongo access.
- **Automated defensive actions** — the agent currently only
  *recommends*; it never blocks IPs or isolates devices automatically.
  This is a deliberate safety boundary for now, to be revisited later
  with proper safeguards.
- **Authentication/authorization** on the dashboard and any future API.
- **Historical analytics/trends** (e.g. risk score over time, charts) —
  Week 1-2 only shows current state and the latest 20 logs.
- **Automated tests** (unit tests for `decision_logic.py` would be a
  natural next addition since those functions are pure and easy to test).

Keep this list visible in your report — reviewers respond well to a
clear, honest scope boundary rather than a project that pretends to
be more finished than it is.
