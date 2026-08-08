# CyberTwin AI — SETUP GUIDE (Absolute Beginner Version)

This guide assumes:

- You have only extracted/opened the `cybertwin` folder in VS Code.
- Nothing else is installed yet.
- You are on **Windows** (most common setup alongside VirtualBox/Kali).
  If you're on Mac/Linux, small notes are added where commands differ.

Follow this top to bottom. Do not skip a step, even if it looks obvious.

---

## PART A: Install the software you need (one-time setup)

### A1. Install Python

1. Go to https://www.python.org/downloads/
2. Download **Python 3.12** (Windows installer).
3. Run the installer.
   ⚠️ **IMPORTANT:** On the first install screen, tick the checkbox
   **"Add python.exe to PATH"** at the bottom before clicking Install.
   This step is the #1 reason people get stuck later.
4. After install, verify it worked. Open VS Code, then open its
   built-in terminal:
   - Menu bar → **Terminal → New Terminal**
5. In that terminal, type:
   ```
   python --version
   ```
   You should see something like `Python 3.12.x`. If you instead see
   an error like "python is not recognized", Python didn't get added
   to PATH — reinstall and make sure to tick that checkbox.

### A2. Install MongoDB Community Server (this is your database)

1. Go to https://www.mongodb.com/try/download/community
2. Choose: Version = latest, Platform = Windows, Package = msi.
3. Download and run the installer.
4. During install, choose **"Complete"** setup type.
5. When asked, tick **"Install MongoDB as a Service"** (this is the
   default and correct choice — it means MongoDB will start
   automatically in the background, and you don't need to manually
   start a server every time).
6. You do NOT need MongoDB Compass for this project, but it's fine to
   install it too if the installer offers it — it's just a visual tool
   to peek inside your database later if you're curious.
7. Finish the installation.

### A3. Verify MongoDB is running

1. Press `Windows key`, type **Services**, open the Services app.
2. Scroll down and find **MongoDB Server (MongoDB)**.
3. Its "Status" column should say **Running**. If it doesn't,
   right-click it → **Start**.

You only need to do Part A once on your laptop, ever.

---

## PART B: Set up the project itself (do this once per project)

Open the `cybertwin` folder in VS Code (File → Open Folder → select it).
Open a terminal in VS Code: **Terminal → New Terminal**.

Make sure your terminal is sitting _inside_ the `cybertwin` folder.
You can check with:

```
dir
```

(Mac/Linux: `ls`) — you should see `requirements.txt`, `agent`, `digital_twin`, `dashboard`, `db`.

### B1. Create a virtual environment

A virtual environment is just an isolated box for this project's
Python packages, so they don't clash with anything else on your
computer.

```
python -m venv venv
```

This creates a new folder called `venv` inside your project. Nothing
visible happens yet — that's expected.

### B2. Activate the virtual environment

**Windows (PowerShell terminal, default in VS Code):**

```
venv\Scripts\activate
```

**Windows (if you get a "running scripts is disabled" error):**
Run this once, type `Y` if asked, then try activating again:

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**Mac/Linux:**

```
source venv/bin/activate
```

✅ You'll know it worked because your terminal prompt will now show
`(venv)` at the start of the line, like:

```
(venv) C:\Users\you\cybertwin>
```

You must do this activation step **every time** you open a new
terminal to work on this project.

### B3. Install the project's required packages

With `(venv)` showing in your terminal:

```
pip install -r requirements.txt
```

This will take a minute or two. It's downloading Flask, Streamlit,
pymongo, pandas, numpy, scikit-learn, python-dotenv — everything
listed in `requirements.txt`.

If it finishes with no red "ERROR" lines, you're done with setup.

---

## PART C: Running the project (do this every time you work on it)

Every time you sit down to work on this:

1. Open VS Code → Open the `cybertwin` folder.
2. Open a terminal.
3. Activate the environment: `venv\Scripts\activate` (Windows) or
   `source venv/bin/activate` (Mac/Linux).
4. Make sure MongoDB service is running (Part A3 — usually it just
   stays running in the background automatically, you rarely need to
   check this again).

Now run the actual project, **in this exact order**:

### C1. Seed the Digital Twin with sample devices

```
cd digital_twin
python sample_data.py
```

**Expected output** (5 lines, one per device):

```
Added router-01  | risk_score = 0
Added srv-01      | risk_score = 45
Added srv-02      | risk_score = 10
Added pc-01       | risk_score = 0
Added pc-02       | risk_score = 25
```

(Exact numbers may vary slightly — that's fine.)

This means 5 devices were written into MongoDB. You only need to run
this again if you want to reset the device list back to the samples.

### C2. Generate some test security events

Go back to the main folder, then into `agent`:

```
cd ..
cd agent
python simulate_events.py
```

**Expected output:**

```
Inserted event evt-xxxxxxxx (port_scan) for srv-01
Inserted event evt-xxxxxxxx (brute_force) for pc-02
Inserted event evt-xxxxxxxx (normal) for srv-02
```

This pretends that 3 things just happened on the network — you can
run this command again anytime you want to "trigger" the agent again
for a demo.

### C3. Run the AI Agent

Still inside the `agent` folder:

```
python ai_agent.py
```

**Expected output:**

```
AI Security Agent started. Press Ctrl+C to stop.
[dashboard] New log available: log-xxxxxxxx (risk=..., suspicious=True)
[dashboard] New log available: log-xxxxxxxx (risk=..., suspicious=True)
[dashboard] New log available: log-xxxxxxxx (risk=0, suspicious=False)
```

The agent picks up the 3 events from Step C2, one at a time (every 5
seconds), decides if each is suspicious, and logs its decision.

Once you've seen it process all 3 events, press **Ctrl+C** in the
terminal to stop it (otherwise it keeps running forever, checking
for new events every 5 seconds — that's intentional, matching your
`while True` requirement).

### C4. Launch the Dashboard

Open a **second terminal** in VS Code (don't close the first one —
click the **+** icon in the terminal panel to open a new tab).
In the new terminal:

```
venv\Scripts\activate
cd dashboard
streamlit run app.py
```

Your web browser should open automatically to something like
`http://localhost:8501`, showing:

- Network Devices table
- Overall Risk Level
- Recent Agent Logs
- Latest Recommendations

If the browser doesn't open by itself, manually copy the URL shown in
the terminal (it will say "Local URL: http://localhost:8501") and
paste it into your browser.

To stop the dashboard, click back on that terminal and press **Ctrl+C**.

---

## PART D: Doing a demo/re-run later

Every time you want to demo this fresh:

```
cd agent
python simulate_events.py     # create new fake events
python ai_agent.py            # let the agent process them, then Ctrl+C
```

Then just refresh your Streamlit browser tab (or click the 🔄 Refresh
button on the dashboard) to see the new logs appear.

---

## PART E: Common errors and exact fixes

**`python is not recognized as an internal or external command`**
→ Python isn't on PATH. Reinstall Python and tick "Add to PATH" (Step A1).

**`ModuleNotFoundError: No module named 'pymongo'` (or streamlit, pandas, etc.)**
→ Your virtual environment isn't activated, or requirements weren't
installed. Run Part B2 then B3 again. Check your terminal shows `(venv)`.

**`pymongo.errors.ServerSelectionTimeoutError` / "connection refused"**
→ MongoDB isn't running. Go to Part A3 and start the MongoDB service.

**Streamlit opens but shows "No devices found"**
→ You skipped Step C1. Run `python sample_data.py` inside `digital_twin`.

**Streamlit opens but shows "No agent logs yet"**
→ You skipped Steps C2 and C3. Run `simulate_events.py` then `ai_agent.py`.

**`ImportError: cannot import name 'DigitalTwin'` when running `ai_agent.py`**
→ Make sure you ran it from _inside_ the `agent` folder, not from the
main `cybertwin` folder. The `cd agent` step matters.

**Terminal shows `(venv)` disappeared after closing/reopening VS Code**
→ Normal — just re-run the activate command (Part B2) again in the
new terminal session.

---

## Quick reference — the exact command sequence, copy-pasteable

```
cd cybertwin
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

cd digital_twin
python sample_data.py

cd ..\agent
python simulate_events.py
python ai_agent.py
```

(then Ctrl+C, and in a second terminal:)

```
cd cybertwin
venv\Scripts\activate
cd dashboard
streamlit run app.py
```

## python -m pip list
