"""
run_dashboard.py
=================
Convenience launcher for Module 5 (Dashboard). Run this from the
project root instead of remembering the full `streamlit run` path.

Usage:
    python run_dashboard.py

This does not contain any dashboard logic itself -- it only invokes
Streamlit against backend/dashboard/dashboard.py using the current
Python interpreter, so it works the same whether you're inside a
virtual environment or not.
"""

import subprocess
import sys
from pathlib import Path


def main() -> None:
    project_root = Path(__file__).resolve().parent
    dashboard_path = project_root / "backend" / "dashboard" / "dashboard.py"

    if not dashboard_path.exists():
        print(f"ERROR: dashboard entry point not found at {dashboard_path}")
        sys.exit(1)

    command = [sys.executable, "-m", "streamlit", "run", str(dashboard_path)]
    print(f"Launching CyberTwinAI Dashboard: {' '.join(command)}")
    subprocess.run(command, cwd=str(project_root))


if __name__ == "__main__":
    main()
