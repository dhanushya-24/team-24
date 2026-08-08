"""
main.py (Discovery Engine orchestrator)
=========================================
RESPONSIBILITY: Control the sequence:

    Scan -> Parse -> Store -> Return result

This file contains NO scanning logic, NO parsing logic, and NO
database logic itself -- it just calls the three specialist files
in the right order. This is the ONLY entry point other modules
(like app.py or the Twin Manager) should use to run a discovery scan.
"""

from backend.discovery.scanner import run_scan
from backend.discovery.parser import parse_scan
from backend.discovery.database import save_devices
from backend.database.mongodb import MongoDBHandler


def discover(target: str, db_handler: MongoDBHandler = None) -> list:
    """
    Run the full Discovery Engine pipeline against `target`.

    Args:
        target: IP, hostname, or CIDR range to scan
                (e.g. your Metasploitable2 VM's IP address).
        db_handler: shared MongoDBHandler instance (recommended),
                    or None to let this function create its own.

    Returns:
        List of parsed device dictionaries (same shape documented
        in parser.py), ready to be handed to the Twin Manager.
    """
    handler = db_handler or MongoDBHandler()

    print(f"[discovery.main] Starting discovery for target: {target}")

    # Step 1: Scan
    xml_path = run_scan(target)

    # Step 2: Parse
    devices = parse_scan(xml_path)

    # Step 3: Store (raw snapshot)
    save_devices(devices, db_handler=handler)

    # Step 4: Return result to the caller (usually app.py, which will
    # pass this same list into the Twin Manager next)
    print(f"[discovery.main] Discovery complete. {len(devices)} device(s) found.")
    return devices
