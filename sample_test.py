"""
sample_test.py
===============
A hands-on demonstration of Module 2 (Digital Twin) logic, using
FAKE discovery output instead of a live Nmap scan. This lets you
verify twin_manager.py's create/update/offline logic works correctly
without needing VirtualBox + Kali + Metasploitable2 set up yet.

Run from the PROJECT ROOT (not from inside tests/):
    python -m tests.sample_test

What this script does, step by step:
    1. Simulates a Discovery Engine result: two fake devices.
    2. Syncs them into the Digital Twin (both should be created as NEW).
    3. Simulates a re-scan where one device has a NEW open port
       (device should be UPDATED, not duplicated).
    4. Simulates a THIRD re-scan where one device no longer responds
       (it should be marked OFFLINE, not deleted).
    5. Prints the final Digital Twin state so you can see the result.
"""

from backend.database.mongodb import MongoDBHandler
from backend.twin.twin_manager import TwinManager


def run_test():
    # Use a separate test database so this script never touches your
    # real scan data in the 'cybertwin' database.
    db_handler = MongoDBHandler(db_name="cybertwin_test")
    twin_manager = TwinManager(db_handler)

    print("\n=== STEP 1: Initial discovery (two fake devices) ===")
    scan_1 = [
        {
            "hostname": "metasploitable.local",
            "ip_address": "192.168.56.101",
            "mac_address": "08:00:27:11:11:11",
            "operating_system": "Linux 2.6.X",
            "status": "up",
            "ports": [21, 22, 80],
            "services": [
                {"port": 21, "protocol": "tcp", "state": "open",
                 "service_name": "ftp", "version": "vsftpd 2.3.4"},
                {"port": 22, "protocol": "tcp", "state": "open",
                 "service_name": "ssh", "version": "OpenSSH 4.7p1"},
                {"port": 80, "protocol": "tcp", "state": "open",
                 "service_name": "http", "version": "Apache 2.2.8"},
            ],
        },
        {
            "hostname": "kali.local",
            "ip_address": "192.168.56.102",
            "mac_address": "08:00:27:22:22:22",
            "operating_system": "Linux Kali",
            "status": "up",
            "ports": [22],
            "services": [
                {"port": 22, "protocol": "tcp", "state": "open",
                 "service_name": "ssh", "version": "OpenSSH 8.4"},
            ],
        },
    ]
    twin_manager.sync_from_discovery(scan_1)

    print("\n=== STEP 2: Re-scan -- Metasploitable now also has port 3306 open ===")
    scan_2 = [
        {
            **scan_1[0],
            "ports": [21, 22, 80, 3306],
            "services": scan_1[0]["services"] + [
                {"port": 3306, "protocol": "tcp", "state": "open",
                 "service_name": "mysql", "version": "MySQL 5.0.51a"},
            ],
        },
        scan_1[1],  # kali unchanged
    ]
    twin_manager.sync_from_discovery(scan_2)

    print("\n=== STEP 3: Re-scan -- Kali machine no longer responds (simulated shutdown) ===")
    scan_3 = [
        scan_2[0],  # only metasploitable responds this time
    ]
    twin_manager.sync_from_discovery(scan_3)

    print("\n=== FINAL DIGITAL TWIN STATE ===")
    all_assets = twin_manager.load_all_assets()
    for asset in all_assets:
        print(f"""
Asset ID:   {asset.asset_id}
Hostname:   {asset.hostname}
IP:         {asset.ip_address}
OS:         {asset.operating_system}
Type:       {asset.device_type}
Status:     {asset.status}
Ports:      {asset.ports}
Risk Score: {asset.risk_score}
""")

    db_handler.close()
    print("=== Test complete. Data was written to the 'cybertwin_test' database. ===")


if __name__ == "__main__":
    run_test()
