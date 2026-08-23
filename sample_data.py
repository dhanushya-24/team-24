"""
sample_data.py
==============
Populates the Digital Twin with a small, realistic-looking network:
    - 1 router
    - 2 servers
    - 2 employee PCs

Run this once to seed MongoDB:
    python sample_data.py
"""

from digital_twin import DigitalTwin


def seed():
    twin = DigitalTwin()

    devices = [
        {
            "_id": "router-01",
            "name": "Main-Gateway-Router",
            "type": "router",
            "ip_address": "192.168.1.1",
            "os": "RouterOS 7.1",
            "open_ports": [80, 443],
            "criticality": "high",       # if the router goes down, everything goes down
            "patch_status": "updated",
            "status": "online",
        },
        {
            "_id": "srv-01",
            "name": "Finance-DB-Server",
            "type": "server",
            "ip_address": "192.168.1.10",
            "os": "Ubuntu 22.04",
            "open_ports": [22, 3306, 443, 8080],
            "criticality": "high",
            "patch_status": "outdated",  # deliberately vulnerable-looking for your demo
            "status": "online",
        },
        {
            "_id": "srv-02",
            "name": "Web-App-Server",
            "type": "server",
            "ip_address": "192.168.1.11",
            "os": "Ubuntu 22.04",
            "open_ports": [80, 443],
            "criticality": "medium",
            "patch_status": "updated",
            "status": "online",
        },
        {
            "_id": "pc-01",
            "name": "Employee-PC-Rahul",
            "type": "employee_pc",
            "ip_address": "192.168.1.51",
            "os": "Windows 11",
            "open_ports": [445],
            "criticality": "low",
            "patch_status": "updated",
            "status": "online",
        },
        {
            "_id": "pc-02",
            "name": "Employee-PC-Anita",
            "type": "employee_pc",
            "ip_address": "192.168.1.52",
            "os": "Windows 11",
            "open_ports": [139, 445, 3389],  # RDP open -> deliberately riskier
            "criticality": "medium",
            "patch_status": "outdated",
            "status": "online",
        },
    ]

    for device in devices:
        saved = twin.add_device(device)
        print(f"Added {saved['_id']:10s} | risk_score = {saved['risk_score']}")

    twin.close()


if __name__ == "__main__":
    seed()
