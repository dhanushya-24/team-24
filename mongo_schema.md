# CyberTwinAI — MongoDB Schema (Module 1 & 2)

Database name: `cybertwin`
(sample_test.py uses a separate `cybertwin_test` database so tests
never touch your real data.)

---

## 1. Collection: `assets`

The canonical Digital Twin state. One document per discovered device.
Written by: `backend/twin/twin_manager.py` (via `save_asset`).
(`backend/discovery/database.py` also writes a raw pre-twin snapshot
here first — see that file's docstring for why.)

```json
{
  "asset_id": "192.168.56.101",
  "hostname": "metasploitable.local",
  "ip_address": "192.168.56.101",
  "mac_address": "08:00:27:11:11:11",
  "operating_system": "Linux 2.6.X",
  "device_type": "server",
  "status": "online",
  "ports": [21, 22, 80],
  "services": [ /* embedded copy, see services collection below */ ],
  "vulnerabilities": [],
  "risk_score": 25,
  "last_updated": "2026-08-02T10:00:00"
}
```

## 2. Collection: `services`

One document per (asset, port, protocol) combination. A standalone
mirror of each asset's `services` list, so future modules can query
across ALL devices without opening every asset document individually
(e.g. "find every device running an outdated Apache version").

```json
{
  "asset_id": "192.168.56.101",
  "port": 80,
  "protocol": "tcp",
  "state": "open",
  "service_name": "http",
  "version": "Apache 2.2.8"
}
```

## 3. Collection: `vulnerabilities`

Defined and ready (see `backend/twin/vulnerability.py`), but NOT
populated by any code in Module 1 or 2. A future Threat Detection
module will match `services` entries against known CVEs and insert
documents here.

```json
{
  "asset_id": "192.168.56.101",
  "cve_id": "CVE-2011-2523",
  "severity": "critical",
  "description": "vsftpd 2.3.4 backdoor command execution",
  "cvss_score": 10.0,
  "status": "open"
}
```

## 4. Collection: `connections`

Defined and ready (see `backend/twin/connection.py`), but NOT
populated yet. A future Knowledge Graph module (built with NetworkX)
will map traffic/topology between assets and insert documents here.

```json
{
  "source_asset": "192.168.56.102",
  "destination_asset": "192.168.56.101",
  "protocol": "tcp",
  "port": 22
}
```
