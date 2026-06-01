# Phase 6 Trusted LAN Operation

Phase 6 makes Netra shareable on a controlled private LAN without adding login screens, role selectors, or user-management workflows.

## Start

```powershell
npm run netra:start:lan
```

The script prints one or more LAN URLs:

```txt
http://<laptop-ip>:8080
```

Use this URL from other laptops on the same trusted private network.

## Access Model

Netra runs in trusted-LAN mode:

- Access mode: `Trusted LAN`
- Authentication: `Disabled`
- Public internet: `Not supported`
- Audit actor: `Local Investigator`
- Audit role: `LAN Operator`

Anyone who can reach port `8080` can operate the platform. Keep this mode limited to a private hackathon room, lab network, or local machine.

## Windows Firewall

If other laptops cannot reach Netra, open PowerShell as Administrator and allow port `8080` only on Private networks:

```powershell
New-NetFirewallRule -DisplayName "Netra LAN 8080" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -Profile Private
```

Do not create an Any/Public-profile rule for Phase 6.

## Service Exposure

LAN mode exposes:

```txt
0.0.0.0:8080 -> frontend/Nginx
```

Debug-only services stay local:

```txt
127.0.0.1:8000 -> backend
127.0.0.1:9200 -> Elasticsearch
127.0.0.1:9092 -> Kafka
localhost:<postgres-port> -> native PostgreSQL for pgAdmin
```

## Sensors

User authentication is disabled, but sensor writes still require the installation-local sensor key:

```txt
NETRA_SENSOR_SHARED_KEY
```

The native sensor sends:

```http
X-Netra-Sensor-Key: <key>
```

This is a local safety key, not a production identity system.

## Validate

```powershell
npm run netra:validate:phase6
```

The validator checks no-header upload, replay, report generation, export generation, evidence download, access logs, and System Monitor LAN status.
