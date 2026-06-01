# Netra Phase 7 Fleet Operations

Phase 7 keeps Netra private-LAN only. Authentication and RBAC remain disabled. Operational actions are logged as `Local Investigator / LAN Operator`.

## Start The Fleet Stack

Native PostgreSQL must be running first. Netra detects its local port and keeps PostgreSQL visible in pgAdmin.

```powershell
npm run netra:start:fleet
```

Open:

```txt
http://localhost:8080/app/sensors
http://localhost:8080/app/schedules
http://localhost:8080/app/system
http://localhost:8080/app/retention
```

Start one or more Windows sensors:

```powershell
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
```

Linux operators can run the Python sensor agent with `dumpcap` or `tcpdump` installed.

## What Is New

- Sensors can be grouped, tagged, located, enabled, and disabled.
- Sensor IDs remain stable across agent restarts.
- Agent uploads retry with bounded exponential backoff.
- One-time, daily, and weekly capture schedules remain bounded by duration and packet limits.
- Fleet mode uses `NETRA_PROCESSING_MODE=async-primary`.
- Stored PCAP uploads return `202` and complete through `pcap-ingestion-worker`.
- Kafka topics are provisioned explicitly.
- Parser workers can run with two replicas.
- Elasticsearch resources use templates, daily backing indexes, aliases, bulk indexing, and lifecycle policies.
- New encrypted artifacts use provider-neutral `local://` storage URIs.
- Retention cleanup deletes finalized capture chunks safely. Immutable evidence remains approval-gated.
- System Monitor exposes capacity, disk pressure, lag posture, workers, and sensors.

## Operator Commands

```powershell
npm run netra:bootstrap:search
npm run netra:retention:preview
npm run netra:retention:run
npm run netra:validate:phase7
npm run netra:benchmark:phase7
```

## PostgreSQL Tables To Inspect

Refresh `Schemas > public > Tables` in pgAdmin after starting Phase 7. Useful additions:

```txt
forensics_sensorgroup
forensics_sensorcommand
forensics_sensorhealthsnapshot
forensics_captureschedule
forensics_analysischunk
forensics_analysisstageresult
forensics_retentionpolicy
forensics_retentioncandidate
forensics_retentionrun
```

## Retention Safety

Default windows:

```txt
Search metadata:            30 days
Finalized capture chunks:    7 days
Immutable PCAP evidence:    90 days
```

Safe cleanup removes only finalized chunks automatically. Expired immutable evidence is listed as `requires-approval`. Legal-hold cases are skipped.

## Security Boundary

Phase 7 is for a controlled private LAN. Do not expose port `8080` to the public internet. Sensor writes use `NETRA_SENSOR_SHARED_KEY`; user login and certificate-based sensor enrollment remain later-phase work.
