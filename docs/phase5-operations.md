# Phase 5 Laptop Operations

Phase 5 keeps Netra honest: every investigation row comes from an uploaded PCAP,
a replayed PCAP feed, a native bounded capture, a worker action, or a real service
probe.

## Start The Platform

Use native Windows PostgreSQL so pgAdmin can show rows live:

```powershell
npm run netra:start:ops
```

Open:

```txt
Console:        http://localhost:8080
Evidence intake http://localhost:8080/app/upload
System monitor: http://localhost:8080/app/system
```

Nginx serves the React console and proxies `/api` to Django, so users work from
one URL.

## Start The Windows Sensor

Wireshark and Npcap must already be installed.

```powershell
npm run netra:sensor:install
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
```

The sensor runs natively because a Docker container cannot reliably sniff Windows
host interfaces. It registers itself, reports real adapters from `dumpcap -D`,
sends heartbeats, polls bounded commands, compiles BPF filters with `dumpcap`,
rotates short PCAP chunks, and uploads each chunk for encryption and analysis.

Some Windows installations restrict the Npcap loopback adapter. If loopback
capture stays empty, select the active Wi-Fi or Ethernet adapter. Run the sensor
terminal as Administrator when Npcap was installed with administrator-only
capture access.

## Capture Safety Limits

```txt
Maximum duration:       15 minutes
Maximum packet limit:   250,000
Chunk interval:         2-30 seconds
Maximum BPF length:     255 characters
```

## Evidence Intake Paths

`/app/upload` presents three concrete actions:

1. Import a historical PCAP or PCAPNG file.
2. Replay an explicitly selected PCAP as timed chunks.
3. Capture bounded traffic from a connected native sensor.

Replay is a forensic data feed. It does not inject packets onto the network.

## Live Events

Django persists operational events in PostgreSQL and exposes:

```http
GET /api/events/stream?captureJobId=<job>
```

The browser reconnects with polling fallback. Chunk counters and progress values
come from server records, not timer animation.

## Backup

```powershell
npm run netra:backup
```

The backup contains a PostgreSQL dump and encrypted storage archive. Keep the
evidence encryption key separately.

Restore explicitly:

```powershell
npm run netra:restore -- -BackupDirectory .\backups\netra-YYYYMMDD-HHMMSS
```

## Validate

```powershell
npm run netra:validate:phase5
```

The validator uploads a renamed PCAP to prove filename-independent detection,
verifies encrypted evidence bytes, checks deep-health payloads, starts a real
chunked replay, and confirms finalized evidence and persisted SSE events.
