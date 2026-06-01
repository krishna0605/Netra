# Netra

Netra is a network and packet forensics platform prototype for authorized cybercrime investigation workflows. It supports real PCAP upload, packet parsing with `tshark`, protocol/session analysis, alerting, anomaly views, graph visualization, and report-ready evidence metadata.

> Use Netra only with packet captures and networks you are authorized to analyze.

## Project Structure

```txt
backend/                 Django API, forensics app, workers, packet analysis
frontend/                React/Vite investigation console served by nginx
ml-services/             Phase 1 AI/anomaly package location
sensor-agent/            Native Windows/Linux dumpcap capture companion
database/                PostgreSQL and Elasticsearch notes/config space
infra/docker/            Docker Compose orchestration
infra/scripts/           One-command startup, logs, stop, validation scripts
docs/                    Architecture, workflow, deployment, PCAP, Zeek guides
samples/pcaps/           Local-only PCAP files for authorized demos (Git ignored)
storage/                 Local evidence layout notes; runtime contents are Git ignored
```

## Prerequisites

- Docker Desktop with Docker Compose
- Node.js and npm
- PowerShell on Windows for the bundled orchestration scripts
- Optional: Wireshark `dumpcap` for bounded native sensor capture

## One-command Startup

Run from the repo root:

```powershell
npm run netra:start
```

The command builds and starts:

- frontend
- backend
- postgres
- elasticsearch
- kafka
- capture-worker
- parser-worker
- decoder-worker
- session-worker
- detection-worker
- anomaly-worker
- report-export-worker

URLs:

```txt
Frontend:      http://localhost:8080
Dashboard:     http://localhost:8080/app/dashboard
Upload:        http://localhost:8080/app/upload
Backend API:   http://localhost:8000/api/health
Elasticsearch: http://localhost:9200
Kafka:         localhost:9092
PostgreSQL:    localhost:5432
```

Netra starts with no seeded users, cases, alerts, integrations, reports, or exports. On a fresh database, open:

```txt
http://localhost:8080/app/upload
```

Upload a real PCAP or PCAPNG file. Database rows are created only by real evidence analysis and investigator actions. The current local workflow intentionally has no sign-in screen or role selector.

Useful commands:

```powershell
npm run netra:start:ops
npm run netra:start:lan
npm run netra:start:fleet
npm run netra:logs
npm run netra:stop
npm run netra:validate
npm run netra:validate:phase4
npm run netra:validate:phase5
npm run netra:validate:phase6
npm run netra:sensor:install
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
npm run netra:backup
npm run zeek:sample
```

Equivalent direct Docker command:

```powershell
docker compose -f infra/docker/docker-compose.yml up --build -d --remove-orphans
```

## Upload a PCAP

Packet captures are intentionally excluded from Git because they can be large
and may contain sensitive network data. Place an authorized capture in
`samples/pcaps/`, then upload it:

```powershell
curl.exe -F "caseId=CYB-GJ-HYDRA-0001" -F "file=@samples\pcaps\hydra_ssh.pcap" http://localhost:8080/api/evidence/upload
```

Then open:

```txt
http://localhost:8080/app/dashboard
```

## Trusted LAN Mode

For a private hackathon room or controlled lab network, run:

```powershell
npm run netra:start:lan
```

This serves the investigation console at `http://<laptop-ip>:8080` and proxies `/api` through the frontend Nginx container. Backend, Kafka, Elasticsearch, and native PostgreSQL stay local/debug-facing; do not expose this mode to the public internet. If another laptop cannot open the URL, allow inbound TCP `8080` on the Windows Private network profile only.

## Frontend Development

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Frontend dev URL:

```txt
http://127.0.0.1:5173/
```

## Backend Local Development

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate --run-syncdb
python manage.py runserver
```

Netra does not include an automatic or optional demo-data seeder. Investigation rows are created by real PCAP uploads and investigator actions.

## Native Windows PostgreSQL

For pgAdmin-visible local tables, install PostgreSQL on Windows, create a `netra` database and `netra` user, then run:

```powershell
npm run netra:start:local-db
npm run netra:validate:local-db
```

See [Local PostgreSQL Setup](docs/local-postgres-setup.md).

Worker dry runs:

```powershell
python manage.py run_netra_worker parser --once
python manage.py run_netra_worker detection --once
python manage.py run_netra_worker anomaly --once
```

## Phase 5 Laptop Operations

For the operational laptop workflow with pgAdmin-visible PostgreSQL:

```powershell
npm run netra:start:ops
npm run netra:sensor:install
npm run netra:sensor:start
```

Open `http://localhost:8080/app/upload`. The intake screen supports:

- historical PCAP import
- replaying an explicitly selected PCAP through the chunk-ingestion pipeline
- bounded native capture from a registered Wireshark `dumpcap` sensor

The UI receives persisted operational events over SSE with polling fallback. Capture
chunks, final evidence, reports, and exports are encrypted at rest.

See [Phase 5 Laptop Operations](docs/phase5-operations.md).
See [Phase 7 Fleet Operations](docs/phase7-fleet-operations.md).

## Current Limitations

- The most reliable demo path remains stored PCAP upload. Replay and native bounded capture are operational additions.
- Phase 4 intentionally removes automatic seeded data from normal startup.
- Zeek is installed inside the backend container and is used during PCAP upload to generate structured forensic evidence.
- Phase 2 adds PostgreSQL persistence, Elasticsearch indexing, case-scoped APIs, role/audit controls, and worker observability while keeping the reliable synchronous upload path.
- Hybrid mode keeps synchronous final analysis reliable while workers publish heartbeats, idempotent stage receipts, and dead-letter records.
- `ml-services/` is prepared for Phase 1 explainable anomaly work but is not a standalone ML service yet.

## Documentation

- [Architecture](docs/architecture.md)
- [API Contract](docs/api-contract.md)
- [Detection Methods](docs/detection-methods.md)
- [Forensic Workflow](docs/forensic-workflow.md)
- [Deployment](docs/deployment.md)
- [Local PostgreSQL Setup](docs/local-postgres-setup.md)
- [PCAP Analysis Guide](docs/pcap-analysis-guide.md)
- [Zeek Setup Guide](docs/zeek-setup-guide.md)
- [Worker Processes](docs/worker-processes.md)
- [Phase 7 Fleet Operations](docs/phase7-fleet-operations.md)
