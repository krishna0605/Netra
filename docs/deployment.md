# Netra Deployment

## One-command Local Stack

Start everything from the repo root:

```powershell
npm run netra:start
```

For the laptop operations profile with native pgAdmin-visible PostgreSQL and
same-origin API routing, use:

```powershell
npm run netra:start:ops
```

This calls:

```powershell
docker compose -f infra/docker/docker-compose.yml up --build -d --remove-orphans
```

## Services

Docker Compose runs:

- `frontend` on `http://localhost:8080`
- `backend` on `http://localhost:8000`
- `postgres` on `localhost:5432`
- `elasticsearch` on `http://localhost:9200`
- `kafka` on `localhost:9092`
- `capture-worker`
- `parser-worker`
- `decoder-worker`
- `session-worker`
- `detection-worker`
- `anomaly-worker`
- `report-export-worker`

No Redis, Celery, MinIO, or Django Channels are used.

## URLs

```txt
Frontend:      http://localhost:8080
Dashboard:     http://localhost:8080/app/dashboard
Upload:        http://localhost:8080/app/upload
Django API:    http://localhost:8000/api/health
Elasticsearch: http://localhost:9200
Kafka:         localhost:9092
PostgreSQL:    localhost:5432
```

## Logs, Stop, and Validate

```powershell
npm run netra:logs
npm run netra:stop
npm run netra:validate
npm run netra:validate:phase1
npm run netra:validate:phase2
npm run netra:validate:phase3
npm run netra:validate:phase4
npm run netra:validate:phase5
```

## Phase 3 Security Defaults

The local Docker stack now enables Phase 3 controls while preserving the Phase 1/2 demo path:

- The current local workflow intentionally has no sign-in screen or role selector.
- A fixed local investigator header keeps the existing protected API plumbing usable until authentication is implemented later.
- PCAPs, reports, and exports are written as encrypted artifacts.
- Evidence manifests record plaintext hash, encrypted hash, key id, and manifest hash.
- Chain-of-custody events are hash-linked and can be verified per case.
- Host interface capture is disabled by default; PCAP replay remains the safe live demo.

For production-style runs, copy `infra/docker/.env.example` to `infra/docker/.env`, set strong secrets, and use:

```powershell
docker compose -f infra/docker/docker-compose.prod.yml up --build -d
```

## PCAP Upload

```powershell
curl.exe -F "caseId=CYB-GJ-HYDRA-0001" -F "file=@samples\pcaps\hydra_ssh.pcap" http://localhost:8080/api/evidence/upload
```

## Local Frontend

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

## Local Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate --run-syncdb
python manage.py runserver
```

Netra does not seed users, cases, alerts, integrations, or reports. Investigation rows are created by real PCAP uploads and local investigator actions. The current local workflow intentionally has no sign-in screen.

## Native Local PostgreSQL

For local pgAdmin visibility, install PostgreSQL on Windows, create the `netra` user/database, and run:

```powershell
npm run netra:start:local-db
npm run netra:validate:local-db
```

See [Local PostgreSQL Setup](local-postgres-setup.md).

## Worker Dry Runs

```powershell
cd backend
python manage.py run_netra_worker parser --once
python manage.py run_netra_worker detection --once
python manage.py run_netra_worker anomaly --once
```

## Live Capture Note

Docker does not sniff Windows host interfaces directly. Phase 5 adds a native
sensor companion that discovers Wireshark `dumpcap.exe`, enumerates real Npcap
adapters, polls bounded capture commands, and uploads encrypted chunks.

```powershell
npm run netra:sensor:install
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
```

Stored PCAP upload remains the reliable primary path. Replay and bounded capture
use the same evidence finalization rules.
