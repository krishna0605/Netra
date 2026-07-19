# Netra

Netra is a network and packet forensics platform for authorized cybercrime investigation workflows. It supports PCAP upload, packet parsing with `tshark` and Zeek, protocol and session analysis, alerting, anomaly views, evidence metadata, and report generation.

> Use Netra only with packet captures and networks you are authorized to analyze.

## Project Structure

```txt
backend/          Django API, forensic analysis, and worker commands
frontend/         React/Vite investigation console served by nginx
infra/docker/     Unified production Docker Compose configuration
infra/scripts/    Public production start, stop, and validation scripts
ml-services/      Explainable anomaly-analysis package
sensor-agent/     Native Windows/Linux capture companion
storage/          Runtime storage layout; generated contents are Git ignored
```

## Prerequisites

- Docker Desktop with Docker Compose
- Node.js and npm
- PowerShell on Windows for the orchestration commands
- A configured Supabase project
- Optional: Wireshark `dumpcap` for bounded native capture

## Production Setup

Create the local production environment file:

```powershell
Copy-Item .env.supabase.production.example .env.supabase.production.local
```

Replace every `replace-*` value in `.env.supabase.production.local`. Never commit that local file. In particular, protect the Supabase service-role key, database password, Django secret, evidence key, sensor key, and webhook signing secret.

Start the current production stack:

```powershell
npm run netra:start
```

This builds the frontend and backend against Supabase Auth, Postgres, Storage, Realtime, and Queues. The default `hackathon-core` profile enables `NETRA_FREE_PLAN_GUARD`: evidence uploads are capped at 25 MiB, replay, direct uploads, deep Storage transfer probes, browser Realtime, and Supabase workers are disabled. Set `NETRA_FREE_PLAN_GUARD=0` before explicitly enabling those higher-traffic features on a paid deployment.

Open:

```txt
Console: http://localhost:8080
Login:   http://localhost:8080/login
```

Useful public commands:

```powershell
npm run netra:start
npm run netra:stop
npm run netra:validate
npm run netra:sensor:install
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
```

Equivalent direct Docker command for the Free-plan-safe web stack:

```powershell
docker compose --env-file .env.supabase.production.local -f infra/docker/compose.netra-production.yml up --build -d --remove-orphans frontend backend
```

Supabase egress is cumulative within a billing cycle. Keep production validation against small fixtures, and do not enable deep Storage health checks for a continuously polled health endpoint.

## Evidence Upload

Packet captures are excluded from Git because they can be large and contain sensitive network data. Upload an authorized PCAP or PCAPNG through the evidence intake screen:

```txt
http://localhost:8080/app/upload
```

Investigation records are created from real evidence and investigator actions. The repository does not ship captured traffic, credentials, or seeded operational data.

## Frontend Development

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Frontend checks:

```powershell
npm test
npm run lint
npm run build
npm run test:e2e
```

## Sensor Agent

The sensor agent supports explicitly authorized bounded capture. On Windows:

```powershell
npm run netra:sensor:install
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
```

Restrict any listening ports to trusted private networks and collect traffic only with authorization.

## Security Notes

- Real `.env` files and local credentials are Git ignored.
- Supabase service-role credentials must remain backend-only.
- Runtime captures, logs, reports, exports, and evidence are Git ignored.
- The backend is not published directly; nginx proxies API traffic from the frontend service.
- Create officer accounts manually in Supabase Auth and rotate production secrets before deployment.
- Review Supabase Row Level Security policies before allowing shared or internet-facing access.

## Current Limitations

- A current Supabase service-role key is required for encrypted evidence storage.
- The most reliable intake path is stored PCAP upload.
- The frontend production bundle is sizeable and would benefit from additional code splitting.
- `ml-services/` is an integrated analysis package rather than an independently deployed service.
