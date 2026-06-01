# Netra Worker Processes

Workers are plain Python/Django management command processes that consume Apache Kafka topics. Phase 5 keeps hybrid mode: the API performs reliable immutable final analysis, while workers record heartbeats, consume real capture chunks, index provisional packet records, emit stage events, and preserve retry/dead-letter boundaries.

No Celery, Redis, MinIO, or Django Channels are used.

Run locally:

```bash
cd backend
python manage.py run_netra_worker parser --once
python manage.py run_netra_worker detection --once
```

Run through Docker Compose:

```bash
docker compose -f infra/docker/docker-compose.yml up parser-worker detection-worker anomaly-worker
```

For the laptop operations profile, use:

```powershell
npm run netra:start:ops
```

The parser worker indexes chunk-level provisional packet records in
`netra-packets-live-v1`. Finalized evidence is analyzed again as one immutable
PCAP and indexed through the normal case analysis path.
