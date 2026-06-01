# Netra Architecture

Netra captures, imports, analyzes, visualizes, and reports on network traffic for cybercrime investigation teams. The repo is split by subsystem so the hackathon demo is easy to run and explain.

## Repository Layout

```txt
backend/        Django API, forensic models, packet analysis, worker commands
frontend/       React/Vite UI served by nginx in Docker
ml-services/    Phase 1 AI-assisted anomaly package
sensor-agent/   Native Windows/Linux dumpcap companion
database/       PostgreSQL and Elasticsearch docs/config placeholders
infra/          Docker Compose and PowerShell orchestration scripts
docs/           Architecture, workflow, deployment, Zeek, and PCAP guides
samples/pcaps/  Real PCAP files for demos and validation
storage/        Storage notes; Docker volume holds runtime evidence
```

## Runtime Flow

```mermaid
flowchart TD
  ROOT["Root package.json"] --> CMD["npm run netra:start"]
  CMD --> COMPOSE["infra/docker/docker-compose.yml"]

  COMPOSE --> FE["frontend container"]
  COMPOSE --> BE["backend container"]
  COMPOSE --> PG["postgres container"]
  COMPOSE --> ES["elasticsearch container"]
  COMPOSE --> KF["kafka container"]
  COMPOSE --> WK["worker containers"]

  FE --> API["Django API"]
  API --> PCAP["netra-storage PCAP volume"]
  API --> ML["ml-services/anomaly-engine"]
  API --> RULES["backend/detection_rules"]
  API --> PG
  API --> ES
  API --> KF
```

## Component Flow

```mermaid
flowchart LR
  UI["React Frontend"] --> API["Django API"]
  API --> PG["PostgreSQL"]
  API --> ES["Elasticsearch"]
  API --> FS["Docker Volume Storage"]
  API --> KAFKA["Kafka"]

  KAFKA --> PARSER["Parser Worker"]
  KAFKA --> DECODER["Decoder Worker"]
  KAFKA --> SESSION["Session Worker"]
  KAFKA --> DETECTION["Detection Worker"]
  KAFKA --> AI["Anomaly Worker"]
  KAFKA --> EXPORT["Report/Export Worker"]
```

## System of Record

PostgreSQL stores investigation records:

- Cases
- Evidence metadata
- Capture and processing jobs
- Alerts
- Detection matches
- Anomaly records
- Reports and exports
- Integrations
- Audit logs
- Compliance records

Elasticsearch is reserved for high-volume search records:

- Packet records
- Protocol decoded records
- Payload findings
- Session timelines
- Alert search documents
- Dashboard analytics records

Docker volumes store:

- Uploaded PCAP files
- Capture chunks
- Generated reports
- Evidence exports
- Analysis logs

## Phase 5 Operational Path

For demo reliability, final PCAP analysis remains synchronous while import,
replay, and native capture converge on immutable evidence finalization:

```mermaid
flowchart LR
  A["Upload PCAP"] --> B["Immutable finalization"]
  R["Replay chunks"] --> B
  S["Native sensor chunks"] --> B
  B --> C["Hash + encrypt + manifest"]
  C --> D["tshark + Zeek"]
  D --> E["Packets + sessions"]
  E --> F["Detections + anomalies"]
  F --> G["PostgreSQL + Elasticsearch"]
  G --> H["Dashboard + graph + report"]
```

Operational events are persisted in PostgreSQL and streamed to the browser using
SSE. Workers publish real heartbeats and idempotent stage receipts.
