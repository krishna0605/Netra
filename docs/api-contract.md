# Netra API Contract

All APIs are mounted under:

```txt
/api
```

## Evidence Intake

```http
POST /api/cases
POST /api/evidence/upload
GET /api/evidence/:evidenceId/manifest
POST /api/evidence/:evidenceId/verify-integrity
GET /api/evidence/:evidenceId/download
GET /api/capture/interfaces
POST /api/capture/live/start
POST /api/capture/live/:jobId/stop
GET /api/capture/live/:jobId/status
POST /api/capture/replay/start
POST /api/capture/replay/:jobId/stop
GET /api/capture/replay/:jobId/status
POST /api/capture/log-import
GET /api/jobs/:jobId/status
```

Phase 6 trusted-LAN mode does not require login, role headers, or case membership headers. Legacy auth endpoints may remain in the backend for future phases, but they are not part of the current operational UI.

## Native Sensors And Events

```http
GET  /api/sensors
POST /api/sensors/register
GET  /api/sensors/:sensorId
POST /api/sensors/:sensorId/heartbeat
GET  /api/sensors/:sensorId/commands/next
POST /api/sensors/:sensorId/chunks
POST /api/sensors/:sensorId/captures/:jobId/complete
GET  /api/events?caseId=&captureJobId=&limit=
GET  /api/events/stream?caseId=&captureJobId=&after=
```

## Investigation Dashboard

```http
GET /api/dashboard/summary
GET /api/dashboard/traffic-timeline
GET /api/dashboard/protocol-distribution
GET /api/alerts
```

## Packet Explorer

```http
GET /api/packets
GET /api/packets/:packetId
POST /api/cases/:caseId/linked-packets
```

Supported filters:

```txt
sourceIp
destinationIp
protocol
port
sessionId
severity
```

## Sessions

```http
GET /api/sessions
GET /api/sessions/:sessionId
GET /api/sessions/:sessionId/timeline
POST /api/cases/:caseId/linked-sessions
```

## Protocol Decoder

```http
GET /api/decoder/summary
GET /api/decoder/dns
GET /api/decoder/http
GET /api/decoder/tls
GET /api/decoder/ftp
GET /api/decoder/smtp
GET /api/decoder/icmp
```

## Payload Inspection

```http
GET /api/payloads
GET /api/payloads/:findingId
POST /api/cases/:caseId/linked-payloads
```

## Detection And AI

```http
GET /api/detection/rules
GET /api/detection/matches
PATCH /api/detection/matches/:matchId/status
GET /api/anomalies
GET /api/anomalies/baseline-comparison
GET /api/anomalies/risk-timeline
```

## Graph

```http
GET /api/graph
GET /api/graph/nodes/:nodeId
GET /api/graph/attack-path
```

## Cases

```http
GET /api/cases
GET /api/cases/:caseId
POST /api/cases/:caseId/notes
GET /api/cases/:caseId/history
GET /api/cases/:caseId/linked-evidence
GET /api/cases/:caseId/custody-ledger
POST /api/cases/:caseId/custody-ledger/verify
GET /api/cases/:caseId/custody-ledger/export
GET /api/cases/:caseId/members
POST /api/cases/:caseId/members
```

## Reports And Exports

```http
GET /api/reports/:caseId/preview?language=en
POST /api/reports/:caseId/generate
GET /api/reports/:reportId/download
GET /api/exports
POST /api/exports
GET /api/exports/:exportId
GET /api/exports/:exportId/download
```

## Integration And Compliance

```http
GET /api/integrations
POST /api/integrations
PATCH /api/integrations/:integrationId
POST /api/integrations/:integrationId/sync
POST /api/integrations/:integrationId/test
POST /api/integrations/:integrationId/send-alerts
GET /api/integrations/:integrationId/deliveries
POST /api/integrations/:integrationId/deliveries/:deliveryId/retry
POST /api/integrations/siem/export
POST /api/integrations/case-link
GET /api/compliance/checklist
GET /api/compliance/roles
GET /api/compliance/security-posture
GET /api/audit/access-logs
GET /api/system/health/deep
GET /api/system/metrics
GET /api/system/storage
GET /api/system/indexes
GET /api/system/kafka
GET /api/system/dead-letter
GET /api/system/workers
GET /api/system/sensors
```
