# Netra Feature Status Matrix

Generated: 2026-06-17 11:39:26 +05:30

## Summary

- API health: ok
- Matrix rows: 21
- ML status: trained-model
- Deployment readiness: blocked

## Feature Status

| Area | Current Status | Target Status | Validation | Notes |
|---|---|---|---|---|
| Supabase Storage |  | Working / Validated | storage-health upload-artifact |  |
| PCAP upload UI |  | Working / Validated | frontend-build |  |
| PCAP upload analysis |  | Working / Validated | netra:validate:supabase |  |
| tshark parsing |  | Working / Validated | packet-tools netra:validate:dpi |  |
| Zeek analysis |  | Working / Validated | packet-tools zeek-summary |  |
| Threat detection |  | Working / Validated for demo | netra:validate:detection |  |
| AI anomaly detection |  | Working / Validated ML prototype | netra:benchmark:ml |  |
| Payload inspection / DPI |  | Working metadata-DPI / Validated | netra:validate:dpi |  |
| Suspicious Activity page |  | Working / Validated | frontend-build case-data |  |
| Traffic Evidence page |  | Working / Validated | frontend-build case-data |  |
| Reports / exports |  | Working / Validated | netra:validate:supabase netra:validate:siem |  |
| Custody ledger / integrity |  | Working / Validated | netra:validate:legal |  |
| Legal review checklist |  | Working / Validated | netra:validate:legal |  |
| Supabase Realtime |  | Working / Validated | system/realtime |  |
| Supabase PGMQ |  | Working / Validated | system/kafka netra:validate:workers |  |
| Kafka / Elasticsearch |  | Removed From Supabase Mode | netra:validate:production |  |
| Sensor capture |  | Advanced / Validated | netra:validate:sensor |  |
| Replay PCAP |  | Advanced / Validated | netra:validate:replay |  |
| SIEM integration |  | Working basic SIEM / Validated | netra:validate:siem |  |
| Production deployment profile |  | Production-Gated / Validated | netra:validate:production |  |
| Production readiness |  | Production-Gated | system/deployment-readiness |  |

## ML Model

- Status: trained-model
- Model available: True
- Version: netra-anomaly-20260616180955
- Model type: RandomForestClassifier
- Training rows: 6

## Deployment Readiness

- Status: blocked
