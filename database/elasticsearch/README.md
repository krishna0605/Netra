# Elasticsearch

Elasticsearch is reserved for searchable, high-volume forensic records:

- Packet records
- Session records
- Protocol decoder output
- Payload findings
- Alert search documents
- Dashboard analytics documents

Phase 0 keeps the service running. Phase 1 and later can add index templates
under `database/elasticsearch/indexes/`.
