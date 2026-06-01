# Netra Database Layer

Netra uses PostgreSQL for case and legal workflow records, Elasticsearch for
high-volume packet/search records, and Docker volumes for uploaded PCAPs,
reports, exports, and generated logs.

Phase 0 keeps the existing Docker-backed services. Later phases will move more
analysis data from JSON artifacts into PostgreSQL and Elasticsearch.
