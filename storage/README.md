# Netra Local Evidence Storage

This directory mirrors the Docker volume layout used by the backend:

- `pcaps/`
- `capture_chunks/`
- `reports/`
- `exports/`
- `logs/`
- `filtered_pcaps/`

The backend stores raw PCAPs, generated reports, filtered PCAPs, and export bundles here for the hackathon/containerized prototype. PostgreSQL stores the path, SHA-256 hash, case ID, timestamps, and chain-of-custody metadata.
