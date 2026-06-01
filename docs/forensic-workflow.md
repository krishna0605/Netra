# Forensic Workflow

## 1. Register Case

The investigator creates or selects a case and records:

- Case number
- Investigator
- Department
- Evidence type
- Source location
- Priority
- Remarks

## 2. Ingest Evidence

Supported intake modes:

- Stored PCAP upload
- Live capture
- Log import

The backend stores:

- File path
- SHA-256 hash
- Upload timestamp
- Case ID
- Investigator
- Chain-of-custody event

## 3. Analyze Traffic

Kafka events trigger workers:

- Parser worker
- Decoder worker
- Session worker
- Detection worker
- Anomaly worker

## 4. Investigate Findings

Investigators review:

- Packet metadata
- Protocol decoded records
- Payload findings
- Sessions
- Alerts
- AI anomalies
- Network graph attack paths

## 5. Build Case History

Every major action adds an audit or history event:

- Evidence uploaded
- Packet viewed
- Alert confirmed
- Note added
- Report generated
- Export downloaded

## 6. Generate Legal Report

Report preview supports:

- English
- Hindi
- Gujarati

Reports include:

- Case summary
- Evidence metadata
- Hash verification
- Alert summary
- DPI summary
- Payload summary
- Session reconstruction
- AI anomaly summary
- Exported evidence
- Compliance notes
