# Netra Phase 6 Detection Benchmark

- Version: `phase6-v1`
- Started: `2026-06-16T15:12:50.927926+00:00`
- Completed: `2026-06-16T15:12:56.553850+00:00`
- Cases: `6`

## Summary Metrics

| Metric | Value |
|---|---:|
| truePositives | 5 |
| falsePositives | 3 |
| falseNegatives | 0 |
| precision | 0.625 |
| recall | 1.0 |
| f1 | 0.7692 |
| benignAccuracy | 1.0 |

## Case Results

| Case | Expected | Predicted | Alerts | Anomalies | Max Alert | Max Anomaly | Result |
|---|---|---|---:|---:|---:|---:|---|
| normal.pcap | Benign | None | 0 | 7 | 0 | 97 | PASS |
| hydra_ssh.pcap | Credential Brute Force | Credential Brute Force, Malware C2 / Beaconing | 2 | 4 | 98 | 97 | REVIEW |
| hydra_ftp.pcap | Credential Brute Force | Credential Brute Force | 1 | 3 | 95 | 97 | PASS |
| distcc_exec_backdoor.pcap | Remote Command Execution | Remote Command Execution | 1 | 2 | 88 | 69 | PASS |
| smtp.pcap | Suspicious SMTP Transfer | Suspicious SMTP Transfer | 1 | 1 | 80 | 80 | PASS |
| netbios_ssn.pcap | SMB / NetBIOS Lateral Movement | Port Scan / Reconnaissance, SMB / NetBIOS Lateral Movement, Suspicious SMTP Transfer | 3 | 8 | 90 | 97 | REVIEW |

## Per-Class Metrics

| Class | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| Credential Brute Force | 2 | 0 | 0 | 1.0 | 1.0 |
| Malware C2 / Beaconing | 0 | 1 | 0 | 0.0 | 1.0 |
| Port Scan / Reconnaissance | 0 | 1 | 0 | 0.0 | 1.0 |
| Remote Command Execution | 1 | 0 | 0 | 1.0 | 1.0 |
| SMB / NetBIOS Lateral Movement | 1 | 0 | 0 | 1.0 | 1.0 |
| Suspicious SMTP Transfer | 1 | 1 | 0 | 0.5 | 1.0 |

## Limitations

- This benchmark uses a small labeled PCAP corpus and measures deterministic behavior rules plus explainable anomaly scoring.
- Scores are engineering smoke metrics, not independent law-enforcement accuracy certification.
- PCAP-only evidence cannot prove account compromise without endpoint/server log correlation.
