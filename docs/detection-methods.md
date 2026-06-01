# Detection Methods

## Signature Detection

Rules are JSON files in `backend/detection_rules/`.

Current rule categories:

- DNS Tunnel
- ICMP Tunnel
- Malware C2 / Beaconing
- Exfiltration
- Port Scan

Each rule defines:

- ID
- Name
- Category
- Attack class
- Keywords
- Minimum keyword matches
- Base confidence

## DNS Tunnel Detection

Signals:

- Long DNS query names
- High-entropy subdomains
- Repeated requests to one suspicious domain
- TXT-like burst patterns
- High query rate from one host

## Exfiltration Detection

Signals:

- Large outbound transfer volume
- Suspicious external destination
- Unusual TLS timing
- High destination reputation risk

## Beaconing / Malware C2 Detection

Signals:

- Periodic session timing
- Low interval variance
- Repeated SNI or destination
- JA3 reuse

## AI Anomaly Detection

V1 uses Scikit-learn-compatible and statistical methods:

- Isolation Forest readiness
- Z-score deviation
- Rolling baseline comparison
- Frequency anomaly scoring

Features:

- DNS frequency
- DNS entropy
- Outbound volume
- Session duration
- Beacon timing regularity
- Destination rarity
- Internal scan fan-out
- Protocol distribution shift

## Encrypted Traffic Policy

Netra does not decrypt TLS payloads.

Allowed metadata:

- SNI
- JA3/JA3S
- Certificate issuer
- Certificate validity
- Cipher metadata
- Packet size
- Timing pattern
- Destination reputation
