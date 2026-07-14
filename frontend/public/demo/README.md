# NETRA sanitized demo assets

These files are deterministic, public-safe hackathon fixtures.

- `netra-sanitized-demo.pcap` contains only RFC 5737 TEST-NET addresses, `.invalid` domains, and harmless simulated protocol commands.
- `netra-sanitized-sample-report.pdf` is generated from synthetic findings and contains no production evidence, credentials, personal data, or live infrastructure identifiers.
- `SHA256SUMS.txt` pins both public artifacts.

Regenerate them from the repository root with:

```powershell
python backend/manage.py generate_demo_assets
```

The anomaly model described in the report is experimental and intended only to assist investigator triage.
