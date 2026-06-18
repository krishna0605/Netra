# NETRA Research Brief

## Research Scope

- **Product:** NETRA, an evidence-first network and packet forensics prototype.
- **Primary audience:** KANAD S.H.I.E.L.D. 2026 judges and technical reviewers.
- **Operational audience:** Authorized cybercrime investigators, network-forensics analysts, supervisors, and evidence custodians.
- **Time horizon:** Current prototype evidence plus a twelve-month maturation program.
- **Research question:** How can a network-forensics workflow connect mature packet-analysis and monitoring tools to traceable case management, explainable findings, and reviewable evidence artifacts?
- **Method:** Triangulation of authoritative standards, official tool documentation, peer-reviewed research, and repository validation evidence. Public community anecdotes were not used to estimate prevalence because the available evidence did not support a reliable frequency claim.
- **Access note:** Each external source listed below returned HTTP 200 and was directly verified on 2026-06-18.

## Executive Synthesis

The evidence does not support presenting packet analysis as an unsolved technical problem. TShark already performs mature capture-file dissection and filtering, Zeek produces structured network-security records, Suricata provides IDS/IPS/NSM capabilities, and SIEM systems centralize security events. Standards also establish that defensible forensic practice extends beyond analysis: evidence must be collected, preserved, examined, analyzed, documented, and reported in a controlled manner [R1-R4]. The product opportunity is therefore an integration and workflow problem. Technical results are commonly produced by different tools, represented with different schemas, and later transferred into case notes and reports. NETRA's proposed contribution is a case-scoped evidence pipeline that connects capture validation, hashing, encrypted storage, packet and protocol analysis, transparent detection, human review, reporting, integrity verification, and custody history.

Repository evidence shows that the current prototype implements substantial parts of this path for stored PCAP/PCAPNG evidence. It does not justify claims of production readiness, legal admissibility, large-scale throughput, or generalizable model accuracy. The correct research position is a validated engineering prototype with a defined evaluation and hardening program.

## Literature-Backed Observations

### O1. Incident response and forensic analysis are lifecycle activities

NIST SP 800-61 Rev. 3 treats incident response as part of cybersecurity risk management rather than a disconnected technical activity [R1]. NIST SP 800-86 describes forensic work across collection, examination, analysis, and reporting [R2]. RFC 3227 further emphasizes evidence collection and archiving principles such as documenting actions and respecting the order of volatility [R4]. Together, these sources support a system design that retains provenance and review context across the whole workflow.

### O2. Existing tools are strong but specialized

TShark supports capture-file reading, protocol dissection, display filters, and multiple output formats [R5]. Zeek generates detailed records describing observed network activity [R6]. Suricata covers intrusion detection, intrusion prevention, and network-security monitoring [R7]. MITRE ATT&CK identifies network traffic as a data source for detecting adversary behavior [R8]. These capabilities are complementary. None of these official sources claims to provide the complete case, custody, evidence-integrity, analyst-review, and reporting workflow proposed for NETRA.

### O3. Log management and case evidence require governance

NIST SP 800-92 describes the infrastructure and operational processes required for log generation, transmission, storage, analysis, and disposal [R3]. This reinforces that useful evidence depends on retention, access control, timestamps, and documented handling, not only detection logic.

### O4. IDS evaluation needs representative labeled data

CICIDS2017 was created to provide labeled benign and attack traffic for intrusion-detection research [R9, R10]. This supports the use of repeatable corpora and per-class metrics. It also exposes a limitation in NETRA's current evidence: a six-case local benchmark is useful for smoke testing, but it is too small for a production accuracy claim.

### O5. Explainability assists review but does not establish correctness

Lundberg and Lee's SHAP work formalizes a method for attributing model predictions to input features [R11]. The broader lesson for NETRA is that a model score should be accompanied by feature-level context and evidence links. Explanation does not make a weak model accurate, and the current six-row Random Forest training set remains experimental.

### O6. AI and security controls require explicit risk management

The NIST AI Risk Management Framework emphasizes governance, measurement, and management of AI risks [R12]. Supabase's Storage documentation explains that access control depends on configured row-level security policies [R13]. These sources support explicit gates for model evaluation, RLS/RBAC review, secret handling, monitoring, and deployment approval.

## Gap Analysis

| Gap | Evidence basis | Operational consequence | NETRA response | Evidence status |
|---|---|---|---|---|
| Fragmented context across packet, log, alert, and report tools | Specialized capabilities in R5-R8 | Analysts must manually preserve relationships and case context | Case-scoped evidence model and linked investigative views | Implemented for the prototype; usability benefit not yet measured |
| Manual evidence-to-report transfer | Lifecycle expectations in R1-R4 | Rework, inconsistent summaries, and possible loss of provenance | Report/export generation from persisted case records | Implemented and validated for selected artifacts |
| Findings without sufficient explanation | Explainability principles in R11 and AI risk guidance in R12 | Reviewers may over-trust or dismiss a score | Rules, feature explanations, confidence, and evidence identifiers | Implemented at prototype level; wider analyst study required |
| Integrity and custody handled outside analysis | R2 and R4 | Technical results can become detached from evidence identity | Hashes, manifests, encrypted artifacts, and hash-linked custody events | Engineering validation passed; legal acceptance not established |
| Small or unrepresentative evaluation corpus | R9 and R10 | Accuracy estimates may not generalize | Broader corpus, independent split, per-class metrics, external samples | Current corpus is insufficient; roadmap item |
| Public deployment security uncertainty | R12 and R13 | Data exposure or excessive privilege | RLS/RBAC review, secret rotation, release gates, monitoring | Production readiness remains blocked |

## Repository Evidence

### Validated or directly observed

- Stored PCAP/PCAPNG upload and case creation.
- TShark and Zeek tool availability in current health checks.
- Packet/session analysis, rule findings, anomaly records, graphs, and timelines.
- Evidence hashing, encrypted artifact storage, manifests, integrity verification, and custody events.
- Report, JSON bundle, and alert CSV workflows; CEF support is implemented.
- Frontend production build and core stack validation.
- A current status matrix with 22 feature areas and explicit deployment gating.

### Prototype evidence requiring careful wording

- The detection benchmark contains six cases. It recorded five true positives, three false positives, no false negatives, precision 0.625, recall 1.0, and F1 0.7692.
- The RandomForestClassifier metadata records six training rows. Perfect local training metrics are not independent validation.
- A technical legal-readiness check passed for a test case, but this is not a court-admissibility determination.

### Not yet established

- Investigator time savings or usability improvement.
- Generalizable detection accuracy.
- Large-PCAP throughput under concurrent workload.
- Production security approval.
- Legal admissibility in a target jurisdiction.
- Reliability of every sensor, replay, and external integration environment.

## Research Implications

1. Position NETRA as an orchestration and evidence-continuity system, not a replacement packet decoder or certified attribution engine.
2. Use an evidence hierarchy in all submissions: standards and official documentation, repository implementation, repeatable validation, then explicit inference.
3. Treat human review as part of the detection method.
4. Make evaluation multi-dimensional: detection quality, integrity, usability, performance, security, and governance.
5. Require measurable exit criteria for every roadmap phase.

## Source Map

| ID | Source | Organization / authors | Date or version | Verified URL | Principal use |
|---|---|---|---|---|---|
| R1 | Incident Response Recommendations and Considerations for Cybersecurity Risk Management, SP 800-61 Rev. 3 | NIST | 2025 | https://csrc.nist.gov/pubs/sp/800/61/r3/final | Incident-response lifecycle and governance |
| R2 | Guide to Integrating Forensic Techniques into Incident Response, SP 800-86 | NIST | 2006 | https://csrc.nist.gov/pubs/sp/800/86/final | Collection, examination, analysis, and reporting |
| R3 | Guide to Computer Security Log Management, SP 800-92 | NIST | 2006 | https://csrc.nist.gov/pubs/sp/800/92/final | Log-management infrastructure and operations |
| R4 | Guidelines for Evidence Collection and Archiving, RFC 3227 | IETF / RFC Editor | 2002 | https://www.rfc-editor.org/rfc/rfc3227 | Evidence collection and documentation principles |
| R5 | tshark(1) Manual Page | Wireshark Foundation | Current, accessed 2026-06-18 | https://www.wireshark.org/docs/man-pages/tshark.html | Packet dissection, filtering, and structured output |
| R6 | About Zeek | Zeek Project | Book of Zeek 8.2.0 | https://docs.zeek.org/en/current/about.html | Structured network-security monitoring records |
| R7 | What is Suricata? | Open Information Security Foundation | 9.0.0-dev documentation | https://docs.suricata.io/en/latest/what-is-suricata.html | IDS, IPS, and NSM comparison |
| R8 | Network Traffic, Data Source DS0029 | MITRE ATT&CK | Current, accessed 2026-06-18 | https://attack.mitre.org/datasources/DS0029/ | Network telemetry as a detection data source |
| R9 | IDS 2017 Dataset | Canadian Institute for Cybersecurity, UNB | Dataset page | https://www.unb.ca/cic/datasets/ids-2017.html | Labeled evaluation corpus |
| R10 | Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization | Sharafaldin, Lashkari, Ghorbani | ICISSP 2018, DOI 10.5220/0006639801080116 | https://www.scitepress.org/Papers/2018/66398/ | Dataset methodology and traffic characterization |
| R11 | A Unified Approach to Interpreting Model Predictions | Lundberg and Lee | NeurIPS 2017 | https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html | Feature-level model explanation |
| R12 | AI Risk Management Framework | NIST | AI RMF 1.0 and supporting resources | https://www.nist.gov/itl/ai-risk-management-framework | AI governance, measurement, and risk management |
| R13 | Storage Access Control | Supabase | Current, accessed 2026-06-18 | https://supabase.com/docs/guides/storage/security/access-control | RLS-based storage authorization |

## Evidence Strength

- **High confidence:** Tool capabilities, standards, repository structure, build status, health checks, and recorded validation outputs.
- **Moderate confidence:** NETRA's proposed ability to improve evidence continuity, because the workflow is implemented but not yet measured with users.
- **Low confidence / future research:** Frequency of investigator pain, quantified time savings, field accuracy, operational resilience at scale, and legal acceptance.
