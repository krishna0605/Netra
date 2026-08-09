# Phase 4 worker image supply chain

- The API and worker images are separate and run as UID/GID 10001.
- The API image installs `requirements.api.txt` and asserts that TShark, Zeek, and tcpdump are absent.
- The worker base is the amd64 Zeek 8.2.1 image manifest `sha256:6ce464c9cc63185ac0ef40b86f1150842350895496520d7e6522c1756d07c755`.
- Wireshark 4.6.7 is downloaded from the official Wireshark source archive and checked against SHA-256 `242929b8c10ba89a8d3bcad7ff2eba8effb648d30f48e270d2e5e6ff94d88613` before compilation.
- Wireshark is compiled without the GUI, dumpcap, Lua, plugins, or tests. The final image receives only installed runtime files, not build tools.
- Runtime capability discovery fails worker readiness unless TShark reports 4.6.7 and Zeek reports 8.2.1.
- No Docker socket, credentials, evidence, external datasets, or production environment files enter either image.

The pinned amd64 worker is intentional for the Railway runtime. A future architecture change requires a separately pinned and tested manifest.

## Local Phase 4 verification

Verified on 9 August 2026 without loading production credentials:

| Image | Local image ID | Verification |
|---|---|---|
| `netra-api:phase4` | `sha256:6b915f4965a7ff2ceec0e18144877180459564ebba95630a3e890e0ea77ee89c` | UID/GID 10001, Django check passes, TShark/Zeek/tcpdump absent |
| `netra-worker:phase4` | `sha256:3a1d36830052cf91cc6a3c188cb0d33092e9aa2d8d32b54a641940a29c1e0720` | UID/GID 10001, TShark 4.6.7, Zeek 8.2.1, compiler/CMake absent |

The worker image passed 12 in-container analysis-tooling, detector-registry, and worker-capability tests using synthetic data. A local SPDX 2.3 SBOM was generated and inspected with `docker sbom`; it is intentionally not committed because it is a generated build artifact. `docker history` contained none of the reviewed secret-variable names.

These local image IDs are evidence for this workstation build, not portable release identifiers. A later controlled build must record registry digests, its own SBOM, vulnerability-scan results, and provenance before deployment.

## Local Phase 7 verification

| Image | Local image ID | Runtime contract |
|---|---|---|
| `netra-api:phase7` | `sha256:f0294fe8fd0b92258126b4494e3c55b9b56f5b43e4e49b3781bcf77a6f103cf8` | UID/GID 10001; no TShark, Zeek, or tcpdump |
| `netra-worker:phase7` | `sha256:6f5a2fc4323d1a1c01098b8a91000e03617c4e7f74614cdf392e35f6d477286d` | UID/GID 10001; TShark 4.6.7; Zeek 8.2.1 |
| `netra-frontend:phase7` | `sha256:6e5dc432f39a016bc5fa44a8ea5bbc5b1b7def4d306b45210cca5c5af8737428` | UID/GID 101; unprivileged Nginx runtime |

Every Docker base and scanner image is digest-pinned. Local CycloneDX SBOMs
were generated for all three images and intentionally ignored as build output.
Trivy found no fixable high/critical finding under the committed policy. The
worker base retains visible unfixed operating-system findings; they are not
silently suppressed from reports and do not receive an unowned VEX waiver.
