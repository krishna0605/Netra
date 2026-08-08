# README Asset Provenance

Inventory verified on 8 August 2026. The original presentation and report files are local-only inputs and are not committed.

| Committed asset | Local source | Public destination | SHA-256 | Sanitization and review |
|---|---|---|---|---|
| `netra-controlled-demo.webp` | `NETRA_FINAL.pptx`, slide 6, Netra landing-page image | N/A | `53a9e20955a76a519f25a89160cc6c53937dfcac7405fde1c362b01d045f3900` | Converted to RGB WebP; metadata stripped; full-resolution review found Netra-only branding and no identity, credential, case, evidence, address, or institutional emblem. Labelled synthetic in README. |
| `qr/live-demo.png` | `NETRA_FINAL.pptx`, slide 10 | `https://netra-hackathon-console-20260714.vercel.app` | `0b49e4e8f869d5d6ab2063e55ed2fb86be557df20645f781f7d46db3dba0af66` | Re-encoded as RGB PNG with metadata stripped; decoded locally to the exact direct URL. |
| `qr/source-code.png` | `NETRA_FINAL.pptx`, slide 10 | `https://github.com/krishna0605/Netra` | `337b2d9337409a1346954d4b9dac6d392cf1875b4c97ea116150e63ea70c06e4` | Re-encoded as RGB PNG with metadata stripped; decoded locally to the exact direct URL. |
| `qr/cic-ids2017.png` | `NETRA_FINAL.pptx`, slide 10 | `https://www.unb.ca/cic/datasets/ids-2017.html` | `b131439b25dc6c0b3880906ebfe67492ffd3dca3165d0249e5bbedb72c2288fe` | Re-encoded as RGB PNG with metadata stripped; decoded locally to the exact direct URL. |
| `qr/unsw-nb15.png` | `NETRA_FINAL.pptx`, slide 10 | `https://research.unsw.edu.au/projects/unsw-nb15-dataset` | `60478c1adf486447d1bdda304e66029a724a366c1618fd656367c4b7b34b9565` | Re-encoded as RGB PNG with metadata stripped; decoded locally to the exact direct URL. |
| `qr/research-paper.png` | `NETRA_FINAL.pptx`, slide 10 | `https://doi.org/10.5220/0006639801080116` | `f7e96b60582d7c3d515305cf7399e22b4d77852c943ee02323b1180b1c31362d` | Re-encoded as RGB PNG with metadata stripped; decoded locally to the exact direct URL. |

Two presentation QR images that decoded through `q.me-qr.com` or `canvaqr.com` were explicitly excluded. Police/institutional emblems, login screenshots, phone numbers, personal email addresses, credentials, real user identities, audit PDFs, and source PDF/PPTX files were also excluded.
