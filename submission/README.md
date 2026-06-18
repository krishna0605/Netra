# NETRA Hackathon Submission Package

Prepared for the KANAD S.H.I.E.L.D. 2026 Student Hackathon form.

## Upload These Files

1. **Road Map / Flow Diagram:** `dist/NETRA_Roadmap_Flow_Diagram.pdf`
2. **Solution Document:** `dist/NETRA_Solution_Document.pdf`

The PNG roadmap is a backup for the form's image upload option. Paste the seven answers from `dist/NETRA_Form_Answers.txt` in the same order as the form.

## Build

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File tools/render_hackathon_diagrams.ps1
& 'C:\Users\ADMIN\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' tools/build_hackathon_submission.py
```

The bundled Python runtime includes Pillow, ReportLab, and PyPDF. A different Python environment can be used after installing those packages.

The builder validates claim references, required form sections, asset presence, likely secret patterns, output size, PDF page count, and extractable text. It writes only to `submission/dist/` and `tmp/pdfs/hackathon-submission/`.

## Source Inputs

- `source/netra-research-brief.md`: verified standards, technical literature, gap synthesis, and evidence-strength assessment.
- `source/netra-claims-matrix.csv`: allowed wording and limitations for material claims.
- `source/netra-form-answers.md`: Markdown and plain-text form copy.
- `source/netra-solution-document.md`: detailed technical research report source.
- `source/netra-roadmap-document.md`: current-state, phased roadmap, metrics, and evidence-gate source.
- `source/diagrams/*.mmd`: eight editable Mermaid research figures covering gaps, architecture, evidence processing, detection, custody, evaluation, and roadmap.
- Existing repository architecture, API, benchmark, audit, security, and readiness evidence.

## Document Design

Both PDFs use a conventional A4 research-report format: white pages, restrained navy/blue accents, embedded Times New Roman and Segoe UI fonts, numbered sections, tables of contents, PDF bookmarks, figure captions, traceability tables, and live reference links. The solution report is 23 pages and the roadmap/flow report is 9 pages.

Protected investigation routes redirected to Supabase Auth, and no test officer credentials were available. The reports therefore use repository validation and technical diagrams instead of fabricated authenticated case screens.

The Google Form screenshot supplied with the request was used only to identify requirements. It is not included in the submission.

## Final Checklist

- [ ] Confirm all seven answers remain within their target word ranges.
- [ ] Open both PDFs and inspect every page at 100% zoom.
- [ ] Confirm the roadmap is readable and not clipped.
- [ ] Confirm the solution report contains at least 22 pages and the roadmap report contains at least 7 pages.
- [ ] Confirm hyperlinks and selectable PDF text work.
- [ ] Confirm each `CLM-*` statement exists in the claims matrix.
- [ ] Confirm all thirteen external references still open.
- [ ] Confirm no credentials, emails, private IPs, raw packet data, or local paths are present.
- [ ] Confirm each upload is under the Google Form's 100 MB maximum.
- [ ] Re-run the validation commands before submission if the application changes.

Validation date: 2026-06-18.
