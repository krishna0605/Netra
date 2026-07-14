from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from django.core.management.base import BaseCommand, CommandError

from apps.forensics.models import AccessLog, Case, EvidenceFile, EvidenceManifest, Export, OperationalEvent, Report
from common.custody import record_custody_event
from common.readiness import audit_export_payload, incident_readiness_payload, legal_review_checklist


class Command(BaseCommand):
    help = "Validate Phase 9 operational readiness and Phase 10 legal evidence readiness helpers."

    def add_arguments(self, parser):
        parser.add_argument("--mode", choices=["operations", "legal", "all"], default="all")
        parser.add_argument("--output-dir", required=True)

    def handle(self, *args, **options):
        output_dir = options["output_dir"]
        case = self._ensure_case()
        results = {
            "checkedAt": datetime.now(timezone.utc).isoformat(),
            "mode": options["mode"],
            "caseId": case.id,
            "operations": None,
            "legal": None,
            "passed": True,
            "failures": [],
        }
        if options["mode"] in {"operations", "all"}:
            operations = incident_readiness_payload()
            audit = audit_export_payload(case)
            failures = []
            if "summary" not in operations or "checks" not in operations:
                failures.append("Incident readiness payload is missing summary/checks.")
            if audit.get("redaction", "").lower().find("secrets") < 0:
                failures.append("Audit export redaction notice is missing.")
            if not audit.get("custodyLedger", {}).get("events"):
                failures.append("Audit export did not include custody ledger events.")
            results["operations"] = {"incidentReadiness": operations, "auditExportCounts": {key: len(value) for key, value in audit.items() if isinstance(value, list)}, "failures": failures}
            results["failures"].extend(failures)
        if options["mode"] in {"legal", "all"}:
            checklist = legal_review_checklist(case)
            failures = []
            if checklist["status"] != "ready-for-legal-review":
                failures.append(f"Expected legal checklist ready-for-legal-review, got {checklist['status']}.")
            if not checklist.get("custodyVerification", {}).get("verified"):
                failures.append("Custody verification did not pass.")
            required = {"evidence-manifest", "custody-ledger-verified", "report-generated", "evidence-exported", "access-logged"}
            present = {item["name"] for item in checklist.get("items", []) if item["status"] in {"complete", "not-applicable", "optional"}}
            missing = sorted(required - present)
            if missing:
                failures.append(f"Legal checklist missing complete controls: {', '.join(missing)}")
            results["legal"] = {"checklist": checklist, "failures": failures}
            results["failures"].extend(failures)
        results["passed"] = not results["failures"]

        from pathlib import Path

        root = Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        json_path = root / f"phase9-10-readiness-validation-{stamp}.json"
        md_path = root / f"phase9-10-readiness-validation-{stamp}.md"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        md_path.write_text(self._markdown(results), encoding="utf-8")
        self.stdout.write(f"Wrote {json_path}")
        self.stdout.write(f"Wrote {md_path}")
        if results["failures"]:
            raise CommandError("; ".join(results["failures"]))
        self.stdout.write(self.style.SUCCESS("Phase 9/10 readiness validation passed."))

    def _ensure_case(self) -> Case:
        suffix = uuid4().hex[:8]
        case = Case.objects.create(
            id=f"CYB-GJ-READY-{suffix}",
            title="Phase 9/10 readiness validation case",
            investigator="Netra readiness validator",
            department="Gujarat Cyber Crime Cell",
            status=Case.Status.OPEN,
            report_status="ready",
        )
        evidence = EvidenceFile.objects.create(
            id=f"ev-ready-{suffix}",
            case=case,
            filename="readiness-validation.pcap",
            stored_path="supabase://netra-evidence/readiness-validation.enc",
            size_bytes=128,
            sha256="a" * 64,
            uploaded_by="Netra readiness validator",
            status=EvidenceFile.Status.VERIFIED,
        )
        EvidenceManifest.objects.create(
            id=f"manifest-ready-{suffix}",
            case=case,
            evidence_file=evidence,
            plaintext_sha256="a" * 64,
            encrypted_sha256="b" * 64,
            storage_uri=evidence.stored_path,
            original_filename=evidence.filename,
            size_bytes=evidence.size_bytes,
            encryption_algorithm="Fernet",
            key_id="validator-key",
            manifest_json={"validator": True},
            manifest_hash="c" * 64,
        )
        record_custody_event(case, "Netra readiness validator", "Evidence uploaded", {"filename": evidence.filename, "sha256": evidence.sha256}, evidence, "EvidenceFile", evidence.id)
        record_custody_event(case, "Netra readiness validator", "Evidence encrypted", {"encryptedSha256": "b" * 64}, evidence, "EvidenceManifest", f"manifest-ready-{suffix}")
        record_custody_event(case, "Netra readiness validator", "Analysis completed", {"summary": {"packets": 0, "alerts": 0}}, evidence, "ProcessingJob", f"job-ready-{suffix}")
        Report.objects.create(id=f"report-ready-{suffix}.html", case=case, language="en", generated_by="Netra readiness validator", stored_path="supabase://netra-reports/report-ready.enc", sha256="d" * 64, status="ready")
        Export.objects.create(id=f"export-ready-{suffix}", case=case, export_type="json", requested_by="Netra readiness validator", stored_path="supabase://netra-exports/export-ready.enc", sha256="e" * 64, status="ready")
        AccessLog.objects.create(user_label="Netra readiness validator", role="Admin", action="readiness.validation", case=case, resource_type="Case", resource_id=case.id, result="allowed")
        OperationalEvent.objects.create(case=case, event_type="readiness.validation", payload_json={"caseId": case.id})
        return case

    def _markdown(self, results: dict) -> str:
        lines = [
            "# Phase 9/10 Readiness Validation",
            "",
            f"- Checked at: `{results['checkedAt']}`",
            f"- Case: `{results['caseId']}`",
            f"- Passed: `{results['passed']}`",
            "",
        ]
        if results.get("operations"):
            ops = results["operations"]["incidentReadiness"]
            lines += ["## Operations", "", f"- Status: `{ops.get('status')}`", f"- Failed jobs: `{ops.get('summary', {}).get('failedJobs')}`", f"- Dead letters: `{ops.get('summary', {}).get('unresolvedDeadLetters')}`", ""]
        if results.get("legal"):
            legal = results["legal"]["checklist"]
            lines += ["## Legal Evidence", "", f"- Status: `{legal.get('status')}`", f"- Ledger verified: `{legal.get('custodyVerification', {}).get('verified')}`", ""]
            for item in legal.get("items", []):
                lines.append(f"- `{item['name']}`: {item['status']} - {item['detail']}")
        if results.get("failures"):
            lines += ["", "## Failures", ""]
            lines.extend(f"- {failure}" for failure in results["failures"])
        return "\n".join(lines) + "\n"
