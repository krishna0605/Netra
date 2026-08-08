from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from django.db import connection, connections, transaction
from django.test import SimpleTestCase, TestCase, TransactionTestCase, skipUnlessDBFeature

from apps.forensics.models import Case, CustodyLedgerEvent, Organization
from common.custody import delete_custody_event, record_custody_event, update_custody_event, verify_case_ledger

from common.custody_anchors import generate_signing_key, verify_anchor


class CustodyAnchorTests(SimpleTestCase):
    def test_generated_signature_verifies_and_tampering_fails(self):
        private, public = generate_signing_key()
        unsigned = {
            "version": "netra-custody-anchor-v1",
            "organizationId": "00000000-0000-0000-0000-000000000001",
            "caseId": "CASE-001",
            "eventCount": 2,
            "rootHash": "a" * 64,
            "latestEventId": "cust-2",
            "latestHash": "b" * 64,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "signingKeyId": "test-key",
            "publicKey": public,
        }
        import base64, json
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signature = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private)).sign(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        )
        anchor = {**unsigned, "signature": base64.b64encode(signature).decode()}
        self.assertEqual(verify_anchor(anchor), anchor)
        tampered = copy.deepcopy(anchor)
        tampered["eventCount"] = 3
        with self.assertRaises(InvalidSignature):
            verify_anchor(tampered)

    def test_anchor_rejects_unapproved_privacy_fields(self):
        private, public = generate_signing_key()
        anchor = {
            "version": "netra-custody-anchor-v1", "organizationId": "org", "caseId": "case",
            "eventCount": 0, "rootHash": "", "latestEventId": "", "latestHash": "",
            "generatedAt": "now", "signingKeyId": "key", "publicKey": public,
            "signature": private, "actorEmail": "operator@example.invalid",
        }
        with self.assertRaisesRegex(ValueError, "unexpected"):
            verify_anchor(anchor)


class CustodyLedgerTests(TestCase):
    def setUp(self):
        organization = Organization.objects.create(name="Ledger Test", slug="ledger-test")
        self.case = Case.objects.create(
            id="CASE-LEDGER-001", organization=organization, display_reference="CASE-LEDGER-001",
            title="Synthetic ledger case", investigator="Synthetic Investigator",
        )

    def test_append_and_verification_use_one_canonical_order(self):
        first = record_custody_event(self.case, "system", "created", {"sequence": 1})
        second = record_custody_event(self.case, "system", "verified", {"sequence": 2})
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertEqual(verify_case_ledger(self.case)["failures"], [])

    def test_outer_rollback_removes_custody_append(self):
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                record_custody_event(self.case, "system", "rolled-back", {})
                raise RuntimeError("force rollback")
        self.assertFalse(CustodyLedgerEvent.objects.filter(case=self.case).exists())

    def test_application_mutation_helpers_reject_changes(self):
        with self.assertRaisesRegex(RuntimeError, "append-only"):
            update_custody_event()
        with self.assertRaisesRegex(RuntimeError, "append-only"):
            delete_custody_event()


class PostgreSQLCustodyConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        organization = Organization.objects.create(name="Concurrency Test", slug="custody-concurrency")
        self.case = Case.objects.create(
            id="CASE-CONCURRENT-001", organization=organization, display_reference="CASE-CONCURRENT-001",
            title="Synthetic concurrency case", investigator="Synthetic Investigator",
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_fifty_concurrent_appends_form_one_valid_chain(self):
        self.assertEqual(connection.vendor, "postgresql")

        def append(sequence: int) -> None:
            connections.close_all()
            case = Case.objects.get(pk=self.case.pk)
            record_custody_event(case, "concurrency-test", "append", {"sequence": sequence})
            connections.close_all()

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(append, range(50)))
        result = verify_case_ledger(Case.objects.get(pk=self.case.pk))
        self.assertEqual(result["eventCount"], 50)
        self.assertEqual(result["failures"], [])
