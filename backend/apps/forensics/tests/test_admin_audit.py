"""The administrator audit chain.

Written against the ways a trail can look intact while being useless: an entry
edited after the fact, an entry removed, a timestamp moved, or an append lost
because two administrators acted at the same moment.
"""

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.forensics.models import AdminAuditEvent, UserProfile
from common.admin_audit import (
    admin_event_dict,
    calculate_event_hash,
    delete_admin_event,
    record_admin_event,
    update_admin_event,
    verify_admin_chain,
)
from common.audit import Actor
from common.tenancy import netra_organization


class AdminAuditChainTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        user = get_user_model().objects.create_user(username="chief@netra.test", email="chief@netra.test")
        UserProfile.objects.create(user=user, organization=self.organization, role=UserProfile.Role.ADMIN)
        self.actor = Actor(
            user="Chief A. Rao",
            role="Admin",
            authenticated=True,
            django_user_id=user.id,
            email="chief@netra.test",
            organization_id=self.organization.id,
            organization_slug="netra",
            aal="aal2",
        )

    def _append(self, action="user.role_changed", **kwargs):
        return record_admin_event(
            organization=self.organization,
            actor=self.actor,
            action=action,
            target_type=kwargs.pop("target_type", "User"),
            target_id=kwargs.pop("target_id", "41"),
            **kwargs,
        )

    def test_the_first_entry_starts_the_chain(self):
        event = self._append()

        self.assertEqual(event.chain_index, 1)
        self.assertEqual(event.previous_hash, "")
        self.assertEqual(len(event.event_hash), 64)

    def test_each_entry_seals_the_one_before_it(self):
        first = self._append()
        second = self._append(action="user.deactivated")

        self.assertEqual(second.chain_index, 2)
        self.assertEqual(second.previous_hash, first.event_hash)

    def test_an_intact_chain_verifies(self):
        for index in range(5):
            self._append(action=f"user.action_{index}")

        report = verify_admin_chain(self.organization)

        self.assertTrue(report["verified"])
        self.assertEqual(report["eventCount"], 5)
        self.assertIsNone(report["firstBrokenIndex"])

    def test_an_empty_chain_verifies(self):
        report = verify_admin_chain(self.organization)

        self.assertTrue(report["verified"])
        self.assertEqual(report["eventCount"], 0)

    def test_editing_an_entry_breaks_verification(self):
        self._append()
        target = self._append(action="user.deactivated")
        self._append(action="user.password_set")

        AdminAuditEvent.objects.filter(pk=target.pk).update(action="user.viewed")
        report = verify_admin_chain(self.organization)

        self.assertFalse(report["verified"])
        self.assertEqual(report["firstBrokenIndex"], 2)

    def test_moving_a_timestamp_breaks_verification(self):
        """CustodyLedgerEvent leaves created_at outside its hashed payload, so
        a time there could be shifted undetected. For a trail whose whole
        purpose is answering "who, and when", when is inside the seal."""
        self._append()
        target = self._append(action="user.deactivated")

        AdminAuditEvent.objects.filter(pk=target.pk).update(
            recorded_at=target.recorded_at - timedelta(hours=6)
        )
        report = verify_admin_chain(self.organization)

        self.assertFalse(report["verified"])
        self.assertEqual(report["firstBrokenIndex"], 2)

    def test_changing_a_reason_breaks_verification(self):
        """The reason is why the action was permissible. Silently rewriting it
        would be the most useful edit an attacker could make."""
        self._append(reason="Officer transferred out of the unit.")
        report_before = verify_admin_chain(self.organization)
        self.assertTrue(report_before["verified"])

        AdminAuditEvent.objects.filter(chain_index=1).update(reason="Routine maintenance.")

        self.assertFalse(verify_admin_chain(self.organization)["verified"])

    def test_removing_an_entry_is_detected_as_a_gap(self):
        """Deleting the row rather than editing it is the obvious way to try to
        beat a hash chain. The index gap is what catches it."""
        self._append()
        middle = self._append(action="user.deactivated")
        self._append(action="user.password_set")

        AdminAuditEvent.objects.filter(pk=middle.pk).delete()
        report = verify_admin_chain(self.organization)

        self.assertFalse(report["verified"])
        self.assertEqual(report["eventCount"], 2)
        self.assertEqual(report["firstBrokenIndex"], 3)

    def test_before_and_after_are_sealed(self):
        event = self._append(before={"role": "Analyst"}, after={"role": "Admin"})

        AdminAuditEvent.objects.filter(pk=event.pk).update(after_json={"role": "Viewer"})

        self.assertFalse(verify_admin_chain(self.organization)["verified"])

    def test_the_chain_is_scoped_to_one_organization(self):
        from apps.forensics.models import Organization

        other = Organization.objects.create(name="Other Cell", slug="other-cell")
        self._append()
        self._append(action="user.deactivated")

        elsewhere = record_admin_event(organization=other, actor=self.actor, action="user.created")

        self.assertEqual(elsewhere.chain_index, 1)
        self.assertEqual(elsewhere.previous_hash, "")
        self.assertTrue(verify_admin_chain(self.organization)["verified"])
        self.assertTrue(verify_admin_chain(other)["verified"])

    def test_the_database_refuses_a_duplicate_index(self):
        """The service takes a lock so this should be unreachable. The
        constraint is there for when the service is wrong."""
        from django.db import IntegrityError, transaction

        self._append()

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AdminAuditEvent.objects.create(
                    organization=self.organization,
                    chain_index=1,
                    recorded_at=timezone.now(),
                    actor_label="Forged",
                    actor_role="Admin",
                    action="user.created",
                    event_hash="0" * 64,
                )

    def test_the_service_refuses_updates_and_deletes(self):
        for helper in (update_admin_event, delete_admin_event):
            with self.subTest(helper=helper.__name__):
                with self.assertRaises(RuntimeError):
                    helper()

    def test_a_rolled_back_transaction_leaves_no_entry(self):
        """An append that is part of a failed operation must not survive it,
        or the trail records changes that never happened."""
        from django.db import transaction

        try:
            with transaction.atomic():
                self._append()
                raise ValueError("the operation failed after recording")
        except ValueError:
            pass

        self.assertEqual(AdminAuditEvent.objects.count(), 0)

    def test_the_console_shape_carries_what_the_screen_renders(self):
        event = self._append(
            before={"role": "Analyst"},
            after={"role": "Investigator"},
            reason="Promoted after completing training.",
        )

        row = admin_event_dict(event)

        self.assertEqual(row["chainIndex"], 1)
        self.assertEqual(row["targetType"], "User")
        self.assertEqual(json.loads(row["after"]), {"role": "Investigator"})
        self.assertEqual(row["previousHash"], "")
        self.assertEqual(len(row["eventHash"]), 64)

    def test_the_hash_is_order_independent_for_equal_content(self):
        """Key ordering must not change the seal, or a chain would fail to
        verify after a harmless serialisation change."""
        first = calculate_event_hash("", {"b": 2, "a": 1})
        second = calculate_event_hash("", {"a": 1, "b": 2})

        self.assertEqual(first, second)
