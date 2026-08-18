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
        event = self._append(before={"role": "Investigator"}, after={"role": "Admin"})

        AdminAuditEvent.objects.filter(pk=event.pk).update(after_json={"role": "Investigator"})

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
            before={"role": "Investigator"},
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


class AdministratorMutationRuleTests(TestCase):
    """The rules that replaced "nothing may touch an administrator".

    That rule, combined with one administrator per organization, meant the one
    person who could act was the one person nobody could act on. A station head
    who lost their authenticator could only be restored by editing the database.
    """

    def setUp(self):
        from apps.forensics.models import Organization

        self.organization = Organization.objects.create(name="Station A", slug="station-a")
        User = get_user_model()
        self.head = User.objects.create_user(username="head@station-a.test", email="head@station-a.test")
        self.deputy = User.objects.create_user(username="deputy@station-a.test", email="deputy@station-a.test")
        self.officer = User.objects.create_user(username="officer@station-a.test", email="officer@station-a.test")
        for user, role in (
            (self.head, UserProfile.Role.ADMIN),
            (self.deputy, UserProfile.Role.ADMIN),
            (self.officer, UserProfile.Role.INVESTIGATOR),
        ):
            UserProfile.objects.create(user=user, organization=self.organization, role=role)

    def _actor(self, user):
        from common.audit import Actor

        return Actor(
            user=user.username,
            role="Admin",
            authenticated=True,
            django_user_id=user.id,
            email=user.email,
            organization_id=self.organization.id,
            organization_slug=self.organization.slug,
            aal="aal2",
        )

    def test_a_deputy_can_act_on_the_station_head_through_the_console(self):
        """The case the old rule made impossible, and the reason it changed."""
        from apps.forensics.services.administration import ensure_console_mutation_allowed

        head_profile = UserProfile.objects.get(user=self.head)

        self.assertIsNone(ensure_console_mutation_allowed(self._actor(self.deputy), head_profile))

    def test_the_generic_user_route_still_refuses_administrator_changes(self):
        """The older route writes nothing to the audit chain, so administrator
        changes stay in the console where every one of them is sealed."""
        from apps.forensics.services.administration import AdministrationProblem, ensure_admin_mutation_allowed

        head_profile = UserProfile.objects.get(user=self.head)

        with self.assertRaises(AdministrationProblem) as raised:
            ensure_admin_mutation_allowed(self._actor(self.deputy), head_profile)

        self.assertEqual(raised.exception.code, "administrator_change_forbidden")

    def test_an_administrator_cannot_act_on_their_own_account(self):
        """Resetting your own authenticator locks you out of the console that
        would have fixed it. Someone else doing it also puts two names in the
        audit trail instead of one."""
        from apps.forensics.services.administration import AdministrationProblem, ensure_console_mutation_allowed

        own_profile = UserProfile.objects.get(user=self.head)

        with self.assertRaises(AdministrationProblem) as raised:
            ensure_console_mutation_allowed(self._actor(self.head), own_profile)

        self.assertEqual(raised.exception.code, "self_mutation_forbidden")
        self.assertEqual(raised.exception.status, 409)

    def test_an_ordinary_officer_can_still_be_administered(self):
        from apps.forensics.services.administration import ensure_admin_mutation_allowed

        officer_profile = UserProfile.objects.get(user=self.officer)

        self.assertIsNone(ensure_admin_mutation_allowed(self._actor(self.head), officer_profile))

    def test_the_last_administrator_cannot_be_removed(self):
        """An organization with no administrator cannot add users, reset
        credentials or recover anyone, and nothing inside the application can
        undo it."""
        from apps.forensics.services.administration import AdministrationProblem, ensure_administrator_remains

        UserProfile.objects.filter(user=self.deputy).update(role=UserProfile.Role.INVESTIGATOR)

        with self.assertRaises(AdministrationProblem) as raised:
            ensure_administrator_remains(self.organization, losing_user_id=self.head.id)

        self.assertEqual(raised.exception.code, "last_administrator")

    def test_one_of_two_administrators_may_be_removed(self):
        from apps.forensics.services.administration import ensure_administrator_remains

        self.assertIsNone(ensure_administrator_remains(self.organization, losing_user_id=self.head.id))

    def test_a_deactivated_administrator_does_not_count_as_cover(self):
        """Counting rows rather than active people would let the last working
        administrator be removed because a disabled account exists."""
        from apps.forensics.services.administration import AdministrationProblem, ensure_administrator_remains

        get_user_model().objects.filter(pk=self.deputy.pk).update(is_active=False)

        with self.assertRaises(AdministrationProblem) as raised:
            ensure_administrator_remains(self.organization, losing_user_id=self.head.id)

        self.assertEqual(raised.exception.code, "last_administrator")

    def test_administrators_in_another_organization_are_not_cover(self):
        """Seven stations, seven sets of administrators. A head at Station B is
        no help to Station A and must not satisfy its minimum."""
        from apps.forensics.models import Organization
        from apps.forensics.services.administration import AdministrationProblem, ensure_administrator_remains

        other = Organization.objects.create(name="Station B", slug="station-b")
        elsewhere = get_user_model().objects.create_user(username="head@station-b.test")
        UserProfile.objects.create(user=elsewhere, organization=other, role=UserProfile.Role.ADMIN)
        UserProfile.objects.filter(user=self.deputy).update(role=UserProfile.Role.INVESTIGATOR)

        with self.assertRaises(AdministrationProblem) as raised:
            ensure_administrator_remains(self.organization, losing_user_id=self.head.id)

        self.assertEqual(raised.exception.code, "last_administrator")
