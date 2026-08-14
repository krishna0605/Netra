"""Permissions resolved from the database.

Two properties carry this file. The migration must not have changed anyone's
access — storage moved, answers did not. And nobody may grant what they do not
themselves hold, which is the difference between a permission hierarchy and a
lock with the key left in it.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.forensics.models import (
    Organization,
    Permission,
    PermissionGrant,
    Role,
    RolePermission,
    UserProfile,
)
from common.audit import ROLE_PERMISSIONS, Actor, can
from common.permissions import (
    bump_permissions_version,
    ceiling_for,
    effective_permissions,
    permissions_for,
    within_ceiling,
)
from common.tenancy import netra_organization


class SeedFidelityTests(TestCase):
    """The migration moved the tables. It must not have moved the answers."""

    def test_every_code_permission_exists_in_the_catalogue(self):
        catalogued = set(Permission.objects.values_list("key", flat=True))
        enforced = set().union(*ROLE_PERMISSIONS.values())

        self.assertEqual(catalogued, enforced)

    def test_every_seeded_role_grants_exactly_what_the_code_granted(self):
        organization = netra_organization()

        for name, expected in ROLE_PERMISSIONS.items():
            with self.subTest(role=name):
                role = Role.objects.get(organization=organization, slug=name.lower().replace(" ", "_"))
                actual = set(RolePermission.objects.filter(role=role).values_list("permission_id", flat=True))
                self.assertEqual(actual, set(expected))

    def test_seeded_roles_are_marked_as_system(self):
        """They may be cloned but not edited. An organization that could strip
        manage_users from its only role holding it would lock itself out."""
        self.assertTrue(all(Role.objects.filter(organization=netra_organization()).values_list("is_system", flat=True)))


class ResolutionTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        User = get_user_model()
        self.analyst = User.objects.create_user(username="analyst@netra.test", email="analyst@netra.test")
        self.profile = UserProfile.objects.create(
            user=self.analyst,
            organization=self.organization,
            role=UserProfile.Role.ANALYST,
            role_ref=Role.objects.get(organization=self.organization, slug="analyst"),
        )

    def _grant(self, key, mode=PermissionGrant.Mode.GRANT, expires_at=None):
        return PermissionGrant.objects.create(
            organization=self.organization,
            user=self.analyst,
            permission_id=key,
            mode=mode,
            reason="Recorded under test.",
            expires_at=expires_at,
        )

    def test_a_role_alone_resolves_to_its_permissions(self):
        self.assertEqual(effective_permissions(self.profile), ROLE_PERMISSIONS["Analyst"])

    def test_a_grant_adds_to_the_role(self):
        self._grant("export")

        self.assertIn("export", effective_permissions(self.profile))

    def test_a_revocation_removes_from_the_role(self):
        self._grant("upload", mode=PermissionGrant.Mode.REVOKE)

        self.assertNotIn("upload", effective_permissions(self.profile))
        self.assertIn("view", effective_permissions(self.profile))

    def test_an_expired_grant_stops_counting(self):
        """A temporary grant that outlives its expiry is the same as one that
        was never temporary."""
        self._grant("export", expires_at=timezone.now() - timedelta(minutes=1))

        self.assertNotIn("export", effective_permissions(self.profile))

    def test_a_grant_expiring_later_still_counts(self):
        self._grant("export", expires_at=timezone.now() + timedelta(days=1))

        self.assertIn("export", effective_permissions(self.profile))

    def test_editing_a_role_changes_what_its_holders_can_do(self):
        """The point of the whole phase: a permission change without a deploy."""
        role = Role.objects.create(organization=self.organization, slug="records_desk", name="Records Desk")
        RolePermission.objects.create(role=role, permission_id="view")
        UserProfile.objects.filter(pk=self.profile.pk).update(role_ref=role)
        self.profile.refresh_from_db()

        self.assertEqual(effective_permissions(self.profile), {"view"})

        RolePermission.objects.create(role=role, permission_id="report")

        self.assertEqual(effective_permissions(self.profile), {"view", "report"})

    def test_a_profile_without_a_database_role_still_resolves(self):
        """role_ref is nullable through the transition. Returning nothing for an
        un-backfilled profile would take away every permission it had."""
        UserProfile.objects.filter(pk=self.profile.pk).update(role_ref=None)
        self.profile.refresh_from_db()

        self.assertEqual(effective_permissions(self.profile), ROLE_PERMISSIONS["Analyst"])

    def test_can_reads_the_resolved_set_when_one_is_present(self):
        actor = Actor(
            user="analyst",
            role="Analyst",
            authenticated=True,
            django_user_id=self.analyst.id,
            organization_id=self.organization.id,
            permissions=frozenset({"view", "export"}),
        )

        self.assertTrue(can(actor, "export"))
        self.assertFalse(can(actor, "manage_users"))

    def test_can_falls_back_to_the_code_table_for_an_actor_with_no_profile(self):
        """Header and trusted-LAN actors have no row. Treating that as an empty
        set would refuse every request rather than admit the situation."""
        actor = Actor(user="dev", role="Investigator", authenticated=True)

        self.assertTrue(can(actor, "review"))
        self.assertFalse(can(actor, "manage_users"))

    def test_permissions_for_reads_the_database(self):
        self._grant("export")

        self.assertIn("export", permissions_for(self.analyst.id, self.organization.id))

    def test_version_bump_invalidates_the_cross_request_cache(self):
        self.assertNotIn("export", permissions_for(self.analyst.id, self.organization.id))
        self._grant("export")
        bump_permissions_version(self.organization)

        self.assertIn("export", permissions_for(self.analyst.id, self.organization.id))


class CeilingTests(TestCase):
    """Nobody may confer what they do not hold.

    Without this, any account with manage_users can grant itself everything and
    the hierarchy means nothing.
    """

    def setUp(self):
        self.organization = netra_organization()
        User = get_user_model()
        self.admin = User.objects.create_user(username="chief@netra.test", email="chief@netra.test")
        UserProfile.objects.create(
            user=self.admin,
            organization=self.organization,
            role=UserProfile.Role.ADMIN,
            role_ref=Role.objects.get(organization=self.organization, slug="admin"),
        )
        self.analyst = User.objects.create_user(username="analyst@netra.test", email="analyst@netra.test")
        UserProfile.objects.create(
            user=self.analyst,
            organization=self.organization,
            role=UserProfile.Role.ANALYST,
            role_ref=Role.objects.get(organization=self.organization, slug="analyst"),
        )

    def _actor(self, user, role):
        return Actor(
            user=user.username,
            role=role,
            authenticated=True,
            django_user_id=user.id,
            organization_id=self.organization.id,
        )

    def test_an_administrator_may_confer_everything_they_hold(self):
        self.assertEqual(ceiling_for(self._actor(self.admin, "Admin")), ROLE_PERMISSIONS["Admin"])

    def test_a_lesser_administrator_cannot_confer_beyond_their_own_set(self):
        requested = {"view", "export", "manage_users"}

        allowed = within_ceiling(self._actor(self.analyst, "Analyst"), requested)

        # Analyst holds view; export and manage_users are refused because the
        # person granting them does not hold them either.
        self.assertEqual(allowed, {"view"})

    def test_the_ceiling_follows_a_revocation(self):
        """Taking a permission away must also take away the ability to hand it
        on, or the revocation is cosmetic."""
        PermissionGrant.objects.create(
            organization=self.organization,
            user=self.admin,
            permission_id="export",
            mode=PermissionGrant.Mode.REVOKE,
            reason="Under review.",
        )

        self.assertNotIn("export", ceiling_for(self._actor(self.admin, "Admin")))

    def test_the_ceiling_is_empty_for_an_actor_with_no_profile(self):
        self.assertEqual(ceiling_for(Actor(user="nobody", role="Viewer")), set())


class VersionTests(TestCase):
    def test_a_permission_change_bumps_the_organization_version(self):
        """The version makes old cross-request cache entries unreachable."""
        organization = netra_organization()
        before = organization.permissions_version

        bump_permissions_version(organization)
        organization.refresh_from_db()

        self.assertEqual(organization.permissions_version, before + 1)


class OwnershipTests(TestCase):
    def test_ownership_is_separate_from_the_administrator_role(self):
        """Several people may administer an organization; one owns it."""
        organization = Organization.objects.create(name="Station C", slug="station-c")
        User = get_user_model()
        head = User.objects.create_user(username="head@station-c.test")
        deputy = User.objects.create_user(username="deputy@station-c.test")
        for user in (head, deputy):
            UserProfile.objects.create(user=user, organization=organization, role=UserProfile.Role.ADMIN)

        organization.owner = head
        organization.save(update_fields=["owner"])

        self.assertEqual(
            UserProfile.objects.filter(organization=organization, role=UserProfile.Role.ADMIN).count(), 2
        )
        self.assertEqual(organization.owner_id, head.id)
