"""Grants, roles, organization settings and ownership, over HTTP.

The property this file exists for is the ceiling: an administrator may confer
only what they hold. It is tested through the endpoint rather than only against
the resolver, because a check that lives in a service and is not called by the
view protects nothing.
"""

import time

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import (
    AdminAuditEvent,
    Organization,
    PermissionGrant,
    Role,
    RolePermission,
    UserProfile,
)
from common.permissions import effective_permissions
from common.tenancy import netra_organization


SECURE_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_RATE_LIMITS_ENABLED=False,
    SUPABASE_URL="",
    SUPABASE_SECRET_KEY="",
)

REASON = "Recorded for the purposes of this test."


class PermissionApiBase(TestCase):
    def setUp(self):
        self.client = Client()
        self.organization = netra_organization()
        User = get_user_model()

        self.head = User.objects.create_user(username="head@gcc.gov.in", email="head@gcc.gov.in", is_active=True)
        self.deputy = User.objects.create_user(username="deputy@gcc.gov.in", email="deputy@gcc.gov.in", is_active=True)
        self.officer = User.objects.create_user(
            username="officer@gcc.gov.in", email="officer@gcc.gov.in", is_active=True
        )
        for user, role in (
            (self.head, "Admin"),
            (self.deputy, "Admin"),
            (self.officer, "Analyst"),
        ):
            UserProfile.objects.create(
                user=user,
                organization=self.organization,
                role=role,
                role_ref=Role.objects.get(organization=self.organization, slug=role.lower()),
            )
        self.organization.owner = self.head
        self.organization.save(update_fields=["owner"])

    def _headers(self, user, *, fresh=True):
        token = RefreshToken.for_user(user).access_token
        token["aal"] = "aal2"
        now = int(time.time())
        token["amr"] = [{"method": "totp", "timestamp": now - (30 if fresh else 8 * 3600)}]
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _code(self, response) -> str:
        body = response.json()
        error = body.get("error")
        return error.get("code", "") if isinstance(error, dict) else body.get("code", "")

    def _send(self, method, path, payload=None, user=None, **kwargs):
        return getattr(self.client, method)(
            path,
            data=payload or {},
            content_type="application/json",
            **self._headers(user or self.head, **kwargs),
        )

    def _profile(self, user):
        return UserProfile.objects.select_related("role_ref").get(user=user)


@SECURE_SETTINGS
class GrantTests(PermissionApiBase):
    def test_granting_adds_a_permission_the_role_does_not_carry(self):
        self.assertNotIn("export", effective_permissions(self._profile(self.officer)))

        response = self._send(
            "post", f"/api/admin/v1/users/{self.officer.id}/grants", {"permission": "export", "reason": REASON}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("export", effective_permissions(self._profile(self.officer)))

    def test_a_grant_beyond_your_own_permissions_is_refused(self):
        """The whole point of the ceiling.

        The deputy is a full administrator whose own export right has been
        taken away. They may still administer accounts — that is what the role
        gives them — and they may not hand on a permission they no longer hold.
        Without this, anyone with manage_users can grant themselves everything.
        """
        PermissionGrant.objects.create(
            organization=self.organization,
            user=self.deputy,
            permission_id="export",
            mode=PermissionGrant.Mode.REVOKE,
            reason="Export rights suspended pending review.",
        )

        response = self._send(
            "post",
            f"/api/admin/v1/users/{self.officer.id}/grants",
            {"permission": "export", "reason": REASON},
            user=self.deputy,
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._code(response), "beyond_your_permissions")
        self.assertNotIn("export", effective_permissions(self._profile(self.officer)))

    def test_the_same_grant_succeeds_from_someone_who_holds_it(self):
        """Otherwise the refusal above could be anything — a broken endpoint
        looks identical to a working ceiling."""
        response = self._send(
            "post", f"/api/admin/v1/users/{self.officer.id}/grants", {"permission": "export", "reason": REASON}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("export", effective_permissions(self._profile(self.officer)))

    def test_revoking_is_not_ceilinged(self):
        """An administrator whose own export right was taken away should still
        be able to stop somebody else exporting. Requiring the permission in
        order to remove it would make the safest action the hardest one."""
        PermissionGrant.objects.create(
            organization=self.organization,
            user=self.deputy,
            permission_id="export",
            mode=PermissionGrant.Mode.REVOKE,
            reason="Export rights suspended pending review.",
        )

        response = self._send(
            "post",
            f"/api/admin/v1/users/{self.officer.id}/grants",
            {"permission": "view", "mode": "revoke", "reason": REASON},
            user=self.deputy,
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("view", effective_permissions(self._profile(self.officer)))

    def test_an_expiry_in_the_past_is_refused(self):
        response = self._send(
            "post",
            f"/api/admin/v1/users/{self.officer.id}/grants",
            {"permission": "export", "reason": REASON, "expiresAt": "2020-01-01T00:00:00Z"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._code(response), "invalid_expiry")

    def test_a_temporary_grant_records_when_it_ends(self):
        response = self._send(
            "post",
            f"/api/admin/v1/users/{self.officer.id}/grants",
            {"permission": "export", "reason": REASON, "expiresAt": "2099-01-01T00:00:00Z"},
        )

        self.assertEqual(response.status_code, 200)
        grant = PermissionGrant.objects.get(user=self.officer, permission_id="export")
        self.assertIsNotNone(grant.expires_at)

    def test_removing_an_override_returns_the_role_to_charge(self):
        self._send("post", f"/api/admin/v1/users/{self.officer.id}/grants", {"permission": "export", "reason": REASON})

        response = self.client.delete(
            f"/api/admin/v1/users/{self.officer.id}/grants",
            data='{"permission": "export", "reason": "No longer required for the case."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("export", effective_permissions(self._profile(self.officer)))

    def test_an_unknown_permission_is_refused(self):
        response = self._send(
            "post", f"/api/admin/v1/users/{self.officer.id}/grants", {"permission": "make_tea", "reason": REASON}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._code(response), "unknown_permission")

    def test_a_grant_is_sealed_into_the_chain_with_both_sides(self):
        self._send("post", f"/api/admin/v1/users/{self.officer.id}/grants", {"permission": "export", "reason": REASON})

        entry = AdminAuditEvent.objects.get(action="permission.granted")
        self.assertNotIn("export", entry.before_json["permissions"])
        self.assertIn("export", entry.after_json["permissions"])

    def test_a_stale_authenticator_refuses_a_grant(self):
        response = self._send(
            "post",
            f"/api/admin/v1/users/{self.officer.id}/grants",
            {"permission": "export", "reason": REASON},
            fresh=False,
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(self._code(response), "step_up_required")


@SECURE_SETTINGS
class RoleTests(PermissionApiBase):
    def test_a_standard_role_cannot_be_edited(self):
        """An organization that could strip manage_users from the only role
        holding it would lock itself out with no way back in."""
        response = self.client.put(
            "/api/admin/v1/roles/analyst/permissions/export",
            data='{"reason": "Should not be permitted at all."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "system_role_locked")

    def test_a_new_role_copies_the_one_it_was_based_on(self):
        response = self._send(
            "post",
            "/api/admin/v1/roles",
            {"name": "Records Desk", "description": "", "baseSlug": "analyst", "reason": REASON},
        )

        self.assertEqual(response.status_code, 201)
        created = Role.objects.get(organization=self.organization, slug="records_desk")
        base = Role.objects.get(organization=self.organization, slug="analyst")
        self.assertFalse(created.is_system)
        self.assertEqual(
            set(RolePermission.objects.filter(role=created).values_list("permission_id", flat=True)),
            set(RolePermission.objects.filter(role=base).values_list("permission_id", flat=True)),
        )

    def test_a_cloned_role_can_be_edited(self):
        self._send(
            "post",
            "/api/admin/v1/roles",
            {"name": "Records Desk", "description": "", "baseSlug": "viewer", "reason": REASON},
        )

        response = self.client.put(
            "/api/admin/v1/roles/records_desk/permissions/report",
            data='{"reason": "The desk now produces disclosure packs."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 200)
        role = Role.objects.get(organization=self.organization, slug="records_desk")
        self.assertIn("report", RolePermission.objects.filter(role=role).values_list("permission_id", flat=True))

    def test_a_duplicate_role_name_is_refused(self):
        payload = {"name": "Records Desk", "description": "", "baseSlug": "viewer", "reason": REASON}
        self._send("post", "/api/admin/v1/roles", payload)

        response = self._send("post", "/api/admin/v1/roles", payload)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "role_exists")

    def test_editing_a_role_changes_what_its_holders_can_do(self):
        """The point of the whole phase: a permission change with no deploy."""
        self._send(
            "post",
            "/api/admin/v1/roles",
            {"name": "Records Desk", "description": "", "baseSlug": "viewer", "reason": REASON},
        )
        role = Role.objects.get(organization=self.organization, slug="records_desk")
        UserProfile.objects.filter(user=self.officer).update(role_ref=role)

        self.assertNotIn("report", effective_permissions(self._profile(self.officer)))

        self.client.put(
            "/api/admin/v1/roles/records_desk/permissions/report",
            data='{"reason": "The desk now produces disclosure packs."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertIn("report", effective_permissions(self._profile(self.officer)))


@SECURE_SETTINGS
class OrganizationTests(PermissionApiBase):
    def test_settings_can_be_changed_and_are_recorded(self):
        response = self.client.patch(
            "/api/admin/v1/organization",
            data='{"name": "Gujarat Cyber Cell", "maxQueuedAnalyses": 8, "reason": "Capacity raised after the upgrade."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 200)
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, "Gujarat Cyber Cell")
        self.assertEqual(self.organization.max_queued_analyses, 8)
        self.assertTrue(AdminAuditEvent.objects.filter(action="organization.updated").exists())

    def test_an_out_of_range_queue_limit_is_refused(self):
        response = self.client.patch(
            "/api/admin/v1/organization",
            data='{"maxQueuedAnalyses": 0, "reason": "Should be refused as out of range."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._code(response), "invalid_queue_limit")


@SECURE_SETTINGS
class OwnershipTests(PermissionApiBase):
    def test_the_owner_can_hand_the_organization_over(self):
        response = self._send(
            "post",
            "/api/admin/v1/organization/owner-transfer",
            {"targetUserId": self.deputy.id, "reason": "Handing over at the end of a posting."},
        )

        self.assertEqual(response.status_code, 200)
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.owner_id, self.deputy.id)

    def test_an_administrator_who_is_not_the_owner_cannot_transfer(self):
        """Several people administer an organization; one owns it. Without this
        any administrator could quietly promote themselves past everyone."""
        response = self._send(
            "post",
            "/api/admin/v1/organization/owner-transfer",
            {"targetUserId": self.officer.id, "reason": "Attempting to seize ownership."},
            user=self.deputy,
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._code(response), "owner_only")
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.owner_id, self.head.id)

    def test_ownership_cannot_go_to_a_non_administrator(self):
        """Handing it to somebody who cannot administer leaves nobody able to
        undo the mistake."""
        response = self._send(
            "post",
            "/api/admin/v1/organization/owner-transfer",
            {"targetUserId": self.officer.id, "reason": "They cannot administer anything."},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "target_not_administrator")

    def test_ownership_cannot_be_transferred_to_yourself(self):
        response = self._send(
            "post",
            "/api/admin/v1/organization/owner-transfer",
            {"targetUserId": self.head.id, "reason": "Already the owner of this organization."},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "self_mutation_forbidden")


@SECURE_SETTINGS
class IsolationTests(PermissionApiBase):
    def test_a_role_in_another_organization_is_not_reachable(self):
        other = Organization.objects.create(name="Station B", slug="station-b")
        Role.objects.create(organization=other, slug="their_role", name="Their Role", is_system=False)

        response = self.client.put(
            "/api/admin/v1/roles/their_role/permissions/view",
            data='{"reason": "Should not be reachable from here."}',
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 404)
