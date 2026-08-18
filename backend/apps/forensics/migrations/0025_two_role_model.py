"""Collapse the role catalogue to Investigator and Admin.

Netra ships two roles: Investigator works cases in the console, Admin does that
and runs the organization. Analyst, Viewer and LAN Operator were seeded by
0022 and never assigned to anybody, and the extra rungs only made the grant
ceiling harder to reason about.

The removal is guarded rather than unconditional. If any profile, grant or
custom role turns out to reference one of the three, the migration refuses and
leaves the catalogue alone — better a failed deploy than a silently
unauthorized account. Reversing re-seeds the three from 0022's definitions.
"""

from django.db import migrations


RETIRED = ("Analyst", "Viewer", "LAN Operator")

# Verbatim from 0022, so a reverse restores exactly what was there before.
RETIRED_PERMISSIONS = {
    "Analyst": {"upload", "review", "view"},
    "Viewer": {"view"},
    "LAN Operator": {
        "upload", "review", "confirm", "report", "export",
        "view", "compliance", "integrations", "operations",
    },
}


def _slug(name):
    return name.lower().replace(" ", "_")


def remove_retired_roles(apps, schema_editor):
    Role = apps.get_model("forensics", "Role")
    UserProfile = apps.get_model("forensics", "UserProfile")
    PermissionGrant = apps.get_model("forensics", "PermissionGrant")
    RolePermission = apps.get_model("forensics", "RolePermission")

    retired = Role.objects.filter(name__in=RETIRED)

    # Refuse rather than orphan. role_ref is SET_NULL, so deleting a role in use
    # would silently drop a profile to its legacy CharField value.
    in_use = UserProfile.objects.filter(role_ref__in=retired)
    if in_use.exists():
        raise RuntimeError(
            "Cannot retire roles still assigned to profiles: "
            + ", ".join(sorted({p.role_ref.name for p in in_use.select_related("role_ref")}))
        )

    legacy_in_use = UserProfile.objects.filter(role__in=RETIRED)
    if legacy_in_use.exists():
        raise RuntimeError(
            "Cannot retire roles still named by UserProfile.role: "
            + ", ".join(sorted({p.role for p in legacy_in_use}))
        )

    granted = PermissionGrant.objects.filter(user__netra_profile__role_ref__in=retired)
    if granted.exists():
        raise RuntimeError("Cannot retire roles that still carry permission grants")

    RolePermission.objects.filter(role__in=retired).delete()
    retired.delete()


def restore_retired_roles(apps, schema_editor):
    Role = apps.get_model("forensics", "Role")
    Permission = apps.get_model("forensics", "Permission")
    RolePermission = apps.get_model("forensics", "RolePermission")
    Organization = apps.get_model("forensics", "Organization")

    for organization in Organization.objects.all():
        for name in RETIRED:
            role, _ = Role.objects.get_or_create(
                organization=organization,
                slug=_slug(name),
                defaults={"name": name, "is_system": True},
            )
            for key in RETIRED_PERMISSIONS[name]:
                permission = Permission.objects.filter(pk=key).first()
                if permission is not None:
                    RolePermission.objects.get_or_create(role=role, permission=permission)


class Migration(migrations.Migration):

    dependencies = [
        ("forensics", "0024_console_context"),
    ]

    operations = [
        migrations.RunPython(remove_retired_roles, restore_retired_roles),
    ]
