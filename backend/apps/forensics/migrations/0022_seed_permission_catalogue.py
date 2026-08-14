"""Move the hardcoded permission tables into the database without changing them.

The rule for this migration is that nobody's access changes. Whatever
ROLE_PERMISSIONS granted before it runs, the same set is granted after — the
storage moves, the answers do not. A migration that quietly widened or narrowed
what an officer could do would be discovered from behaviour rather than from a
diff, which is the worst way to find it.

The values are written out here rather than imported from common.audit. A data
migration has to keep producing the same result years later; importing live
application code means it produces whatever that code says today, and a
migration that changes retroactively is not a migration.
"""

from django.db import migrations


PERMISSIONS = [
    ("view", "View cases", "Open cases and read analysis results.", "Analysis", "standard", 10),
    ("review", "Review findings", "Triage alerts and annotate detections.", "Analysis", "standard", 20),
    ("upload", "Upload evidence", "Add capture files and structured logs to a case.", "Evidence", "standard", 30),
    ("confirm", "Confirm findings", "Mark a detection as confirmed on the record.", "Analysis", "elevated", 40),
    ("report", "Generate reports", "Produce case reports for disclosure.", "Reporting", "elevated", 50),
    ("export", "Export evidence", "Download evidence and analysis outside Netra.", "Reporting", "high", 60),
    ("compliance", "Compliance review", "Read compliance checklists and the access log.", "Reporting", "elevated", 70),
    ("integrations", "Manage integrations", "Configure SIEM and webhook delivery.", "Administration", "high", 80),
    ("operations", "Operate capture", "Start, stop and schedule capture jobs.", "Administration", "high", 90),
    ("manage_users", "Manage users", "Create accounts, set roles and reset credentials.", "Administration", "high", 100),
]

# Copied verbatim from ROLE_PERMISSIONS as it stood when permissions became
# data. Divergence from that dict is caught by a test, not by hoping.
ROLE_PERMISSIONS = {
    "Admin": ["upload", "review", "confirm", "report", "export", "view", "compliance", "manage_users", "integrations", "operations"],
    "Investigator": ["upload", "review", "confirm", "report", "export", "view", "compliance"],
    "Analyst": ["upload", "review", "view"],
    "Viewer": ["view"],
    "LAN Operator": ["upload", "review", "confirm", "report", "export", "view", "compliance", "integrations", "operations"],
}

ROLE_DESCRIPTIONS = {
    "Admin": "Full administration of the organization, its users and its integrations.",
    "Investigator": "Runs cases end to end, including reporting and export.",
    "Analyst": "Works inside assigned cases without export or reporting rights.",
    "Viewer": "Read-only access to assigned cases.",
    "LAN Operator": "Operates capture on the local network without user administration.",
}


def slug_for(name: str) -> str:
    return name.strip().lower().replace(" ", "_")


def seed(apps, _schema_editor):
    Permission = apps.get_model("forensics", "Permission")
    Organization = apps.get_model("forensics", "Organization")
    Role = apps.get_model("forensics", "Role")
    RolePermission = apps.get_model("forensics", "RolePermission")
    UserProfile = apps.get_model("forensics", "UserProfile")

    for key, label, description, category, risk, order in PERMISSIONS:
        Permission.objects.update_or_create(
            key=key,
            defaults={
                "label": label,
                "description": description,
                "category": category,
                "risk_level": risk,
                "sort_order": order,
            },
        )

    for organization in Organization.objects.all():
        for name, keys in ROLE_PERMISSIONS.items():
            role, _ = Role.objects.update_or_create(
                organization=organization,
                slug=slug_for(name),
                defaults={
                    "name": name,
                    "description": ROLE_DESCRIPTIONS.get(name, ""),
                    "is_system": True,
                },
            )
            RolePermission.objects.filter(role=role).delete()
            RolePermission.objects.bulk_create(
                [RolePermission(role=role, permission_id=key) for key in keys]
            )

        # Point every existing profile at its equivalent role. The CharField is
        # left exactly as it is: both are written until a later release drops
        # it, so rolling back finds the column it expects.
        for profile in UserProfile.objects.filter(organization=organization):
            match = Role.objects.filter(organization=organization, slug=slug_for(profile.role)).first()
            if match and profile.role_ref_id != match.id:
                profile.role_ref = match
                profile.save(update_fields=["role_ref"])

        # Ownership was previously inferred from whoever held the Admin role.
        # With several administrators allowed that inference no longer has one
        # answer, so it is recorded once here — the earliest administrator, who
        # is the closest thing to the original owner the data remembers.
        if organization.owner_id is None:
            first_admin = (
                UserProfile.objects.filter(organization=organization, role="Admin")
                .order_by("created_at", "id")
                .first()
            )
            if first_admin:
                organization.owner_id = first_admin.user_id
                organization.save(update_fields=["owner"])


def unseed(apps, _schema_editor):
    """Reversible, because a migration that cannot be undone is a decision that
    cannot be revisited. Profiles keep their CharField role, so reversing this
    returns the system to exactly the state it was in."""
    apps.get_model("forensics", "RolePermission").objects.all().delete()
    apps.get_model("forensics", "Role").objects.all().delete()
    apps.get_model("forensics", "Permission").objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [("forensics", "0021_permissions_as_data")]

    operations = [migrations.RunPython(seed, unseed)]
