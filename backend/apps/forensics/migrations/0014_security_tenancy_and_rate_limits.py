import uuid

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


NETRA_ORGANIZATION_ID = uuid.UUID("d1a04e58-9de1-5ed9-82d0-68b836ef3e10")


def seed_and_backfill_netra_organization(apps, _schema_editor):
    Organization = apps.get_model("forensics", "Organization")
    UserProfile = apps.get_model("forensics", "UserProfile")
    Case = apps.get_model("forensics", "Case")
    EvidenceUploadSession = apps.get_model("forensics", "EvidenceUploadSession")
    AccessLog = apps.get_model("forensics", "AccessLog")
    OperationalEvent = apps.get_model("forensics", "OperationalEvent")

    if UserProfile.objects.filter(role="Admin").count() > 1:
        raise RuntimeError(
            "Phase 2 tenancy migration found more than one legacy Admin. "
            "Resolve the administrator ownership explicitly before retrying."
        )

    organization, _ = Organization.objects.update_or_create(
        id=NETRA_ORGANIZATION_ID,
        defaults={"name": "Netra", "slug": "netra", "max_queued_analyses": 5},
    )
    organization_id = organization.id

    UserProfile.objects.filter(organization__isnull=True).update(organization_id=organization_id)
    AccessLog.objects.filter(organization__isnull=True).update(organization_id=organization_id)
    OperationalEvent.objects.filter(organization__isnull=True).update(organization_id=organization_id)

    for case in Case.objects.filter(organization__isnull=True).iterator():
        case.organization_id = organization_id
        case.display_reference = case.id
        case.save(update_fields=["organization", "display_reference"])

    for session in EvidenceUploadSession.objects.filter(organization__isnull=True).iterator():
        label = (session.legacy_organization_label or "").strip()
        intake = session.intake_json if isinstance(session.intake_json, dict) else {}
        if label and label.lower() != "netra":
            intake = {**intake, "legacyOrganizationLabel": label}
        session.organization_id = organization_id
        session.intake_json = intake
        session.save(update_fields=["organization", "intake_json"])

    null_checks = {
        "profiles": UserProfile.objects.filter(organization__isnull=True).count(),
        "cases": Case.objects.filter(organization__isnull=True).count(),
        "case display references": Case.objects.filter(display_reference__isnull=True).count(),
        "upload sessions": EvidenceUploadSession.objects.filter(organization__isnull=True).count(),
        "access logs": AccessLog.objects.filter(organization__isnull=True).count(),
        "operational events": OperationalEvent.objects.filter(organization__isnull=True).count(),
    }
    invalid = [f"{name}={count}" for name, count in null_checks.items() if count]
    if invalid:
        raise RuntimeError(f"Phase 2 tenancy backfill left invalid rows: {', '.join(invalid)}")


def restore_legacy_organization_labels(apps, _schema_editor):
    EvidenceUploadSession = apps.get_model("forensics", "EvidenceUploadSession")
    for session in EvidenceUploadSession.objects.select_related("organization").iterator():
        label = session.organization.name if session.organization_id else "Netra"
        session.legacy_organization_label = label
        session.save(update_fields=["legacy_organization_label"])


class Migration(migrations.Migration):
    dependencies = [("forensics", "0013_case_route_ref_and_statuses")]

    operations = [
        migrations.CreateModel(
            name="Organization",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=120)),
                ("slug", models.SlugField(max_length=80, unique=True)),
                (
                    "max_queued_analyses",
                    models.PositiveIntegerField(default=5, validators=[django.core.validators.MinValueValidator(1)]),
                ),
            ],
            options={
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(("max_queued_analyses__gte", 1)),
                        name="netra_org_queue_min_one",
                    )
                ]
            },
        ),
        migrations.CreateModel(
            name="ApiRateLimitBucket",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("scope_key", models.CharField(max_length=160)),
                ("route_key", models.CharField(max_length=80)),
                ("window_start", models.DateTimeField()),
                ("window_seconds", models.PositiveIntegerField()),
                ("request_count", models.PositiveIntegerField(default=0)),
                ("byte_count", models.PositiveBigIntegerField(default=0)),
                ("expires_at", models.DateTimeField()),
                (
                    "organization",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="rate_limit_buckets", to="forensics.organization"),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="netra_rate_limit_buckets",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["organization", "route_key", "window_start"], name="netra_rate_org_route_idx"),
                    models.Index(fields=["expires_at"], name="netra_rate_expiry_idx"),
                ],
                "constraints": [
                    models.UniqueConstraint(fields=("organization", "scope_key", "route_key"), name="netra_rate_bucket_uniq"),
                    models.CheckConstraint(condition=models.Q(("window_seconds__gte", 1)), name="netra_rate_window_positive"),
                    models.CheckConstraint(condition=models.Q(("request_count__gte", 0)), name="netra_rate_count_nonnegative"),
                    models.CheckConstraint(condition=models.Q(("byte_count__gte", 0)), name="netra_rate_bytes_nonnegative"),
                    models.CheckConstraint(
                        condition=(
                            models.Q(("scope_key__startswith", "user:"), ("user__isnull", False))
                            | models.Q(("scope_key__startswith", "org:"), ("user__isnull", True))
                        ),
                        name="netra_rate_scope_user_match",
                    ),
                ],
            },
        ),
        migrations.RemoveIndex(
            model_name="evidenceuploadsession",
            name="netra_upload_org_status_idx",
        ),
        migrations.RenameField(
            model_name="evidenceuploadsession",
            old_name="organization",
            new_name="legacy_organization_label",
        ),
        migrations.AlterField(
            model_name="evidenceuploadsession",
            name="legacy_organization_label",
            field=models.CharField(max_length=160, null=True),
        ),
        migrations.AddField(
            model_name="case",
            name="display_reference",
            field=models.CharField(max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="case",
            name="organization",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name="cases", to="forensics.organization"),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="organization",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name="user_profiles", to="forensics.organization"),
        ),
        migrations.AddField(
            model_name="evidenceuploadsession",
            name="organization",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name="upload_sessions", to="forensics.organization"),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="organization",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name="access_logs", to="forensics.organization"),
        ),
        migrations.AddField(
            model_name="operationalevent",
            name="organization",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name="operational_events", to="forensics.organization"),
        ),
        migrations.RunPython(seed_and_backfill_netra_organization, restore_legacy_organization_labels),
        migrations.RemoveField(model_name="evidenceuploadsession", name="legacy_organization_label"),
        migrations.AlterField(
            model_name="case",
            name="display_reference",
            field=models.CharField(max_length=64),
        ),
        migrations.AlterField(
            model_name="case",
            name="organization",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="cases", to="forensics.organization"),
        ),
        migrations.AlterField(
            model_name="userprofile",
            name="organization",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="user_profiles", to="forensics.organization"),
        ),
        migrations.AlterField(
            model_name="evidenceuploadsession",
            name="organization",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="upload_sessions", to="forensics.organization"),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="organization",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="access_logs", to="forensics.organization"),
        ),
        migrations.AlterField(
            model_name="operationalevent",
            name="organization",
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="operational_events", to="forensics.organization"),
        ),
        migrations.AddIndex(
            model_name="case",
            index=models.Index(fields=["organization", "status", "updated_at"], name="netra_case_org_status_idx"),
        ),
        migrations.AddIndex(
            model_name="userprofile",
            index=models.Index(fields=["organization", "role"], name="netra_profile_org_role_idx"),
        ),
        migrations.AddIndex(
            model_name="evidenceuploadsession",
            index=models.Index(fields=["organization", "user", "status", "expires_at"], name="netra_upload_org_usr_idx"),
        ),
        migrations.AddIndex(
            model_name="accesslog",
            index=models.Index(fields=["organization", "created_at"], name="netra_access_org_created_idx"),
        ),
        migrations.AddIndex(
            model_name="accesslog",
            index=models.Index(fields=["organization", "case", "created_at"], name="netra_access_org_case_idx"),
        ),
        migrations.AddIndex(
            model_name="operationalevent",
            index=models.Index(fields=["organization", "created_at"], name="netra_ops_org_created_idx"),
        ),
        migrations.AddIndex(
            model_name="operationalevent",
            index=models.Index(fields=["organization", "id"], name="netra_ops_org_id_idx"),
        ),
        migrations.AddConstraint(
            model_name="case",
            constraint=models.UniqueConstraint(fields=("organization", "display_reference"), name="netra_case_org_display_uniq"),
        ),
        migrations.AddConstraint(
            model_name="userprofile",
            constraint=models.UniqueConstraint(condition=models.Q(("role", "Admin")), fields=("organization",), name="netra_one_admin_per_org"),
        ),
    ]
