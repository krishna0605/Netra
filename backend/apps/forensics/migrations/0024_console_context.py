from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0023_partition_access_logs"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="must_change_password",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="mfa_reset_required",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="ConsoleContext",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("session_id", models.CharField(max_length=128)),
                ("permissions_version", models.PositiveBigIntegerField()),
                ("assurance_level", models.CharField(default="aal2", max_length=8)),
                ("active_workspace", models.CharField(default="investigation", max_length=24)),
                ("allowed_workspaces_json", models.JSONField(default=list)),
                ("last_seen_at", models.DateTimeField()),
                ("expires_at", models.DateTimeField()),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_reason", models.CharField(blank=True, max_length=160)),
                (
                    "organization",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="console_contexts", to="forensics.organization"),
                ),
                (
                    "user",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="netra_console_contexts", to=settings.AUTH_USER_MODEL),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["user", "session_id", "revoked_at"], name="netra_ctx_user_session_idx"),
                    models.Index(fields=["organization", "expires_at"], name="netra_ctx_org_expiry_idx"),
                ],
            },
        ),
    ]
