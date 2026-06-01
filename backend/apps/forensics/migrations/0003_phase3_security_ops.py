from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("forensics", "0002_phase2_persistence"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("role", models.CharField(choices=[("Admin", "Admin"), ("Investigator", "Investigator"), ("Analyst", "Analyst"), ("Viewer", "Viewer")], default="Investigator", max_length=32)),
                ("display_name", models.CharField(blank=True, max_length=160)),
                ("department", models.CharField(default="Gujarat Cyber Crime Cell", max_length=160)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="netra_profile", to=settings.AUTH_USER_MODEL)),
            ],
            options={"abstract": False},
        ),
        migrations.CreateModel(
            name="CaseMembership",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("role", models.CharField(choices=[("Admin", "Admin"), ("Investigator", "Investigator"), ("Analyst", "Analyst"), ("Viewer", "Viewer")], max_length=32)),
                ("added_by", models.CharField(blank=True, max_length=160)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="memberships", to="forensics.case")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="netra_case_memberships", to=settings.AUTH_USER_MODEL)),
            ],
            options={"unique_together": {("case", "user")}},
        ),
        migrations.CreateModel(
            name="EvidenceManifest",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=80, primary_key=True, serialize=False)),
                ("plaintext_sha256", models.CharField(max_length=64)),
                ("encrypted_sha256", models.CharField(max_length=64)),
                ("storage_uri", models.CharField(max_length=500)),
                ("original_filename", models.CharField(max_length=255)),
                ("size_bytes", models.BigIntegerField(default=0)),
                ("encryption_algorithm", models.CharField(max_length=80)),
                ("key_id", models.CharField(max_length=80)),
                ("manifest_json", models.JSONField(blank=True, default=dict)),
                ("manifest_hash", models.CharField(max_length=64)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="evidence_manifests", to="forensics.case")),
                ("evidence_file", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="manifest", to="forensics.evidencefile")),
            ],
            options={"abstract": False},
        ),
        migrations.CreateModel(
            name="IntegrationCredential",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("secret_label", models.CharField(blank=True, max_length=160)),
                ("secret_value", models.TextField(blank=True)),
                ("integration", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="credential", to="forensics.integrationconnection")),
            ],
            options={"abstract": False},
        ),
        migrations.CreateModel(
            name="IntegrationDelivery",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("delivery_type", models.CharField(max_length=80)),
                ("payload_json", models.JSONField(blank=True, default=dict)),
                ("result", models.CharField(default="queued", max_length=32)),
                ("response_summary", models.TextField(blank=True)),
                ("artifact_path", models.CharField(blank=True, max_length=500)),
                ("artifact_sha256", models.CharField(blank=True, max_length=64)),
                ("case", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="integration_deliveries", to="forensics.case")),
                ("integration", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="deliveries", to="forensics.integrationconnection")),
            ],
            options={"abstract": False},
        ),
        migrations.CreateModel(
            name="CustodyLedgerEvent",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=80, primary_key=True, serialize=False)),
                ("actor_user", models.CharField(blank=True, max_length=160)),
                ("actor_label", models.CharField(max_length=160)),
                ("actor_role", models.CharField(max_length=32)),
                ("action", models.CharField(max_length=160)),
                ("resource_type", models.CharField(blank=True, max_length=80)),
                ("resource_id", models.CharField(blank=True, max_length=160)),
                ("details_json", models.JSONField(blank=True, default=dict)),
                ("previous_hash", models.CharField(blank=True, max_length=64)),
                ("event_hash", models.CharField(max_length=64)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="custody_ledger", to="forensics.case")),
                ("evidence_file", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="custody_ledger", to="forensics.evidencefile")),
            ],
            options={"abstract": False},
        ),
        migrations.CreateModel(
            name="DeadLetterEvent",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=80, primary_key=True, serialize=False)),
                ("topic", models.CharField(max_length=160)),
                ("worker_name", models.CharField(max_length=80)),
                ("job_id", models.CharField(blank=True, max_length=80)),
                ("case_id", models.CharField(blank=True, max_length=80)),
                ("evidence_id", models.CharField(blank=True, max_length=80)),
                ("payload_json", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField()),
                ("traceback_summary", models.TextField(blank=True)),
                ("retry_count", models.PositiveIntegerField(default=0)),
                ("status", models.CharField(choices=[("new", "New"), ("retrying", "Retrying"), ("resolved", "Resolved"), ("ignored", "Ignored")], default="new", max_length=32)),
            ],
            options={"abstract": False},
        ),
    ]
