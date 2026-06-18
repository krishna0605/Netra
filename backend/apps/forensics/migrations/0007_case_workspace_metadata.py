from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("forensics", "0006_analysischunk_analysisstageresult_captureschedule_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="case",
            name="closed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="case",
            name="flags_json",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="case",
            name="is_test",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="case",
            name="opened_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="case",
            name="origin",
            field=models.CharField(
                choices=[
                    ("officer_upload", "Officer upload"),
                    ("sensor_capture", "Sensor capture"),
                    ("replay", "Replay"),
                    ("validator", "Validator"),
                    ("system_test", "System test"),
                ],
                default="officer_upload",
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="CaseLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("relation_type", models.CharField(default="manual_link", max_length=80)),
                ("notes", models.TextField(blank=True)),
                ("created_by", models.CharField(blank=True, max_length=160)),
                ("source_case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="outgoing_links", to="forensics.case")),
                ("target_case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="incoming_links", to="forensics.case")),
            ],
            options={
                "indexes": [
                    models.Index(fields=["source_case", "created_at"], name="netra_caselink_src_idx"),
                    models.Index(fields=["target_case", "created_at"], name="netra_caselink_tgt_idx"),
                ],
                "unique_together": {("source_case", "target_case", "relation_type")},
            },
        ),
        migrations.AddIndex(
            model_name="case",
            index=models.Index(fields=["is_test", "updated_at"], name="netra_case_test_upd_idx"),
        ),
        migrations.AddIndex(
            model_name="case",
            index=models.Index(fields=["origin", "updated_at"], name="netra_case_origin_upd_idx"),
        ),
    ]
