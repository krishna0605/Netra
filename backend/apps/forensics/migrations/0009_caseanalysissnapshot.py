from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0008_alter_case_priority"),
    ]

    operations = [
        migrations.CreateModel(
            name="CaseAnalysisSnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("schema_version", models.CharField(default="case-workspace-v1", max_length=40)),
                ("snapshot_json", models.JSONField(blank=True, default=dict)),
                ("generated_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("case", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="analysis_snapshot", to="forensics.case")),
                ("processing_job", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="case_snapshots", to="forensics.processingjob")),
            ],
        ),
        migrations.AddIndex(
            model_name="caseanalysissnapshot",
            index=models.Index(fields=["case", "generated_at"], name="netra_case_snap_case_gen_idx"),
        ),
        migrations.AddIndex(
            model_name="caseanalysissnapshot",
            index=models.Index(fields=["schema_version", "generated_at"], name="netra_case_snap_schema_idx"),
        ),
    ]
