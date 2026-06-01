import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("forensics", "0001_initial"),
    ]

    operations = [
        migrations.AddField("processingjob", "steps", models.JSONField(blank=True, default=list)),
        migrations.AddField("processingjob", "events", models.JSONField(blank=True, default=list)),
        migrations.AddField("processingjob", "started_at", models.DateTimeField(blank=True, null=True)),
        migrations.AddField("processingjob", "completed_at", models.DateTimeField(blank=True, null=True)),
        migrations.AddField("alert", "rule_id", models.CharField(blank=True, max_length=120)),
        migrations.AddField("alert", "evidence_packet_ids", models.JSONField(blank=True, default=list)),
        migrations.AddField("alert", "evidence_session_ids", models.JSONField(blank=True, default=list)),
        migrations.AddField("alert", "recommended_action", models.TextField(blank=True)),
        migrations.AddField("detectionmatch", "rule_id", models.CharField(blank=True, max_length=120)),
        migrations.AddField("detectionmatch", "attack_class", models.CharField(blank=True, max_length=120)),
        migrations.AddField("detectionmatch", "evidence_packet_ids", models.JSONField(blank=True, default=list)),
        migrations.AddField("detectionmatch", "evidence_session_ids", models.JSONField(blank=True, default=list)),
        migrations.AddField("detectionmatch", "recommended_action", models.TextField(blank=True)),
        migrations.AddField("anomalyrecord", "top_features", models.JSONField(blank=True, default=list)),
        migrations.AddField("anomalyrecord", "recommended_action", models.TextField(blank=True)),
        migrations.CreateModel(
            name="ZeekLogSummary",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=80, primary_key=True, serialize=False)),
                ("job_id", models.CharField(max_length=80)),
                ("status", models.CharField(default="not-run", max_length=40)),
                ("log_dir", models.CharField(blank=True, max_length=500)),
                ("logs", models.JSONField(blank=True, default=list)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("top_services", models.JSONField(blank=True, default=list)),
                ("top_dns_queries", models.JSONField(blank=True, default=list)),
                ("top_external_hosts", models.JSONField(blank=True, default=list)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="zeek_summaries", to="forensics.case")),
                ("evidence_file", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="zeek_summaries", to="forensics.evidencefile")),
            ],
            options={"abstract": False},
        ),
        migrations.AddIndex("case", models.Index(fields=["status", "updated_at"], name="netra_case_status_upd_idx")),
        migrations.AddIndex("evidencefile", models.Index(fields=["case", "created_at"], name="netra_ev_case_created_idx")),
        migrations.AddIndex("processingjob", models.Index(fields=["case", "status"], name="netra_job_case_status_idx")),
        migrations.AddIndex("alert", models.Index(fields=["case", "status", "severity"], name="netra_alert_case_stat_idx")),
        migrations.AddIndex("sessionsummary", models.Index(fields=["case", "protocol"], name="netra_sess_case_proto_idx")),
    ]
