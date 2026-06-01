from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0004_integration_pending_default"),
    ]

    operations = [
        migrations.CreateModel(
            name="Sensor",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=80, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=160)),
                ("hostname", models.CharField(max_length=160)),
                ("platform", models.CharField(max_length=80)),
                ("agent_version", models.CharField(default="phase5-v1", max_length=40)),
                ("capture_engine", models.CharField(max_length=160)),
                ("capture_engine_version", models.CharField(blank=True, max_length=255)),
                ("status", models.CharField(choices=[("online", "Online"), ("stale", "Stale"), ("offline", "Offline")], default="online", max_length=24)),
                ("last_heartbeat_at", models.DateTimeField(blank=True, null=True)),
                ("interfaces_json", models.JSONField(blank=True, default=list)),
                ("metadata_json", models.JSONField(blank=True, default=dict)),
            ],
        ),
        migrations.AddField(model_name="capturejob", name="chunk_count", field=models.PositiveIntegerField(default=0)),
        migrations.AddField(model_name="capturejob", name="chunk_interval_seconds", field=models.PositiveIntegerField(default=5)),
        migrations.AddField(model_name="capturejob", name="completed_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="capturejob", name="final_evidence_file", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="capture_sources", to="forensics.evidencefile")),
        migrations.AddField(model_name="capturejob", name="last_chunk_sequence", field=models.PositiveIntegerField(default=0)),
        migrations.AddField(model_name="capturejob", name="progress", field=models.PositiveIntegerField(default=0)),
        migrations.AddField(model_name="capturejob", name="sensor", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="capture_jobs", to="forensics.sensor")),
        migrations.AddField(model_name="capturejob", name="source_label", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="capturejob", name="started_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AlterField(model_name="capturejob", name="mode", field=models.CharField(choices=[("stored_pcap", "Stored PCAP"), ("replay", "Replay"), ("live_capture", "Live Capture"), ("log_import", "Log Import")], max_length=32)),
        migrations.AlterField(model_name="capturejob", name="status", field=models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("stopped", "Stopped"), ("completed", "Completed"), ("failed", "Failed")], default="queued", max_length=32)),
        migrations.CreateModel(
            name="CaptureChunk",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=100, primary_key=True, serialize=False)),
                ("sequence", models.PositiveIntegerField()),
                ("stored_path", models.CharField(max_length=500)),
                ("plaintext_sha256", models.CharField(max_length=64)),
                ("encrypted_sha256", models.CharField(max_length=64)),
                ("packet_count", models.PositiveIntegerField(default=0)),
                ("byte_count", models.BigIntegerField(default=0)),
                ("captured_from", models.DateTimeField(blank=True, null=True)),
                ("captured_to", models.DateTimeField(blank=True, null=True)),
                ("status", models.CharField(choices=[("received", "Received"), ("parsed", "Parsed"), ("failed", "Failed")], default="received", max_length=24)),
                ("capture_job", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="chunks", to="forensics.capturejob")),
                ("sensor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="capture_chunks", to="forensics.sensor")),
            ],
            options={"unique_together": {("capture_job", "sequence")}},
        ),
        migrations.CreateModel(
            name="OperationalEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("event_type", models.CharField(max_length=120)),
                ("payload_json", models.JSONField(blank=True, default=dict)),
                ("capture_job", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="operational_events", to="forensics.capturejob")),
                ("case", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="operational_events", to="forensics.case")),
            ],
            options={"indexes": [models.Index(fields=["capture_job", "id"], name="netra_ops_job_id_idx")]},
        ),
        migrations.CreateModel(
            name="WorkerHeartbeat",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("worker_name", models.CharField(max_length=80)),
                ("instance_id", models.CharField(max_length=160)),
                ("status", models.CharField(default="healthy", max_length=24)),
                ("last_seen_at", models.DateTimeField()),
                ("current_job_id", models.CharField(blank=True, max_length=80)),
                ("details_json", models.JSONField(blank=True, default=dict)),
            ],
            options={"unique_together": {("worker_name", "instance_id")}},
        ),
        migrations.CreateModel(
            name="WorkerStageReceipt",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("idempotency_key", models.CharField(max_length=255, primary_key=True, serialize=False)),
                ("worker_name", models.CharField(max_length=80)),
                ("job_id", models.CharField(max_length=80)),
                ("chunk_id", models.CharField(blank=True, max_length=100)),
                ("stage", models.CharField(max_length=80)),
                ("result_json", models.JSONField(blank=True, default=dict)),
            ],
        ),
    ]
