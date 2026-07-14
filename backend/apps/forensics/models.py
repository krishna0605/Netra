from django.conf import settings
from django.db import models
from django.utils import timezone


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Case(TimeStampedModel):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        REVIEWING = "reviewing", "Reviewing"
        REPORT_READY = "report-ready", "Report ready"

    class Priority(models.TextChoices):
        UNSET = "", "Unset"
        STANDARD = "Standard", "Standard"
        URGENT = "Urgent", "Urgent"
        CRITICAL = "Critical", "Critical"

    class Origin(models.TextChoices):
        OFFICER_UPLOAD = "officer_upload", "Officer upload"
        SENSOR_CAPTURE = "sensor_capture", "Sensor capture"
        REPLAY = "replay", "Replay"
        VALIDATOR = "validator", "Validator"
        SYSTEM_TEST = "system_test", "System test"

    id = models.CharField(max_length=64, primary_key=True)
    title = models.CharField(max_length=255)
    investigator = models.CharField(max_length=160)
    department = models.CharField(max_length=160, default="Gujarat Cyber Crime Cell")
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.OPEN)
    priority = models.CharField(max_length=32, choices=Priority.choices, default=Priority.STANDARD)
    report_status = models.CharField(max_length=32, default="draft")
    origin = models.CharField(max_length=32, choices=Origin.choices, default=Origin.OFFICER_UPLOAD)
    is_test = models.BooleanField(default=False)
    opened_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    source_location = models.CharField(max_length=255, blank=True)
    remarks = models.TextField(blank=True)
    flags_json = models.JSONField(default=list, blank=True)
    legal_hold = models.BooleanField(default=False)
    legal_hold_reason = models.TextField(blank=True)

    def __str__(self) -> str:
        return self.id

    class Meta:
        indexes = [
            models.Index(fields=["status", "updated_at"], name="netra_case_status_upd_idx"),
            models.Index(fields=["is_test", "updated_at"], name="netra_case_test_upd_idx"),
            models.Index(fields=["origin", "updated_at"], name="netra_case_origin_upd_idx"),
        ]


class CaseLink(TimeStampedModel):
    source_case = models.ForeignKey(Case, related_name="outgoing_links", on_delete=models.CASCADE)
    target_case = models.ForeignKey(Case, related_name="incoming_links", on_delete=models.CASCADE)
    relation_type = models.CharField(max_length=80, default="manual_link")
    notes = models.TextField(blank=True)
    created_by = models.CharField(max_length=160, blank=True)

    class Meta:
        unique_together = ("source_case", "target_case", "relation_type")
        indexes = [
            models.Index(fields=["source_case", "created_at"], name="netra_caselink_src_idx"),
            models.Index(fields=["target_case", "created_at"], name="netra_caselink_tgt_idx"),
        ]


class UserProfile(TimeStampedModel):
    class Role(models.TextChoices):
        ADMIN = "Admin", "Admin"
        INVESTIGATOR = "Investigator", "Investigator"
        ANALYST = "Analyst", "Analyst"
        VIEWER = "Viewer", "Viewer"

    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name="netra_profile", on_delete=models.CASCADE)
    role = models.CharField(max_length=32, choices=Role.choices, default=Role.VIEWER)
    display_name = models.CharField(max_length=160, blank=True)
    department = models.CharField(max_length=160, default="Gujarat Cyber Crime Cell")

    def __str__(self) -> str:
        return f"{self.display_name or self.user.get_username()} ({self.role})"


class CaseMembership(TimeStampedModel):
    case = models.ForeignKey(Case, related_name="memberships", on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="netra_case_memberships", on_delete=models.CASCADE)
    role = models.CharField(max_length=32, choices=UserProfile.Role.choices)
    added_by = models.CharField(max_length=160, blank=True)

    class Meta:
        unique_together = ("case", "user")


class EvidenceFile(TimeStampedModel):
    class EvidenceType(models.TextChoices):
        PCAP = "PCAP", "PCAP"
        FIREWALL_LOGS = "Firewall Logs", "Firewall Logs"
        DNS_LOGS = "DNS Logs", "DNS Logs"
        TLS_METADATA = "TLS Metadata", "TLS Metadata"
        MIXED = "Mixed Evidence", "Mixed Evidence"

    class Status(models.TextChoices):
        VERIFIED = "verified", "Verified"
        PROCESSING = "processing", "Processing"
        FAILED = "failed", "Failed"

    id = models.CharField(max_length=64, primary_key=True)
    case = models.ForeignKey(Case, related_name="evidence_files", on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    stored_path = models.CharField(max_length=500)
    evidence_type = models.CharField(max_length=64, choices=EvidenceType.choices, default=EvidenceType.PCAP)
    size_bytes = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64)
    captured_at = models.DateTimeField(null=True, blank=True)
    uploaded_by = models.CharField(max_length=160)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.VERIFIED)
    retention_expires_at = models.DateTimeField(null=True, blank=True)
    legal_hold = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.filename

    class Meta:
        indexes = [models.Index(fields=["case", "created_at"], name="netra_ev_case_created_idx")]


class EvidenceManifest(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="evidence_manifests", on_delete=models.CASCADE)
    evidence_file = models.OneToOneField(EvidenceFile, related_name="manifest", on_delete=models.CASCADE)
    plaintext_sha256 = models.CharField(max_length=64)
    encrypted_sha256 = models.CharField(max_length=64)
    storage_uri = models.CharField(max_length=500)
    original_filename = models.CharField(max_length=255)
    size_bytes = models.BigIntegerField(default=0)
    encryption_algorithm = models.CharField(max_length=80)
    key_id = models.CharField(max_length=80)
    manifest_json = models.JSONField(default=dict, blank=True)
    manifest_hash = models.CharField(max_length=64)


class CaptureJob(TimeStampedModel):
    class Mode(models.TextChoices):
        STORED_PCAP = "stored_pcap", "Stored PCAP"
        REPLAY = "replay", "Replay"
        LIVE_CAPTURE = "live_capture", "Live Capture"
        LOG_IMPORT = "log_import", "Log Import"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        STOPPED = "stopped", "Stopped"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.CharField(max_length=64, primary_key=True)
    case = models.ForeignKey(Case, related_name="capture_jobs", on_delete=models.CASCADE)
    mode = models.CharField(max_length=32, choices=Mode.choices)
    interface_name = models.CharField(max_length=80, blank=True)
    duration_seconds = models.PositiveIntegerField(default=0)
    packet_limit = models.PositiveIntegerField(default=0)
    bpf_filter = models.CharField(max_length=255, blank=True)
    source_ip_filter = models.GenericIPAddressField(null=True, blank=True)
    destination_ip_filter = models.CharField(max_length=255, blank=True)
    protocol_filter = models.CharField(max_length=40, blank=True)
    port_filter = models.PositiveIntegerField(null=True, blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)
    packets_captured = models.PositiveIntegerField(default=0)
    bytes_captured = models.BigIntegerField(default=0)
    error_message = models.TextField(blank=True)
    sensor = models.ForeignKey("Sensor", null=True, blank=True, related_name="capture_jobs", on_delete=models.SET_NULL)
    chunk_count = models.PositiveIntegerField(default=0)
    last_chunk_sequence = models.PositiveIntegerField(default=0)
    chunk_interval_seconds = models.PositiveIntegerField(default=5)
    progress = models.PositiveIntegerField(default=0)
    source_label = models.CharField(max_length=160, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    final_evidence_file = models.ForeignKey(EvidenceFile, null=True, blank=True, related_name="capture_sources", on_delete=models.SET_NULL)

    class Meta:
        indexes = [models.Index(fields=["sensor", "status", "created_at"], name="netra_cap_sensor_stat_idx")]


class SensorGroup(TimeStampedModel):
    name = models.CharField(max_length=160, unique=True)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=20, default="#2563eb")

    def __str__(self) -> str:
        return self.name


class Sensor(TimeStampedModel):
    class Status(models.TextChoices):
        ONLINE = "online", "Online"
        STALE = "stale", "Stale"
        OFFLINE = "offline", "Offline"
        DISABLED = "disabled", "Disabled"
        CAPTURING = "capturing", "Capturing"
        WARNING = "warning", "Warning"

    id = models.CharField(max_length=80, primary_key=True)
    name = models.CharField(max_length=160)
    hostname = models.CharField(max_length=160)
    platform = models.CharField(max_length=80)
    agent_version = models.CharField(max_length=40, default="phase5-v1")
    capture_engine = models.CharField(max_length=160)
    capture_engine_version = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.ONLINE)
    last_heartbeat_at = models.DateTimeField(null=True, blank=True)
    interfaces_json = models.JSONField(default=list, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)
    group = models.ForeignKey(SensorGroup, null=True, blank=True, related_name="sensors", on_delete=models.SET_NULL)
    location = models.CharField(max_length=255, blank=True)
    tags_json = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    last_command_at = models.DateTimeField(null=True, blank=True)
    current_capture_job = models.CharField(max_length=80, blank=True)
    total_chunks_uploaded = models.PositiveIntegerField(default=0)
    total_bytes_uploaded = models.BigIntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=["status", "last_heartbeat_at"], name="netra_sensor_health_idx"),
            models.Index(fields=["group", "status"], name="netra_sensor_group_stat_idx"),
        ]


class CaptureChunk(TimeStampedModel):
    class Status(models.TextChoices):
        RECEIVED = "received", "Received"
        PARSED = "parsed", "Parsed"
        FAILED = "failed", "Failed"

    id = models.CharField(max_length=100, primary_key=True)
    capture_job = models.ForeignKey(CaptureJob, related_name="chunks", on_delete=models.CASCADE)
    sensor = models.ForeignKey(Sensor, null=True, blank=True, related_name="capture_chunks", on_delete=models.SET_NULL)
    sequence = models.PositiveIntegerField()
    stored_path = models.CharField(max_length=500)
    plaintext_sha256 = models.CharField(max_length=64)
    encrypted_sha256 = models.CharField(max_length=64)
    packet_count = models.PositiveIntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)
    captured_from = models.DateTimeField(null=True, blank=True)
    captured_to = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.RECEIVED)
    retention_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("capture_job", "sequence")
        indexes = [models.Index(fields=["created_at", "status"], name="netra_chunk_created_stat_idx")]


class SensorCommand(TimeStampedModel):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        CLAIMED = "claimed", "Claimed"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"

    sensor = models.ForeignKey(Sensor, related_name="commands", on_delete=models.CASCADE)
    capture_job = models.ForeignKey(CaptureJob, null=True, blank=True, related_name="sensor_commands", on_delete=models.SET_NULL)
    command_type = models.CharField(max_length=80)
    payload_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.QUEUED)
    issued_at = models.DateTimeField(auto_now_add=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        indexes = [models.Index(fields=["sensor", "status", "issued_at"], name="netra_sensor_cmd_stat_idx")]


class SensorHealthSnapshot(TimeStampedModel):
    sensor = models.ForeignKey(Sensor, related_name="health_snapshots", on_delete=models.CASCADE)
    status = models.CharField(max_length=24)
    heartbeat_age_seconds = models.PositiveIntegerField(default=0)
    capture_engine = models.CharField(max_length=160, blank=True)
    interface_count = models.PositiveIntegerField(default=0)
    current_job_id = models.CharField(max_length=80, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)


class CaptureSchedule(TimeStampedModel):
    class ScheduleType(models.TextChoices):
        ONE_TIME = "one-time", "One time"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"

    name = models.CharField(max_length=160)
    sensor = models.ForeignKey(Sensor, related_name="capture_schedules", on_delete=models.CASCADE)
    enabled = models.BooleanField(default=True)
    schedule_type = models.CharField(max_length=24, choices=ScheduleType.choices)
    start_at = models.DateTimeField()
    timezone = models.CharField(max_length=80, default="Asia/Kolkata")
    weekdays_json = models.JSONField(default=list, blank=True)
    duration_seconds = models.PositiveIntegerField(default=60)
    packet_limit = models.PositiveIntegerField(default=10000)
    chunk_interval_seconds = models.PositiveIntegerField(default=5)
    interface_name = models.CharField(max_length=255)
    bpf_filter = models.CharField(max_length=255, blank=True)
    case_id_prefix = models.CharField(max_length=80, default="CYB-GJ-SCHEDULED")
    last_run_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)
    last_job = models.ForeignKey(CaptureJob, null=True, blank=True, related_name="schedule_runs", on_delete=models.SET_NULL)


class OperationalEvent(TimeStampedModel):
    case = models.ForeignKey(Case, null=True, blank=True, related_name="operational_events", on_delete=models.CASCADE)
    capture_job = models.ForeignKey(CaptureJob, null=True, blank=True, related_name="operational_events", on_delete=models.CASCADE)
    event_type = models.CharField(max_length=120)
    payload_json = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["capture_job", "id"], name="netra_ops_job_id_idx"),
            models.Index(fields=["created_at"], name="netra_ops_created_idx"),
        ]


class WorkerHeartbeat(TimeStampedModel):
    worker_name = models.CharField(max_length=80)
    instance_id = models.CharField(max_length=160)
    status = models.CharField(max_length=24, default="healthy")
    last_seen_at = models.DateTimeField()
    current_job_id = models.CharField(max_length=80, blank=True)
    details_json = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = ("worker_name", "instance_id")
        indexes = [models.Index(fields=["worker_name", "last_seen_at"], name="netra_worker_seen_idx")]


class WorkerStageReceipt(TimeStampedModel):
    idempotency_key = models.CharField(max_length=255, primary_key=True)
    worker_name = models.CharField(max_length=80)
    job_id = models.CharField(max_length=80)
    chunk_id = models.CharField(max_length=100, blank=True)
    stage = models.CharField(max_length=80)
    result_json = models.JSONField(default=dict, blank=True)


class ProcessingJob(TimeStampedModel):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.CharField(max_length=64, primary_key=True)
    case = models.ForeignKey(Case, related_name="processing_jobs", on_delete=models.CASCADE)
    evidence_file = models.ForeignKey(EvidenceFile, related_name="processing_jobs", null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)
    step = models.CharField(max_length=80, default="queued")
    progress = models.PositiveIntegerField(default=0)
    stats = models.JSONField(default=dict, blank=True)
    steps = models.JSONField(default=list, blank=True)
    events = models.JSONField(default=list, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    processing_path = models.CharField(max_length=32, default="sync-fallback")
    fallback_reason = models.TextField(blank=True)
    stage_deadline_at = models.DateTimeField(null=True, blank=True)
    last_progress_at = models.DateTimeField(null=True, blank=True)
    source_capture_job = models.ForeignKey(CaptureJob, null=True, blank=True, related_name="processing_jobs", on_delete=models.SET_NULL)
    expected_chunk_count = models.PositiveIntegerField(default=0)
    completed_chunk_count = models.PositiveIntegerField(default=0)
    completeness_status = models.CharField(max_length=40, default="complete")

    class Meta:
        indexes = [
            models.Index(fields=["case", "status"], name="netra_job_case_status_idx"),
            models.Index(fields=["status", "updated_at"], name="netra_job_status_upd_idx"),
            models.Index(fields=["case", "created_at"], name="netra_job_case_created_idx"),
        ]


class CaseAnalysisSnapshot(TimeStampedModel):
    case = models.OneToOneField(Case, related_name="analysis_snapshot", on_delete=models.CASCADE)
    processing_job = models.ForeignKey(ProcessingJob, null=True, blank=True, related_name="case_snapshots", on_delete=models.SET_NULL)
    schema_version = models.CharField(max_length=40, default="case-workspace-v1")
    snapshot_json = models.JSONField(default=dict, blank=True)
    generated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=["case", "generated_at"], name="netra_case_snap_case_gen_idx"),
            models.Index(fields=["schema_version", "generated_at"], name="netra_case_snap_schema_idx"),
        ]


class AnalysisChunk(TimeStampedModel):
    processing_job = models.ForeignKey(ProcessingJob, related_name="analysis_chunks", on_delete=models.CASCADE)
    sequence = models.PositiveIntegerField()
    encrypted_source_path = models.CharField(max_length=500)
    plaintext_sha256 = models.CharField(max_length=64)
    packet_count = models.PositiveIntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)
    status = models.CharField(max_length=32, default="queued")
    parser_completed_at = models.DateTimeField(null=True, blank=True)
    decoder_completed_at = models.DateTimeField(null=True, blank=True)
    session_completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        unique_together = ("processing_job", "sequence")
        indexes = [models.Index(fields=["status", "created_at"], name="netra_analysis_chunk_idx")]


class AnalysisStageResult(TimeStampedModel):
    processing_job = models.ForeignKey(ProcessingJob, related_name="stage_results", on_delete=models.CASCADE)
    analysis_chunk = models.ForeignKey(AnalysisChunk, null=True, blank=True, related_name="stage_results", on_delete=models.CASCADE)
    stage = models.CharField(max_length=80)
    status = models.CharField(max_length=32)
    payload_json = models.JSONField(default=dict, blank=True)
    idempotency_key = models.CharField(max_length=255, unique=True)
    completed_at = models.DateTimeField(null=True, blank=True)


class SessionSummary(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="sessions", on_delete=models.CASCADE)
    source = models.CharField(max_length=255)
    destination = models.CharField(max_length=255)
    protocol = models.CharField(max_length=40)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(default=0)
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)
    packet_count = models.PositiveIntegerField(default=0)
    risk_score = models.PositiveIntegerField(default=0)
    related_alert_ids = models.JSONField(default=list, blank=True)

    class Meta:
        indexes = [models.Index(fields=["case", "protocol"], name="netra_sess_case_proto_idx")]


class Alert(TimeStampedModel):
    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        NEW = "new", "New"
        REVIEWING = "reviewing", "Reviewing"
        CONFIRMED = "confirmed", "Confirmed"
        DISMISSED = "dismissed", "Dismissed"

    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="alerts", on_delete=models.CASCADE)
    severity = models.CharField(max_length=32, choices=Severity.choices)
    attack_class = models.CharField(max_length=80)
    alert_type = models.CharField(max_length=255)
    source_ip = models.CharField(max_length=80)
    destination = models.CharField(max_length=255)
    protocol = models.CharField(max_length=40)
    event_timestamp = models.DateTimeField(null=True, blank=True)
    confidence = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.NEW)
    rule_id = models.CharField(max_length=120, blank=True)
    evidence_packet_ids = models.JSONField(default=list, blank=True)
    evidence_session_ids = models.JSONField(default=list, blank=True)
    explanation = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)

    class Meta:
        indexes = [models.Index(fields=["case", "status", "severity"], name="netra_alert_case_stat_idx")]


class DetectionMatch(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="detection_matches", on_delete=models.CASCADE)
    rule_id = models.CharField(max_length=120, blank=True)
    rule_name = models.CharField(max_length=160)
    category = models.CharField(max_length=80)
    attack_class = models.CharField(max_length=120, blank=True)
    matched_entity = models.CharField(max_length=160)
    confidence = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=32, default="new")
    evidence_packet_ids = models.JSONField(default=list, blank=True)
    evidence_session_ids = models.JSONField(default=list, blank=True)
    explanation = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)


class AnomalyRecord(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="anomalies", on_delete=models.CASCADE)
    entity = models.CharField(max_length=160)
    behaviour = models.CharField(max_length=160)
    baseline = models.CharField(max_length=160)
    observed = models.CharField(max_length=160)
    deviation = models.CharField(max_length=80)
    confidence = models.PositiveIntegerField(default=0)
    hypothesis = models.CharField(max_length=160)
    top_features = models.JSONField(default=list, blank=True)
    recommended_action = models.TextField(blank=True)
    model_version = models.CharField(max_length=80, default="scikit-v1")


class ZeekLogSummary(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="zeek_summaries", on_delete=models.CASCADE)
    evidence_file = models.ForeignKey(EvidenceFile, related_name="zeek_summaries", null=True, blank=True, on_delete=models.SET_NULL)
    job_id = models.CharField(max_length=80)
    status = models.CharField(max_length=40, default="not-run")
    log_dir = models.CharField(max_length=500, blank=True)
    logs = models.JSONField(default=list, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    top_services = models.JSONField(default=list, blank=True)
    top_dns_queries = models.JSONField(default=list, blank=True)
    top_external_hosts = models.JSONField(default=list, blank=True)


class Report(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="reports", on_delete=models.CASCADE)
    language = models.CharField(max_length=20, default="en")
    generated_by = models.CharField(max_length=160)
    stored_path = models.CharField(max_length=500, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=32, default="ready")


class Export(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="exports", on_delete=models.CASCADE)
    export_type = models.CharField(max_length=80)
    requested_by = models.CharField(max_length=160)
    stored_path = models.CharField(max_length=500, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=32, default="queued")


class IntegrationConnection(TimeStampedModel):
    system_name = models.CharField(max_length=160, unique=True)
    status = models.CharField(max_length=32, default="pending")
    last_sync_at = models.DateTimeField(null=True, blank=True)
    linked_cases_count = models.PositiveIntegerField(default=0)
    api_mode = models.CharField(max_length=160)
    config = models.JSONField(default=dict, blank=True)


class IntegrationCredential(TimeStampedModel):
    integration = models.OneToOneField(IntegrationConnection, related_name="credential", on_delete=models.CASCADE)
    secret_label = models.CharField(max_length=160, blank=True)
    secret_value = models.TextField(blank=True)


class IntegrationDelivery(TimeStampedModel):
    integration = models.ForeignKey(IntegrationConnection, related_name="deliveries", on_delete=models.CASCADE)
    case = models.ForeignKey(Case, null=True, blank=True, related_name="integration_deliveries", on_delete=models.SET_NULL)
    delivery_type = models.CharField(max_length=80)
    payload_json = models.JSONField(default=dict, blank=True)
    result = models.CharField(max_length=32, default="queued")
    response_summary = models.TextField(blank=True)
    artifact_path = models.CharField(max_length=500, blank=True)
    artifact_sha256 = models.CharField(max_length=64, blank=True)


class CaseHistoryEvent(TimeStampedModel):
    case = models.ForeignKey(Case, related_name="history", on_delete=models.CASCADE)
    actor_name = models.CharField(max_length=160)
    action = models.CharField(max_length=160)
    details = models.TextField()
    event_hash = models.CharField(max_length=64, blank=True)


class CustodyLedgerEvent(TimeStampedModel):
    id = models.CharField(max_length=80, primary_key=True)
    case = models.ForeignKey(Case, related_name="custody_ledger", on_delete=models.CASCADE)
    evidence_file = models.ForeignKey(EvidenceFile, null=True, blank=True, related_name="custody_ledger", on_delete=models.SET_NULL)
    actor_user = models.CharField(max_length=160, blank=True)
    actor_label = models.CharField(max_length=160)
    actor_role = models.CharField(max_length=32)
    action = models.CharField(max_length=160)
    resource_type = models.CharField(max_length=80, blank=True)
    resource_id = models.CharField(max_length=160, blank=True)
    details_json = models.JSONField(default=dict, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64)

    class Meta:
        indexes = [models.Index(fields=["case", "created_at"], name="netra_custody_case_idx")]


class AccessLog(TimeStampedModel):
    class Role(models.TextChoices):
        ADMIN = "Admin", "Admin"
        INVESTIGATOR = "Investigator", "Investigator"
        ANALYST = "Analyst", "Analyst"
        VIEWER = "Viewer", "Viewer"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    user_label = models.CharField(max_length=160)
    role = models.CharField(max_length=32, choices=Role.choices)
    action = models.CharField(max_length=160)
    resource_type = models.CharField(max_length=80, blank=True)
    resource_id = models.CharField(max_length=160, blank=True)
    case = models.ForeignKey(Case, null=True, blank=True, related_name="access_logs", on_delete=models.SET_NULL)
    result = models.CharField(max_length=32, default="allowed")
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["created_at"], name="netra_access_created_idx")]


class ComplianceControl(TimeStampedModel):
    item = models.CharField(max_length=160)
    status = models.CharField(max_length=32)
    detail = models.TextField()
    case = models.ForeignKey(Case, null=True, blank=True, related_name="compliance_controls", on_delete=models.CASCADE)


class DeadLetterEvent(TimeStampedModel):
    class Status(models.TextChoices):
        NEW = "new", "New"
        RETRYING = "retrying", "Retrying"
        RESOLVED = "resolved", "Resolved"
        IGNORED = "ignored", "Ignored"

    id = models.CharField(max_length=80, primary_key=True)
    topic = models.CharField(max_length=160)
    worker_name = models.CharField(max_length=80)
    job_id = models.CharField(max_length=80, blank=True)
    case_id = models.CharField(max_length=80, blank=True)
    evidence_id = models.CharField(max_length=80, blank=True)
    payload_json = models.JSONField(default=dict, blank=True)
    error_message = models.TextField()
    traceback_summary = models.TextField(blank=True)
    retry_count = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.NEW)


class RetentionPolicy(TimeStampedModel):
    name = models.CharField(max_length=160, unique=True)
    high_volume_search_days = models.PositiveIntegerField(default=30)
    evidence_days = models.PositiveIntegerField(default=90)
    capture_chunk_days = models.PositiveIntegerField(default=7)
    enabled = models.BooleanField(default=True)


class RetentionRun(TimeStampedModel):
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    mode = models.CharField(max_length=32, default="preview")
    status = models.CharField(max_length=32, default="running")
    candidates_json = models.JSONField(default=list, blank=True)
    deleted_json = models.JSONField(default=list, blank=True)
    bytes_reclaimed = models.BigIntegerField(default=0)
    error_message = models.TextField(blank=True)


class RetentionCandidate(TimeStampedModel):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SKIPPED = "skipped", "Skipped"
        DELETED = "deleted", "Deleted"
        REQUIRES_APPROVAL = "requires-approval", "Requires approval"

    resource_type = models.CharField(max_length=80)
    resource_id = models.CharField(max_length=160)
    case = models.ForeignKey(Case, null=True, blank=True, related_name="retention_candidates", on_delete=models.SET_NULL)
    reason = models.TextField()
    expires_at = models.DateTimeField()
    legal_hold = models.BooleanField(default=False)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PENDING)
