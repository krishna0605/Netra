from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from apps.forensics.models import ProcessingJob


JOB_STEPS = ["queued", "uploaded", "hash_verified", "packet_parsing", "zeek_decoding", "session_reconstruction", "detection", "anomaly_scoring", "indexing", "report_ready", "completed"]


def initial_steps(active: str = "queued") -> list[dict[str, str]]:
    output = []
    for step in JOB_STEPS:
        if step == active:
            status = "running"
        elif JOB_STEPS.index(step) < JOB_STEPS.index(active):
            status = "completed"
        else:
            status = "pending"
        output.append({"name": step, "status": status})
    return output


def completed_steps() -> list[dict[str, str]]:
    return [{"name": step, "status": "completed"} for step in JOB_STEPS]


def append_job_event(job: ProcessingJob, event: str, detail: str = "") -> None:
    events = list(job.events or [])
    events.append({"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, "detail": detail})
    job.events = events[-100:]
    job.save(update_fields=["events", "updated_at"])


def job_status_payload(job: ProcessingJob) -> dict[str, Any]:
    return {
        "jobId": job.id,
        "status": job.status,
        "progress": job.progress,
        "step": job.step,
        "steps": job.steps or initial_steps(job.step),
        "stats": job.stats.get("summary", job.stats),
        "events": job.events or [],
        "startedAt": job.started_at.isoformat() if job.started_at else None,
        "completedAt": job.completed_at.isoformat() if job.completed_at else None,
    }
