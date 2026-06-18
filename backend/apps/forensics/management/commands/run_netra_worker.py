import logging
import socket
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import F
from django.utils import timezone

from common.analysis import _packet_from_row, _read_packets_with_tshark
from common.artifacts import generate_export_artifact, generate_report_artifact
from common.audit import Actor
from common.async_pipeline import process_queued_evidence
from common.detection import classify_detection
from common.jobs import append_job_event
from common.kafka import consume_events, publish_event
from common.indexing import ensure_write_index, index_live_packets
from common.operations import emit_operational_event
from common.persistence import analysis_for_case
from common.search import index_document, index_documents
from common.vault import decrypt_file
from apps.forensics.models import AnalysisChunk, CaptureChunk, CaptureJob, DeadLetterEvent, ProcessingJob, WorkerHeartbeat, WorkerStageReceipt

logger = logging.getLogger(__name__)


WORKER_TOPICS = {
    "capture": ["netra.capture.raw", "netra.capture.chunk.received"],
    "pcap-ingestion": ["netra.pcap.uploaded"],
    "parser": ["netra.pcap.processing", "netra.pcap.uploaded", "netra.capture.chunk.received", "netra.analysis.chunk.ready", "netra.worker.validation"],
    "decoder": ["netra.packets.normalized"],
    "session": ["netra.packets.normalized"],
    "detection": ["netra.protocol.decoded", "netra.payload.findings", "netra.sessions.reconstructed"],
    "anomaly": ["netra.sessions.reconstructed", "netra.packets.normalized"],
    "report-export": ["netra.export.requests"],
    "analysis-finalizer": ["netra.analysis.finalize"],
}


class Command(BaseCommand):
    help = "Run one allowed-stack Netra queue worker process."

    def add_arguments(self, parser) -> None:
        parser.add_argument("worker", choices=sorted(WORKER_TOPICS))
        parser.add_argument("--once", action="store_true", help="Run one dry cycle without connecting forever.")
        parser.add_argument("--max-messages", type=int, default=0, help="Process up to N queued messages and exit.")
        parser.add_argument("--idle-timeout", type=int, default=20, help="Seconds to wait for messages when --max-messages is used.")
        parser.add_argument("--topic", action="append", default=[], help="Restrict this worker to a specific allowed topic. Can be repeated.")

    def handle(self, *args, **options) -> None:
        worker = options["worker"]
        topics = options["topic"] or WORKER_TOPICS[worker]
        invalid_topics = sorted(set(topics) - set(WORKER_TOPICS[worker]))
        if invalid_topics:
            raise ValueError(f"{worker} worker cannot consume topic(s): {', '.join(invalid_topics)}")
        self.instance_id = f"{socket.gethostname()}-{worker}-{uuid4().hex[:6]}"
        self.stdout.write(self.style.SUCCESS(f"Starting Netra {worker} worker on topics: {', '.join(topics)}"))
        if options["once"]:
            self._heartbeat(worker)
            self._process_with_retries(worker, {"type": "worker.dry_run", "worker": worker})
            return
        if options["max_messages"]:
            self._run_bounded(worker, topics, options["max_messages"], options["idle_timeout"])
            return
        try:
            consumer = consume_events(topics, group_id=f"netra-{worker}")
            while True:
                self._heartbeat(worker)
                records = consumer.poll(timeout_ms=5000)
                for messages in records.values():
                    for message in messages:
                        self._process_with_retries(worker, message.value)
                        if hasattr(consumer, "commit_message"):
                            consumer.commit_message(message)
                if records and not hasattr(consumer, "commit_message"):
                    consumer.commit()
        except KeyboardInterrupt:
            self.stdout.write("Worker stopped.")
        except Exception as exc:
            self.stderr.write(f"Queue worker could not stay connected: {exc}")
            self.stderr.write("Sleeping so Docker restart policy can keep the service observable.")
            time.sleep(10)

    def _heartbeat(self, worker: str, current_job_id: str = "") -> None:
        WorkerHeartbeat.objects.update_or_create(
            worker_name=worker,
            instance_id=self.instance_id,
            defaults={"status": "healthy", "last_seen_at": timezone.now(), "current_job_id": current_job_id, "details_json": {"topics": WORKER_TOPICS[worker], "queueProvider": getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka")}},
        )

    def _run_bounded(self, worker: str, topics: list[str], max_messages: int, idle_timeout: int) -> None:
        consumer = consume_events(topics, group_id=f"netra-{worker}-bounded-{uuid4().hex[:6]}")
        processed = 0
        deadline = time.monotonic() + max(1, idle_timeout)
        while processed < max_messages and time.monotonic() < deadline:
            self._heartbeat(worker)
            if hasattr(consumer, "queue_names"):
                consumer.quantity_override = max(1, max_messages - processed)
            records = consumer.poll(timeout_ms=1000)
            if not records:
                continue
            for messages in records.values():
                for message in messages:
                    self._process_with_retries(worker, message.value)
                    if hasattr(consumer, "commit_message"):
                        consumer.commit_message(message)
                    processed += 1
                    if processed >= max_messages:
                        break
                if processed >= max_messages:
                    break
            if records and not hasattr(consumer, "commit_message"):
                consumer.commit()
        if processed < max_messages:
            raise RuntimeError(f"{worker} worker processed {processed}/{max_messages} messages before idle timeout.")
        self.stdout.write(self.style.SUCCESS(f"{worker} worker processed {processed} queued message(s)."))

    def _process_with_retries(self, worker: str, payload: dict[str, Any]) -> None:
        job_id = payload.get("jobId", "")
        chunk_id = payload.get("chunkId", "")
        stage = payload.get("type", "event")
        item_id = payload.get("packetId") or payload.get("id") or chunk_id
        receipt_key = f"{job_id}:{item_id}:{worker}:{stage}"
        if job_id and WorkerStageReceipt.objects.filter(idempotency_key=receipt_key).exists():
            return
        max_retries = int(getattr(settings, "NETRA_WORKER_MAX_RETRIES", 3))
        for attempt in range(1, max_retries + 1):
            try:
                self._heartbeat(worker, job_id)
                self._handle_message(worker, payload)
                if job_id:
                    WorkerStageReceipt.objects.update_or_create(idempotency_key=receipt_key, defaults={"worker_name": worker, "job_id": job_id, "chunk_id": chunk_id, "stage": stage, "result_json": {"status": "completed"}})
                return
            except Exception as exc:
                if payload.get("forceWorkerError"):
                    logger.warning("%s worker failed validation attempt %s: %s", worker, attempt, exc)
                else:
                    logger.exception("%s worker failed attempt %s", worker, attempt)
                if attempt < max_retries:
                    time.sleep(0.25 * attempt)
                    continue
                original_topic = payload.get("_queueTopic") or payload.get("topic") or WORKER_TOPICS[worker][0]
                event = DeadLetterEvent.objects.create(
                    id=f"dlq-{uuid4().hex[:8]}",
                    topic=original_topic,
                    worker_name=worker,
                    job_id=job_id,
                    case_id=payload.get("caseId", ""),
                    evidence_id=payload.get("evidenceId", ""),
                    payload_json=payload,
                    error_message=str(exc),
                    traceback_summary=traceback.format_exc(limit=6),
                    retry_count=max_retries,
                )
                publish_event("netra.dead_letter", {"deadLetterId": event.id, **payload})
                emit_operational_event("worker.warning", {"worker": worker, "deadLetterId": event.id, "error": str(exc), "jobId": job_id})
                return

    def _handle_message(self, worker: str, payload: dict[str, Any]) -> None:
        if payload.get("forceWorkerError"):
            raise RuntimeError(payload.get("error") or "Forced worker validation error")
        handlers = {
            "capture": self._capture,
            "pcap-ingestion": self._pcap_ingestion,
            "parser": self._parser,
            "decoder": self._decoder,
            "session": self._session,
            "detection": self._detection,
            "anomaly": self._anomaly,
            "report-export": self._report_export,
            "analysis-finalizer": self._analysis_finalizer,
        }
        handlers[worker](payload)

    def _capture(self, payload: dict[str, Any]) -> None:
        job = CaptureJob.objects.filter(id=payload.get("jobId")).first()
        emit_operational_event("capture.worker_observed", {"worker": "capture", **payload}, capture_job=job)
        publish_event("netra.capture.status", {"type": "capture.status", "status": "observed", "source": payload})

    def _pcap_ingestion(self, payload: dict[str, Any]) -> None:
        if payload.get("saved") and payload.get("jobId"):
            process_queued_evidence(payload)
            publish_event("netra.analysis.finalize", {"type": "analysis.finalize", "jobId": payload["jobId"], "caseId": payload.get("caseId"), "evidenceId": payload.get("evidenceId")}, key=payload["jobId"])
        else:
            publish_event("netra.pcap.processing", {"type": "pcap.processing.started", **payload})

    def _parser(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "parser-worker observed uploaded evidence")
        analysis_chunk_id = payload.get("analysisChunkId")
        if analysis_chunk_id:
            chunk = AnalysisChunk.objects.filter(id=analysis_chunk_id).select_related("processing_job").first()
            if not chunk:
                raise ValueError(f"Analysis chunk {analysis_chunk_id} was not found.")
            handle = tempfile.NamedTemporaryFile(prefix=f"analysis-{chunk.id}-", suffix=".pcap", delete=False)
            handle.close()
            temporary_path = Path(handle.name)
            try:
                decrypt_file(chunk.encrypted_source_path, temporary_path)
                packets = [_packet_from_row(row, index) for index, row in enumerate(_read_packets_with_tshark(temporary_path), start=1)]
                documents = []
                for packet in packets:
                    document = {
                        **packet,
                        "id": f"{chunk.processing_job_id}-analysis-{chunk.sequence}-{packet['id']}",
                        "caseId": chunk.processing_job.case_id,
                        "evidenceId": chunk.processing_job.evidence_file_id,
                        "jobId": chunk.processing_job_id,
                        "analysisChunkId": chunk.id,
                        "provisional": False,
                    }
                    documents.append((document["id"], document))
                index_documents(ensure_write_index("packets"), documents)
            finally:
                temporary_path.unlink(missing_ok=True)
            chunk.status = "parsed"
            chunk.packet_count = len(packets)
            chunk.parser_completed_at = timezone.now()
            chunk.save(update_fields=["status", "packet_count", "parser_completed_at", "updated_at"])
            ProcessingJob.objects.filter(id=chunk.processing_job_id).update(completed_chunk_count=F("completed_chunk_count") + 1)
            emit_operational_event(
                "analysis.chunk_parsed",
                {"jobId": chunk.processing_job_id, "analysisChunkId": chunk.id, "sequence": chunk.sequence, "indexedPackets": len(packets)},
            )
            return
        chunk_id = payload.get("chunkId")
        if chunk_id:
            chunk = CaptureChunk.objects.filter(id=chunk_id).select_related("capture_job").first()
            if not chunk:
                raise ValueError(f"Capture chunk {chunk_id} was not found.")
            handle = tempfile.NamedTemporaryFile(prefix=f"{chunk.id}-", suffix=".pcap", delete=False)
            handle.close()
            temporary_path = Path(handle.name)
            try:
                decrypt_file(chunk.stored_path, temporary_path)
                packets = [_packet_from_row(row, index) for index, row in enumerate(_read_packets_with_tshark(temporary_path), start=1)]
                documents = []
                for packet in packets:
                    document = {
                        **packet,
                        "id": f"{chunk.id}-{packet['id']}",
                        "caseId": chunk.capture_job.case_id,
                        "captureJobId": chunk.capture_job_id,
                        "captureChunkId": chunk.id,
                        "provisional": True,
                    }
                    documents.append((document["id"], document))
                index_live_packets(documents)
            finally:
                temporary_path.unlink(missing_ok=True)
            protocol_counts = Counter(packet.get("protocol") or "UNKNOWN" for packet in packets)
            sessions: dict[tuple[Any, ...], dict[str, Any]] = {}
            for packet in packets:
                key = (
                    packet.get("sourceIp"),
                    packet.get("destinationIp"),
                    packet.get("sourcePort"),
                    packet.get("destinationPort"),
                    packet.get("protocol"),
                )
                session = sessions.setdefault(
                    key,
                    {
                        "sessionId": f"{chunk.id}-sess-{len(sessions) + 1:05d}",
                        "sourceIp": packet.get("sourceIp"),
                        "destinationIp": packet.get("destinationIp"),
                        "sourcePort": packet.get("sourcePort"),
                        "destinationPort": packet.get("destinationPort"),
                        "protocol": packet.get("protocol"),
                        "packetCount": 0,
                    },
                )
                session["packetCount"] += 1
            parsed_payload = {
                **payload,
                "type": "capture.chunk.parsed",
                "indexedPackets": len(packets),
                "protocolCounts": [{"protocol": protocol, "packetCount": count} for protocol, count in protocol_counts.most_common()],
                "sessions": sorted(sessions.values(), key=lambda item: item["packetCount"], reverse=True)[:250],
                "provisional": True,
            }
            emit_operational_event("capture.chunk_parsed", parsed_payload, capture_job=chunk.capture_job)
            publish_event("netra.packets.normalized", parsed_payload)
            return
        packet_id = payload.get("packetId") or payload.get("id")
        source_ip = payload.get("sourceIp")
        destination_ip = payload.get("destinationIp")
        if not packet_id or not source_ip or not destination_ip:
            if payload.get("jobId"):
                index_document("netra-worker-events-v1", f"{payload['jobId']}-parser", {"worker": "parser", "jobId": payload["jobId"], "caseId": payload.get("caseId"), "summary": payload.get("summary", {})})
                emit_operational_event("worker.stage_completed", {"worker": "parser", "jobId": payload["jobId"], "detail": "Uploaded evidence or capture chunk observed."}, capture_job=CaptureJob.objects.filter(id=payload["jobId"]).first())
            return
        packet = {
            "id": packet_id,
            "sourceIp": source_ip,
            "destinationIp": destination_ip,
            "protocol": payload.get("protocol", "UNKNOWN"),
            "sessionId": payload.get("sessionId", ""),
            "riskScore": payload.get("riskScore", 0),
        }
        index_document("netra-packets-v1", packet["id"], packet)
        if payload.get("jobId"):
            index_document("netra-worker-events-v1", f"{payload['jobId']}-parser", {"worker": "parser", "jobId": payload["jobId"], "caseId": payload.get("caseId"), "summary": payload.get("summary", {})})
        publish_event("netra.packets.normalized", packet)

    def _decoder(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "decoder-worker decoded packet metadata")
        if payload.get("chunkId") and payload.get("protocolCounts") is not None:
            decoded = {
                "type": "protocol.decoded",
                "chunkId": payload["chunkId"],
                "jobId": payload.get("jobId"),
                "caseId": payload.get("caseId"),
                "protocolCounts": payload["protocolCounts"],
                "provisional": True,
                "detail": "Protocol summary extracted from a captured chunk.",
            }
            index_document("netra-protocols-live-v1", payload["chunkId"], decoded)
            publish_event("netra.protocol.decoded", decoded)
            return
        if not payload.get("packetId") or not payload.get("sourceIp") or not payload.get("destinationIp"):
            return
        decoded = {
            "type": "protocol.decoded",
            "protocol": payload.get("protocol", "DNS"),
            "packetId": payload["packetId"],
            "jobId": payload.get("jobId"),
            "caseId": payload.get("caseId"),
            "sourceIp": payload["sourceIp"],
            "destinationIp": payload["destinationIp"],
            "sourcePort": payload.get("sourcePort"),
            "destinationPort": payload.get("destinationPort"),
            "provisional": bool(payload.get("provisional")),
            "detail": "Decoded metadata extracted from a captured packet.",
        }
        index_document("netra-protocols-live-v1", decoded["packetId"], decoded)
        publish_event("netra.protocol.decoded", decoded)

    def _session(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "session-worker reconstructed session metadata")
        if payload.get("chunkId") and payload.get("sessions") is not None:
            sessions = [
                {
                    **session,
                    "type": "session.reconstructed",
                    "jobId": payload.get("jobId"),
                    "caseId": payload.get("caseId"),
                    "chunkId": payload["chunkId"],
                    "provisional": True,
                }
                for session in payload["sessions"]
            ]
            index_documents(ensure_write_index("sessions"), [(session["sessionId"], session) for session in sessions])
            publish_event("netra.sessions.reconstructed", {**payload, "type": "session.reconstructed", "sessions": sessions})
            return
        if not payload.get("packetId") or not payload.get("sourceIp") or not payload.get("destinationIp"):
            return
        session_id = payload.get("sessionId") or payload["packetId"]
        session = {
            "type": "session.reconstructed",
            "sessionId": session_id,
            "jobId": payload.get("jobId"),
            "caseId": payload.get("caseId"),
            "source": payload["sourceIp"],
            "destination": payload["destinationIp"],
            "protocol": payload.get("protocol"),
            "provisional": bool(payload.get("provisional")),
        }
        index_document("netra-sessions-live-v1", f"{payload.get('jobId', '')}-{session_id}", session)
        publish_event(
            "netra.sessions.reconstructed",
            session,
        )

    def _detection(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "detection-worker evaluated signatures")
        matches = self._provisional_session_matches(payload)
        if not matches and not payload.get("sessions"):
            matches = classify_detection(payload)
        for match in matches:
            alert = {"type": "alert.provisional", "source": payload, "provisional": True, **match}
            publish_event("netra.detection.matches", match)
            publish_event("netra.alerts.provisional", alert)
            emit_operational_event("alert.provisional", alert, capture_job=CaptureJob.objects.filter(id=payload.get("jobId")).first())

    def _anomaly(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "anomaly-worker observed packet or session metadata; final scoring runs after immutable evidence finalization")

    def _report_export(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "report-export-worker observed export request")
        message_type = payload.get("type")
        if message_type == "report.generate":
            case_id = payload.get("caseId", "")
            language = payload.get("language", "en")
            analysis = analysis_for_case(case_id)
            if not analysis:
                raise ValueError(f"No completed analysis found for report case {case_id}")
            actor = Actor(payload.get("actor") or "Netra report worker", "System", authenticated=True)
            artifact = generate_report_artifact(case_id, language, analysis, actor, filename=payload.get("reportId") or None)
            publish_event("netra.export.completed", {"type": "report.generated", "caseId": case_id, **artifact})
            emit_operational_event("report.generated", {"worker": "report-export", "caseId": case_id, "filename": artifact["filename"]})
            return
        if message_type == "export.generate":
            case_id = payload.get("caseId", "")
            export_type = payload.get("exportType") or payload.get("type") or "json"
            analysis = analysis_for_case(case_id)
            if not analysis:
                raise ValueError(f"No completed analysis found for export case {case_id}")
            actor = Actor(payload.get("actor") or "Netra export worker", "System", authenticated=True)
            artifact = generate_export_artifact(case_id, export_type, analysis, actor, export_id=payload.get("exportId") or None)
            publish_event("netra.export.completed", {"type": "export.generated", "caseId": case_id, **artifact})
            emit_operational_event("export.generated", {"worker": "report-export", "caseId": case_id, "exportId": artifact["id"]})
            return
        publish_event("netra.export.observed", {"type": "export.observed", "request": payload, "status": "observed"})

    def _analysis_finalizer(self, payload: dict[str, Any]) -> None:
        self._touch_job(payload, "analysis-finalizer observed completed chunk aggregation")
        publish_event("netra.analysis.finalized", {"type": "analysis.finalized", **payload})

    def _touch_job(self, payload: dict[str, Any], detail: str) -> None:
        job_id = payload.get("jobId")
        if not job_id:
            return
        job = ProcessingJob.objects.filter(id=job_id).first()
        if job:
            append_job_event(job, "worker.observed", detail)

    def _provisional_session_matches(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        sessions = payload.get("sessions") or []
        if not sessions:
            return []
        ssh_groups: Counter[tuple[str, str]] = Counter()
        destinations_by_source: dict[str, set[str]] = {}
        ports_by_source: dict[str, set[int]] = {}
        for session in sessions:
            source = session.get("sourceIp") or "unknown"
            destination = session.get("destinationIp") or "unknown"
            port = int(session.get("destinationPort") or 0)
            if port == 22:
                ssh_groups[(source, destination)] += 1
            destinations_by_source.setdefault(source, set()).add(destination)
            if port:
                ports_by_source.setdefault(source, set()).add(port)
        matches = []
        if ssh_groups:
            (source, destination), count = ssh_groups.most_common(1)[0]
            if count >= 20:
                matches.append(
                    {
                        "ruleId": "rule-bruteforce-ssh-provisional",
                        "ruleName": "Provisional SSH Credential Brute Force",
                        "category": "Credential Attack",
                        "attackClass": "Credential Brute Force",
                        "confidence": min(94, 70 + count),
                        "observedSignals": [f"{count} SSH sessions from {source} to {destination} in a partial capture"],
                        "limitations": "Provisional partial-evidence finding. Final classification runs after immutable evidence finalization.",
                    }
                )
        for source, destinations in destinations_by_source.items():
            ports = ports_by_source.get(source, set())
            if len(destinations) >= 40 or len(ports) >= 100:
                matches.append(
                    {
                        "ruleId": "rule-recon-provisional",
                        "ruleName": "Provisional Port Scan / Reconnaissance",
                        "category": "Reconnaissance",
                        "attackClass": "Port Scan / Reconnaissance",
                        "confidence": 82,
                        "observedSignals": [f"{source} contacted {len(destinations)} destinations and {len(ports)} destination ports in a partial capture"],
                        "limitations": "Provisional partial-evidence finding. Final classification runs after immutable evidence finalization.",
                    }
                )
                break
        return matches
