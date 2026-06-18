import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import connection

logger = logging.getLogger(__name__)
_producer = None
_producer_lock = threading.Lock()

TOPIC_QUEUE_MAP = {
    "netra.pcap.uploaded": "pcap-uploaded",
    "netra.analysis.chunk.ready": "analysis-chunk-ready",
    "netra.capture.chunk.received": "capture-chunk-received",
    "netra.capture.raw": "capture-chunk-received",
    "netra.packets.normalized": "packets-normalized",
    "netra.protocol.decoded": "protocol-decoded",
    "netra.sessions.reconstructed": "sessions-reconstructed",
    "netra.features.ready": "features-ready",
    "netra.alerts.created": "alerts-created",
    "netra.alerts.provisional": "alerts-created",
    "netra.anomaly.events": "anomaly-events",
    "netra.analysis.finalize": "analysis-finalize",
    "netra.export.requests": "report-export",
    "netra.operational.events": "operational-events",
    "netra.dead_letter": "dead-letter",
    "netra.queue.health": "dead-letter",
    "netra.worker.validation": "worker-validation",
}


def queue_name_for_topic(topic: str) -> str:
    return TOPIC_QUEUE_MAP.get(topic, topic.removeprefix("netra.").replace(".", "-").replace("_", "-"))


def _get_producer():
    global _producer
    if _producer is None:
        from kafka import KafkaProducer

        _producer = KafkaProducer(
            bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            key_serializer=lambda value: value.encode("utf-8") if value else None,
        )
    return _producer


def publish_event(topic: str, payload: dict[str, Any], key: str | None = None) -> bool:
    if getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka") == "supabase-pgmq":
        return publish_supabase_queue(topic, payload, key=key)
    global _producer
    try:
        with _producer_lock:
            producer = _get_producer()
            producer.send(topic, key=key, value=payload).get(timeout=5)
        return True
    except Exception as exc:  # Kafka may be offline during local API-only demos.
        _producer = None
        logger.warning("Kafka publish skipped for topic %s: %s", topic, exc)
        return False


def consume_events(topics: list[str], group_id: str):
    if getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka") == "supabase-pgmq":
        return SupabaseQueueConsumer(topics, group_id)
    from kafka import KafkaConsumer

    return KafkaConsumer(
        *topics,
        bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP,
        group_id=group_id,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=False,
    )


def publish_supabase_queue(topic: str, payload: dict[str, Any], key: str | None = None) -> bool:
    queue_name = queue_name_for_topic(topic)
    message = {"topic": topic, "key": key or payload.get("jobId") or payload.get("caseId") or "", "payload": payload}
    try:
        with connection.cursor() as cursor:
            _ensure_supabase_queue(cursor, queue_name)
            cursor.execute("select pgmq.send(%s, %s::jsonb)", [queue_name, json.dumps(message)])
        return True
    except Exception as exc:
        logger.warning("Supabase queue publish skipped for topic %s/%s: %s", topic, queue_name, exc)
        return False


def _ensure_supabase_queue(cursor, queue_name: str) -> None:
    cursor.execute("select exists(select 1 from information_schema.tables where table_schema = 'pgmq' and table_name = %s)", [f"q_{queue_name}"])
    if cursor.fetchone()[0]:
        return
    cursor.execute("select pgmq.create(%s)", [queue_name])


@dataclass(frozen=True)
class SupabaseQueueMessage:
    value: dict[str, Any]
    queue_name: str
    msg_id: int


class SupabaseQueueConsumer:
    def __init__(self, topics: list[str], group_id: str):
        self.topics = topics
        self.group_id = group_id
        self.queue_names = [queue_name_for_topic(topic) for topic in topics]
        self._pending: list[SupabaseQueueMessage] = []

    def poll(self, timeout_ms: int = 5000):
        self._pending = []
        grouped = defaultdict(list)
        sleep_seconds = max(1, min(30, int(timeout_ms / 1000)))
        quantity = max(1, int(getattr(self, "quantity_override", getattr(settings, "SUPABASE_QUEUE_BATCH_SIZE", 10))))
        visibility = max(1, int(getattr(settings, "SUPABASE_QUEUE_VISIBILITY_SECONDS", 60)))
        for queue_name in self.queue_names:
            rows = self._read_queue(queue_name, visibility, quantity, sleep_seconds)
            for row in rows:
                message = row.get("message") or row.get("msg") or {}
                if isinstance(message, str):
                    try:
                        message = json.loads(message)
                    except json.JSONDecodeError:
                        message = {"payload": {"raw": message}}
                payload = message.get("payload", message)
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        payload = {"raw": payload}
                if isinstance(payload, dict):
                    payload = {"_queueTopic": message.get("topic", ""), "_queueKey": message.get("key", ""), "_queueName": queue_name, "_queueMsgId": int(row["msg_id"]), **payload}
                wrapped = SupabaseQueueMessage(value=payload, queue_name=queue_name, msg_id=int(row["msg_id"]))
                self._pending.append(wrapped)
                grouped[queue_name].append(wrapped)
        return dict(grouped)

    def commit_message(self, message: SupabaseQueueMessage) -> None:
        try:
            with connection.cursor() as cursor:
                cursor.execute("select pgmq.archive(%s, %s::bigint)", [message.queue_name, message.msg_id])
        except Exception as exc:
            logger.warning("Supabase queue archive failed for %s/%s: %s", message.queue_name, message.msg_id, exc)
            raise
        self._pending = [pending for pending in self._pending if pending.msg_id != message.msg_id or pending.queue_name != message.queue_name]

    def commit(self):
        for message in list(self._pending):
            self.commit_message(message)
        self._pending = []

    def _read_queue(self, queue_name: str, visibility: int, quantity: int, sleep_seconds: int) -> list[dict[str, Any]]:
        try:
            with connection.cursor() as cursor:
                cursor.execute("select * from pgmq.read(%s, %s::integer, %s::integer)", [queue_name, visibility, quantity])
                columns = [column[0] for column in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as exc:
            logger.warning("Supabase queue read failed for %s: %s", queue_name, exc)
            time_to_sleep = min(sleep_seconds, 5)
            if time_to_sleep:
                time.sleep(time_to_sleep)
            return []


def supabase_queue_depths() -> dict[str, int]:
    depths: dict[str, int] = {}
    with connection.cursor() as cursor:
        cursor.execute(
            """
            select table_name
            from information_schema.tables
            where table_schema = 'pgmq' and table_name like 'q_%'
            order by table_name
            """
        )
        tables = [row[0] for row in cursor.fetchall()]
        for table in tables:
            queue_name = table.removeprefix("q_")
            cursor.execute(f'select count(*) from pgmq."{table}"')
            depths[queue_name] = int(cursor.fetchone()[0])
    return depths


def probe_supabase_queue() -> dict[str, Any]:
    queue_name = queue_name_for_topic("netra.queue.health")
    probe_payload = {"type": "queue.health", "createdAt": int(time.time())}
    message_id = None
    try:
        with connection.cursor() as cursor:
            cursor.execute("select exists(select 1 from pg_extension where extname = 'pgmq')")
            if not cursor.fetchone()[0]:
                return {"status": "failed", "provider": "supabase-pgmq", "detail": "pgmq extension is not enabled"}
            cursor.execute("select exists(select 1 from information_schema.tables where table_schema = 'pgmq' and table_name = %s)", [f"q_{queue_name}"])
            if not cursor.fetchone()[0]:
                return {"status": "failed", "provider": "supabase-pgmq", "detail": f"queue {queue_name} is missing"}
            cursor.execute("select pgmq.send(%s, %s::jsonb)", [queue_name, json.dumps({"topic": "netra.queue.health", "payload": probe_payload})])
            sent = cursor.fetchone()
            message_id = sent[0] if sent else None
            cursor.execute("select * from pgmq.read(%s, %s::integer, %s::integer)", [queue_name, 30, 1])
            columns = [column[0] for column in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
            if not rows:
                return {"status": "failed", "provider": "supabase-pgmq", "detail": "queue probe message was not readable"}
            cursor.execute("select pgmq.archive(%s, %s::bigint)", [queue_name, int(rows[0]["msg_id"])])
        depths = supabase_queue_depths()
        return {"status": "ok", "provider": "supabase-pgmq", "detail": "pgmq send/read/archive probe succeeded", "queue": queue_name, "messageId": message_id, "depth": depths.get(queue_name, 0), "queues": depths}
    except Exception as exc:
        logger.warning("Supabase queue probe failed: %s", exc)
        return {"status": "failed", "provider": "supabase-pgmq", "detail": str(exc), "queue": queue_name}
