import json
import logging
import threading
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)
_producer = None
_producer_lock = threading.Lock()


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
    from kafka import KafkaConsumer

    return KafkaConsumer(
        *topics,
        bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP,
        group_id=group_id,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=False,
    )
