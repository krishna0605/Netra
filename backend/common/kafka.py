import json
import logging
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)


def publish_event(topic: str, payload: dict[str, Any]) -> bool:
    try:
        from kafka import KafkaProducer

        producer = KafkaProducer(
            bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
        )
        producer.send(topic, payload)
        producer.flush(timeout=5)
        producer.close()
        return True
    except Exception as exc:  # Kafka may be offline during local API-only demos.
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
        enable_auto_commit=True,
    )
