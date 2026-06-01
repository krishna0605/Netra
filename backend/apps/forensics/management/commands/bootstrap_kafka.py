import json

from django.conf import settings
from django.core.management.base import BaseCommand


TOPICS = {
    "netra.pcap.uploaded": 3,
    "netra.analysis.chunk.ready": 6,
    "netra.capture.chunk.received": 6,
    "netra.packets.normalized": 6,
    "netra.protocol.decoded": 6,
    "netra.sessions.reconstructed": 6,
    "netra.features.ready": 3,
    "netra.alerts.created": 3,
    "netra.anomaly.events": 3,
    "netra.analysis.finalize": 3,
    "netra.operational.events": 3,
    "netra.dead_letter": 3,
}


class Command(BaseCommand):
    help = "Provision Phase 7 Kafka topics idempotently for the local fleet stack."

    def handle(self, *args, **options):
        from kafka.admin import KafkaAdminClient, NewPartitions, NewTopic
        from kafka.errors import TopicAlreadyExistsError

        admin = KafkaAdminClient(bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP, request_timeout_ms=5000)
        existing = set(admin.list_topics())
        created, expanded, reused = [], [], []
        for topic, partitions in TOPICS.items():
            if topic not in existing:
                try:
                    admin.create_topics([NewTopic(name=topic, num_partitions=partitions, replication_factor=1)])
                    created.append(topic)
                except TopicAlreadyExistsError:
                    reused.append(topic)
            else:
                reused.append(topic)
        descriptions = admin.describe_topics(list(TOPICS))
        expansion = {}
        for row in descriptions:
            desired = TOPICS[row["topic"]]
            if len(row["partitions"]) < desired:
                expansion[row["topic"]] = NewPartitions(total_count=desired)
        if expansion:
            admin.create_partitions(expansion)
            expanded.extend(expansion)
        admin.close()
        self.stdout.write(json.dumps({"created": created, "expanded": expanded, "reused": reused}, indent=2))
        self.stdout.write(self.style.SUCCESS("Kafka topic bootstrap completed."))
