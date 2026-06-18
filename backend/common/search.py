import logging
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)


def get_elasticsearch_client():
    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        raise RuntimeError("Elasticsearch is disabled; Netra is using Postgres-backed search.")
    from elasticsearch import Elasticsearch

    return Elasticsearch(settings.NETRA_ELASTICSEARCH_URL)


def index_document(index: str, document_id: str, document: dict[str, Any]) -> bool:
    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        return True
    try:
        client = get_elasticsearch_client()
        client.index(index=index, id=document_id, document=document)
        return True
    except Exception as exc:
        logger.warning("Elasticsearch index skipped for %s/%s: %s", index, document_id, exc)
        return False


def index_documents(index: str, documents: list[tuple[str, dict[str, Any]]]) -> bool:
    if not documents:
        return True
    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        return True
    try:
        from elasticsearch.helpers import bulk

        client = get_elasticsearch_client()
        bulk(client, ({"_index": index, "_id": document_id, "_source": document} for document_id, document in documents))
        return True
    except Exception as exc:
        logger.warning("Elasticsearch bulk index skipped for %s: %s", index, exc)
        return False


def search_documents(index: str, query: dict[str, Any], fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        return fallback
    try:
        client = get_elasticsearch_client()
        response = client.search(index=index, query=query, size=100)
        return [hit["_source"] | {"id": hit["_id"]} for hit in response["hits"]["hits"]]
    except Exception as exc:
        logger.warning("Elasticsearch search fallback for %s: %s", index, exc)
        return fallback
