from apps.forensics.api.errors import api_error
from common.storage_cache import StorageCacheUnavailable


class StorageCacheFailureMiddleware:
    """Convert fail-closed cache errors into a stable service response."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if not isinstance(exception, StorageCacheUnavailable):
            return None
        return api_error(
            request,
            "storage_cache_unavailable",
            "Encrypted evidence storage is temporarily unavailable.",
            status=503,
        )
