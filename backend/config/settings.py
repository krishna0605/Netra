import base64
import binascii
import os
import sys
from pathlib import Path

import dj_database_url


BASE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BASE_DIR.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "netra-development-only-secret")
DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,backend").split(",")
NETRA_DEPLOYMENT_PROFILE = os.getenv("NETRA_DEPLOYMENT_PROFILE", "local").strip().lower()
if NETRA_DEPLOYMENT_PROFILE not in {"local", "hackathon-core", "full"}:
    raise RuntimeError("NETRA_DEPLOYMENT_PROFILE must be local, hackathon-core, or full")
NETRA_FREE_PLAN_GUARD = os.getenv(
    "NETRA_FREE_PLAN_GUARD",
    "1" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else "0",
) == "1"
NETRA_DEPLOYMENT_ENV = os.getenv("NETRA_DEPLOYMENT_ENV", "local").lower()


def _reject_conflicting_alias(legacy_name: str, canonical_name: str, canonical_value: str) -> None:
    """Fail closed when a retired deployment alias disagrees with its canonical variable.

    Railway carried several pre-remediation aliases. Until every environment is
    cleaned up, a stale alias that disagrees with the canonical variable must
    abort startup rather than silently win or be silently ignored.
    """
    legacy_value = (os.getenv(legacy_name) or "").strip()
    canonical = (canonical_value or "").strip()
    if not legacy_value or not canonical:
        return
    if legacy_value != canonical:
        raise RuntimeError(f"{legacy_name} conflicts with {canonical_name}; remove the retired alias")


def _reject_retired_secret_alias(legacy_name: str, canonical_name: str) -> None:
    """Never accept a retired secret-bearing variable, even when values match."""
    if os.getenv(legacy_name) is not None:
        raise RuntimeError(f"{legacy_name} is retired; configure {canonical_name} and remove the alias")


INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "apps.forensics",
]

MIDDLEWARE = [
    "common.cors.LocalCorsMiddleware",
    # Inside LocalCors so a rejection still carries CORS headers and stays
    # debuggable for a misconfigured deployment, rather than surfacing to the
    # operator as an opaque browser error.
    "common.admin_origin.AdminConsoleOriginMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "common.security_headers.ApiSecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "common.api_auth.NetraApiAuthMiddleware",
    "common.rate_limit_middleware.NetraRateLimitMiddleware",
    "common.storage_cache_middleware.StorageCacheFailureMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASE_URL = os.getenv("DATABASE_URL")
_reject_conflicting_alias("SUPABASE_POOLER_DATABASE_URL", "DATABASE_URL", DATABASE_URL or "")
_reject_conflicting_alias("SUPABASE_DIRECT_DATABASE_URL", "DATABASE_URL", DATABASE_URL or "")
# Transport policy is explicit so a disposable loopback CI service can run
# without TLS while every hosted deployment keeps requiring it.
NETRA_DATABASE_SSL_REQUIRED = os.getenv("NETRA_DATABASE_SSL_REQUIRED", "1") == "1"
if NETRA_DEPLOYMENT_ENV == "production" and not NETRA_DATABASE_SSL_REQUIRED:
    raise RuntimeError("NETRA_DATABASE_SSL_REQUIRED cannot be disabled when NETRA_DEPLOYMENT_ENV=production")
DATABASE_CONN_MAX_AGE = int(os.getenv("DATABASE_CONN_MAX_AGE", "0" if os.getenv("NETRA_DATABASE_PROVIDER", "").lower() == "supabase" else "60"))
NETRA_TEST_POSTGRES = os.getenv("NETRA_TEST_POSTGRES", "0") == "1"
NETRA_TEST_SQLITE = not NETRA_TEST_POSTGRES and (
    os.getenv("NETRA_TEST_SQLITE", "0") == "1" or ("test" in sys.argv and not DATABASE_URL)
)
if NETRA_TEST_SQLITE:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "test.sqlite3"}}
elif DATABASE_URL:
    DATABASES = {"default": dj_database_url.parse(DATABASE_URL, conn_max_age=DATABASE_CONN_MAX_AGE, ssl_require=NETRA_DATABASE_SSL_REQUIRED)}
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "netra"),
            "USER": os.getenv("POSTGRES_USER", "netra"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", "netra"),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

NETRA_STORAGE_ROOT = Path(os.getenv("NETRA_STORAGE_ROOT", REPO_ROOT / "storage"))
NETRA_TEMP_ROOT = Path(os.getenv("NETRA_TEMP_ROOT", REPO_ROOT / ".netra-tmp"))
NETRA_DATABASE_PROVIDER = os.getenv("NETRA_DATABASE_PROVIDER", "postgres").lower()
NETRA_STORAGE_PROVIDER = os.getenv("NETRA_STORAGE_PROVIDER", "local").lower()
NETRA_QUEUE_PROVIDER = os.getenv("NETRA_QUEUE_PROVIDER", "postgres-row-lock").lower()
NETRA_REALTIME_PROVIDER = os.getenv("NETRA_REALTIME_PROVIDER", "sse").lower()
if NETRA_FREE_PLAN_GUARD and NETRA_REALTIME_PROVIDER == "supabase":
    # Database Realtime can consume the free project's egress continuously.
    # Keep stale deployment variables from overriding the guarded profile.
    NETRA_REALTIME_PROVIDER = "sse"
NETRA_AUTH_PROVIDER = os.getenv("NETRA_AUTH_PROVIDER", "django").lower()
NETRA_MFA_POLICY = os.getenv("NETRA_MFA_POLICY", "admin_required").strip().lower()
if NETRA_MFA_POLICY not in {"admin_required", "optional"}:
    raise RuntimeError("NETRA_MFA_POLICY must be admin_required or optional")
NETRA_AUTH_INVITATIONS_ENABLED = os.getenv("NETRA_AUTH_INVITATIONS_ENABLED", "0") == "1"
NETRA_PASSWORD_RECOVERY_ENABLED = os.getenv("NETRA_PASSWORD_RECOVERY_ENABLED", "0") == "1"
NETRA_AUTH_INVITE_REDIRECT_URL = os.getenv("NETRA_AUTH_INVITE_REDIRECT_URL", "").strip()
NETRA_AUTH_ADMIN_TIMEOUT_SECONDS = max(1, min(15, int(os.getenv("NETRA_AUTH_ADMIN_TIMEOUT_SECONDS", "5"))))
NETRA_AUTH_ADMIN_RESPONSE_MAX_BYTES = max(4096, min(1048576, int(os.getenv("NETRA_AUTH_ADMIN_RESPONSE_MAX_BYTES", "65536"))))
NETRA_AUTH_ADMIN_LIST_PAGE_SIZE = max(1, min(100, int(os.getenv("NETRA_AUTH_ADMIN_LIST_PAGE_SIZE", "100"))))
# Ceiling on the pages one directory read may walk, so a large tenant cannot
# turn a single console load into an unbounded fan-out against Supabase Auth.
NETRA_AUTH_ADMIN_MAX_LIST_PAGES = max(1, min(50, int(os.getenv("NETRA_AUTH_ADMIN_MAX_LIST_PAGES", "10"))))
# Reported to the administration console so the retention window is stated
# rather than assumed. Enforcing it is a scheduled-job concern, not a read one.
NETRA_ACCESS_LOG_RETENTION_DAYS = max(1, min(3650, int(os.getenv("NETRA_ACCESS_LOG_RETENTION_DAYS", "365"))))
NETRA_SEARCH_PROVIDER = os.getenv("NETRA_SEARCH_PROVIDER", "postgres").lower()
NETRA_DATABASE_MODE = os.getenv("NETRA_DATABASE_MODE", "docker-postgres")
NETRA_KAFKA_BOOTSTRAP = os.getenv("NETRA_KAFKA_BOOTSTRAP", "localhost:9092")
NETRA_ELASTICSEARCH_URL = os.getenv("NETRA_ELASTICSEARCH_URL", "http://localhost:9200")
SUPABASE_PROJECT_REF = os.getenv("SUPABASE_PROJECT_REF", "")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_PUBLISHABLE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
_reject_retired_secret_alias("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY")
NETRA_SUPABASE_JWT_MODE = os.getenv("NETRA_SUPABASE_JWT_MODE", "remote").strip().lower()
if NETRA_SUPABASE_JWT_MODE not in {"remote", "asymmetric-jwks"}:
    raise RuntimeError("NETRA_SUPABASE_JWT_MODE must be remote or asymmetric-jwks")
NETRA_SUPABASE_JWKS_CACHE_SECONDS = max(60, min(3600, int(os.getenv("NETRA_SUPABASE_JWKS_CACHE_SECONDS", "600"))))
NETRA_SUPABASE_JWKS_TIMEOUT_SECONDS = max(1, min(10, int(os.getenv("NETRA_SUPABASE_JWKS_TIMEOUT_SECONDS", "3"))))
NETRA_SUPABASE_JWKS_RESPONSE_MAX_BYTES = max(
    4096,
    min(1048576, int(os.getenv("NETRA_SUPABASE_JWKS_RESPONSE_MAX_BYTES", "131072"))),
)
NETRA_SUPABASE_JWT_AUDIENCE = os.getenv("NETRA_SUPABASE_JWT_AUDIENCE", "authenticated").strip()
NETRA_SUPABASE_PRIVILEGED_VERIFY_TIMEOUT_SECONDS = max(
    1,
    min(10, int(os.getenv("NETRA_SUPABASE_PRIVILEGED_VERIFY_TIMEOUT_SECONDS", "3"))),
)
SUPABASE_STORAGE_BUCKET_EVIDENCE = os.getenv("SUPABASE_STORAGE_BUCKET_EVIDENCE", "netra-evidence")
SUPABASE_STORAGE_BUCKET_CAPTURE_CHUNKS = os.getenv("SUPABASE_STORAGE_BUCKET_CAPTURE_CHUNKS", "netra-capture-chunks")
SUPABASE_STORAGE_BUCKET_ANALYSIS_CHUNKS = os.getenv("SUPABASE_STORAGE_BUCKET_ANALYSIS_CHUNKS", "netra-analysis-chunks")
SUPABASE_STORAGE_BUCKET_ZEEK_LOGS = os.getenv("SUPABASE_STORAGE_BUCKET_ZEEK_LOGS", "netra-zeek-logs")
SUPABASE_STORAGE_BUCKET_REPORTS = os.getenv("SUPABASE_STORAGE_BUCKET_REPORTS", "netra-reports")
SUPABASE_STORAGE_BUCKET_EXPORTS = os.getenv("SUPABASE_STORAGE_BUCKET_EXPORTS", "netra-exports")
SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE = os.getenv("SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE", "evidence-quarantine")
SUPABASE_QUEUE_VISIBILITY_SECONDS = int(os.getenv("SUPABASE_QUEUE_VISIBILITY_SECONDS", "60"))
SUPABASE_QUEUE_BATCH_SIZE = int(os.getenv("SUPABASE_QUEUE_BATCH_SIZE", "10"))
NETRA_SUPABASE_START_WORKERS = os.getenv("NETRA_SUPABASE_START_WORKERS", "0") == "1" and not NETRA_FREE_PLAN_GUARD
_legacy_service_kind = os.getenv("NETRA_SERVICE_KIND", "").strip().lower()
NETRA_RUNTIME_ROLE = os.getenv("NETRA_RUNTIME_ROLE", _legacy_service_kind or "api").strip().lower()
if NETRA_RUNTIME_ROLE not in {"api", "worker"}:
    raise RuntimeError("NETRA_RUNTIME_ROLE must be api or worker")
if _legacy_service_kind and _legacy_service_kind != NETRA_RUNTIME_ROLE:
    raise RuntimeError("NETRA_SERVICE_KIND conflicts with NETRA_RUNTIME_ROLE")
NETRA_PROCESSING_MODE = os.getenv("NETRA_PROCESSING_MODE", "postgres-worker").strip().lower()
_reject_conflicting_alias("NETRA_SUPABASE_PROCESSING_MODE", "NETRA_PROCESSING_MODE", NETRA_PROCESSING_MODE)
NETRA_DEV_ROLE_HEADERS = os.getenv(
    "NETRA_DEV_ROLE_HEADERS",
    "1" if DEBUG and NETRA_DEPLOYMENT_PROFILE == "local" else "0",
) == "1"
NETRA_ACCESS_MODE = os.getenv("NETRA_ACCESS_MODE", "bearer").lower()
NETRA_PUBLIC_API_AUTH_REQUIRED = os.getenv("NETRA_PUBLIC_API_AUTH_REQUIRED", "1") == "1"
_LEGACY_LAB_TOOLS_DEFAULT = os.getenv("NETRA_ENABLE_LAB_TOOLS", "1")
NETRA_ENABLE_PCAP_REPLAY = os.getenv(
    "NETRA_ENABLE_PCAP_REPLAY",
    "0" if NETRA_FREE_PLAN_GUARD else ("1" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else _LEGACY_LAB_TOOLS_DEFAULT),
) == "1" and not NETRA_FREE_PLAN_GUARD
NETRA_ENABLE_SENSOR_CAPTURE = os.getenv(
    "NETRA_ENABLE_SENSOR_CAPTURE",
    "0" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else _LEGACY_LAB_TOOLS_DEFAULT,
) == "1"
# Compatibility aggregate for older operational checks. API authorization uses
# the narrower replay and sensor flags below instead of exposing both together.
NETRA_ENABLE_LAB_TOOLS = NETRA_ENABLE_PCAP_REPLAY or NETRA_ENABLE_SENSOR_CAPTURE
NETRA_ENABLE_INTEGRATIONS = os.getenv(
    "NETRA_ENABLE_INTEGRATIONS",
    "0" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else "1",
) == "1"
NETRA_ENABLE_STRUCTURED_IMPORTS = os.getenv(
    "NETRA_ENABLE_STRUCTURED_IMPORTS",
    "0" if NETRA_FREE_PLAN_GUARD else "1",
) == "1"
NETRA_ENABLE_CAPTURE_SCHEDULES = os.getenv(
    "NETRA_ENABLE_CAPTURE_SCHEDULES",
    "0" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else "1",
) == "1"
NETRA_ENABLE_RETENTION_OPERATIONS = os.getenv(
    "NETRA_ENABLE_RETENTION_OPERATIONS",
    "0" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else "1",
) == "1"
NETRA_AUTH_PROXY_ENABLED = os.getenv(
    "NETRA_AUTH_PROXY_ENABLED",
    "1" if DEBUG and NETRA_DEPLOYMENT_PROFILE == "local" and os.getenv("NETRA_AUTH_PROVIDER", "django").lower() == "django" else "0",
) == "1"
NETRA_STORAGE_DEEP_HEALTHCHECK = os.getenv("NETRA_STORAGE_DEEP_HEALTHCHECK", "0") == "1" and not NETRA_FREE_PLAN_GUARD
NETRA_TRUSTED_LAN_ACTOR = os.getenv("NETRA_TRUSTED_LAN_ACTOR", "Local Investigator")
NETRA_TRUSTED_LAN_ROLE = os.getenv("NETRA_TRUSTED_LAN_ROLE", "LAN Operator")
NETRA_EVIDENCE_ENCRYPTION = os.getenv("NETRA_EVIDENCE_ENCRYPTION", "on")
NETRA_EVIDENCE_KEY = os.getenv("NETRA_EVIDENCE_KEY", "netra-development-evidence-key")
NETRA_EVIDENCE_KEY_ID = os.getenv("NETRA_EVIDENCE_KEY_ID", "dev-key-001")
NETRA_STORAGE_CACHE_ENABLED = os.getenv("NETRA_STORAGE_CACHE_ENABLED", "1") == "1"
NETRA_STORAGE_CACHE_MAX_BYTES = int(os.getenv("NETRA_STORAGE_CACHE_MAX_BYTES", str(600 * 1024 * 1024)))
NETRA_STORAGE_CACHE_MIN_FREE_BYTES = int(os.getenv("NETRA_STORAGE_CACHE_MIN_FREE_BYTES", str(200 * 1024 * 1024)))
NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS = int(os.getenv("NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS", "3600"))
NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS = int(os.getenv("NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS", "60"))
NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS = int(os.getenv("NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS", "30"))
NETRA_CUSTODY_ANCHORS_ENABLED = os.getenv("NETRA_CUSTODY_ANCHORS_ENABLED", "0") == "1"
NETRA_CUSTODY_SIGNING_PRIVATE_KEY = os.getenv("NETRA_CUSTODY_SIGNING_PRIVATE_KEY", "")
NETRA_CUSTODY_SIGNING_KEY_ID = os.getenv("NETRA_CUSTODY_SIGNING_KEY_ID", "")
if NETRA_STORAGE_CACHE_MAX_BYTES <= 0 or NETRA_STORAGE_CACHE_MIN_FREE_BYTES <= 0:
    raise RuntimeError("Storage cache maximum and minimum free-space values must be positive")
NETRA_EVIDENCE_PREVIOUS_KEYS = [item.strip() for item in os.getenv("NETRA_EVIDENCE_PREVIOUS_KEYS", "").split(",") if item.strip()]
NETRA_EVIDENCE_WRITE_FORMAT = os.getenv("NETRA_EVIDENCE_WRITE_FORMAT", "v2").lower()
NETRA_MAX_UPLOAD_MB = max(
    1,
    min(
        int(os.getenv("NETRA_MAX_UPLOAD_MB", "25" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else "500")),
        25 if NETRA_FREE_PLAN_GUARD else 1024,
    ),
)
NETRA_DIRECT_UPLOAD_ENABLED = os.getenv("NETRA_DIRECT_UPLOAD_ENABLED", "0") == "1" and not NETRA_FREE_PLAN_GUARD
NETRA_DIRECT_UPLOAD_MAX_MB = max(
    1,
    min(
        int(os.getenv("NETRA_DIRECT_UPLOAD_MAX_MB", "25" if NETRA_DEPLOYMENT_PROFILE == "hackathon-core" else "500")),
        500,
    ),
)
NETRA_UPLOAD_SESSION_TTL_SECONDS = max(300, min(int(os.getenv("NETRA_UPLOAD_SESSION_TTL_SECONDS", "86400")), 86400))
NETRA_UPLOAD_TUS_CHUNK_BYTES = 6 * 1024 * 1024
NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES = max(
    1024 * 1024,
    min(int(os.getenv("NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES", str(8 * 1024 * 1024))), 16 * 1024 * 1024),
)
NETRA_MAX_INMEMORY_ARTIFACT_BYTES = max(
    1,
    min(int(os.getenv("NETRA_MAX_INMEMORY_ARTIFACT_BYTES", str(8 * 1024 * 1024))), 8 * 1024 * 1024),
)
NETRA_RATE_LIMITS_ENABLED = os.getenv("NETRA_RATE_LIMITS_ENABLED", "1") == "1"
NETRA_RATE_LIMIT_READ_PER_MINUTE = max(1, int(os.getenv("NETRA_RATE_LIMIT_READ_PER_MINUTE", "300")))
NETRA_RATE_LIMIT_MUTATION_PER_MINUTE = max(1, int(os.getenv("NETRA_RATE_LIMIT_MUTATION_PER_MINUTE", "60")))
NETRA_RATE_LIMIT_UPLOAD_USER_PER_HOUR = max(1, int(os.getenv("NETRA_RATE_LIMIT_UPLOAD_USER_PER_HOUR", "10")))
NETRA_RATE_LIMIT_UPLOAD_ORG_PER_HOUR = max(1, int(os.getenv("NETRA_RATE_LIMIT_UPLOAD_ORG_PER_HOUR", "25")))
NETRA_RATE_LIMIT_REPORT_USER_PER_HOUR = max(1, int(os.getenv("NETRA_RATE_LIMIT_REPORT_USER_PER_HOUR", "10")))
NETRA_RATE_LIMIT_EXPORT_USER_PER_HOUR = max(1, int(os.getenv("NETRA_RATE_LIMIT_EXPORT_USER_PER_HOUR", "10")))
NETRA_RATE_LIMIT_WEBHOOK_TEST_ADMIN_PER_HOUR = max(1, int(os.getenv("NETRA_RATE_LIMIT_WEBHOOK_TEST_ADMIN_PER_HOUR", "5")))
NETRA_RATE_LIMIT_SSE_USER_PER_MINUTE = max(1, int(os.getenv("NETRA_RATE_LIMIT_SSE_USER_PER_MINUTE", "12")))
NETRA_RATE_LIMIT_SSE_ORG_PER_MINUTE = max(1, int(os.getenv("NETRA_RATE_LIMIT_SSE_ORG_PER_MINUTE", "60")))
NETRA_SSE_MAX_SECONDS = max(1.0, min(float(os.getenv("NETRA_SSE_MAX_SECONDS", "300")), 300.0))
NETRA_SSE_HEARTBEAT_SECONDS = max(1.0, min(float(os.getenv("NETRA_SSE_HEARTBEAT_SECONDS", "15")), 60.0))
NETRA_SSE_POLL_SECONDS = max(0.1, min(float(os.getenv("NETRA_SSE_POLL_SECONDS", "5")), 30.0))
NETRA_SSE_BATCH_SIZE = max(1, min(int(os.getenv("NETRA_SSE_BATCH_SIZE", "100")), 100))
NETRA_BPF_FILTER_ENABLED = os.getenv("NETRA_BPF_FILTER_ENABLED", "0") == "1"
NETRA_ENABLE_HOST_CAPTURE = os.getenv("NETRA_ENABLE_HOST_CAPTURE", "0") == "1"
NETRA_WORKER_MAX_RETRIES = max(1, int(os.getenv("NETRA_WORKER_MAX_RETRIES", "3")))
NETRA_JOB_LEASE_SECONDS = max(60, int(os.getenv("NETRA_JOB_LEASE_SECONDS", "900")))
NETRA_JOB_POLL_SECONDS = max(1, int(os.getenv("NETRA_JOB_POLL_SECONDS", "2")))
NETRA_JOB_HEARTBEAT_SECONDS = max(5, min(int(os.getenv("NETRA_JOB_HEARTBEAT_SECONDS", "10")), 15))
NETRA_QUARANTINE_ORPHAN_SECONDS = max(3600, int(os.getenv("NETRA_QUARANTINE_ORPHAN_SECONDS", "3600")))
NETRA_CLEANUP_INTERVAL_SECONDS = max(300, int(os.getenv("NETRA_CLEANUP_INTERVAL_SECONDS", "900")))
NETRA_SENSOR_SHARED_KEY = os.getenv("NETRA_SENSOR_SHARED_KEY", "netra-local-sensor-key")
NETRA_WEBHOOK_ALLOWED_HOSTS = [
    value.strip()
    for value in os.getenv("NETRA_WEBHOOK_ALLOWED_HOSTS", "").split(",")
    if value.strip()
]
NETRA_WEBHOOK_CONNECT_TIMEOUT_SECONDS = max(1, min(int(os.getenv("NETRA_WEBHOOK_CONNECT_TIMEOUT_SECONDS", "3")), 10))
NETRA_WEBHOOK_READ_TIMEOUT_SECONDS = max(1, min(int(os.getenv("NETRA_WEBHOOK_READ_TIMEOUT_SECONDS", "5")), 15))
NETRA_WEBHOOK_REQUEST_MAX_BYTES = max(1024, min(int(os.getenv("NETRA_WEBHOOK_REQUEST_MAX_BYTES", str(256 * 1024))), 1024 * 1024))
NETRA_WEBHOOK_RESPONSE_MAX_BYTES = max(1024, min(int(os.getenv("NETRA_WEBHOOK_RESPONSE_MAX_BYTES", str(32 * 1024))), 256 * 1024))
NETRA_WEBHOOK_MAX_ATTEMPTS = max(1, min(int(os.getenv("NETRA_WEBHOOK_MAX_ATTEMPTS", "2")), 2))
NETRA_SYNC_FALLBACK_ENABLED = os.getenv("NETRA_SYNC_FALLBACK_ENABLED", "0") == "1"
NETRA_WORKER_HEARTBEAT_SECONDS = max(5, min(int(os.getenv("NETRA_WORKER_HEARTBEAT_SECONDS", "15")), 60))
NETRA_WORKER_STALE_AFTER_SECONDS = max(
    NETRA_WORKER_HEARTBEAT_SECONDS * 2,
    min(int(os.getenv("NETRA_WORKER_STALE_AFTER_SECONDS", "45")), 300),
)
NETRA_WORKER_CAPACITY_CACHE_SECONDS = max(0, min(int(os.getenv("NETRA_WORKER_CAPACITY_CACHE_SECONDS", "10")), 60))
NETRA_REQUIRED_TSHARK_VERSION = os.getenv("NETRA_REQUIRED_TSHARK_VERSION", "4.6.7").strip()
NETRA_REQUIRED_ZEEK_VERSION = os.getenv("NETRA_REQUIRED_ZEEK_VERSION", "8.2.1").strip()
NETRA_REQUIRE_WORKER_RELEASE_MATCH = os.getenv("NETRA_REQUIRE_WORKER_RELEASE_MATCH", "1") == "1"
NETRA_SYNC_FALLBACK_TIMEOUT_SECONDS = int(os.getenv("NETRA_SYNC_FALLBACK_TIMEOUT_SECONDS", "180"))
NETRA_PARSER_TIMEOUT_SECONDS = max(1, int(os.getenv("NETRA_PARSER_TIMEOUT_SECONDS", "180")))
NETRA_PARSER_STDOUT_MAX_BYTES = max(1024, int(os.getenv("NETRA_PARSER_STDOUT_MAX_BYTES", str(64 * 1024 * 1024))))
NETRA_PARSER_STDERR_MAX_BYTES = max(1024, int(os.getenv("NETRA_PARSER_STDERR_MAX_BYTES", str(1024 * 1024))))
NETRA_PARSER_CPU_SECONDS = max(1, int(os.getenv("NETRA_PARSER_CPU_SECONDS", "180")))
NETRA_PARSER_MEMORY_MAX_BYTES = max(64 * 1024 * 1024, int(os.getenv("NETRA_PARSER_MEMORY_MAX_BYTES", str(512 * 1024 * 1024))))
NETRA_PARSER_MAX_OPEN_FILES = max(16, int(os.getenv("NETRA_PARSER_MAX_OPEN_FILES", "64")))
NETRA_PARSER_MAX_PROCESSES = max(1, int(os.getenv("NETRA_PARSER_MAX_PROCESSES", "16")))
NETRA_PARSER_TEMP_MAX_BYTES = max(1024 * 1024, int(os.getenv("NETRA_PARSER_TEMP_MAX_BYTES", str(1024 * 1024 * 1024))))
NETRA_REPLAY_TIMEOUT_SECONDS = int(os.getenv("NETRA_REPLAY_TIMEOUT_SECONDS", "180"))
NETRA_ANALYSIS_SPLIT_THRESHOLD_MB = int(os.getenv("NETRA_ANALYSIS_SPLIT_THRESHOLD_MB", "100"))
NETRA_ANALYSIS_CHUNK_PACKETS = int(os.getenv("NETRA_ANALYSIS_CHUNK_PACKETS", "50000"))
NETRA_PACKET_INDEX_CAP = int(os.getenv("NETRA_PACKET_INDEX_CAP", "1000000"))
NETRA_KAFKA_LAG_WARNING = int(os.getenv("NETRA_KAFKA_LAG_WARNING", "1000"))
NETRA_KAFKA_LAG_CRITICAL = int(os.getenv("NETRA_KAFKA_LAG_CRITICAL", "5000"))
NETRA_DISK_WARNING_PERCENT = int(os.getenv("NETRA_DISK_WARNING_PERCENT", "80"))
NETRA_DISK_CRITICAL_PERCENT = int(os.getenv("NETRA_DISK_CRITICAL_PERCENT", "90"))
NETRA_FRONTEND_ORIGINS = os.getenv("NETRA_FRONTEND_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080").split(",")
# Browser origins permitted to reach /api/admin/v1/. Deliberately a separate,
# narrower list than NETRA_FRONTEND_ORIGINS: the investigator console is served
# to every officer, the administration console to a handful of them. It falls
# back to the frontend list rather than to "everything" so that an unset
# variable narrows to the origins already trusted instead of opening the
# namespace to any site. The admin console ships from the console origin, so
# that fallback is correct for the same-origin hosting decision.
NETRA_ADMIN_ORIGINS = [
    item.strip()
    for item in os.getenv("NETRA_ADMIN_ORIGINS", ",".join(NETRA_FRONTEND_ORIGINS)).split(",")
    if item.strip()
]
NETRA_PUBLIC_BASE_URL = os.getenv("NETRA_PUBLIC_BASE_URL", "http://localhost:8080")
NETRA_REQUIRE_HTTPS = os.getenv("NETRA_REQUIRE_HTTPS", "0") == "1"
NETRA_RELEASE_ID = os.getenv("NETRA_RELEASE_ID", "local-dev")
NETRA_ALLOWED_STACK = [
    "Django/Gunicorn on Railway",
    "Supabase Postgres/Auth/Storage",
    "React/Vite on Vercel",
    "PostgreSQL row-locked processing jobs",
    "TShark 4.6.7",
    "Zeek 8.2.1",
    "Deterministic detector registry",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    )
}

# Django's default configuration only reaches the console while DEBUG is on, so
# a hosted deployment returns 500 with no trace of why. Unhandled request
# exceptions and deliberate service warnings go to stderr, where the platform
# log collector already reads them. Request payloads are never logged.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"netra": {"format": "[%(asctime)s] %(levelname)s %(name)s: %(message)s"}},
    "handlers": {
        "console": {"class": "logging.StreamHandler", "stream": sys.stderr, "formatter": "netra"},
    },
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "common": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "apps.forensics": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}

if not DEBUG:
    if SECRET_KEY == "netra-development-only-secret":
        raise RuntimeError("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG=0")
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_REFERRER_POLICY = "no-referrer"
    SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = NETRA_REQUIRE_HTTPS
    # Railway's private deployment probe is HTTP inside its network. Exempt only
    # the minimal health route while retaining HTTPS redirects everywhere else.
    SECURE_REDIRECT_EXEMPT = [r"^api/health/?$"]
    SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_SECURE_HSTS_SECONDS", "0"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = os.getenv("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", "0") == "1"
    SECURE_HSTS_PRELOAD = os.getenv("DJANGO_SECURE_HSTS_PRELOAD", "0") == "1"
    CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if origin.strip()]
    if os.getenv("DJANGO_SECURE_PROXY_SSL_HEADER", "0") == "1":
        SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    if NETRA_DEV_ROLE_HEADERS or NETRA_ACCESS_MODE != "bearer":
        raise RuntimeError("Hosted deployments require bearer access mode and disabled development role headers")
    if NETRA_AUTH_PROVIDER == "supabase" and (not SUPABASE_URL or not SUPABASE_PUBLISHABLE_KEY):
        raise RuntimeError("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are required for Supabase authentication")
    if NETRA_AUTH_INVITATIONS_ENABLED:
        if NETRA_AUTH_PROVIDER != "supabase" or not SUPABASE_SECRET_KEY:
            raise RuntimeError("Hosted invitations require Supabase Auth and a backend secret key")
        if not NETRA_AUTH_INVITE_REDIRECT_URL.startswith("https://"):
            raise RuntimeError("NETRA_AUTH_INVITE_REDIRECT_URL must be an exact HTTPS URL")
    if NETRA_EVIDENCE_ENCRYPTION == "on" and NETRA_EVIDENCE_KEY == "netra-development-evidence-key":
        raise RuntimeError("NETRA_EVIDENCE_KEY must be replaced outside local development")
    if NETRA_EVIDENCE_ENCRYPTION != "on" or NETRA_EVIDENCE_WRITE_FORMAT != "v2":
        raise RuntimeError("Hosted deployments require encrypted v2 artifact writes")
    if not NETRA_STORAGE_CACHE_ENABLED:
        raise RuntimeError("Hosted deployments require the persistent encrypted Storage cache")
    if NETRA_CUSTODY_ANCHORS_ENABLED:
        if not NETRA_CUSTODY_SIGNING_PRIVATE_KEY or not NETRA_CUSTODY_SIGNING_KEY_ID:
            raise RuntimeError("Signed custody anchors require a private key and stable key ID")
        try:
            if len(base64.b64decode(NETRA_CUSTODY_SIGNING_PRIVATE_KEY, validate=True)) != 32:
                raise ValueError
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError("NETRA_CUSTODY_SIGNING_PRIVATE_KEY must be 32 raw Ed25519 bytes in base64") from exc
    if NETRA_DIRECT_UPLOAD_ENABLED:
        if NETRA_DEPLOYMENT_PROFILE != "full":
            raise RuntimeError("NETRA_DIRECT_UPLOAD_ENABLED requires NETRA_DEPLOYMENT_PROFILE=full")
        if NETRA_STORAGE_PROVIDER != "supabase" or NETRA_AUTH_PROVIDER != "supabase":
            raise RuntimeError("Direct evidence upload requires Supabase Auth and Storage")
        if not SUPABASE_SECRET_KEY:
            raise RuntimeError("SUPABASE_SECRET_KEY is required for quarantine validation")
    if NETRA_DEPLOYMENT_PROFILE == "full" and NETRA_SENSOR_SHARED_KEY == "netra-local-sensor-key":
        raise RuntimeError("NETRA_SENSOR_SHARED_KEY must be replaced for the full deployment profile")
