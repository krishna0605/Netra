import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BASE_DIR.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "netra-development-only-secret")
DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,backend").split(",")

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
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
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
NETRA_DATABASE_MODE = os.getenv("NETRA_DATABASE_MODE", "docker-postgres")
NETRA_KAFKA_BOOTSTRAP = os.getenv("NETRA_KAFKA_BOOTSTRAP", "localhost:9092")
NETRA_ELASTICSEARCH_URL = os.getenv("NETRA_ELASTICSEARCH_URL", "http://localhost:9200")
NETRA_PROCESSING_MODE = os.getenv("NETRA_PROCESSING_MODE", "hybrid")
NETRA_DEV_ROLE_HEADERS = os.getenv("NETRA_DEV_ROLE_HEADERS", "1") == "1"
NETRA_ACCESS_MODE = os.getenv("NETRA_ACCESS_MODE", "role-headers").lower()
NETRA_TRUSTED_LAN_ACTOR = os.getenv("NETRA_TRUSTED_LAN_ACTOR", "Local Investigator")
NETRA_TRUSTED_LAN_ROLE = os.getenv("NETRA_TRUSTED_LAN_ROLE", "LAN Operator")
NETRA_EVIDENCE_ENCRYPTION = os.getenv("NETRA_EVIDENCE_ENCRYPTION", "on")
NETRA_EVIDENCE_KEY = os.getenv("NETRA_EVIDENCE_KEY", "netra-phase3-development-evidence-key")
NETRA_EVIDENCE_KEY_ID = os.getenv("NETRA_EVIDENCE_KEY_ID", "dev-key-001")
NETRA_MAX_UPLOAD_MB = int(os.getenv("NETRA_MAX_UPLOAD_MB", "200"))
NETRA_ENABLE_HOST_CAPTURE = os.getenv("NETRA_ENABLE_HOST_CAPTURE", "0") == "1"
NETRA_WORKER_MAX_RETRIES = int(os.getenv("NETRA_WORKER_MAX_RETRIES", "3"))
NETRA_SENSOR_SHARED_KEY = os.getenv("NETRA_SENSOR_SHARED_KEY", "netra-phase5-local-sensor-key")
NETRA_SYNC_FALLBACK_ENABLED = os.getenv("NETRA_SYNC_FALLBACK_ENABLED", "1") == "1"
NETRA_SYNC_FALLBACK_TIMEOUT_SECONDS = int(os.getenv("NETRA_SYNC_FALLBACK_TIMEOUT_SECONDS", "180"))
NETRA_ANALYSIS_SPLIT_THRESHOLD_MB = int(os.getenv("NETRA_ANALYSIS_SPLIT_THRESHOLD_MB", "100"))
NETRA_ANALYSIS_CHUNK_PACKETS = int(os.getenv("NETRA_ANALYSIS_CHUNK_PACKETS", "50000"))
NETRA_PACKET_INDEX_CAP = int(os.getenv("NETRA_PACKET_INDEX_CAP", "1000000"))
NETRA_KAFKA_LAG_WARNING = int(os.getenv("NETRA_KAFKA_LAG_WARNING", "1000"))
NETRA_KAFKA_LAG_CRITICAL = int(os.getenv("NETRA_KAFKA_LAG_CRITICAL", "5000"))
NETRA_DISK_WARNING_PERCENT = int(os.getenv("NETRA_DISK_WARNING_PERCENT", "80"))
NETRA_DISK_CRITICAL_PERCENT = int(os.getenv("NETRA_DISK_CRITICAL_PERCENT", "90"))
NETRA_FRONTEND_ORIGINS = os.getenv("NETRA_FRONTEND_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080").split(",")
NETRA_ALLOWED_STACK = [
    "Django",
    "PostgreSQL",
    "Elasticsearch",
    "Apache Kafka",
    "Scapy",
    "tshark/Wireshark",
    "Zeek",
    "Scikit-learn",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    )
}

if not DEBUG:
    if SECRET_KEY == "netra-development-only-secret":
        raise RuntimeError("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG=0")
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
