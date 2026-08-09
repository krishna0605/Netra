import importlib.util
import os
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase


SETTINGS_PATH = Path(settings.BASE_DIR) / "config" / "settings.py"

# Force the DATABASE_URL branch regardless of how the outer suite is running.
BASE_ENVIRONMENT = {
    "DJANGO_DEBUG": "1",
    "NETRA_TEST_SQLITE": "0",
    "NETRA_TEST_POSTGRES": "0",
    "NETRA_DEPLOYMENT_PROFILE": "local",
    "NETRA_DEPLOYMENT_ENV": "local",
    "DATABASE_URL": "postgresql://netra:netra@127.0.0.1:5432/netra",
}

RETIRED_ALIASES = (
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_POOLER_DATABASE_URL",
    "SUPABASE_DIRECT_DATABASE_URL",
    "NETRA_SUPABASE_PROCESSING_MODE",
    "NETRA_SERVICE_KIND",
)


def load_settings(**overrides):
    """Execute config/settings.py in an isolated namespace under a patched environment.

    The real ``config.settings`` module stays untouched, so a probe can assert
    startup guards without disturbing the running test process.
    """
    environment = {**BASE_ENVIRONMENT, **{k: v for k, v in overrides.items() if v is not None}}
    cleared = {alias: None for alias in RETIRED_ALIASES if alias not in overrides}
    with mock.patch.dict(os.environ, environment, clear=False):
        for name in [*cleared, *[k for k, v in overrides.items() if v is None]]:
            os.environ.pop(name, None)
        spec = importlib.util.spec_from_file_location("netra_settings_probe", SETTINGS_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class DatabaseTransportPolicyTests(SimpleTestCase):
    def test_transport_layer_security_is_required_by_default(self):
        probe = load_settings()

        self.assertTrue(probe.NETRA_DATABASE_SSL_REQUIRED)
        self.assertEqual(probe.DATABASES["default"]["OPTIONS"]["sslmode"], "require")

    def test_loopback_continuous_integration_may_opt_out(self):
        probe = load_settings(NETRA_DATABASE_SSL_REQUIRED="0")

        self.assertFalse(probe.NETRA_DATABASE_SSL_REQUIRED)
        self.assertNotIn("sslmode", probe.DATABASES["default"].get("OPTIONS", {}))

    def test_production_refuses_to_start_without_transport_layer_security(self):
        with self.assertRaises(RuntimeError) as raised:
            load_settings(NETRA_DEPLOYMENT_ENV="production", NETRA_DATABASE_SSL_REQUIRED="0")

        self.assertIn("NETRA_DATABASE_SSL_REQUIRED", str(raised.exception))

    def test_production_keeps_requiring_transport_layer_security_by_default(self):
        probe = load_settings(NETRA_DEPLOYMENT_ENV="production")

        self.assertTrue(probe.NETRA_DATABASE_SSL_REQUIRED)
        self.assertEqual(probe.DATABASES["default"]["OPTIONS"]["sslmode"], "require")


class RetiredEnvironmentAliasTests(SimpleTestCase):
    def test_conflicting_database_alias_aborts_startup(self):
        with self.assertRaises(RuntimeError) as raised:
            load_settings(SUPABASE_POOLER_DATABASE_URL="postgresql://other:other@127.0.0.1:5432/other")

        self.assertIn("SUPABASE_POOLER_DATABASE_URL", str(raised.exception))

    def test_conflicting_direct_database_alias_aborts_startup(self):
        with self.assertRaises(RuntimeError):
            load_settings(SUPABASE_DIRECT_DATABASE_URL="postgresql://other:other@127.0.0.1:5432/other")

    def test_conflicting_secret_key_alias_aborts_startup(self):
        with self.assertRaises(RuntimeError) as raised:
            load_settings(SUPABASE_SECRET_KEY="sb_secret_canonical", SUPABASE_SERVICE_ROLE_KEY="legacy-jwt")

        self.assertIn("SUPABASE_SERVICE_ROLE_KEY", str(raised.exception))

    def test_conflicting_processing_mode_alias_aborts_startup(self):
        with self.assertRaises(RuntimeError) as raised:
            load_settings(NETRA_PROCESSING_MODE="postgres-worker", NETRA_SUPABASE_PROCESSING_MODE="hybrid")

        self.assertIn("NETRA_SUPABASE_PROCESSING_MODE", str(raised.exception))

    def test_matching_alias_is_accepted_during_the_transition(self):
        probe = load_settings(
            DATABASE_URL="postgresql://netra:netra@127.0.0.1:5432/netra",
            SUPABASE_POOLER_DATABASE_URL="postgresql://netra:netra@127.0.0.1:5432/netra",
            SUPABASE_SECRET_KEY="sb_secret_canonical",
            SUPABASE_SERVICE_ROLE_KEY="sb_secret_canonical",
            NETRA_PROCESSING_MODE="postgres-worker",
            NETRA_SUPABASE_PROCESSING_MODE="postgres-worker",
        )

        self.assertEqual(probe.NETRA_PROCESSING_MODE, "postgres-worker")

    def test_alias_alone_does_not_abort_startup(self):
        probe = load_settings(SUPABASE_SECRET_KEY=None, SUPABASE_SERVICE_ROLE_KEY="legacy-jwt")

        self.assertEqual(probe.SUPABASE_SECRET_KEY, "")


class DeploymentEnvironmentTests(SimpleTestCase):
    def test_deployment_environment_is_resolved_before_database_configuration(self):
        source = SETTINGS_PATH.read_text(encoding="utf-8")

        self.assertLess(
            source.index("NETRA_DEPLOYMENT_ENV = "),
            source.index("DATABASE_URL = os.getenv"),
            "NETRA_DEPLOYMENT_ENV must be resolved before the database transport guard runs",
        )
        self.assertEqual(source.count("NETRA_DEPLOYMENT_ENV = os.getenv"), 1)
