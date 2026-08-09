from unittest import TestCase
from unittest.mock import MagicMock, patch

from django.test import override_settings

from apps.forensics.management.commands.bootstrap_supabase import BUCKETS, Command, REALTIME_TABLES


class SupabaseBootstrapEgressTests(TestCase):
    def test_default_bucket_bootstrap_never_transfers_objects(self):
        command = Command()

        with override_settings(
            SUPABASE_URL="https://exampleproject.supabase.co",
            SUPABASE_SECRET_KEY="test-secret-key",
        ), patch.object(command, "_storage_request", return_value="[]") as storage_request, patch.object(
            command, "_probe_bucket"
        ) as probe:
            result = command._buckets()

        probe.assert_not_called()
        self.assertEqual(storage_request.call_count, 1 + len(result) // 2)
        self.assertTrue(all(item.startswith(("created:", "metadata-verified:")) for item in result))

    def test_deep_bucket_check_is_explicit(self):
        command = Command()

        with override_settings(
            SUPABASE_URL="https://exampleproject.supabase.co",
            SUPABASE_SECRET_KEY="test-secret-key",
        ), patch.object(command, "_storage_request", return_value="[]"), patch.object(command, "_probe_bucket") as probe:
            result = command._buckets(deep_storage_check=True)

        self.assertEqual(probe.call_count, len(BUCKETS))
        self.assertTrue(any(item.startswith("deep-verified:") for item in result))

    def test_only_pgmq_extension_is_requested(self):
        command = Command()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor

        with patch("apps.forensics.management.commands.bootstrap_supabase.connection.cursor", return_value=cursor_context):
            result = command._extensions()

        self.assertEqual(result, ["create extension if not exists pgmq"])
        cursor.execute.assert_called_once_with("create extension if not exists pgmq")


class SupabaseBootstrapRealtimeTests(TestCase):
    @override_settings(NETRA_REALTIME_PROVIDER="sse")
    def test_disabled_provider_removes_only_netra_tables(self):
        command = Command()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [(True,)] + [(True,) for _ in REALTIME_TABLES]
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor

        with patch.object(command, "_realtime_tables", wraps=command._realtime_tables), patch(
            "apps.forensics.management.commands.bootstrap_supabase.connection.introspection.table_names",
            return_value=REALTIME_TABLES + ["unrelated_table"],
        ), patch("apps.forensics.management.commands.bootstrap_supabase.connection.cursor", return_value=cursor_context):
            result = command._realtime_tables()

        self.assertEqual(result, [f"removed:{table}" for table in REALTIME_TABLES])
        executed = [item.args[0] for item in cursor.execute.call_args_list]
        for table in REALTIME_TABLES:
            self.assertIn(f'alter publication supabase_realtime drop table public."{table}"', executed)
        self.assertFalse(any("unrelated_table" in statement for statement in executed))

    @override_settings(NETRA_REALTIME_PROVIDER="supabase")
    def test_supabase_provider_can_opt_in_to_publication(self):
        command = Command()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [(True,)] + [(False,) for _ in REALTIME_TABLES]
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor

        with patch(
            "apps.forensics.management.commands.bootstrap_supabase.connection.introspection.table_names",
            return_value=REALTIME_TABLES,
        ), patch("apps.forensics.management.commands.bootstrap_supabase.connection.cursor", return_value=cursor_context):
            result = command._realtime_tables()

        self.assertEqual(result, [f"added:{table}" for table in REALTIME_TABLES])

    @override_settings(NETRA_REALTIME_PROVIDER="supabase", NETRA_FREE_PLAN_GUARD=True)
    def test_free_plan_guard_overrides_stale_realtime_setting(self):
        command = Command()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [(True,)] + [(True,) for _ in REALTIME_TABLES]
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor

        with patch(
            "apps.forensics.management.commands.bootstrap_supabase.connection.introspection.table_names",
            return_value=REALTIME_TABLES,
        ), patch("apps.forensics.management.commands.bootstrap_supabase.connection.cursor", return_value=cursor_context):
            result = command._realtime_tables()

        self.assertEqual(result, [f"removed:{table}" for table in REALTIME_TABLES])
