from django.test import TestCase, override_settings

from common.readiness import deployment_readiness_payload, status_matrix_payload


class FreePlanMigrationReadinessTests(TestCase):
    @override_settings(
        NETRA_FREE_PLAN_GUARD=True,
        NETRA_REALTIME_PROVIDER="sse",
        NETRA_STORAGE_DEEP_HEALTHCHECK=False,
        NETRA_STORAGE_ROOT="/app/storage",
        NETRA_QUEUE_PROVIDER="postgres-row-lock",
    )
    def test_egress_guards_pass_for_target_configuration(self):
        checks = {item["name"]: item for item in deployment_readiness_payload()["checks"]}

        for name in (
            "free-plan-egress-guard",
            "database-realtime-disabled",
            "deep-storage-check-disabled",
            "persistent-storage-contract",
            "queue-provider",
        ):
            self.assertEqual(checks[name]["status"], "pass")

    @override_settings(NETRA_QUEUE_PROVIDER="postgres-row-lock")
    def test_existing_postgres_worker_topology_is_a_valid_queue_provider(self):
        checks = {item["name"]: item for item in deployment_readiness_payload()["checks"]}

        self.assertEqual(checks["queue-provider"]["status"], "pass")

    @override_settings(NETRA_REALTIME_PROVIDER="sse")
    def test_status_matrix_does_not_claim_database_realtime_is_enabled(self):
        realtime = next(item for item in status_matrix_payload()["results"] if item["area"] == "Supabase Realtime")

        self.assertEqual(realtime["targetStatus"], "Removed From Supabase Mode")
        self.assertIn("not published", realtime["detail"])
