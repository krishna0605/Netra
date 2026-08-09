from pathlib import Path

from django.test import SimpleTestCase

from apps.forensics.urls import urlpatterns
from apps.forensics.route_policies import RoutePolicy
from common.capabilities import capability_registry


class ApiModuleBoundaryTests(SimpleTestCase):
    def test_routes_resolve_to_owning_modules_not_legacy_facades(self):
        forbidden = {
            "apps.forensics.views",
            "apps.forensics.api.legacy_views",
        }
        self.assertGreaterEqual(len(urlpatterns), 183)
        for pattern in urlpatterns:
            callback_module = pattern.callback.__module__
            self.assertNotIn(callback_module, forbidden, str(pattern.pattern))

    def test_feature_modules_are_bounded_and_do_not_wildcard_import_legacy(self):
        api_root = Path(__file__).resolve().parents[1] / "api"
        for filename in (
            "cases.py",
            "evidence.py",
            "capture.py",
            "operations.py",
            "reports.py",
            "compliance.py",
            "legacy_support.py",
            "legacy_views.py",
        ):
            source = (api_root / filename).read_text(encoding="utf-8")
            nonempty_lines = [line for line in source.splitlines() if line.strip()]
            self.assertLessEqual(len(nonempty_lines), 800, filename)
            self.assertNotIn("legacy_views import *", source, filename)

    def test_legacy_facade_contains_only_deprecated_adapters(self):
        api_root = Path(__file__).resolve().parents[1] / "api"
        source = (api_root / "legacy_views.py").read_text(encoding="utf-8")
        self.assertIn("Deprecated compatibility adapters", source)
        self.assertNotIn("def cases(", source)
        self.assertNotIn("def evidence_upload(", source)
        self.assertNotIn("def report_download(", source)

    def test_every_route_declares_complete_security_policy(self):
        anonymous_routes = set()
        capability_keys = set(capability_registry())
        for pattern in urlpatterns:
            policy = getattr(pattern, "netra_route_policy", None)
            self.assertIsInstance(policy, RoutePolicy, str(pattern.pattern))
            if policy.authentication == "anonymous":
                anonymous_routes.add(str(pattern.pattern).strip("/"))
                self.assertEqual(policy.scope, "none")
                self.assertEqual(policy.aal, "none")
                self.assertEqual(policy.rate_category, "excluded")
            if policy.authentication == "sensor-key":
                self.assertEqual(policy.scope, "none")
                self.assertEqual(policy.rate_category, "excluded")
            if policy.scope == "case+job":
                route = str(pattern.pattern)
                self.assertTrue("job_id" in route or route.strip("/") == "search")
            if policy.aal == "aal2":
                route = str(pattern.pattern).strip("/")
                self.assertTrue(
                    route.startswith(("setup/", "users", "admin/"))
                    or (route.startswith("integrations/") and route.endswith("/credential"))
                )
            if policy.capability is not None:
                self.assertIn(policy.capability, capability_keys)
        self.assertEqual(anonymous_routes, {"health", "auth/login", "auth/refresh"})
