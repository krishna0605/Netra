from django.test import SimpleTestCase
from django.urls import resolve


class SecuritySensitiveRouteModularityTests(SimpleTestCase):
    def test_authentication_and_administration_routes_use_dedicated_module(self):
        routes = (
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/logout",
            "/api/auth/me",
            "/api/users",
            "/api/users/123",
            "/api/admin/organizations/d1a04e58-9de1-5ed9-82d0-68b836ef3e10/admin-transfer",
        )
        for route in routes:
            with self.subTest(route=route):
                self.assertEqual(resolve(route).func.__module__, "apps.forensics.api.authentication")

    def test_administration_console_routes_use_dedicated_module(self):
        """The routes that expose the whole directory live in one file.

        Same reasoning as the authentication module above: a route that can
        read every account in the organization should not become reachable
        because someone added a handler to a module whose job is analysis.
        """
        for route in ("/api/admin/v1/session", "/api/admin/v1/directory"):
            with self.subTest(route=route):
                self.assertEqual(resolve(route).func.__module__, "apps.forensics.api.admin_console")
