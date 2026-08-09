from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import SimpleTestCase, override_settings

from common.jwt_verifier import (
    SupabaseTokenInvalid,
    SupabaseVerificationUnavailable,
    reset_jwks_cache,
    verify_es256_token,
)


@override_settings(
    SUPABASE_URL="https://example-project.supabase.co",
    NETRA_SUPABASE_JWT_AUDIENCE="authenticated",
    NETRA_SUPABASE_JWKS_CACHE_SECONDS=600,
)
class SupabaseJwtVerificationTests(SimpleTestCase):
    def setUp(self):
        reset_jwks_cache()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.kid = "phase7-local-test-key"
        self.jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        self.jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})

    def tearDown(self):
        reset_jwks_cache()

    def _token(self, **overrides):
        now = datetime.now(UTC)
        claims = {
            "iss": "https://example-project.supabase.co/auth/v1",
            "aud": "authenticated",
            "exp": now + timedelta(minutes=10),
            "iat": now,
            "sub": str(uuid4()),
            "aal": "aal2",
            "role": "authenticated",
            "email": "admin@example.test",
            "app_metadata": {"netra_role": "Admin"},
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="ES256", headers={"kid": self.kid, "typ": "JWT"})

    def test_valid_es256_token_returns_bounded_verified_identity(self):
        with patch("common.jwt_verifier._fetch_jwks", return_value={self.kid: self.private_key.public_key()}):
            verified = verify_es256_token(self._token())
        self.assertEqual(verified.algorithm, "ES256")
        self.assertEqual(verified.aal, "aal2")
        self.assertEqual(verified.email, "admin@example.test")
        self.assertEqual(len(verified.token_fingerprint), 64)
        self.assertFalse(hasattr(verified, "role"))

    def test_algorithm_confusion_is_rejected_before_key_resolution(self):
        token = jwt.encode(
            {"sub": str(uuid4())},
            "local-test-secret",
            algorithm="HS256",
            headers={"kid": self.kid},
        )
        with patch("common.jwt_verifier._fetch_jwks") as fetch:
            with self.assertRaises(SupabaseTokenInvalid):
                verify_es256_token(token)
        fetch.assert_not_called()

    def test_unknown_kid_refreshes_once_and_is_negatively_cached(self):
        token = jwt.encode(
            {
                "iss": "https://example-project.supabase.co/auth/v1",
                "aud": "authenticated",
                "exp": datetime.now(UTC) + timedelta(minutes=5),
                "iat": datetime.now(UTC),
                "sub": str(uuid4()),
                "aal": "aal1",
                "role": "authenticated",
            },
            ec.generate_private_key(ec.SECP256R1()),
            algorithm="ES256",
            headers={"kid": "unknown-key"},
        )
        with patch("common.jwt_verifier._fetch_jwks", return_value={self.kid: self.private_key.public_key()}) as fetch:
            for _ in range(2):
                with self.assertRaises(SupabaseTokenInvalid):
                    verify_es256_token(token)
        self.assertEqual(fetch.call_count, 1)

    def test_cached_key_survives_short_jwks_outage(self):
        token = self._token()
        with patch("common.jwt_verifier._fetch_jwks", return_value={self.kid: self.private_key.public_key()}) as fetch:
            verify_es256_token(token)
            fetch.side_effect = SupabaseVerificationUnavailable("offline")
            verify_es256_token(token)
        self.assertEqual(fetch.call_count, 1)

    def test_outage_without_cached_key_fails_closed(self):
        with patch("common.jwt_verifier._fetch_jwks", side_effect=SupabaseVerificationUnavailable("offline")):
            with self.assertRaises(SupabaseVerificationUnavailable):
                verify_es256_token(self._token())

    def test_wrong_issuer_audience_role_and_aal_are_rejected(self):
        invalid_claims = (
            {"iss": "https://attacker.invalid/auth/v1"},
            {"aud": "anonymous"},
            {"role": "service_role"},
            {"aal": "aal3"},
        )
        for claims in invalid_claims:
            reset_jwks_cache()
            with self.subTest(claims=claims), patch(
                "common.jwt_verifier._fetch_jwks", return_value={self.kid: self.private_key.public_key()}
            ):
                with self.assertRaises(SupabaseTokenInvalid):
                    verify_es256_token(self._token(**claims))

    def test_future_issued_token_is_rejected(self):
        with patch("common.jwt_verifier._fetch_jwks", return_value={self.kid: self.private_key.public_key()}):
            with self.assertRaises(SupabaseTokenInvalid):
                verify_es256_token(self._token(iat=int(time.time()) + 120))

    def test_oversized_token_is_rejected_without_network(self):
        with patch("common.jwt_verifier._fetch_jwks") as fetch:
            with self.assertRaises(SupabaseTokenInvalid):
                verify_es256_token("a" * (16 * 1024 + 1))
        fetch.assert_not_called()
