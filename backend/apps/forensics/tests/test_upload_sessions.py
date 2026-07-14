from uuid import uuid4

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.forensics.models import UserProfile
from common.audit import Actor
from common.upload_sessions import UploadSessionProblem, create_upload_session, upload_session_payload


@override_settings(
    NETRA_DIRECT_UPLOAD_ENABLED=True,
    NETRA_DIRECT_UPLOAD_MAX_MB=500,
    NETRA_STORAGE_PROVIDER="supabase",
    NETRA_AUTH_PROVIDER="supabase",
    SUPABASE_URL="https://exampleproject.supabase.co",
    SUPABASE_PROJECT_REF="exampleproject",
    SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE="evidence-quarantine",
    NETRA_UPLOAD_SESSION_TTL_SECONDS=86400,
    NETRA_UPLOAD_TUS_CHUNK_BYTES=6 * 1024 * 1024,
)
class EvidenceUploadSessionTests(TestCase):
    def test_session_is_owner_scoped_idempotent_and_single_active(self):
        external_id = str(uuid4())
        user = get_user_model().objects.create_user(username="investigator@example.invalid")
        UserProfile.objects.create(user=user, role=UserProfile.Role.INVESTIGATOR, department="Test Cyber Unit")
        actor = Actor(
            user="Test Investigator",
            role=UserProfile.Role.INVESTIGATOR,
            authenticated=True,
            django_user_id=user.id,
            external_id=external_id,
        )
        request = {
            "caseId": "CYB-GJ-SESSION-001",
            "filename": "capture.pcapng",
            "sizeBytes": 64 * 1024 * 1024,
            "evidenceType": "Auto-detect",
            "lastModified": "1720000000000",
        }

        session, replayed = create_upload_session(actor, request, "same-request")
        repeated, repeated_replay = create_upload_session(actor, request, "same-request")
        response = upload_session_payload(session)

        self.assertFalse(replayed)
        self.assertTrue(repeated_replay)
        self.assertEqual(repeated.id, session.id)
        self.assertTrue(session.storage_path.startswith(f"{external_id}/{session.id}/"))
        self.assertEqual(response["tus"]["chunkSizeBytes"], 6 * 1024 * 1024)
        self.assertFalse(response["tus"]["upsert"])
        with self.assertRaises(UploadSessionProblem) as raised:
            create_upload_session(actor, {**request, "caseId": "CYB-GJ-SESSION-002"}, "different-request")
        self.assertEqual(raised.exception.code, "active_upload_exists")
