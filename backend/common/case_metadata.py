from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apps.forensics.models import UserProfile

if TYPE_CHECKING:
    from common.audit import Actor


DEFAULT_DEPARTMENT = "Gujarat Cyber Crime Cell"

# Case flags are workflow metadata, not free-form notes. Keeping this list on
# the server prevents clients from injecting arbitrary labels into reports,
# search results, and custody-related views.
ALLOWED_CASE_FLAGS = (
    "urgent",
    "ransomware",
    "insider-threat",
    "exfiltration",
    "related-case",
    "needs-review",
    "synthetic",
    "release-gate",
)
ALLOWED_CASE_FLAG_SET = frozenset(ALLOWED_CASE_FLAGS)


class InvalidCaseFlags(ValueError):
    def __init__(self, invalid_flags: list[str]):
        self.invalid_flags = invalid_flags
        joined = ", ".join(invalid_flags)
        super().__init__(f"Unsupported case flag(s): {joined}.")


def server_case_identity(actor: Actor) -> tuple[str, str]:
    """Return audit identity exclusively from the authenticated server profile."""

    profile = None
    if actor.django_user_id:
        profile = UserProfile.objects.filter(user_id=actor.django_user_id).first()
    investigator = (profile.display_name if profile else "") or actor.user
    department = (profile.department if profile else "") or DEFAULT_DEPARTMENT
    return investigator.strip()[:160], department.strip()[:160]


def validated_case_flags(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise InvalidCaseFlags(["invalid-format"])

    cleaned: list[str] = []
    for raw_flag in value:
        flag = str(raw_flag).strip().lower()
        if flag and flag not in cleaned:
            cleaned.append(flag)

    invalid = [flag for flag in cleaned if flag not in ALLOWED_CASE_FLAG_SET]
    if invalid:
        raise InvalidCaseFlags(invalid)
    return cleaned
