from __future__ import annotations

import re
from datetime import datetime
from uuid import uuid4


CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")


class InvalidCaseId(ValueError):
    """Raised when an external case identifier is not safe to persist or reuse."""


def validate_case_id(value: object) -> str:
    if not isinstance(value, str):
        raise InvalidCaseId("Case ID must be a string between 3 and 64 characters.")
    if value != value.strip() or not CASE_ID_PATTERN.fullmatch(value):
        raise InvalidCaseId(
            "Case ID must be 3 to 64 characters and contain only letters, numbers, underscores, and hyphens."
        )
    return value


def generate_case_id(*, prefix: str = "CYB-GJ", now: datetime | None = None) -> str:
    current = now or datetime.now()
    return validate_case_id(f"{prefix}-{current.year}-{uuid4().hex[:8].upper()}")
