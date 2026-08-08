from __future__ import annotations

from uuid import UUID

from apps.forensics.models import Organization


NETRA_ORGANIZATION_ID = UUID("d1a04e58-9de1-5ed9-82d0-68b836ef3e10")


def netra_organization() -> Organization:
    return Organization.objects.get(pk=NETRA_ORGANIZATION_ID)
