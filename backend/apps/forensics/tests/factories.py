from apps.forensics.models import Organization
from common.tenancy import NETRA_ORGANIZATION_ID


def netra_organization() -> Organization:
    return Organization.objects.get(pk=NETRA_ORGANIZATION_ID)
