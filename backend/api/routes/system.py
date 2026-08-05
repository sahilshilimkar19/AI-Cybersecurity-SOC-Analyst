"""What the signed-in caller is permitted to do.

The SPA asks rather than assumes. Duplicating the RBAC table in TypeScript would
create a second copy of a security-relevant rule that nothing keeps in step with
the first, and the copy would be the one the interface obeys.

Hiding a control the caller cannot use is a courtesy, not a control: every
endpoint checks the same capability again on every request regardless of what the
client chose to render.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.api.deps import get_current_principal
from backend.api.schemas.system import CapabilitiesResponse
from backend.auth.rbac import capabilities_for
from backend.auth.schemas import Principal

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/capabilities", response_model=CapabilitiesResponse)
def get_capabilities(
    principal: Principal = Depends(get_current_principal),
) -> CapabilitiesResponse:
    """The caller's role and the capabilities it grants."""
    return CapabilitiesResponse(
        role=principal.role,
        capabilities=sorted(capability.value for capability in capabilities_for(principal.role)),
    )
