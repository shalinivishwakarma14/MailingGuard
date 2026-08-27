from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.geolocation import get_ip_geolocation
from app.utils.ip_utils import validate_ip


router = APIRouter(
    prefix="/api/origin",
    tags=["Origin Tracing"],
)


class OriginRequest(BaseModel):
    ip: str


@router.post("/trace")
def trace_origin(request: OriginRequest):
    """
    Validate an IP address and return approximate origin information.
    """

    # Step 1: Validate the IP address
    ip_info = validate_ip(request.ip)

    if not ip_info.get("valid"):
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address",
        )

    # Step 2: Reject private, loopback, reserved,
    # or otherwise non-global addresses
    if not ip_info.get("global"):
        raise HTTPException(
            status_code=400,
            detail="IP address is private or not globally routable",
        )

    # Step 3: Get geolocation information
    result = get_ip_geolocation(request.ip)

    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "error",
                "Origin tracing failed",
            ),
        )

    # Step 4: Return origin information
    return {
        "origin": result,
        "ip_validation": ip_info,
    }