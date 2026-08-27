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

    # Validate IP
    ip_info = validate_ip(request.ip)

    if not ip_info.get("valid"):
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address",
        )

    # Only allow publicly routable IP addresses
    if not ip_info.get("global"):
        raise HTTPException(
            status_code=400,
            detail="IP address is private or not globally routable",
        )

    # Get geolocation
    result = get_ip_geolocation(request.ip)

    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "error",
                "Origin tracing failed",
            ),
        )

    return {
        "origin": result,
        "ip_validation": ip_info,
    }