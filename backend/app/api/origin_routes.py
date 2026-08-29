from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.origin_tracing import (
    trace_origin,
    trace_origin_from_headers
)


router = APIRouter(
    prefix="/api/origin",
    tags=["Origin Tracing"],
)


class OriginRequest(BaseModel):
    ip: str


class HeaderOriginRequest(BaseModel):
    headers: str


@router.post("/trace")
def trace_origin_route(request: OriginRequest):

    result = trace_origin(request.ip)

    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "error",
                "Origin tracing failed"
            )
        )

    return {
        "origin": result
    }


@router.post("/trace-headers")
def trace_headers_route(request: HeaderOriginRequest):

    result = trace_origin_from_headers(request.headers)

    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "error",
                "Origin tracing failed"
            )
        )

    return result