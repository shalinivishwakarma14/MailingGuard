from app.utils.ip_utils import validate_ip
from app.services.geolocation import get_ip_geolocation


def trace_origin(ip: str):
    """
    Validate an IP and retrieve its approximate origin.
    """

    validation = validate_ip(ip)

    if not validation["valid"]:
        return {
            "success": False,
            "ip": ip,
            "error": "Invalid IP address"
        }

    if not validation["global"]:
        return {
            "success": False,
            "ip": ip,
            "error": "IP is not a public address"
        }

    return get_ip_geolocation(ip)


def trace_origin_from_headers(headers: str):
    """
    Extract public IP addresses from email Received headers
    and trace their approximate origins.
    """

    from app.services.header_parser import extract_origin_candidates

    candidates = extract_origin_candidates(headers)

    results = []

    for ip in candidates["public_ips"]:
        result = trace_origin(ip)

        if result.get("success"):
            results.append(result)

    return {
        "success": True,
        "candidates": candidates,
        "origins": results
    }