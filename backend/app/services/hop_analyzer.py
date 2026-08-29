import ipaddress
from typing import List, Dict

from app.services.header_parser import extract_ips_from_received
from app.services.geolocation import get_ip_geolocation


def classify_ip(ip: str) -> str:
    """
    Classify an IP address as public, private,
    loopback, reserved, or invalid.
    """

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "loopback"

        if address.is_private:
            return "private"

        if address.is_reserved:
            return "reserved"

        if address.is_global:
            return "public"

        return "unknown"

    except ValueError:
        return "invalid"


def analyze_hops(headers: str) -> Dict:
    """
    Analyze IP addresses found in email Received headers.

    Returns hop-by-hop classification and geolocation
    for public IP addresses.
    """

    ips = extract_ips_from_received(headers)

    hops: List[Dict] = []

    for index, ip in enumerate(ips, start=1):

        ip_type = classify_ip(ip)

        hop = {
            "hop": index,
            "ip": ip,
            "type": ip_type,
            "origin_candidate": False,
            "geolocation": None,
        }

        if ip_type == "public":
            hop["origin_candidate"] = True

            geo = get_ip_geolocation(ip)

            if geo.get("success"):
                hop["geolocation"] = geo

        hops.append(hop)

    public_hops = [
        hop for hop in hops
        if hop["type"] == "public"
    ]

    return {
        "total_hops": len(hops),
        "public_hops": len(public_hops),
        "private_hops": len([
            hop for hop in hops
            if hop["type"] == "private"
        ]),
        "hops": hops,
        "origin_candidates": [
            hop["ip"]
            for hop in public_hops
        ],
    }