import ipaddress
import re
from typing import List, Dict


# Matches IPv4 and IPv6 addresses inside email headers
IP_PATTERN = re.compile(
    r"""
    (?<![0-9a-fA-F:])

    (?:
        (?:\d{1,3}\.){3}\d{1,3}
        |
        (?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}
    )

    (?![0-9a-fA-F:])
    """,
    re.VERBOSE,
)


def extract_ips_from_received(headers: str) -> List[str]:
    """
    Extract IP addresses from Received headers.

    Returns unique IP addresses while preserving
    their order of appearance.
    """

    if not headers:
        return []

    received_headers = re.findall(
        r"(?im)^Received:.*?(?=^\S|\Z)",
        headers,
        re.DOTALL,
    )

    ips = []

    for received in received_headers:
        matches = IP_PATTERN.findall(received)

        for ip in matches:
            try:
                address = ipaddress.ip_address(ip)

                normalized_ip = str(address)

                if normalized_ip not in ips:
                    ips.append(normalized_ip)

            except ValueError:
                # Ignore invalid IP-like strings
                continue

    return ips


def classify_ips(ips: List[str]) -> Dict[str, List[str]]:
    """
    Separate extracted IPs into public and non-public addresses.
    """

    public_ips = []
    private_ips = []
    loopback_ips = []
    reserved_ips = []

    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)

            if address.is_loopback:
                loopback_ips.append(ip)

            elif address.is_private:
                private_ips.append(ip)

            elif address.is_reserved:
                reserved_ips.append(ip)

            elif address.is_global:
                public_ips.append(ip)

        except ValueError:
            continue

    return {
        "public": public_ips,
        "private": private_ips,
        "loopback": loopback_ips,
        "reserved": reserved_ips,
    }


def extract_origin_candidates(headers: str) -> Dict:
    """
    Extract and classify IP addresses found in Received headers.

    Public IPs are returned as origin candidates.
    """

    all_ips = extract_ips_from_received(headers)

    classified = classify_ips(all_ips)

    return {
        "all_ips": all_ips,
        "public_ips": classified["public"],
        "private_ips": classified["private"],
        "loopback_ips": classified["loopback"],
        "reserved_ips": classified["reserved"],
        "candidate_count": len(classified["public"]),
    }