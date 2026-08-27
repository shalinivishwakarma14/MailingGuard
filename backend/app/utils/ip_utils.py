import ipaddress


def validate_ip(ip: str) -> dict:
    """
    Validate an IPv4 or IPv6 address and identify
    whether it is private, loopback, reserved, or public.
    """

    try:
        address = ipaddress.ip_address(ip)

        return {
            "valid": True,
            "ip": ip,
            "version": address.version,
            "private": address.is_private,
            "loopback": address.is_loopback,
            "reserved": address.is_reserved,
            "global": address.is_global
        }

    except ValueError:
        return {
            "valid": False,
            "ip": ip
        }