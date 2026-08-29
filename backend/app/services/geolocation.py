import ipaddress
import requests

IP_API_URL = "http://ip-api.com/json/{ip}"

TIMEOUT = 5


def is_public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_reserved
        )

    except ValueError:
        return False


def get_ip_geolocation(ip):
    """
    Get approximate location and infrastructure information
    for a public IP address.
    """

    ip = ip.strip()

    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "success": False,
            "error": "Invalid IP address"
        }

    # Don't send private IPs to ip-api
    if not is_public_ip(ip):
        return {
            "success": False,
            "error": "Private or non-public IP address"
        }

    try:

        response = requests.get(
            IP_API_URL.format(ip=ip),
            params={
                "fields": (
                    "status,message,query,country,countryCode,"
                    "regionName,city,zip,lat,lon,timezone,"
                    "isp,org,as,proxy,hosting"
                )
            },
            timeout=TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            return {
                "success": False,
                "error": data.get(
                    "message",
                    "Geolocation lookup failed"
                )
            }

        is_proxy = bool(data.get("proxy"))
        is_hosting = bool(data.get("hosting"))

        return {
            "success": True,

            "ip": data.get("query"),

            "country": data.get("country"),
            "country_code": data.get("countryCode"),

            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),

            "latitude": data.get("lat"),
            "longitude": data.get("lon"),

            "timezone": data.get("timezone"),

            "isp": data.get("isp"),
            "organization": data.get("org"),
            "asn": data.get("as"),

            # Security indicators
            "vpn_or_proxy": is_proxy,
            "hosting_provider": is_hosting,

            "suspicious": is_proxy or is_hosting
        }

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "error": "Geolocation request timed out"
        }

    except requests.exceptions.RequestException as error:

        return {
            "success": False,
            "error": f"Geolocation request failed: {error}"
        }

    except ValueError:

        return {
            "success": False,
            "error": "Invalid response from geolocation service"
        }