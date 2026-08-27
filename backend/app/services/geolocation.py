import requests


def get_ip_geolocation(ip: str) -> dict:
    """
    Get approximate geolocation and network information
    for a public IP address using ip-api.com.
    """

    url = f"http://ip-api.com/json/{ip}"

    try:
        response = requests.get(
            url,
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            return {
                "success": False,
                "error": data.get(
                    "message",
                    "Invalid IP query"
                ),
            }

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
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "error": str(error),
        }

    except ValueError:
        return {
            "success": False,
            "error": "Invalid JSON response from ip-api.com",
        }