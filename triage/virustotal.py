
"""Optional, read-only VirusTotal URL reputation lookup."""

import base64
import requests


def lookup_url(url: str, api_key: str) -> dict:
    """Retrieve an existing VirusTotal URL report."""

    if not api_key:
        return {
            "status": "error",
            "message": "VirusTotal API key is missing."
        }

    if not url.startswith(("https://", "http://")):
        return {
            "status": "error",
            "message": "Invalid HTTP/HTTPS URL."
        }

    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").strip("=")

    endpoint = (
        f"https://www.virustotal.com/api/v3/urls/{url_id}"
    )

    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=15
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "No existing VirusTotal report."
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "message": "VirusTotal API quota exceeded."
            }

        response.raise_for_status()

        attributes = response.json()["data"]["attributes"]

        stats = attributes.get(
            "last_analysis_stats", {}
        )

        return {
            "status": "success",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0)
        }

    except (requests.RequestException, ValueError, KeyError, TypeError) as error:
        return {
            "status": "error",
            "message": f"VirusTotal lookup failed: {type(error).__name__}"
        }
