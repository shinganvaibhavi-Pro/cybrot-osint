import os
import re
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone


def validate_domain(domain):
    domain = domain.strip().lower().rstrip(".")

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


def virustotal_lookup(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "CYBROT-OSINT/0.2"
        }
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.loads(response.read(2_000_000))

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "source": "VirusTotal",
        "status": "success",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date")
    }


def google_safe_browsing_lookup(domain, api_key):
    url = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={api_key}"
    )

    payload = {
        "client": {
            "clientId": "cybrot-osint",
            "clientVersion": "0.2"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": f"https://{domain}/"}
            ]
        }
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "CYBROT-OSINT/0.2"
        },
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.loads(response.read(2_000_000))

    matches = data.get("matches", [])

    return {
        "source": "Google Safe Browsing",
        "status": "success",
        "matches_found": len(matches),
        "matches": [
            {
                "threat_type": item.get("threatType"),
                "platform": item.get("platformType"),
                "url": item.get("threat", {}).get("url")
            }
            for item in matches
        ]
    }


def run_threat_intelligence(domain):
    domain = validate_domain(domain)

    results = []
    errors = []

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not vt_key and not google_key:
        return {
            "status": "not_configured",
            "domain": domain,
            "message": "Configure at least one threat intelligence API key.",
            "available_sources": [
                "VirusTotal",
                "Google Safe Browsing"
            ],
            "checked_at": datetime.now(timezone.utc).isoformat()
        }

    if vt_key:
        try:
            results.append(virustotal_lookup(domain, vt_key))
        except Exception as error:
            errors.append({
                "source": "VirusTotal",
                "error": str(error)[:250]
            })

    if google_key:
        try:
            results.append(
                google_safe_browsing_lookup(domain, google_key)
            )
        except Exception as error:
            errors.append({
                "source": "Google Safe Browsing",
                "error": str(error)[:250]
            })

    if not results:
        status = "unavailable"
    elif errors:
        status = "partial"
    else:
        status = "success"

    return {
        "status": status,
        "domain": domain,
        "results": results,
        "errors": errors,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "No detection does not guarantee that a domain is safe. "
            "Results depend on the coverage and freshness of each source."
        )
    }
