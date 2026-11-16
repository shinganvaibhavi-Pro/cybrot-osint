
import os
import re
import json
import urllib.request
import urllib.error

from pathlib import Path
from urllib.parse import urlencode
from datetime import datetime, timezone

from dotenv import load_dotenv


# ============================================================
# ENVIRONMENT CONFIGURATION
# ============================================================

# Automatically load backend/.env regardless of the current
# PowerShell working directory.
BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BACKEND_DIR / ".env"

load_dotenv(dotenv_path=ENV_FILE, override=False)


# ============================================================
# DOMAIN VALIDATION
# ============================================================

def validate_domain(domain: str) -> str:

    if not isinstance(domain, str):
        raise ValueError("Domain must be a string")

    domain = domain.strip().lower().rstrip(".")

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


# ============================================================
# COMMON HTTP REQUEST HANDLER
# ============================================================

def make_request(url, headers=None, payload=None, method="GET"):

    request_data = None

    if payload is not None:
        request_data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=request_data,
        headers=headers or {},
        method=method
    )

    try:

        with urllib.request.urlopen(request, timeout=15) as response:

            raw_data = response.read(2_000_000)

            return json.loads(raw_data.decode("utf-8"))

    except urllib.error.HTTPError as error:

        try:
            body = error.read(4096).decode(
                "utf-8",
                errors="replace"
            )

            details = json.loads(body)

            error.provider_message = (
                details.get("error", {}).get(
                    "message",
                    "No additional details provided"
                )
            )

        except Exception:
            error.provider_message = (
                "No additional error details available."
            )

        raise


# ============================================================
# VIRUSTOTAL DOMAIN INTELLIGENCE
# ============================================================

def virustotal_lookup(domain, api_key):

    url = (
        f"https://www.virustotal.com/api/v3/domains/{domain}"
    )

    data = make_request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "CYBROT-OSINT/0.2"
        }
    )

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
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        )
    }


# ============================================================
# GOOGLE SAFE BROWSING
# ============================================================

def google_safe_browsing_lookup(domain, api_key):

    query = urlencode({
        "key": api_key
    })

    url = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?{query}"
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

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {
                    "url": f"https://{domain}/"
                },
                {
                    "url": f"http://{domain}/"
                }
            ]
        }
    }

    data = make_request(
        url,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CYBROT-OSINT/0.2"
        },
        payload=payload,
        method="POST"
    )

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


# ============================================================
# PROVIDER ERROR HANDLING
# ============================================================

def get_provider_error(error):

    if isinstance(error, urllib.error.HTTPError):

        message = getattr(
            error,
            "provider_message",
            "No additional details available."
        )

        return f"HTTP {error.code}: {message}"

    if isinstance(error, urllib.error.URLError):

        return "Provider connection failed or timed out."

    if isinstance(error, TimeoutError):

        return "Provider request timed out."

    if isinstance(error, json.JSONDecodeError):

        return "Provider returned an invalid JSON response."

    return "Provider request failed."


# ============================================================
# MAIN THREAT INTELLIGENCE ENGINE
# ============================================================

def run_threat_intelligence(domain):

    domain = validate_domain(domain)

    results = []
    errors = []

    vt_key = os.getenv(
        "VIRUSTOTAL_API_KEY", ""
    ).strip()

    google_key = os.getenv(
        "GOOGLE_SAFE_BROWSING_API_KEY", ""
    ).strip()

    configured_sources = []

    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------

    if vt_key:

        configured_sources.append("VirusTotal")

        try:

            result = virustotal_lookup(
                domain,
                vt_key
            )

            results.append(result)

        except Exception as error:

            errors.append({

                "source": "VirusTotal",

                "error": get_provider_error(error)

            })

    # --------------------------------------------------------
    # GOOGLE SAFE BROWSING
    # --------------------------------------------------------

    if google_key:

        configured_sources.append(
            "Google Safe Browsing"
        )

        try:

            result = google_safe_browsing_lookup(
                domain,
                google_key
            )

            results.append(result)

        except Exception as error:

            errors.append({

                "source": "Google Safe Browsing",

                "error": get_provider_error(error)

            })

    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    checked_at = datetime.now(
        timezone.utc
    ).isoformat()

    # --------------------------------------------------------
    # NO API KEYS CONFIGURED
    # --------------------------------------------------------

    if not configured_sources:

        return {

            "status": "not_configured",

            "domain": domain,

            "configured_sources": [],

            "available_sources": [
                "VirusTotal",
                "Google Safe Browsing"
            ],

            "results": [],

            "errors": [],

            "checked_at": checked_at,

            "message": (
                "Configure at least one threat "
                "intelligence API key."
            )
        }

    # --------------------------------------------------------
    # FINAL MODULE STATUS
    # --------------------------------------------------------

    if not results:

        status = "unavailable"

    elif errors:

        status = "partial"

    else:

        status = "success"

    # --------------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------------

    return {

        "status": status,

        "domain": domain,

        "configured_sources": configured_sources,

        "results": results,

        "errors": errors,

        "checked_at": checked_at,

        "note": (
            "No detection does not guarantee that a domain "
            "is safe. Results depend on provider coverage "
            "and freshness."
        )
    }
