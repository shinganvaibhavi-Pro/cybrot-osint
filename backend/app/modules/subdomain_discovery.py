
import re
import json
import csv
import io
import socket
import secrets
import urllib.request
import urllib.parse
from datetime import datetime, timezone


USER_AGENT = "CYBROT-OSINT/0.4"

REQUEST_TIMEOUT = 10
DNS_TIMEOUT = 5
MAX_RESPONSE_SIZE = 5_000_000

GOOGLE_DNS_URL = "https://dns.google/resolve"


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


def is_valid_subdomain(hostname, domain):
    hostname = hostname.strip().lower().rstrip(".").lstrip("*.")

    if hostname == domain:
        return False

    if not hostname.endswith("." + domain):
        return False

    if len(hostname) > 253:
        return False

    label_pattern = (
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    labels = hostname.split(".")

    return all(
        re.fullmatch(label_pattern, label)
        for label in labels
    )


def fetch_url(url, timeout=REQUEST_TIMEOUT, accept="application/json,text/plain,*/*"):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": accept
        }
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        content = response.read(MAX_RESPONSE_SIZE + 1)

        if len(content) > MAX_RESPONSE_SIZE:
            raise ValueError("Response exceeded maximum allowed size")

        return content.decode("utf-8", errors="replace")


# --------------------------------------------------
# PASSIVE SUBDOMAIN SOURCES
# --------------------------------------------------

def fetch_crtsh(domain):
    url = "https://crt.sh/?" + urllib.parse.urlencode({
        "q": f"%.{domain}",
        "output": "json"
    })

    data = json.loads(fetch_url(url))

    if not isinstance(data, list):
        raise ValueError("Unexpected crt.sh response")

    found = set()

    for record in data:
        if not isinstance(record, dict):
            continue

        names = record.get("name_value", "")

        for name in names.splitlines():
            name = name.strip().lower().lstrip("*.")

            if is_valid_subdomain(name, domain):
                found.add(name)

    return found


def fetch_hackertarget(domain):
    url = "https://api.hackertarget.com/hostsearch/?" + urllib.parse.urlencode({
        "q": domain
    })

    response = fetch_url(url)
    found = set()

    if (
        "error" in response.lower()
        or "api count limit" in response.lower()
    ):
        raise RuntimeError(response.strip()[:200])

    for row in csv.reader(io.StringIO(response)):
        if not row:
            continue

        hostname = row[0].strip().lower().rstrip(".")

        if is_valid_subdomain(hostname, domain):
            found.add(hostname)

    return found


# --------------------------------------------------
# DNS-OVER-HTTPS INTELLIGENCE
# --------------------------------------------------

def query_google_dns(hostname, record_type="A"):
    """
    Query Google's public DNS-over-HTTPS JSON API.
    Supported record types include A, AAAA and CNAME.
    """

    url = GOOGLE_DNS_URL + "?" + urllib.parse.urlencode({
        "name": hostname,
        "type": record_type
    })

    response = fetch_url(
        url,
        timeout=DNS_TIMEOUT,
        accept="application/dns-json"
    )

    data = json.loads(response)

    if not isinstance(data, dict):
        raise ValueError("Unexpected DNS response")

    answers = []

    for record in data.get("Answer", []):
        if not isinstance(record, dict):
            continue

        answers.append({
            "name": record.get("name", "").rstrip("."),
            "type": record.get("type"),
            "ttl": record.get("TTL"),
            "data": record.get("data", "").rstrip(".")
        })

    return {
        "status_code": data.get("Status"),
        "answers": answers
    }


def fetch_cname_records(hostname):
    """
    Collect CNAME records for a hostname.
    """

    result = {
        "status": "not_found",
        "records": [],
        "targets": [],
        "error": None
    }

    try:
        dns_result = query_google_dns(hostname, "CNAME")

        records = [
            record
            for record in dns_result["answers"]
            if record.get("type") == 5
        ]

        targets = sorted({
            record["data"]
            for record in records
            if record.get("data")
        })

        result["records"] = records
        result["targets"] = targets

        if targets:
            result["status"] = "found"

        elif dns_result["status_code"] == 0:
            result["status"] = "not_found"

        else:
            result["status"] = "lookup_failed"

    except Exception as error:
        result["status"] = "lookup_failed"
        result["error"] = str(error)[:200]

    return result


# --------------------------------------------------
# WILDCARD DNS DETECTION
# --------------------------------------------------

def detect_wildcard_dns(domain):
    """
    Query a random hostname beneath the target domain.

    If it resolves, wildcard DNS may be configured.
    This is an indicator, not proof that every subdomain
    is generated by a wildcard record.
    """

    random_label = "cybrot-" + secrets.token_hex(8)
    test_hostname = f"{random_label}.{domain}"

    result = {
        "detected": False,
        "test_hostname": test_hostname,
        "status": "unknown",
        "records": [],
        "error": None,
        "note": (
            "A successful random hostname lookup suggests "
            "wildcard DNS configuration. Verify manually."
        )
    }

    try:
        dns_result = query_google_dns(test_hostname, "A")

        answers = dns_result["answers"]

        useful_answers = [
            record for record in answers
            if record.get("type") in (1, 5)
        ]

        result["records"] = useful_answers

        if useful_answers:
            result["detected"] = True
            result["status"] = "possible_wildcard"

        elif dns_result["status_code"] == 3:
            result["status"] = "not_detected"

        elif dns_result["status_code"] == 0:
            result["status"] = "not_detected"

        else:
            result["status"] = "lookup_failed"

    except Exception as error:
        result["status"] = "lookup_failed"
        result["error"] = str(error)[:200]

    return result


# --------------------------------------------------
# A / AAAA DNS RESOLUTION
# --------------------------------------------------

def resolve_subdomain(hostname):
    result = {
        "hostname": hostname,
        "dns_status": "unresolved",
        "ip_addresses": [],
        "A": [],
        "AAAA": [],
        "CNAME": {
            "status": "not_checked",
            "records": [],
            "targets": [],
            "error": None
        }
    }

    # Resolve IPv4 and IPv6 addresses.
    try:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM
        )

        ipv4 = set()
        ipv6 = set()

        for record in records:
            ip_address = record[4][0]

            if record[0] == socket.AF_INET:
                ipv4.add(ip_address)

            elif record[0] == socket.AF_INET6:
                ipv6.add(ip_address)

        result["A"] = sorted(ipv4)
        result["AAAA"] = sorted(ipv6)

        result["ip_addresses"] = sorted(ipv4 | ipv6)

        if result["ip_addresses"]:
            result["dns_status"] = "resolved"

    except (socket.gaierror, OSError):
        pass

    # Collect CNAME intelligence independently.
    result["CNAME"] = fetch_cname_records(hostname)

    return result


# --------------------------------------------------
# MAIN SUBDOMAIN DISCOVERY
# --------------------------------------------------

def discover_subdomains(domain):
    domain = validate_domain(domain)

    sources = [
        ("crt.sh", fetch_crtsh),
        ("HackerTarget", fetch_hackertarget)
    ]

    discovered = {}

    successful_sources = []
    errors = []

    for source_name, source_function in sources:
        try:
            source_results = source_function(domain)

            successful_sources.append(source_name)

            for hostname in source_results:
                if not is_valid_subdomain(hostname, domain):
                    continue

                discovered.setdefault(hostname, set()).add(source_name)

        except Exception as error:
            errors.append(
                f"{source_name}: {str(error)[:250]}"
            )

    if not successful_sources:
        raise RuntimeError(
            "All subdomain sources failed. " + " | ".join(errors)
        )

    # Check wildcard DNS once per domain.
    wildcard_result = detect_wildcard_dns(domain)

    # Resolve discovered subdomains.
    assets = []

    for hostname in sorted(discovered):
        dns_data = resolve_subdomain(hostname)

        assets.append({
            **dns_data,
            "sources": sorted(discovered[hostname])
        })

    subdomains = sorted(discovered.keys())

    resolved_count = sum(
        1 for asset in assets
        if asset["dns_status"] == "resolved"
    )

    cname_count = sum(
        1 for asset in assets
        if asset["CNAME"]["status"] == "found"
    )

    return {
        "status": "success",
        "domain": domain,

        "total": len(subdomains),
        "subdomains": subdomains,

        "sources": successful_sources,
        "source_errors": errors,

        "assets": assets,

        "total_resolved": resolved_count,
        "total_unresolved": len(assets) - resolved_count,

        "cname_intelligence": {
            "total_with_cname": cname_count
        },

        "wildcard_dns": wildcard_result,

        "collection_type": "passive_with_dns_queries",

        "checked_at": datetime.now(timezone.utc).isoformat()
    }
