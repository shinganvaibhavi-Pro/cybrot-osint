import re
import socket
import ipaddress
import urllib.request
import json
from datetime import datetime, timezone


def validate_domain(domain):
    domain = domain.strip().lower()

    pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


def get_asn_information(ip):
    url = f"https://rdap.org/ip/{ip}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CYBROT-OSINT/0.1"}
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        data = json.loads(response.read(1000000))

    entities = []

    for entity in data.get("entities", []):
        for item in entity.get("vcardArray", [[]])[1]:
            if len(item) >= 4 and item[0] == "fn":
                entities.append(item[3])

    return {
        "network_name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "organizations": entities
    }


def analyze_infrastructure(domain):
    domain = validate_domain(domain)

    try:
        records = socket.getaddrinfo(
            domain, None, type=socket.SOCK_STREAM
        )

        addresses = sorted({
            item[4][0] for item in records
            if ipaddress.ip_address(item[4][0]).is_global
        })

        results = []

        for ip in addresses:
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except OSError:
                reverse_dns = None

            try:
                network_info = get_asn_information(ip)
            except Exception:
                network_info = {
                    "lookup_status": "unavailable"
                }

            results.append({
                "ip_address": ip,
                "ip_version": ipaddress.ip_address(ip).version,
                "reverse_dns": reverse_dns,
                "rdap": network_info
            })

        return {
            "status": "success",
            "domain": domain,
            "total_public_ips": len(results),
            "infrastructure": results,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "source": "DNS and RDAP"
        }

    except socket.gaierror as error:
        raise RuntimeError(f"DNS resolution failed: {error}")
    except OSError as error:
        raise RuntimeError(f"Infrastructure lookup failed: {error}")
