import json
import re
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

def lookup_domain(domain: str):
    domain = domain.strip().lower()

    pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"

    if not re.fullmatch(pattern, domain):
        raise ValueError("Invalid domain name")

    tld = domain.rsplit(".", 1)[-1]

    try:
        bootstrap_request = Request(
            BOOTSTRAP_URL,
            headers={"User-Agent": "CYBROT-OSINT/0.1"}
        )

        with urlopen(bootstrap_request, timeout=10) as response:
            bootstrap = json.loads(response.read().decode("utf-8"))

        rdap_base = None

        for service in bootstrap.get("services", []):
            tlds, urls = service

            if tld in [item.lower() for item in tlds]:
                rdap_base = urls[0]
                break

        if not rdap_base or not rdap_base.startswith("https://"):
            return {"status": "unavailable", "domain": domain}

        rdap_url = rdap_base.rstrip("/") + "/domain/" + domain

        request = Request(
            rdap_url,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "CYBROT-OSINT/0.1"
            }
        )

        with urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        events = {}
        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")
            if action and date:
                events[action] = date

        nameservers = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        ]

        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for item in entity.get("vcardArray", [None, []])[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break

        return {
            "status": "success",
            "domain": data.get("ldhName", domain),
            "handle": data.get("handle"),
            "registrar": registrar,
            "registration_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "nameservers": nameservers,
            "domain_status": data.get("status", []),
            "source": "RDAP"
        }

    except HTTPError as error:
        if error.code == 404:
            return {
                "status": "not_found",
                "domain": domain,
                "message": "No RDAP registration record found"
            }
        raise RuntimeError(f"RDAP server returned HTTP {error.code}")

    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"RDAP lookup failed: {error}")
