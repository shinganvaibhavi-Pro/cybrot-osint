import re
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone


def validate_domain(domain):
    domain = domain.strip().lower()

    pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


def fetch_json(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CYBROT-OSINT/0.1"}
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read(5_000_000))


def discover_subdomains(domain):
    domain = validate_domain(domain)

    sources = [
        (
            "crt.sh",
            "https://crt.sh/?" + urllib.parse.urlencode({
                "q": f"%.{domain}",
                "output": "json"
            })
        ),
        (
            "Google CT",
            "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"
            + "?" + urllib.parse.urlencode({"domain": domain})
        )
    ]

    errors = []

    for source_name, url in sources:
        try:
            data = fetch_json(url)

            subdomains = set()

            if source_name == "crt.sh":
                for record in data:
                    for name in record.get("name_value", "").splitlines():
                        name = name.strip().lower().lstrip("*.")

                        if name == domain or name.endswith("." + domain):
                            subdomains.add(name)

            else:
                # Google CT response is not a stable public JSON API.
                # Do not interpret an unknown response format as valid data.
                errors.append(
                    "Google CT response format is not supported for reliable parsing"
                )
                continue

            return {
                "status": "success",
                "domain": domain,
                "total": len(subdomains),
                "subdomains": sorted(subdomains),
                "source": source_name,
                "checked_at": datetime.now(timezone.utc).isoformat()
            }

        except Exception as error:
            errors.append(f"{source_name}: {error}")

    raise RuntimeError(
        "All supported Certificate Transparency sources failed. "
        + " | ".join(errors)
    )
