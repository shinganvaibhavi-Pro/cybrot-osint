import re
from datetime import datetime, timezone

import dns.resolver
import dns.exception

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

def analyze_dns(domain: str):
    domain = domain.strip().lower()

    pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"

    if not re.fullmatch(pattern, domain):
        raise ValueError("Invalid domain name")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 8

    results = {}

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(
                domain,
                record_type,
                search=False
            )

            records = []

            for answer in answers:
                if record_type == "MX":
                    records.append({
                        "priority": answer.preference,
                        "server": str(answer.exchange)
                    })
                elif record_type == "TXT":
                    records.append(
                        answer.to_text().strip('"')
                    )
                else:
                    records.append(answer.to_text())

            results[record_type] = records

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN
        ):
            results[record_type] = []

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            results[record_type] = []

    return {
        "status": "success",
        "domain": domain,
        "source": "DNS",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "records": results
    }
