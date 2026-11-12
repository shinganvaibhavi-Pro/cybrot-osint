import re
from datetime import datetime, timezone

import dns.resolver


def validate_domain(domain):
    domain = domain.strip().lower()

    pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


def get_txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        return [
            b"".join(record.strings).decode("utf-8", errors="replace")
            for record in answers
        ]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def analyze_email_security(domain):
    domain = validate_domain(domain)

    txt_records = get_txt_records(domain)

    spf_records = [
        record for record in txt_records
        if record.lower().startswith("v=spf1")
    ]

    dmarc_records = get_txt_records(f"_dmarc.{domain}")

    dmarc_records = [
        record for record in dmarc_records
        if record.lower().startswith("v=dmarc1")
    ]

    dkim_status = "not_checked"
    dkim_note = (
        "DKIM requires a known selector. "
        "No selector was provided, so DKIM cannot be confirmed."
    )

    return {
        "status": "success",
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "spf": {
            "status": "present" if spf_records else "missing",
            "records": spf_records
        },
        "dmarc": {
            "status": "present" if dmarc_records else "missing",
            "records": dmarc_records
        },
        "dkim": {
            "status": dkim_status,
            "note": dkim_note
        },
        "source": "DNS TXT records"
    }
