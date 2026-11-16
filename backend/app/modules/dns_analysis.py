
import re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.exception


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

DNS_TIMEOUT = 1.5
DNS_LIFETIME = 3.0
MAX_WORKERS = 5


# --------------------------------------------------
# DOMAIN VALIDATION
# --------------------------------------------------

def validate_domain(domain):
    domain = domain.strip().lower().rstrip(".")

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    if not re.fullmatch(pattern, domain):
        raise ValueError("Invalid domain name")

    return domain


# --------------------------------------------------
# DNS QUERY ENGINE
# --------------------------------------------------

def query_dns(name, record_type):
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME

    try:
        answers = resolver.resolve(
            name,
            record_type,
            search=False
        )

        records = []

        for answer in answers:

            # MX records, including Null MX.
            if record_type == "MX":
                exchange = str(answer.exchange).rstrip(".")

                records.append({
                    "priority": answer.preference,
                    "server": exchange,
                    "is_null_mx": (
                        answer.preference == 0
                        and exchange == ""
                    )
                })

            # TXT records.
            elif record_type == "TXT":
                value = b"".join(answer.strings).decode(
                    "utf-8",
                    errors="replace"
                )

                records.append(value)

            else:
                records.append(answer.to_text())

        return {
            "status": "success",
            "records": records,
            "error": None
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "nxdomain",
            "records": [],
            "error": "Domain does not exist"
        }

    except dns.resolver.NoAnswer:
        return {
            "status": "no_records",
            "records": [],
            "error": None
        }

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ) as error:
        return {
            "status": "lookup_failed",
            "records": [],
            "error": str(error)[:200]
        }

    except Exception as error:
        return {
            "status": "lookup_failed",
            "records": [],
            "error": str(error)[:200]
        }


# --------------------------------------------------
# MX INTELLIGENCE
# --------------------------------------------------

def analyze_mx(mx_records):

    null_mx = any(
        record.get("is_null_mx", False)
        for record in mx_records
    )

    valid_servers = [
        record for record in mx_records
        if not record.get("is_null_mx", False)
    ]

    if null_mx:
        status = "null_mx"

    elif valid_servers:
        status = "configured"

    else:
        status = "not_found"

    return {
        "status": status,
        "accepts_email": bool(valid_servers) and not null_mx,
        "records": mx_records,
        "total_mail_servers": len(valid_servers)
    }


# --------------------------------------------------
# SPF ANALYSIS
# --------------------------------------------------

def analyze_spf(txt_records):

    spf_records = [
        record.strip()
        for record in txt_records
        if record.strip().lower().startswith("v=spf1")
    ]

    result = {
        "status": "not_found",
        "records": spf_records,
        "record_count": len(spf_records),
        "policy": None,
        "mechanisms": [],
        "qualifiers": {},
        "warnings": []
    }

    if not spf_records:
        result["warnings"].append("No SPF record found.")
        return result

    if len(spf_records) > 1:
        result["status"] = "multiple_records"
        result["warnings"].append(
            "Multiple SPF records detected. "
            "A domain should publish one SPF policy."
        )
        return result

    record = spf_records[0]
    tokens = record.split()

    result["policy"] = record

    if not tokens or tokens[0].lower() != "v=spf1":
        result["status"] = "invalid"
        return result

    result["mechanisms"] = tokens[1:]

    all_mechanisms = [
        token for token in tokens[1:]
        if re.fullmatch(r"[+\-~?]?all", token, re.IGNORECASE)
    ]

    if len(all_mechanisms) > 1:
        result["warnings"].append(
            "Multiple SPF all mechanisms detected."
        )

    if all_mechanisms:

        mechanism = all_mechanisms[-1]

        qualifier = (
            mechanism[0]
            if mechanism[0] in "+-~?"
            else "+"
        )

        descriptions = {
            "+": "pass",
            "-": "fail",
            "~": "softfail",
            "?": "neutral"
        }

        result["qualifiers"]["all"] = descriptions[qualifier]

    else:
        result["warnings"].append(
            "SPF policy has no all mechanism."
        )

    result["status"] = "found"

    return result


# --------------------------------------------------
# DMARC ANALYSIS
# --------------------------------------------------

def analyze_dmarc(txt_records):

    dmarc_records = [
        record.strip()
        for record in txt_records
        if record.strip().lower().startswith("v=dmarc1")
    ]

    result = {
        "status": "not_found",
        "records": dmarc_records,
        "policy": None,
        "tags": {},
        "warnings": []
    }

    if not dmarc_records:
        result["warnings"].append("No DMARC record found.")
        return result

    if len(dmarc_records) > 1:
        result["status"] = "multiple_records"
        result["warnings"].append(
            "Multiple DMARC records detected."
        )
        return result

    record = dmarc_records[0]
    tags = {}

    for item in record.split(";"):
        item = item.strip()

        if "=" not in item:
            continue

        key, value = item.split("=", 1)
        tags[key.strip().lower()] = value.strip()

    result["tags"] = tags

    if tags.get("v", "").upper() != "DMARC1":
        result["status"] = "invalid"
        return result

    policy = tags.get("p", "").lower()

    if policy not in ("none", "quarantine", "reject"):
        result["status"] = "invalid"
        result["warnings"].append(
            "Missing or invalid DMARC policy."
        )
        return result

    result["policy"] = policy
    result["status"] = "found"

    if policy == "none":
        result["warnings"].append(
            "DMARC policy is monitoring-only (p=none)."
        )

    return result


# --------------------------------------------------
# DNSSEC INSPECTION
# --------------------------------------------------

def analyze_dnssec(domain, dnskey_result, ds_result):

    dnskeys = dnskey_result["records"]
    ds_records = ds_result["records"]

    result = {
        "status": "unknown",
        "dnskey_records": dnskeys,
        "ds_records": ds_records,
        "dnskey_lookup": dnskey_result["status"],
        "ds_lookup": ds_result["status"],
        "note": (
            "Record presence is not proof of a valid DNSSEC chain. "
            "Full DNSSEC validation requires cryptographic chain validation."
        )
    }

    if dnskeys and ds_records:
        result["status"] = "records_observed"

    elif dnskeys and not ds_records:
        result["status"] = "dnskey_without_observed_ds"

    elif (
        dnskey_result["status"] == "no_records"
        and ds_result["status"] == "no_records"
    ):
        result["status"] = "no_records_observed"

    elif (
        dnskey_result["status"] == "nxdomain"
        or ds_result["status"] == "nxdomain"
    ):
        result["status"] = "lookup_failed"

    else:
        result["status"] = "inconclusive"

    return result


# --------------------------------------------------
# MAIN DNS INTELLIGENCE
# --------------------------------------------------

def analyze_dns(domain: str):

    domain = validate_domain(domain)

    dmarc_domain = f"_dmarc.{domain}"

    queries = {
        record_type: (domain, record_type)
        for record_type in RECORD_TYPES
    }

    queries.update({
        "DMARC": (dmarc_domain, "TXT"),
        "DNSKEY": (domain, "DNSKEY"),
        "DS": (domain, "DS")
    })

    query_results = {}

    # Execute DNS queries concurrently.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = {
            executor.submit(query_dns, name, record_type): key
            for key, (name, record_type) in queries.items()
        }

        for future in as_completed(futures):

            key = futures[future]

            try:
                query_results[key] = future.result()

            except Exception as error:
                query_results[key] = {
                    "status": "lookup_failed",
                    "records": [],
                    "error": str(error)[:200]
                }

    # Preserve the original DNS records structure.
    records = {
        record_type: query_results[record_type]["records"]
        for record_type in RECORD_TYPES
    }

    # Email security analysis.
    spf = analyze_spf(records["TXT"])

    dmarc = analyze_dmarc(
        query_results["DMARC"]["records"]
    )

    # DNSSEC inspection.
    dnssec = analyze_dnssec(
        domain,
        query_results["DNSKEY"],
        query_results["DS"]
    )

    # MX analysis.
    mx_intelligence = analyze_mx(records["MX"])

    # Collect DNS query errors.
    errors = {
        key: value["error"]
        for key, value in query_results.items()
        if value.get("error")
    }

    return {
        "status": "success",
        "domain": domain,
        "source": "DNS",

        "collected_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "records": records,

        "record_status": {
            key: value["status"]
            for key, value in query_results.items()
        },

        "email_security": {
            "SPF": spf,
            "DMARC": dmarc
        },

        "dnssec": dnssec,

        "nameserver_intelligence": {
            "nameservers": records["NS"],
            "total_nameservers": len(records["NS"])
        },

        "mail_server_intelligence": mx_intelligence,

        "errors": errors
    }
