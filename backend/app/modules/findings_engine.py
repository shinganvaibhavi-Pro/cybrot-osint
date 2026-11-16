
from datetime import datetime, timezone


def _module_data(module_results, module_name):
    """Return data only when the requested module completed successfully."""
    module = module_results.get(module_name, {})

    if not isinstance(module, dict):
        return None

    if str(module.get("status", "")).lower() != "success":
        return None

    data = module.get("data", module)

    return data if isinstance(data, dict) else None


def _add_finding(
    findings,
    finding_id,
    title,
    severity,
    category,
    description,
    evidence,
    recommendation,
):
    findings.append({
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": "CYBROT OSINT automated analysis",
    })


def analyze_findings(module_results):
    """
    Analyse successful module results and produce evidence-based
    security observations.

    This engine does not treat failed or unconfigured modules
    as confirmed vulnerabilities.
    """
    findings = []

    if not isinstance(module_results, dict):
        module_results = {}

    # --------------------------------------------------
    # 1. SECURITY HEADERS
    # --------------------------------------------------
    headers_data = _module_data(
        module_results,
        "security_headers"
    )

    if headers_data:
        headers = headers_data.get("headers", {})

        if not isinstance(headers, dict):
            headers = {}

        missing_headers = headers_data.get("missing_headers", [])

        if not isinstance(missing_headers, list):
            missing_headers = []

        # Derive missing headers when the module did not provide
        # an explicit missing_headers list.
        if not missing_headers and headers:
            missing_headers = [
                name for name, value in headers.items()
                if value is None or str(value).strip() == ""
            ]

        missing = {
            str(header).lower().replace("_", "-")
            for header in missing_headers
        }

        final_url = str(headers_data.get("final_url", "")).lower()
        is_https = final_url.startswith("https://")

        header_rules = {
            "content-security-policy": {
                "title": "Content Security Policy Not Detected",
                "severity": "Medium",
                "description": (
                    "The website response did not include a Content "
                    "Security Policy (CSP) header. CSP can help reduce "
                    "the impact of certain content injection attacks."
                ),
                "recommendation": (
                    "Review the website's content requirements and "
                    "deploy a suitable Content Security Policy. Start "
                    "with report-only mode where appropriate."
                ),
            },
            "strict-transport-security": {
                "title": "HTTP Strict Transport Security Not Detected",
                "severity": "Low",
                "description": (
                    "The HTTPS response did not include the "
                    "Strict-Transport-Security header. This header "
                    "instructs supported browsers to use HTTPS for "
                    "future connections."
                ),
                "recommendation": (
                    "After confirming that HTTPS is correctly "
                    "configured across the domain and relevant "
                    "subdomains, consider deploying an appropriate "
                    "HSTS policy."
                ),
            },
            "x-content-type-options": {
                "title": "X-Content-Type-Options Not Detected",
                "severity": "Low",
                "description": (
                    "The response did not include X-Content-Type-Options. "
                    "The nosniff value helps prevent browsers from "
                    "performing MIME-type sniffing."
                ),
                "recommendation": (
                    "Configure the response header as "
                    "X-Content-Type-Options: nosniff."
                ),
            },
            "x-frame-options": {
                "title": "Clickjacking Protection Header Not Detected",
                "severity": "Low",
                "description": (
                    "The response did not include X-Frame-Options. "
                    "Without an appropriate framing policy, the site "
                    "may be more exposed to clickjacking. CSP "
                    "frame-ancestors can provide modern protection."
                ),
                "recommendation": (
                    "Configure an appropriate CSP frame-ancestors "
                    "directive. Consider X-Frame-Options for legacy "
                    "browser compatibility."
                ),
            },
            "referrer-policy": {
                "title": "Referrer Policy Not Detected",
                "severity": "Low",
                "description": (
                    "The response did not include a Referrer-Policy "
                    "header to control how much referrer information "
                    "browsers send to other destinations."
                ),
                "recommendation": (
                    "Consider setting Referrer-Policy to "
                    "strict-origin-when-cross-origin or another "
                    "policy suitable for the application."
                ),
            },
            "permissions-policy": {
                "title": "Permissions Policy Not Detected",
                "severity": "Informational",
                "description": (
                    "The response did not include a Permissions-Policy "
                    "header. This header can restrict browser features "
                    "such as camera, microphone and geolocation."
                ),
                "recommendation": (
                    "Review which browser features the application "
                    "needs and configure a restrictive Permissions-Policy."
                ),
            },
        }

        for header_name, rule in header_rules.items():
            if header_name in missing and (
                header_name != "strict-transport-security" or is_https
            ):
                _add_finding(
                    findings=findings,
                    finding_id=f"HEADER-{header_name.upper().replace('-', '-')}",
                    title=rule["title"],
                    severity=rule["severity"],
                    category="Security Headers",
                    description=rule["description"],
                    evidence={
                        "header": header_name,
                        "observed_value": headers.get(header_name),
                        "final_url": headers_data.get("final_url"),
                        "http_status": headers_data.get("http_status"),
                    },
                    recommendation=rule["recommendation"],
                )

    # --------------------------------------------------
    # 2. EMAIL SECURITY
    # --------------------------------------------------
    email_data = _module_data(
        module_results,
        "email_security"
    )

    if email_data:
        spf = email_data.get("spf", {})
        dmarc = email_data.get("dmarc", {})

        if not isinstance(spf, dict):
            spf = {}

        if not isinstance(dmarc, dict):
            dmarc = {}

        spf_status = str(spf.get("status", "")).lower()
        dmarc_status = str(dmarc.get("status", "")).lower()

        if spf_status in ("missing", "not_found", "absent"):
            _add_finding(
                findings,
                "EMAIL-SPF-MISSING",
                "SPF Record Not Detected",
                "Medium",
                "Email Security",
                (
                    "No SPF record was detected by the email security "
                    "module. SPF helps receiving mail servers verify "
                    "which systems are authorised to send email for "
                    "a domain."
                ),
                {
                    "spf_status": spf_status,
                    "records": spf.get("records", []),
                },
                (
                    "Identify all legitimate email-sending services "
                    "and publish an appropriate SPF TXT record in DNS."
                ),
            )

        if dmarc_status in ("missing", "not_found", "absent"):
            _add_finding(
                findings,
                "EMAIL-DMARC-MISSING",
                "DMARC Record Not Detected",
                "Medium",
                "Email Security",
                (
                    "No DMARC record was detected. DMARC allows domain "
                    "owners to define how receiving servers handle "
                    "messages that fail SPF and DKIM alignment."
                ),
                {
                    "dmarc_status": dmarc_status,
                    "records": dmarc.get("records", []),
                },
                (
                    "Publish a DMARC record. Start with a monitoring "
                    "policy if necessary, review reports, and move "
                    "toward quarantine or reject when legitimate "
                    "mail flows are correctly configured."
                ),
            )

        # A monitoring-only DMARC policy is weaker than quarantine
        # or reject, but it is not automatically a vulnerability.
        dmarc_records = dmarc.get("records", [])

        if isinstance(dmarc_records, str):
            dmarc_records = [dmarc_records]

        for record in dmarc_records:
            if not isinstance(record, str):
                continue

            normalized_record = record.lower().replace(" ", "")

            if "v=dmarc1" in normalized_record and (
                "p=none" in normalized_record
            ):
                _add_finding(
                    findings,
                    "EMAIL-DMARC-MONITORING",
                    "DMARC Policy Is Monitoring Only",
                    "Low",
                    "Email Security",
                    (
                        "The detected DMARC policy uses p=none. "
                        "This enables monitoring but does not instruct "
                        "receiving servers to quarantine or reject "
                        "messages that fail DMARC."
                    ),
                    {
                        "dmarc_record": record,
                    },
                    (
                        "Review DMARC aggregate reports and, once "
                        "legitimate sending sources are aligned, "
                        "consider moving to p=quarantine or p=reject."
                    ),
                )
                break

    # --------------------------------------------------
    # 3. SUMMARY
    # --------------------------------------------------
    severity_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ]

    severity_summary = {
        severity: sum(
            1 for finding in findings
            if finding["severity"] == severity
        )
        for severity in severity_order
    }

    return {
        "status": "success",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "severity_summary": severity_summary,
        "findings": findings,
        "notes": [
            (
                "Findings are automated observations and should be "
                "manually validated."
            ),
            (
                "A missing security header does not automatically "
                "confirm an exploitable vulnerability."
            ),
            (
                "Modules that failed or were not configured are "
                "excluded from vulnerability conclusions."
            ),
        ],
    }
