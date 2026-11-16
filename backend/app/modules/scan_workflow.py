
from app.modules.domain_intelligence import lookup_domain
from app.modules.dns_analysis import analyze_dns
from app.modules.subdomain_discovery import discover_subdomains
from app.modules.live_host_detection import detect_live_hosts
from app.modules.ssl_analysis import analyze_ssl
from app.modules.technology_stack import analyze_technology
from app.modules.infrastructure import analyze_infrastructure
from app.modules.security_headers import analyze_headers
from app.modules.email_security import analyze_email_security
from app.modules.threat_intelligence import run_threat_intelligence
from app.modules.findings_engine import analyze_findings

def run_scan(domain):
    modules = {
        "domain_intelligence": lookup_domain,
        "dns_analysis": analyze_dns,
        "subdomain_discovery": discover_subdomains,
        "ssl_tls": analyze_ssl,
        "technology_stack": analyze_technology,
        "infrastructure": analyze_infrastructure,
        "security_headers": analyze_headers,
        "email_security": analyze_email_security,
        "threat_intelligence": run_threat_intelligence,
    }

    results = {}

    for module_name, module_function in modules.items():
        try:
            data = module_function(domain)

            if module_name == "threat_intelligence":
                module_status = data.get("status", "success")
            else:
                module_status = "success"

            results[module_name] = {
                "status": module_status,
                "data": data
            }

        except Exception as error:
            results[module_name] = {
                "status": "failed",
                "error": str(error)
            }

    # Live Host Detection depends on discovered subdomains.
    subdomain_result = results.get("subdomain_discovery", {})

    if subdomain_result.get("status") == "success":
        assets = (
            subdomain_result.get("data", {}).get("assets", [])
        )

        try:
            live_data = detect_live_hosts(domain, assets)

            results["live_host_detection"] = {
                "status": live_data.get("status", "success"),
                "data": live_data
            }

        except Exception as error:
            results["live_host_detection"] = {
                "status": "failed",
                "error": str(error)
            }
    else:
        results["live_host_detection"] = {
            "status": "skipped",
            "error": "Subdomain discovery was unsuccessful."
        }

    # Count only fully successful modules.
    successful = sum(
        1
        for result in results.values()
        if result["status"] == "success"
    )

    total_modules = len(results)

    if successful == total_modules:
        overall_status = "completed"
    elif successful > 0:
        overall_status = "partial"
    else:
        overall_status = "failed"

    try:
        findings = analyze_findings(results)

    except Exception as error:
        findings = {
            "status": "failed",
            "total_findings": 0,
            "severity_summary": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Informational": 0,
            },
            "findings": [],
            "error": str(error),
        }

    return {
        "domain": domain,
        "status": overall_status,
        "total_modules": total_modules,
        "successful_modules": successful,
        "results": results,
        "findings": findings,
    }