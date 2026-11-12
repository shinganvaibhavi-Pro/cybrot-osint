from app.modules.domain_intelligence import lookup_domain
from app.modules.dns_analysis import analyze_dns
from app.modules.subdomain_discovery import discover_subdomains
from app.modules.ssl_analysis import analyze_ssl
from app.modules.technology_stack import analyze_technology
from app.modules.infrastructure import analyze_infrastructure
from app.modules.security_headers import analyze_headers
from app.modules.email_security import analyze_email_security
from app.modules.threat_intelligence import run_threat_intelligence


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

    successful = sum(
        1 for result in results.values()
        if result["status"] == "success"
    )

    if successful == len(modules):
        overall_status = "completed"
    elif successful > 0:
        overall_status = "partial"
    else:
        overall_status = "failed"

    return {
        "domain": domain,
        "status": overall_status,
        "total_modules": len(modules),
        "successful_modules": successful,
        "results": results
    }
