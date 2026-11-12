import re
import socket
import ssl
import ipaddress
import http.client
from datetime import datetime, timezone


def validate_domain(domain):
    domain = domain.strip().lower()

    pattern = r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, domain, ip, timeout=10, context=None):
        super().__init__(domain, timeout=timeout, context=context)
        self.pinned_ip = ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=self.timeout
        )

        self.sock = self._context.wrap_socket(
            raw_socket,
            server_hostname=self.host
        )


def analyze_technology(domain):
    domain = validate_domain(domain)

    try:
        addresses = socket.getaddrinfo(
            domain, 443, type=socket.SOCK_STREAM
        )

        public_ips = sorted({
            item[4][0]
            for item in addresses
            if ipaddress.ip_address(item[4][0]).is_global
        })

        if not public_ips:
            raise RuntimeError("No public IP address found")

        context = ssl.create_default_context()
        response = None

        for ip in public_ips:
            connection = PinnedHTTPSConnection(
                domain, ip, timeout=10, context=context
            )

            try:
                connection.request(
                    "GET",
                    "/",
                    headers={
                        "Host": domain,
                        "User-Agent": "CYBROT-OSINT/0.1",
                        "Connection": "close"
                    }
                )

                response = connection.getresponse()
                headers = {
                    key.lower(): value
                    for key, value in response.getheaders()
                }

                html = response.read(500000).decode(
                    "utf-8", errors="replace"
                )
                status_code = response.status
                break

            except (OSError, ssl.SSLError, http.client.HTTPException):
                connection.close()
                raise
            finally:
                connection.close()

        if response is None:
            raise RuntimeError("Could not retrieve HTTPS response")

        technologies = []

        def add(name, evidence):
            technologies.append({
                "name": name,
                "evidence": evidence
            })

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")

        if "nginx" in server.lower():
            add("Nginx", server)
        elif "apache" in server.lower():
            add("Apache", server)
        elif "cloudflare" in server.lower():
            add("Cloudflare", server)

        if powered:
            add("Technology from X-Powered-By", powered)

        html_lower = html.lower()

        if "wp-content" in html_lower or "wp-includes" in html_lower:
            add("WordPress", "WordPress paths found in HTML")

        if "__next" in html_lower:
            add("Next.js", "Next.js page markers found")

        return {
            "status": "success",
            "domain": domain,
            "http_status": status_code,
            "technologies": technologies,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "detection_note": "Passive HTTP inspection. Indicators are not definitive proof.",
            "source": "HTTPS response"
        }

    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise RuntimeError(f"Technology detection failed: {error}")
