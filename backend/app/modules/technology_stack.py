
import re
import socket
import ssl
import ipaddress
import http.client
import certifi

from datetime import datetime, timezone


MAX_HTML_SIZE = 500_000
CONNECT_TIMEOUT = 10


def validate_domain(domain):
    """Validate a fully qualified hostname."""

    if not isinstance(domain, str):
        raise ValueError("Domain must be a string")

    domain = domain.strip().lower().rstrip(".")

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    if not re.fullmatch(pattern, domain):
        raise ValueError("Enter a valid domain name")

    return domain


def resolve_public_ips(domain):
    """
    Resolve domain and reject non-public addresses.
    Reject mixed public/private DNS responses.
    """

    addresses = socket.getaddrinfo(
        domain,
        443,
        type=socket.SOCK_STREAM
    )

    resolved_ips = set()

    for item in addresses:
        ip = ipaddress.ip_address(
            item[4][0].split("%")[0]
        )

        if not ip.is_global:
            raise ValueError(
                "Non-public IP address rejected"
            )

        resolved_ips.add(str(ip))

    if not resolved_ips:
        raise RuntimeError("No public IP address found")

    return sorted(resolved_ips)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a previously validated IP."""

    def __init__(self, domain, ip, timeout=10, context=None):
        super().__init__(
            domain,
            timeout=timeout,
            context=context
        )

        self.pinned_ip = ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=self.timeout
        )

        try:
            # Keep the original hostname for SNI and
            # certificate hostname verification.
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host
            )

        except Exception:
            raw_socket.close()
            raise


def analyze_technology(domain):
    """
    Passive website technology fingerprinting.

    Collects:
    - HTTP server information
    - X-Powered-By information
    - WordPress indicators
    - Next.js indicators

    Uses certificate verification and pinned public IPs.
    """

    domain = validate_domain(domain)

    try:
        public_ips = resolve_public_ips(domain)

        # Use the Certifi CA bundle instead of relying
        # on the system's default CA configuration.
        context = ssl.create_default_context(
            cafile=certifi.where()
        )

        response = None
        last_error = None

        for ip in public_ips:

            connection = PinnedHTTPSConnection(
                domain,
                ip,
                timeout=CONNECT_TIMEOUT,
                context=context
            )

            try:
                connection.request(
                    "GET",
                    "/",
                    headers={
                        "User-Agent": "CYBROT-OSINT/0.2",
                        "Accept": "text/html,application/xhtml+xml",
                        "Connection": "close"
                    }
                )

                response = connection.getresponse()

                headers = {
                    key.lower(): value
                    for key, value in response.getheaders()
                }

                status_code = response.status

                html = response.read(
                    MAX_HTML_SIZE
                ).decode(
                    "utf-8",
                    errors="replace"
                )

                break

            except (
                OSError,
                ssl.SSLError,
                http.client.HTTPException
            ) as error:

                last_error = error
                response = None

            finally:
                connection.close()

        if response is None:
            raise RuntimeError(
                f"Could not retrieve HTTPS response: {last_error}"
            )

        technologies = []

        def add(name, evidence):
            technologies.append({
                "name": name,
                "evidence": evidence
            })

        # Server fingerprinting
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")

        server_lower = server.lower()

        if "nginx" in server_lower:
            add("Nginx", server)

        elif "apache" in server_lower:
            add("Apache", server)

        elif "cloudflare" in server_lower:
            add("Cloudflare", server)

        elif server:
            add("Web Server", server)

        # Application framework indicators
        if powered:
            add(
                "Technology from X-Powered-By",
                powered
            )

        html_lower = html.lower()

        if (
            "wp-content" in html_lower
            or "wp-includes" in html_lower
        ):
            add(
                "WordPress",
                "WordPress paths found in HTML"
            )

        if "__next" in html_lower:
            add(
                "Next.js",
                "Next.js page markers found"
            )

        # Additional passive indicators
        if "react" in html_lower and (
            "reactroot" in html_lower
            or "data-reactroot" in html_lower
        ):
            add(
                "React",
                "React root indicators found in HTML"
            )

        if "vue" in html_lower and (
            "data-v-" in html_lower
            or "vue-app" in html_lower
        ):
            add(
                "Vue.js",
                "Vue.js indicators found in HTML"
            )

        # Remove duplicate technology names.
        unique_technologies = []
        seen = set()

        for technology in technologies:
            key = technology["name"].lower()

            if key not in seen:
                seen.add(key)
                unique_technologies.append(technology)

        return {
            "status": "success",
            "domain": domain,
            "http_status": status_code,
            "technologies": unique_technologies,
            "total_detected": len(unique_technologies),
            "checked_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "detection_note": (
                "Passive HTTP inspection. "
                "Indicators are not definitive proof."
            ),
            "source": "HTTPS response"
        }

    except ValueError:
        raise

    except (
        OSError,
        ssl.SSLError,
        http.client.HTTPException,
        RuntimeError
    ) as error:

        raise RuntimeError(
            f"Technology detection failed: "
            f"{type(error).__name__}: {error}"
        ) from error
