
import ipaddress
import socket
import ssl
import certifi
import traceback

from urllib.parse import urlparse, urljoin
from urllib.request import Request
from http.client import HTTPSConnection
from datetime import datetime, timezone


SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]

MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 8
REQUEST_TIMEOUT = 10


def validate_domain(domain: str) -> str:
    """Validate a public hostname."""

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain")

    if not domain.isascii():
        raise ValueError("Internationalized domains are not supported")

    if any(c in domain for c in "/:@?#\\"):
        raise ValueError("Enter a valid hostname only")

    if domain == "localhost":
        raise ValueError("Localhost is not allowed")

    try:
        socket.inet_aton(domain)
        raise ValueError("IP addresses are not accepted; enter a domain")
    except OSError:
        pass

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("Enter a fully qualified domain name")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
        ):
            raise ValueError("Invalid hostname format")

    return domain


def resolve_public_ip(domain: str) -> str:
    """Resolve domain and reject any non-public address."""

    addresses = socket.getaddrinfo(
        domain,
        443,
        type=socket.SOCK_STREAM
    )

    public_ips = set()

    for item in addresses:
        ip = ipaddress.ip_address(item[4][0].split("%")[0])

        if not ip.is_global:
            raise ValueError(
                "Non-public IP address rejected"
            )

        public_ips.add(str(ip))

    if not public_ips:
        raise RuntimeError("No public IP address found")

    return sorted(public_ips)[0]


def fetch_https(domain: str, path: str):
    """
    Fetch HTTPS response using a validated, pinned IP.
    The original hostname is retained for TLS verification.
    """

    selected_ip = resolve_public_ip(domain)

    context = ssl.create_default_context(
        cafile=certifi.where()
    )

    connection = HTTPSConnection(
        host=domain,
        port=443,
        timeout=CONNECT_TIMEOUT,
        context=context
    )

    try:
        # Connect directly to the previously validated IP.
        connection.sock = socket.create_connection(
            (selected_ip, 443),
            timeout=CONNECT_TIMEOUT
        )

        # Verify the certificate against the original hostname.
        connection.sock = context.wrap_socket(
            connection.sock,
            server_hostname=domain
        )

        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": "CYBROT-OSINT/0.2",
                "Accept": "*/*",
                "Connection": "close"
            }
        )

        response = connection.getresponse()

        headers = {
            key.lower(): value
            for key, value in response.getheaders()
        }

        status_code = response.status

        # Do not download an entire website.
        response.read(4096)

        return status_code, headers

    finally:
        connection.close()


def analyze_headers(domain: str):
    """
    Collect HTTP security headers with:
    - Public IP validation
    - Pinned HTTPS connections
    - Certificate verification
    - Safe redirect handling
    """

    domain = validate_domain(domain)

    current_url = f"https://{domain}/"
    redirect_count = 0
    redirect_history = []

    try:
        while True:

            parsed = urlparse(current_url)

            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.port not in (None, 443)
            ):
                raise ValueError(
                    "Unsafe redirect destination rejected"
                )

            current_domain = validate_domain(
                parsed.hostname
            )

            path = parsed.path or "/"

            if parsed.query:
                path += "?" + parsed.query

            status_code, received = fetch_https(
                current_domain,
                path
            )

            # Handle redirects manually to validate every destination.
            if status_code in (301, 302, 303, 307, 308):

                location = received.get("location")

                if not location:
                    break

                if redirect_count >= MAX_REDIRECTS:
                    raise RuntimeError(
                        "Maximum redirect limit exceeded"
                    )

                next_url = urljoin(
                    current_url,
                    location
                )

                next_parsed = urlparse(next_url)

                if (
                    next_parsed.scheme != "https"
                    or not next_parsed.hostname
                    or next_parsed.username
                    or next_parsed.password
                    or next_parsed.port not in (None, 443)
                ):
                    raise ValueError(
                        "Unsafe redirect destination rejected"
                    )

                redirect_history.append(next_url)
                current_url = next_url
                redirect_count += 1

                continue

            break

        results = {}

        for header in SECURITY_HEADERS:
            results[header] = received.get(header)

        present = sum(
            value is not None
            for value in results.values()
        )

        missing = [
            header
            for header, value in results.items()
            if value is None
        ]

        return {
            "status": "success",
            "domain": domain,
            "final_url": current_url,
            "http_status": status_code,
            "headers": results,
            "summary": {
                "total_checked": len(SECURITY_HEADERS),
                "present": present,
                "missing": len(missing)
            },
            "missing_headers": missing,
            "redirects_followed": redirect_count,
            "redirect_history": redirect_history,
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "source": "HTTPS response headers"
        }

    except ValueError:
        raise

    except Exception as error:

        print("\n========== CYBROT SECURITY HEADER DEBUG ==========")
        print("Error type:", type(error).__name__)
        print("Error details:", repr(error))
        traceback.print_exc()
        print("=================================================\n")

        raise RuntimeError(
            f"Header lookup failed: "
            f"{type(error).__name__}: {repr(error)}"
        ) from error
