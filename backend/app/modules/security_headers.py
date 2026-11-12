import ipaddress
import socket
from urllib.parse import urlparse
from urllib.request import Request, HTTPSHandler, build_opener
import ssl

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]

def analyze_headers(domain: str):
    domain = domain.strip().lower()

    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain")

    if not domain.isascii() or any(c in domain for c in "/:@?#"):
        raise ValueError("Enter a valid hostname only")

    try:
        addresses = socket.getaddrinfo(
            domain, 443, type=socket.SOCK_STREAM
        )

        public_ips = set()

        for item in addresses:
            ip = ipaddress.ip_address(item[4][0].split("%")[0])
            if not ip.is_global:
                raise ValueError("Non-public IP address rejected")
            public_ips.add(str(ip))

        if not public_ips:
            raise RuntimeError("No public IP address found")

        # Connect only to a validated public IP, while retaining
        # the original hostname for TLS certificate verification.
        selected_ip = sorted(public_ips)[0]

        class PinnedHTTPSConnection:
            pass

        class PinnedHTTPSHandler(HTTPSHandler):
            def https_open(self, req):
                from http.client import HTTPSConnection
                from urllib.request import AbstractHTTPHandler

                class Connection(HTTPSConnection):
                    def connect(self):
                        self.sock = socket.create_connection(
                            (selected_ip, self.port), timeout=8
                        )
                        self.sock = self._context.wrap_socket(
                            self.sock, server_hostname=domain
                        )

                return AbstractHTTPHandler.do_open(
                    self, lambda host, **kwargs: Connection(
                        host, context=self._context, **kwargs
                    ), req
                )

        context = ssl.create_default_context()
        opener = build_opener(PinnedHTTPSHandler(context=context))

        request = Request(
            f"https://{domain}/",
            headers={"User-Agent": "CYBROT-OSINT/0.1"},
            method="GET"
        )

        with opener.open(request, timeout=10) as response:
            received = {
                key.lower(): value
                for key, value in response.headers.items()
            }
            status_code = response.status

        results = {}
        for header in SECURITY_HEADERS:
            results[header] = received.get(header)

        present = sum(value is not None for value in results.values())

        return {
            "status": "success",
            "domain": domain,
            "http_status": status_code,
            "headers": results,
            "summary": {
                "total_checked": len(SECURITY_HEADERS),
                "present": present,
                "missing": len(SECURITY_HEADERS) - present
            },
            "source": "HTTPS response headers"
        }

    except ValueError:
        raise
    except Exception as error:
        raise RuntimeError(f"Header lookup failed: {error}")
