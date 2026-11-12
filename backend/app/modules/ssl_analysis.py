import socket
import ssl
import ipaddress
import hashlib
from datetime import datetime, timezone

def analyze_ssl(domain: str):
    domain = domain.strip().lower()

    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain")

    context = ssl.create_default_context()

    try:
        addresses = socket.getaddrinfo(
            domain, 443, type=socket.SOCK_STREAM
        )

        public_ips = []

        for item in addresses:
            ip = item[4][0].split("%")[0]
            address = ipaddress.ip_address(ip)

            if not address.is_global:
                raise ValueError(
                    "Domain resolves to a non-public IP address"
                )

            if ip not in public_ips:
                public_ips.append(ip)

        if not public_ips:
            raise RuntimeError("No public IP address found")

        with socket.create_connection(
            (public_ips[0], 443), timeout=8
        ) as connection:

            with context.wrap_socket(
                connection, server_hostname=domain
            ) as secure_connection:

                certificate = secure_connection.getpeercert()
                der_certificate = secure_connection.getpeercert(
                    binary_form=True
                )

                return {
                    "status": "success",
                    "domain": domain,
                    "port": 443,
                    "tls_version": secure_connection.version(),
                    "cipher": secure_connection.cipher()[0],
                    "certificate": {
                        "subject": certificate.get("subject"),
                        "issuer": certificate.get("issuer"),
                        "valid_from": certificate.get("notBefore"),
                        "valid_until": certificate.get("notAfter"),
                        "subject_alt_names": certificate.get("subjectAltName"),
                        "sha256_fingerprint": hashlib.sha256(
                            der_certificate
                        ).hexdigest()
                    },
                    "certificate_verified": True,
                    "checked_at": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "source": "TLS handshake"
                }

    except ValueError:
        raise
    except (OSError, ssl.SSLError) as error:
        raise RuntimeError(f"SSL/TLS lookup failed: {error}")
