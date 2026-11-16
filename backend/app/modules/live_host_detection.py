
import ipaddress
import re
import socket
import ssl
import time
import certifi
from urllib.parse import urlsplit


TIMEOUT = 5
MAX_HOSTS = 100
MAX_IPS_PER_HOST = 5
MAX_RESPONSE_SIZE = 256_000


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract_response(raw):
    header_data, separator, body = raw.partition(b"\r\n\r\n")

    if not separator:
        return None

    lines = header_data.decode("iso-8859-1", errors="replace").split("\r\n")

    status_match = re.match(
        r"HTTP/\d(?:\.\d)?\s+(\d{3})",
        lines[0]
    )

    if not status_match:
        return None

    headers = {}

    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    title_match = re.search(
        rb"<title[^>]*>(.*?)</title>",
        body,
        re.IGNORECASE | re.DOTALL
    )

    title = None

    if title_match:
        title = title_match.group(1).decode(
            "utf-8", errors="replace"
        ).strip()

        title = re.sub(r"\s+", " ", title)[:300]

    return {
        "status_code": int(status_match.group(1)),
        "headers": headers,
        "title": title
    }


def probe_host(hostname, ip_address, scheme):
    port = 443 if scheme == "https" else 80
    started = time.perf_counter()

    result = {
        "scheme": scheme,
        "url": f"{scheme}://{hostname}",
        "ip_address": ip_address,
        "reachable": False,
        "status_code": None,
        "redirect_location": None,
        "title": None,
        "server": None,
        "response_time_ms": None,
        "error": None
    }

    connection = None

    try:
        raw_socket = socket.create_connection(
            (ip_address, port),
            timeout=TIMEOUT
        )

        if scheme == "https":
            context = ssl.create_default_context(
                cafile=certifi.where()
            )

            connection = context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            )
        else:
            connection = raw_socket

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"User-Agent: CYBROT-OSINT/0.3\r\n"
            f"Accept: text/html,*/*;q=0.8\r\n"
            f"Accept-Encoding: identity\r\n"
            f"Connection: close\r\n\r\n"
        )

        connection.sendall(request.encode("ascii"))

        response = bytearray()

        while len(response) < MAX_RESPONSE_SIZE:
            chunk = connection.recv(
                min(8192, MAX_RESPONSE_SIZE - len(response))
            )

            if not chunk:
                break

            response.extend(chunk)

        parsed = extract_response(bytes(response))

        if not parsed:
            raise ValueError("Invalid HTTP response")

        headers = parsed["headers"]

        result.update({
            "reachable": True,
            "status_code": parsed["status_code"],
            "redirect_location": headers.get("location"),
            "title": parsed["title"],
            "server": headers.get("server"),
            "response_time_ms": round(
                (time.perf_counter() - started) * 1000,
                2
            )
        })

    except Exception as error:
        result["error"] = str(error)[:200]

    finally:
        if connection:
            try:
                connection.close()
            except OSError:
                pass

    return result


def detect_live_hosts(domain, assets):
    domain = domain.strip().lower().rstrip(".")

    live_hosts = []
    checked_hosts = 0

    for asset in assets[:MAX_HOSTS]:
        hostname = asset.get("hostname", "").lower().rstrip(".")

        if not (
            hostname == domain
            or hostname.endswith("." + domain)
        ):
            continue

        checked_hosts += 1

        addresses = asset.get("ip_addresses", [])

        public_ips = sorted({
            ip for ip in addresses
            if is_public_ip(ip)
        })[:MAX_IPS_PER_HOST]

        host_result = {
            "hostname": hostname,
            "dns_status": asset.get("dns_status"),
            "services": [],
            "http_status": "not_checked"
        }

        if not public_ips:
            host_result["http_status"] = "no_public_ip"
            live_hosts.append(host_result)
            continue

        for ip_address in public_ips:
            for scheme in ("http", "https"):
                probe = probe_host(
                    hostname,
                    ip_address,
                    scheme
                )

                host_result["services"].append(probe)

                # Small delay between network requests.
                time.sleep(0.2)

        if any(
            service["reachable"]
            for service in host_result["services"]
        ):
            host_result["http_status"] = "reachable"
        else:
            host_result["http_status"] = "unreachable"

        live_hosts.append(host_result)

    reachable_count = sum(
        1 for host in live_hosts
        if host["http_status"] == "reachable"
    )

    return {
        "status": "success",
        "domain": domain,
        "total_hosts_checked": checked_hosts,
        "total_hosts": len(live_hosts),
        "reachable_hosts": reachable_count,
        "unreachable_hosts": sum(
            1 for host in live_hosts
            if host["http_status"] == "unreachable"
        ),
        "hosts": live_hosts,
        "collection_type": "passive_discovery_with_basic_http_probing"
    }
