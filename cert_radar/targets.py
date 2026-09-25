"""Target parsing: DNS names, IPs, URLs, IP ranges (a.b.c.d-e) and CIDR (TZ 3.3)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 443

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def _port_from_scheme(url: str) -> int:
    scheme = urlsplit(url).scheme.lower()
    if scheme in {"https", "ldaps"}:
        return 443 if scheme == "https" else 636
    return 443


def parse_targets(raw: str | list[str]) -> list[Target]:
    """Parse a newline/comma separated list (or list object) into targets.

    Supported forms:
      example.com                 -> example.com:443
      example.com:8443            -> example.com:8443
      https://example.com:8443/   -> example.com:8443
      192.168.1.10                -> 192.168.1.10:443
      192.168.1.10-192.168.1.20   -> whole range :443
      192.168.1.0/24              -> whole CIDR :443
    """
    items: list[str] = []
    if isinstance(raw, str):
        for chunk in raw.replace(",", "\n").splitlines():
            chunk = chunk.strip()
            if chunk:
                items.extend(x.strip() for x in chunk.split())
    else:
        items = [str(x).strip() for x in raw if str(x).strip()]

    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()

    def add(host: str, port: int) -> None:
        key = (host, port)
        if key not in seen:
            seen.add(key)
            targets.append(Target(host=host, port=port))

    for item in items:
        # URL form
        if "://" in item:
            u = urlsplit(item)
            host = u.hostname or ""
            if not host:
                continue
            add(host, u.port or _port_from_scheme(item))
            continue

        # CIDR network
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if net.num_addresses > 65536:
                raise ValueError(f"Network {item} is too large (max /112)")
            for ip in net.hosts():
                add(str(ip), 443)
            continue

        # plain host:port
        if ":" in item and item.count(":") == 1:
            host, _, port = item.partition(":")
            if port.isdigit():
                add(host.strip("[]"), int(port))
                continue

        # IP range a.b.c.d-e.f.g.h  or  a.b.c.d-e (last octet)
        if "-" in item and not _looks_like_hostname(item):
            lo_s, _, hi_s = item.partition("-")
            lo_s, hi_s = lo_s.strip(), hi_s.strip()
            try:
                lo = ipaddress.ip_address(lo_s)
                hi = ipaddress.ip_address(
                    f"{lo_s.rsplit('.', 1)[0]}.{hi_s}" if hi_s.isdigit() and "." not in hi_s
                    else hi_s)
            except ValueError:
                add(item, 443)
                continue
            start = int(lo)
            end = int(hi)
            if end < start or end - start > 65536:
                raise ValueError(f"Invalid range {item}")
            for i in range(start, end + 1):
                add(str(ipaddress.ip_address(i)), 443)
            continue

        add(item, 443)

    return targets


def _looks_like_hostname(item: str) -> bool:
    host_part = item.split("-")[0]
    return any(c.isalpha() for c in host_part)
