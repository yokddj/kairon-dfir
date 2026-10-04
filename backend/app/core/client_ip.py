"""The address of the person making a request.

Behind the bundled Nginx every request reaches the backend from the Nginx container, so
``request.client.host`` is the same address for everyone. Nginx passes the browser's address in
``X-Real-IP``; it is believed only when the request came from a private or loopback address (the
proxy), never from a public one, which could set the header to anything.
"""
from __future__ import annotations

import ipaddress

from starlette.requests import Request


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    peer_ip = _ip(peer)
    if peer_ip is not None and (peer_ip.is_private or peer_ip.is_loopback):
        forwarded = _ip(request.headers.get("x-real-ip"))
        if forwarded is not None:
            return str(forwarded)
    return peer or "unknown"
