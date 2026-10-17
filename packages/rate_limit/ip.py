"""CyberSentinel AI — Safe Client IP Resolution (CSAI-SEC-API-RATE-LIMIT)

Extracts client IP safely. Forwarded headers (X-Forwarded-For, X-Real-IP) are
only trusted when direct connection originates from an explicitly trusted proxy.
"""

from typing import Set

from starlette.requests import Request

DEFAULT_TRUSTED_PROXIES: Set[str] = {"127.0.0.1", "::1", "localhost"}


def get_safe_client_ip(
    request: Request,
    trusted_proxies: Set[str] | None = None,
) -> str:
    """Extract client IP address safely, preventing spoofing via forwarded headers.

    If direct peer (request.client.host) is NOT in trusted_proxies, X-Forwarded-For
    and X-Real-IP are strictly ignored, returning request.client.host directly.
    """
    proxies = trusted_proxies if trusted_proxies is not None else DEFAULT_TRUSTED_PROXIES

    direct_ip = request.client.host if request.client else "127.0.0.1"

    # If peer is untrusted, never trust forwarded headers
    if direct_ip not in proxies:
        return direct_ip

    # If peer is a trusted proxy, inspect forwarded headers
    xff = request.headers.get("X-Forwarded-For") or request.headers.get("x-forwarded-for")
    if xff:
        # X-Forwarded-For: <client>, <proxy1>, <proxy2>
        # Split and clean
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            # First non-trusted IP from right, or leftmost client IP
            # For standard reverse proxy setups, leftmost is the originating client
            return parts[0]

    x_real_ip = request.headers.get("X-Real-IP") or request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()

    return direct_ip
