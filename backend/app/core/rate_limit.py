"""Shared rate limiter configuration for the application."""

import ipaddress

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from app.core.config import settings


def _clean_ip(value: str) -> str | None:
    """Return ``value`` only if it parses as a well-formed IP address.

    Proxy headers are attacker-controlled input. Returning the raw header value
    lets a crafted header (e.g. containing CR/LF) inject forged lines into any
    log line built from this IP - so we validate strictly and return None for
    anything that is not a real address rather than passing it through.
    """
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return value.strip()


def get_real_client_ip(request: Request) -> str:
    """
    Get the real client IP address, accounting for proxies.

    Only trusts X-Forwarded-For/X-Real-IP headers when BEHIND_PROXY=True,
    preventing header spoofing when directly exposed to the internet. The
    header value is validated as a real IP address before use: this value is
    written to logs (failed-login events), so an unvalidated header would be a
    log-injection vector.
    """
    if settings.BEHIND_PROXY:
        # X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2, ...
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            candidate = _clean_ip(forwarded_for.split(",")[0])
            if candidate:
                return candidate

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            candidate = _clean_ip(real_ip)
            if candidate:
                return candidate

    # Direct connection IP (or BEHIND_PROXY not set, or the header was malformed)
    return get_remote_address(request)


# Shared limiter instance - import this in endpoints
limiter = Limiter(key_func=get_real_client_ip, default_limits=["100/minute"])
