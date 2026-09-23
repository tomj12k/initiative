"""Shared rate limiter configuration for the application."""

import os

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from app.core.config import settings


def get_real_client_ip(request: Request) -> str:
    """
    Get the real client IP address, accounting for proxies.

    Only trusts X-Forwarded-For/X-Real-IP headers when BEHIND_PROXY=True,
    preventing header spoofing when directly exposed to the internet.
    """
    if settings.BEHIND_PROXY:
        # X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2, ...
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

    # Direct connection IP (or BEHIND_PROXY not set)
    return get_remote_address(request)


# Shared limiter instance - import this in endpoints.
#
# RATE_LIMIT_STORAGE_URI selects the counter backend. The default "memory://"
# keeps counters per-process: correct for a single-process deployment, but in a
# multi-worker/multi-replica deployment each process keeps its OWN counter, so the
# effective limit multiplies by the worker/replica count. Point this at a SHARED
# store (e.g. "redis://redis:6379/0") in those deployments to enforce the limit
# globally. A shared backend requires its client library to be installed (redis).
_RATE_LIMIT_STORAGE_URI = os.getenv("RATE_LIMIT_STORAGE_URI", "memory://")


def _verify_storage_backend(uri: str) -> None:
    """Fail fast with an actionable message if a non-memory backend is configured
    without its client library.

    slowapi resolves the storage backend eagerly inside ``Limiter(...)``, which runs
    at import time; a missing driver would otherwise surface as an opaque
    ``ConfigurationError`` during app startup.
    """
    scheme = uri.split("://", 1)[0].lower()
    if scheme.startswith("redis"):
        try:
            import redis  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on deploy extras
            raise RuntimeError(
                "RATE_LIMIT_STORAGE_URI is set to a redis backend but the 'redis' "
                "package is not installed. Add 'redis' to requirements.txt, or unset "
                "RATE_LIMIT_STORAGE_URI to fall back to in-memory limits."
            ) from exc


_verify_storage_backend(_RATE_LIMIT_STORAGE_URI)
limiter = Limiter(
    key_func=get_real_client_ip,
    default_limits=["100/minute"],
    storage_uri=_RATE_LIMIT_STORAGE_URI,
)
