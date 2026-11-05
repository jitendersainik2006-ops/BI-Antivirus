"""
BI Antivirus - Local REST API Package
Provides secure, loopback-only REST endpoints for n8n automation and voice alert integration.
"""

from bi_antivirus.api.auth import get_or_create_api_key, verify_api_key, rate_limiter
from bi_antivirus.api.server import LocalAPIServer
from bi_antivirus.api.n8n_daemon import N8nLocalDaemon, n8n_daemon, check_n8n_health

__all__ = [
    "get_or_create_api_key",
    "verify_api_key",
    "rate_limiter",
    "LocalAPIServer",
    "N8nLocalDaemon",
    "n8n_daemon",
    "check_n8n_health",
]
