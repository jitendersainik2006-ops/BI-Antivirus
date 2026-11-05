"""
BI Antivirus - Local API Authentication and Rate Limiting
Manages high-entropy API keys on D: drive, constant-time validation,
and sliding-window rate limiting for loopback automation.
"""

import os
import hmac
import time
import secrets
import logging
from pathlib import Path
from collections import defaultdict
from typing import Tuple

from bi_antivirus.config import DATA_DIR

logger = logging.getLogger("bi_antivirus.api.auth")

API_KEY_FILE = DATA_DIR / "api_key.txt"


def get_or_create_api_key() -> str:
    """Retrieve existing local API key from D: drive or generate a fresh 256-bit token."""
    API_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if API_KEY_FILE.exists():
        try:
            with open(API_KEY_FILE, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        except Exception as e:
            logger.error(f"Error reading API key file: {e}")

    # Generate new 64-character cryptographically secure token
    fresh_key = secrets.token_hex(32)
    try:
        with open(API_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(fresh_key)
        # Attempt to restrict permissions on Windows if possible
        try:
            os.chmod(API_KEY_FILE, 0o600)
        except Exception:
            pass
        logger.info(f"Generated new secure BI Antivirus API key at {API_KEY_FILE}")
    except Exception as e:
        logger.error(f"Failed saving API key to {API_KEY_FILE}: {e}")

    return fresh_key


def verify_api_key(provided_key: str) -> bool:
    """Validate supplied key using constant-time comparison to prevent timing attacks."""
    if not provided_key:
        return False
    current_key = get_or_create_api_key()
    return hmac.compare_digest(provided_key.strip(), current_key)


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, client_id: str = "127.0.0.1") -> Tuple[bool, int]:
        """Check if request is within limits. Returns (allowed, remaining_requests)."""
        now = time.time()
        window_start = now - self.window_seconds
        # Clean expired timestamps
        self.requests[client_id] = [t for t in self.requests[client_id] if t > window_start]

        if len(self.requests[client_id]) >= self.max_requests:
            return False, 0

        self.requests[client_id].append(now)
        remaining = self.max_requests - len(self.requests[client_id])
        return True, remaining


rate_limiter = RateLimiter(max_requests=60, window_seconds=60)
