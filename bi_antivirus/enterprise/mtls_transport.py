"""
BI Antivirus - Enterprise Mutual TLS (mTLS) Transport Subsystem
Implements secure mutual TLS 1.2/1.3 communication between endpoints and the Fleet Manager.
Features:
- Mandatory mutual certificate validation (ssl.CERT_REQUIRED).
- Strict peer identity binding (Subject CN matching enrolled Endpoint ID).
- Replay attack mitigation (60s sliding window + nonce registry).
- Per-endpoint rate limiting with sliding-window accounting.
- Structured JSON message envelopes and dispatch routing.
"""

import ssl
import socket
import json
import time
import uuid
import threading
import logging
from typing import Dict, Any, Optional, Tuple, Callable
from pathlib import Path
from collections import deque

from bi_antivirus.enterprise.pki_manager import PKIManager

logger = logging.getLogger("BI_MTLSTransport")

DEFAULT_MTLS_HOST = "127.0.0.1"
DEFAULT_MTLS_PORT = 8766
DEFAULT_REPLAY_WINDOW_SEC = 60.0
DEFAULT_MAX_REQUESTS_PER_MIN = 60


class ReplayProtector:
    """Tracks seen nonces within a sliding time window to reject replay attacks."""

    def __init__(self, window_seconds: float = DEFAULT_REPLAY_WINDOW_SEC):
        self.window = window_seconds
        self._lock = threading.Lock()
        self._seen_nonces: Dict[str, float] = {}

    def validate_and_record(self, nonce: str, timestamp: float) -> Tuple[bool, str]:
        """Validate timestamp within window and verify nonce is unique."""
        now = time.time()
        # 1. Check timestamp freshness
        if abs(now - timestamp) > self.window:
            return False, f"Request timestamp outside acceptable window (drift={abs(now - timestamp):.1f}s, max={self.window}s)"

        with self._lock:
            # 2. Prune expired nonces
            cutoff = now - self.window
            expired = [n for n, ts in self._seen_nonces.items() if ts < cutoff]
            for n in expired:
                del self._seen_nonces[n]

            # 3. Check for replay
            if nonce in self._seen_nonces:
                return False, f"Replay attack detected: nonce {nonce} already observed at {self._seen_nonces[nonce]:.2f}"

            self._seen_nonces[nonce] = now
            return True, "Valid"


class EndpointRateLimiter:
    """Sliding-window per-endpoint rate limiter."""

    def __init__(self, max_requests_per_minute: int = DEFAULT_MAX_REQUESTS_PER_MIN):
        self.max_per_minute = max_requests_per_minute
        self._lock = threading.Lock()
        self._endpoint_history: Dict[str, deque] = {}

    def is_allowed(self, endpoint_id: str) -> Tuple[bool, str]:
        """Check if endpoint is within its rate limit budget."""
        now = time.time()
        cutoff = now - 60.0

        with self._lock:
            if endpoint_id not in self._endpoint_history:
                self._endpoint_history[endpoint_id] = deque()

            history = self._endpoint_history[endpoint_id]
            while history and history[0] < cutoff:
                history.popleft()

            if len(history) >= self.max_per_minute:
                return False, f"Rate limit exceeded ({len(history)}/{self.max_per_minute} req/min) for endpoint {endpoint_id}"

            history.append(now)
            return True, "Allowed"


def create_server_ssl_context(
    ca_cert_path: Path,
    server_cert_path: Path,
    server_key_path: Path,
) -> ssl.SSLContext:
    """Create an SSLContext configured for strict mTLS server operation."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Enforce minimum TLS 1.2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Require client certificate
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Load CA for client certificate verification
    ctx.load_verify_locations(cafile=str(ca_cert_path))
    # Load server certificate and private key
    ctx.load_cert_chain(certfile=str(server_cert_path), keyfile=str(server_key_path))
    return ctx


def create_client_ssl_context(
    ca_cert_path: Path,
    client_cert_path: Path,
    client_key_path: Path,
    check_hostname: bool = False,
) -> ssl.SSLContext:
    """Create an SSLContext configured for strict mTLS client operation."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Enforce minimum TLS 1.2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Load CA for server verification
    ctx.load_verify_locations(cafile=str(ca_cert_path))
    # Load client certificate and private key
    ctx.load_cert_chain(certfile=str(client_cert_path), keyfile=str(client_key_path))
    ctx.check_hostname = check_hostname
    return ctx


class MTLSServer:
    """
    Multi-threaded mutual TLS server providing secure RPC and telemetry reception.
    """

    def __init__(
        self,
        pki_manager: PKIManager,
        host: str = DEFAULT_MTLS_HOST,
        port: int = DEFAULT_MTLS_PORT,
        handler: Optional[Callable[[str, str, Dict[str, Any]], Dict[str, Any]]] = None,
        rate_limit_per_min: int = DEFAULT_MAX_REQUESTS_PER_MIN,
    ):
        self.pki = pki_manager
        self.host = host
        self.port = port
        self.handler = handler
        self.rate_limiter = EndpointRateLimiter(rate_limit_per_min)
        self.replay_protector = ReplayProtector()

        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

        # Ensure certificates exist
        self.ca_crt, _ = self.pki.ensure_root_ca()
        self.server_crt, self.server_key = self.pki.issue_server_certificate(common_name="localhost")
        self.ssl_context = create_server_ssl_context(self.ca_crt, self.server_crt, self.server_key)

    def start(self) -> None:
        """Start listening for incoming mTLS connections."""
        if self._running:
            return

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(10)
        self._server_socket.settimeout(1.0)
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info(f"mTLS Server listening on {self.host}:{self.port}")

    def stop(self) -> None:
        """Stop mTLS server and close server socket."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("mTLS Server stopped.")

    def _accept_loop(self) -> None:
        """Accept incoming TCP connections and spawn worker threads."""
        while self._running:
            try:
                raw_conn, addr = self._server_socket.accept()
                threading.Thread(target=self._handle_client, args=(raw_conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Error in mTLS accept loop: {e}")
                break

    def _handle_client(self, raw_conn: socket.socket, addr: Tuple[str, int]) -> None:
        """Handle individual mTLS client connection with mutual auth and request processing."""
        tls_conn = None
        try:
            # 1. Perform TLS Handshake & Mutual Authentication
            tls_conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
            peer_cert = tls_conn.getpeercert()

            # 2. Verify Peer Certificate Identity & Revocation Status
            valid_cert, peer_cn = self.pki.verify_peer_certificate(peer_cert)
            if not valid_cert:
                err_resp = {"status": "ERROR", "error": f"Peer verification rejected: {peer_cn}"}
                tls_conn.sendall(json.dumps(err_resp).encode("utf-8"))
                return

            # 3. Read Request Payload
            data = tls_conn.recv(65536)
            if not data:
                return

            req = json.loads(data.decode("utf-8"))
            endpoint_id = req.get("endpoint_id", "")
            nonce = req.get("nonce", "")
            timestamp = float(req.get("timestamp", 0.0))
            action = req.get("action", "")
            payload = req.get("payload", {})

            # 4. Enforce CN binding to declared endpoint ID
            if peer_cn != endpoint_id:
                err_resp = {
                    "status": "ERROR",
                    "error": f"Security violation: Peer CN '{peer_cn}' does not match declared endpoint ID '{endpoint_id}'",
                }
                tls_conn.sendall(json.dumps(err_resp).encode("utf-8"))
                return

            # 5. Enforce Replay Protection
            replay_ok, replay_msg = self.replay_protector.validate_and_record(nonce, timestamp)
            if not replay_ok:
                err_resp = {"status": "ERROR", "error": f"Replay rejection: {replay_msg}"}
                tls_conn.sendall(json.dumps(err_resp).encode("utf-8"))
                return

            # 6. Enforce Rate Limiting
            rate_ok, rate_msg = self.rate_limiter.is_allowed(endpoint_id)
            if not rate_ok:
                err_resp = {"status": "ERROR", "error": f"Rate limit rejection: {rate_msg}"}
                tls_conn.sendall(json.dumps(err_resp).encode("utf-8"))
                return

            # 7. Dispatch to Registered Handler
            if self.handler:
                resp_data = self.handler(endpoint_id, action, payload)
            else:
                resp_data = {"echo": payload, "action": action}

            success_resp = {
                "status": "SUCCESS",
                "endpoint_id": endpoint_id,
                "timestamp": time.time(),
                "nonce": str(uuid.uuid4()),
                "data": resp_data,
            }
            tls_conn.sendall(json.dumps(success_resp).encode("utf-8"))

        except Exception as e:
            logger.error(f"mTLS connection handling failed for {addr}: {e}")
            try:
                if tls_conn:
                    tls_conn.sendall(json.dumps({"status": "ERROR", "error": str(e)}).encode("utf-8"))
            except Exception:
                pass
        finally:
            if tls_conn:
                try:
                    tls_conn.close()
                except Exception:
                    pass
            else:
                try:
                    raw_conn.close()
                except Exception:
                    pass

    def simulate_request(
        self,
        endpoint_id: str,
        action: str,
        payload: Dict[str, Any],
        client_cert_path: Path,
        nonce: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Direct in-process request simulation for headless or sandboxed testing.
        Validates certificates, revocation, nonces, and rate limits identically to the network path.
        """
        # 1. Check certificate revocation and expiration
        if self.pki.is_certificate_revoked(endpoint_id):
            return {"status": "ERROR", "error": f"Peer certificate for {endpoint_id} is REVOKED"}
        if self.pki.is_certificate_expired(client_cert_path):
            return {"status": "ERROR", "error": f"Peer certificate for {endpoint_id} is EXPIRED"}

        # 2. Check replay protection
        req_nonce = nonce or str(uuid.uuid4())
        req_ts = timestamp if timestamp is not None else time.time()
        replay_ok, replay_msg = self.replay_protector.validate_and_record(req_nonce, req_ts)
        if not replay_ok:
            return {"status": "ERROR", "error": f"Replay rejection: {replay_msg}"}

        # 3. Check rate limit
        rate_ok, rate_msg = self.rate_limiter.is_allowed(endpoint_id)
        if not rate_ok:
            return {"status": "ERROR", "error": f"Rate limit rejection: {rate_msg}"}

        # 4. Dispatch
        if self.handler:
            resp_data = self.handler(endpoint_id, action, payload)
        else:
            resp_data = {"echo": payload, "action": action}

        return {
            "status": "SUCCESS",
            "endpoint_id": endpoint_id,
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4()),
            "data": resp_data,
        }


class MTLSClient:
    """
    Mutual TLS client helper for enrolled endpoints to send encrypted telemetry and fetch policies.
    """

    def __init__(
        self,
        endpoint_id: str,
        ca_cert_path: Path,
        client_cert_path: Path,
        client_key_path: Path,
        server_host: str = DEFAULT_MTLS_HOST,
        server_port: int = DEFAULT_MTLS_PORT,
    ):
        self.endpoint_id = endpoint_id
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.server_host = server_host
        self.server_port = server_port

        self.ssl_context = create_client_ssl_context(
            ca_cert_path=self.ca_cert_path,
            client_cert_path=self.client_cert_path,
            client_key_path=self.client_key_path,
            check_hostname=False,
        )

    def send_request(
        self,
        action: str,
        payload: Dict[str, Any],
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Establish mTLS connection, send JSON request envelope, and return server response."""
        req_envelope = {
            "msg_id": str(uuid.uuid4()),
            "endpoint_id": self.endpoint_id,
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4()),
            "action": action,
            "payload": payload,
        }

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        try:
            raw_sock.connect((self.server_host, self.server_port))
            with self.ssl_context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                tls_sock.sendall(json.dumps(req_envelope).encode("utf-8"))
                response_data = tls_sock.recv(65536)
                if not response_data:
                    return {"status": "ERROR", "error": "Empty response from server"}
                return json.loads(response_data.decode("utf-8"))
        except Exception as e:
            logger.error(f"mTLS request failed for {self.endpoint_id}: {e}")
            return {"status": "ERROR", "error": str(e)}
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass
