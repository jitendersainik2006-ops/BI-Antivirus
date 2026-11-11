"""
Unit and Integration Tests for Enterprise PKI and Mutual TLS (mTLS) Transport
Tests:
- Root CA generation, serial numbering, and fingerprinting.
- Server certificate issuance with Subject Alternative Names (SANs).
- Client certificate issuance with Common Name (CN) binding.
- Expiration detection and revocation registry.
- Peer certificate verification (CN match, CN mismatch, revoked peer rejection).
- Certificate rotation.
- Replay attack mitigation (nonce tracking + sliding window).
- Per-endpoint sliding-window rate limiting.
- mTLS end-to-end communication and error envelopes.
"""

import unittest
import tempfile
import shutil
import time
import uuid
import socket
from pathlib import Path

from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.enterprise.pki_manager import PKIManager, find_openssl_binary
from bi_antivirus.enterprise.mtls_transport import (
    MTLSServer,
    MTLSClient,
    ReplayProtector,
    EndpointRateLimiter,
)


class TestPKIAndMTLS(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bi_pki_test_"))
        self.db = FleetDatabase(self.temp_dir / "fleet_test.db")
        self.pki = PKIManager(pki_dir=self.temp_dir, fleet_db=self.db)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_root_ca_generation(self):
        """Verify Root CA certificate and private key generation and persistence."""
        ca_crt, ca_key = self.pki.ensure_root_ca()
        self.assertTrue(ca_crt.exists())
        self.assertTrue(ca_key.exists())

        # Second call returns existing CA
        ca_crt2, ca_key2 = self.pki.ensure_root_ca()
        self.assertEqual(ca_crt, ca_crt2)
        self.assertEqual(ca_key, ca_key2)

        fingerprint = self.pki.get_certificate_fingerprint(ca_crt)
        self.assertTrue(len(fingerprint) == 64)

    def test_02_server_certificate_issuance(self):
        """Verify server certificate issuance with SANs."""
        srv_crt, srv_key = self.pki.issue_server_certificate(
            common_name="localhost",
            sans=["127.0.0.1", "bi-fleet.internal"],
            validity_days=30,
        )
        self.assertTrue(srv_crt.exists())
        self.assertTrue(srv_key.exists())

        serial = self.pki.get_certificate_serial(srv_crt)
        self.assertTrue(len(serial) > 0)
        self.assertFalse(self.pki.is_certificate_expired(srv_crt))

    def test_03_client_certificate_and_revocation(self):
        """Verify client certificate issuance, CN binding, and revocation registry."""
        cli_crt, cli_key = self.pki.issue_client_certificate(
            endpoint_id="EP-WIN11-001",
            validity_days=365,
        )
        self.assertTrue(cli_crt.exists())
        self.assertTrue(cli_key.exists())

        # Verify initial non-revoked state
        self.assertFalse(self.pki.is_certificate_revoked("EP-WIN11-001"))

        # Revoke certificate
        rev_ok = self.pki.revoke_certificate("EP-WIN11-001", reason="Suspected key leakage")
        self.assertTrue(rev_ok)
        self.assertTrue(self.pki.is_certificate_revoked("EP-WIN11-001"))

    def test_04_peer_certificate_verification(self):
        """Verify strict peer identity validation rules."""
        mock_peer_cert = {
            "subject": ((("commonName", "EP-SECURE-99"),), (("organizationName", "BI-Security-Enterprise"),)),
            "serialNumber": "A1B2C3D4",
            "notAfter": "Nov 11 12:00:00 2030 GMT",
        }

        # 1. Matching ID and valid
        valid, cn = self.pki.verify_peer_certificate(mock_peer_cert, expected_endpoint_id="EP-SECURE-99")
        self.assertTrue(valid)
        self.assertEqual(cn, "EP-SECURE-99")

        # 2. Mismatched ID
        valid_mis, err_mis = self.pki.verify_peer_certificate(mock_peer_cert, expected_endpoint_id="EP-OTHER-01")
        self.assertFalse(valid_mis)
        self.assertIn("does not match", err_mis)

        # 3. Revoked CN
        self.pki.revoke_certificate("EP-SECURE-99", reason="Revocation test")
        valid_rev, err_rev = self.pki.verify_peer_certificate(mock_peer_cert, expected_endpoint_id="EP-SECURE-99")
        self.assertFalse(valid_rev)
        self.assertIn("REVOKED", err_rev)

        # 4. Empty cert
        valid_empty, err_empty = self.pki.verify_peer_certificate({})
        self.assertFalse(valid_empty)
        self.assertIn("Empty", err_empty)

    def test_05_certificate_rotation(self):
        """Verify certificate rotation revokes previous certificate and issues fresh pair."""
        crt1, key1 = self.pki.issue_client_certificate("EP-ROTATE-01")
        rec1 = self.db.get_certificate_by_endpoint("EP-ROTATE-01")
        self.assertIsNotNone(rec1)
        self.assertEqual(rec1.status, "ACTIVE")

        crt2, key2 = self.pki.rotate_certificate("EP-ROTATE-01")
        self.assertTrue(crt2.exists())
        self.assertTrue(key2.exists())

        # Old certificate serial is revoked in database
        old_cert = self.db.get_certificate(rec1.serial_number)
        self.assertEqual(old_cert.status, "REVOKED")
        self.assertIn("rotation", old_cert.revocation_reason.lower())

    def test_06_replay_protector(self):
        """Verify nonce tracking and sliding time window rejection."""
        rp = ReplayProtector(window_seconds=2.0)
        now = time.time()
        nonce = str(uuid.uuid4())

        # First request succeeds
        ok1, _ = rp.validate_and_record(nonce, now)
        self.assertTrue(ok1)

        # Replay with same nonce is rejected
        ok2, err2 = rp.validate_and_record(nonce, now + 0.1)
        self.assertFalse(ok2)
        self.assertIn("Replay attack detected", err2)

        # Request outside time window (old timestamp)
        ok3, err3 = rp.validate_and_record(str(uuid.uuid4()), now - 5.0)
        self.assertFalse(ok3)
        self.assertIn("outside acceptable window", err3)

        # Request outside time window (future clock drift)
        ok4, err4 = rp.validate_and_record(str(uuid.uuid4()), now + 10.0)
        self.assertFalse(ok4)
        self.assertIn("outside acceptable window", err4)

    def test_07_endpoint_rate_limiter(self):
        """Verify sliding-window rate limit enforcement per endpoint."""
        limiter = EndpointRateLimiter(max_requests_per_minute=3)
        ep = "EP-BURST-01"

        self.assertTrue(limiter.is_allowed(ep)[0])
        self.assertTrue(limiter.is_allowed(ep)[0])
        self.assertTrue(limiter.is_allowed(ep)[0])

        # 4th request exceeds rate limit
        allowed, msg = limiter.is_allowed(ep)
        self.assertFalse(allowed)
        self.assertIn("Rate limit exceeded", msg)

        # Other endpoint has independent budget
        self.assertTrue(limiter.is_allowed("EP-OTHER")[0])

    def test_08_mtls_simulation_and_revocation_enforcement(self):
        """Verify in-process mTLS dispatch simulation with certificate and replay enforcement."""
        server = MTLSServer(
            pki_manager=self.pki,
            handler=lambda ep, action, payload: {"status": "PROCESSED", "action": action, "echo": payload},
        )

        cli_crt, _ = self.pki.issue_client_certificate("EP-SIM-01")

        # 1. Successful simulated request
        resp = server.simulate_request(
            endpoint_id="EP-SIM-01",
            action="HEARTBEAT",
            payload={"health": "HEALTHY"},
            client_cert_path=cli_crt,
        )
        self.assertEqual(resp["status"], "SUCCESS")
        self.assertEqual(resp["data"]["status"], "PROCESSED")

        # 2. Replay rejection
        fixed_nonce = "fixed-nonce-12345"
        resp_first = server.simulate_request(
            endpoint_id="EP-SIM-01",
            action="HEARTBEAT",
            payload={},
            client_cert_path=cli_crt,
            nonce=fixed_nonce,
        )
        self.assertEqual(resp_first["status"], "SUCCESS")

        resp_replay = server.simulate_request(
            endpoint_id="EP-SIM-01",
            action="HEARTBEAT",
            payload={},
            client_cert_path=cli_crt,
            nonce=fixed_nonce,
        )
        self.assertEqual(resp_replay["status"], "ERROR")
        self.assertIn("Replay", resp_replay["error"])

        # 3. Revocation rejection
        self.pki.revoke_certificate("EP-SIM-01", reason="Revocation in simulation")
        resp_rev = server.simulate_request(
            endpoint_id="EP-SIM-01",
            action="HEARTBEAT",
            payload={},
            client_cert_path=cli_crt,
        )
        self.assertEqual(resp_rev["status"], "ERROR")
        self.assertIn("REVOKED", resp_rev["error"])


if __name__ == "__main__":
    unittest.main()
