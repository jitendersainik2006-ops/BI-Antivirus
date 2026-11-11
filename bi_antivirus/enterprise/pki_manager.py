"""
BI Antivirus - Enterprise Public Key Infrastructure (PKI) & Certificate Manager
Manages local Certificate Authority (CA), X.509 certificate issuance, expiration checking,
peer certificate validation, certificate rotation, and revocation registry.
Backbone for mutual TLS (mTLS) endpoint authentication.
"""

import os
import sys
import shutil
import subprocess
import hashlib
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from bi_antivirus.enterprise.fleet_models import CertificateRecord
from bi_antivirus.enterprise.fleet_database import FleetDatabase
from bi_antivirus.config import DATA_DIR

logger = logging.getLogger("BI_PKIManager")

DEFAULT_PKI_DIR = DATA_DIR / "pki"


def find_openssl_binary() -> str:
    """Discover a functional OpenSSL executable on the local system."""
    # 1. PATH lookup
    discovered = shutil.which("openssl")
    if discovered and Path(discovered).exists():
        return discovered

    # 2. Standard Git / Windows OpenSSL locations
    candidates = [
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    raise RuntimeError(
        "OpenSSL binary not found. Please install Git for Windows or OpenSSL-Win64."
    )


class PKIManager:
    """Enterprise PKI Certificate Authority & Lifecycle Manager."""

    def __init__(
        self,
        pki_dir: Optional[Path] = None,
        fleet_db: Optional[FleetDatabase] = None,
        openssl_bin: Optional[str] = None,
    ):
        self.pki_dir = Path(pki_dir or DEFAULT_PKI_DIR)
        self.pki_dir.mkdir(parents=True, exist_ok=True)
        self.ca_dir = self.pki_dir / "ca"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir = self.pki_dir / "certs"
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        self.db = fleet_db or FleetDatabase()
        self.openssl_bin = openssl_bin or find_openssl_binary()

        self.ca_key = self.ca_dir / "ca.key"
        self.ca_crt = self.ca_dir / "ca.crt"
        self.ca_srl = self.ca_dir / "ca.srl"

        # In-memory revocation cache for fast lookups
        self._revocation_cache: set = set()

        # Ensure Root CA exists
        self.ensure_root_ca()
        self._sync_revocation_cache()

    def _sync_revocation_cache(self) -> None:
        """Sync in-memory revocation cache from database."""
        try:
            revoked = self.db.list_certificates(status="REVOKED")
            for cert in revoked:
                self._revocation_cache.add(cert.serial_number)
                self._revocation_cache.add(cert.endpoint_id)
                self._revocation_cache.add(cert.common_name)
        except Exception as e:
            logger.warning(f"Could not sync revocation cache: {e}")

    def _run_openssl(self, args: List[str]) -> str:
        """Execute OpenSSL command safely and return stdout."""
        cmd = [self.openssl_bin] + args
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            raise RuntimeError(f"OpenSSL failed ({res.returncode}): {err}")
        return res.stdout

    def ensure_root_ca(self, validity_days: int = 3650) -> Tuple[Path, Path]:
        """Generate or verify Root Certificate Authority key and certificate."""
        if self.ca_key.exists() and self.ca_crt.exists():
            return self.ca_crt, self.ca_key

        logger.info("Initializing new BI Antivirus Enterprise Root CA...")
        # 1. Generate RSA 2048 Root CA Private Key
        self._run_openssl(["genrsa", "-out", str(self.ca_key), "2048"])

        # Restrict key file permissions on Windows where supported
        try:
            os.chmod(self.ca_key, 0o600)
        except Exception:
            pass

        # 2. Self-sign X.509 Root CA Certificate
        self._run_openssl([
            "req", "-x509", "-new", "-nodes",
            "-key", str(self.ca_key),
            "-sha256",
            "-days", str(validity_days),
            "-out", str(self.ca_crt),
            "-subj", "/CN=BI-Antivirus-Root-CA/O=BI-Security-Enterprise/OU=PKI",
        ])

        # Record CA in database
        serial = self.get_certificate_serial(self.ca_crt)
        fingerprint = self.get_certificate_fingerprint(self.ca_crt)
        ca_record = CertificateRecord(
            serial_number=serial,
            endpoint_id="ROOT_CA",
            common_name="BI-Antivirus-Root-CA",
            certificate_type="CA",
            status="ACTIVE",
            issued_at=time.time(),
            expires_at=time.time() + (validity_days * 86400),
            cert_path=str(self.ca_crt),
            fingerprint_sha256=fingerprint,
        )
        self.db.record_certificate(ca_record)
        logger.info(f"Root CA generated: serial={serial}, sha256={fingerprint[:16]}...")
        return self.ca_crt, self.ca_key

    def get_certificate_serial(self, cert_path: Path) -> str:
        """Extract hex serial number from an X.509 certificate."""
        output = self._run_openssl(["x509", "-serial", "-noout", "-in", str(cert_path)])
        for line in output.strip().splitlines():
            if line.startswith("serial="):
                return line.split("=", 1)[1].strip()
        # Fallback to file hash if serial output is unavailable
        return hashlib.sha256(cert_path.read_bytes()).hexdigest()[:16]

    def get_certificate_fingerprint(self, cert_path: Path) -> str:
        """Compute SHA-256 fingerprint of certificate."""
        output = self._run_openssl(["x509", "-fingerprint", "-sha256", "-noout", "-in", str(cert_path)])
        for line in output.strip().splitlines():
            if line.startswith("SHA256 Fingerprint="):
                return line.split("=", 1)[1].strip().replace(":", "").lower()
        return hashlib.sha256(cert_path.read_bytes()).hexdigest().lower()

    def issue_server_certificate(
        self,
        common_name: str = "localhost",
        sans: Optional[List[str]] = None,
        validity_days: int = 365,
    ) -> Tuple[Path, Path]:
        """Issue an mTLS server certificate with Subject Alternative Names (SANs)."""
        server_key = self.certs_dir / f"server_{common_name}.key"
        server_csr = self.certs_dir / f"server_{common_name}.csr"
        server_crt = self.certs_dir / f"server_{common_name}.crt"
        san_cnf = self.certs_dir / f"server_{common_name}_san.cnf"

        # SAN configuration
        san_entries = [f"DNS:{common_name}", "DNS:localhost", "IP:127.0.0.1"]
        if sans:
            for s in sans:
                if ":" in s:
                    san_entries.append(s)
                else:
                    san_entries.append(f"DNS:{s}")

        san_cnf.write_text(f"subjectAltName = {','.join(san_entries)}\n", encoding="utf-8")

        # 1. Generate Server Private Key
        self._run_openssl(["genrsa", "-out", str(server_key), "2048"])

        # 2. Generate CSR
        self._run_openssl([
            "req", "-new", "-key", str(server_key),
            "-out", str(server_csr),
            "-subj", f"/CN={common_name}/O=BI-Security-Enterprise/OU=Server",
        ])

        # 3. Sign CSR with Root CA
        self._run_openssl([
            "x509", "-req", "-in", str(server_csr),
            "-CA", str(self.ca_crt),
            "-CAkey", str(self.ca_key),
            "-CAcreateserial",
            "-out", str(server_crt),
            "-days", str(validity_days),
            "-sha256",
            "-extfile", str(san_cnf),
        ])

        # Cleanup CSR and temporary SAN config
        server_csr.unlink(missing_ok=True)
        san_cnf.unlink(missing_ok=True)

        serial = self.get_certificate_serial(server_crt)
        fingerprint = self.get_certificate_fingerprint(server_crt)
        record = CertificateRecord(
            serial_number=serial,
            endpoint_id="FLEET_MANAGER_SERVER",
            common_name=common_name,
            certificate_type="SERVER",
            status="ACTIVE",
            issued_at=time.time(),
            expires_at=time.time() + (validity_days * 86400),
            cert_path=str(server_crt),
            fingerprint_sha256=fingerprint,
        )
        self.db.record_certificate(record)
        return server_crt, server_key

    def issue_client_certificate(
        self,
        endpoint_id: str,
        common_name: Optional[str] = None,
        validity_days: int = 365,
    ) -> Tuple[Path, Path]:
        """Issue an mTLS client certificate for an enrolled endpoint."""
        cn = common_name or endpoint_id
        client_key = self.certs_dir / f"client_{endpoint_id}.key"
        client_csr = self.certs_dir / f"client_{endpoint_id}.csr"
        client_crt = self.certs_dir / f"client_{endpoint_id}.crt"

        # 1. Generate Client Key
        self._run_openssl(["genrsa", "-out", str(client_key), "2048"])

        # 2. Generate CSR
        self._run_openssl([
            "req", "-new", "-key", str(client_key),
            "-out", str(client_csr),
            "-subj", f"/CN={cn}/O=BI-Security-Enterprise/OU=Endpoint",
        ])

        # 3. Sign CSR with Root CA
        self._run_openssl([
            "x509", "-req", "-in", str(client_csr),
            "-CA", str(self.ca_crt),
            "-CAkey", str(self.ca_key),
            "-CAcreateserial",
            "-out", str(client_crt),
            "-days", str(validity_days),
            "-sha256",
        ])

        client_csr.unlink(missing_ok=True)

        serial = self.get_certificate_serial(client_crt)
        fingerprint = self.get_certificate_fingerprint(client_crt)
        record = CertificateRecord(
            serial_number=serial,
            endpoint_id=endpoint_id,
            common_name=cn,
            certificate_type="CLIENT",
            status="ACTIVE",
            issued_at=time.time(),
            expires_at=time.time() + (validity_days * 86400),
            cert_path=str(client_crt),
            fingerprint_sha256=fingerprint,
        )
        self.db.record_certificate(record)
        logger.info(f"Issued client cert for {endpoint_id}: serial={serial}")
        return client_crt, client_key

    def is_certificate_expired(self, cert_path: Path) -> bool:
        """Check if certificate has exceeded its validity period."""
        if not cert_path.exists():
            return True
        try:
            output = self._run_openssl(["x509", "-enddate", "-noout", "-in", str(cert_path)])
            for line in output.strip().splitlines():
                if line.startswith("notAfter="):
                    date_str = line.split("=", 1)[1].strip()
                    # OpenSSL format e.g. "Nov 11 10:20:30 2027 GMT"
                    dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                    return datetime.now(timezone.utc) > dt
            return False
        except Exception as e:
            logger.error(f"Error checking cert expiration: {e}")
            return False

    def is_certificate_revoked(self, serial_or_id: str) -> bool:
        """Check if certificate serial or endpoint identifier is revoked."""
        if serial_or_id in self._revocation_cache:
            return True
        revoked = self.db.is_certificate_revoked(serial_or_id)
        if revoked:
            self._revocation_cache.add(serial_or_id)
        return revoked

    def revoke_certificate(
        self,
        serial_or_id: str,
        reason: str = "Administrative revocation",
    ) -> bool:
        """Revoke a certificate by serial number or endpoint ID."""
        self.db.revoke_certificate(serial_or_id, reason=reason)
        self._revocation_cache.add(serial_or_id)
        logger.warning(f"Certificate {serial_or_id} revoked: {reason}")
        return True

    def rotate_certificate(
        self,
        endpoint_id: str,
        validity_days: int = 365,
    ) -> Tuple[Path, Path]:
        """Rotate endpoint certificate: revokes existing active certificate and issues fresh pair."""
        # Find existing active certificate
        existing = self.db.get_certificate_by_endpoint(endpoint_id)
        if existing and existing.status == "ACTIVE":
            self.revoke_certificate(existing.serial_number, reason="Superseded by certificate rotation")

        # Issue new certificate
        return self.issue_client_certificate(endpoint_id, validity_days=validity_days)

    def verify_peer_certificate(
        self,
        peer_cert_dict: Dict[str, Any],
        expected_endpoint_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Validate peer certificate dictionary returned by SSLSocket.getpeercert().
        Verifies:
        1. Certificate is non-empty.
        2. CN exists and matches expected endpoint ID if specified.
        3. Certificate serial or CN is not in revocation list.
        4. Expiration date is valid.
        """
        if not peer_cert_dict:
            return False, "Empty or missing peer certificate (mTLS mutual auth required)"

        # Extract Common Name (CN)
        subject_tuples = peer_cert_dict.get("subject", ())
        cn = ""
        for rdn in subject_tuples:
            for key, val in rdn:
                if key == "commonName":
                    cn = val
                    break

        if not cn:
            return False, "Peer certificate missing Subject Common Name (CN)"

        # Extract Serial Number
        serial = peer_cert_dict.get("serialNumber", "")

        # Check Revocation
        if self.is_certificate_revoked(serial) or self.is_certificate_revoked(cn):
            return False, f"Peer certificate for {cn} (serial={serial}) is REVOKED"

        # Check Expected ID Match
        if expected_endpoint_id and cn != expected_endpoint_id:
            return False, f"Peer CN '{cn}' does not match expected endpoint ID '{expected_endpoint_id}'"

        # Check Expiration from notAfter
        not_after_str = peer_cert_dict.get("notAfter", "")
        if not_after_str:
            try:
                dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > dt:
                    return False, f"Peer certificate for {cn} is EXPIRED (expired on {not_after_str})"
            except Exception:
                pass

        return True, cn
