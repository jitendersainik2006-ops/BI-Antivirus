"""
Unit tests for Full Disk Encryption (BitLocker) Sentinel.
"""

import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from bi_antivirus.monitors.encryption_manager import DiskEncryptionSentinel
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.engine import AntivirusEngine


MOCK_MANAGE_BDE_OUTPUT = """
BitLocker Drive Encryption: Configuration Tool version 10.0.19041
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

Disk volumes that can be protected with
BitLocker Drive Encryption:
Volume C: [OSDisk]
[OS Volume]

    Size:                 237.89 GB
    BitLocker Version:    2.0
    Conversion Status:    Fully Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 128
    Protection Status:    Protection On
    Lock Status:          Unlocked
    Identification Field: None
    Key Protectors:
        TPM
        Numerical Password

Volume D: [DataDisk]
[Data Volume]

    Size:                 465.75 GB
    BitLocker Version:    None
    Conversion Status:    Fully Decrypted
    Percentage Encrypted: 0.0%
    Encryption Method:    None
    Protection Status:    Protection Off
    Lock Status:          Unlocked
    Identification Field: None
    Key Protectors:       None Found
"""


D_DRIVE_SCRATCH = Path(r"D:\bit defender\data\crypto_test_scratch")


class TestDiskEncryptionSentinel(unittest.TestCase):
    """Test suite for BitLocker drive encryption auditing."""

    def setUp(self):
        D_DRIVE_SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=str(D_DRIVE_SCRATCH), ignore_cleanup_errors=True)
        self.db_file = Path(self.temp_dir.name) / "test_history.db"
        self.history_db = HistoryDatabase(db_path=self.db_file)
        self.sentinel = DiskEncryptionSentinel(history_db=self.history_db)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    @patch("subprocess.run")
    def test_manage_bde_output_parsing(self, mock_run):
        """Verify parsing of manage-bde volume blocks and encryption fields."""
        mock_proc = MagicMock()
        mock_proc.stdout = MOCK_MANAGE_BDE_OUTPUT
        mock_run.return_value = mock_proc

        volumes = DiskEncryptionSentinel.audit_volumes_via_manage_bde()
        self.assertEqual(len(volumes), 2)

        # Volume C (Encrypted)
        vol_c = volumes[0]
        self.assertEqual(vol_c["drive_letter"], "C:\\")
        self.assertEqual(vol_c["percentage_encrypted"], 100.0)
        self.assertEqual(vol_c["encryption_method"], "XTS-AES 128")
        self.assertTrue(vol_c["is_compliant"])
        self.assertIn("TPM", vol_c["key_protectors"])
        self.assertIn("Recovery Password", vol_c["key_protectors"])

        # Volume D (Unencrypted)
        vol_d = volumes[1]
        self.assertEqual(vol_d["drive_letter"], "D:\\")
        self.assertEqual(vol_d["percentage_encrypted"], 0.0)
        self.assertFalse(vol_d["is_compliant"])

    @patch("subprocess.run")
    def test_compliance_audit_and_event_logging(self, mock_run):
        """Verify compliance calculation and event logging for unencrypted drives."""
        mock_proc = MagicMock()
        mock_proc.stdout = MOCK_MANAGE_BDE_OUTPUT
        mock_run.return_value = mock_proc

        alerts = []
        self.sentinel.on_compliance_alert = lambda a: alerts.append(a)

        audit = self.sentinel.run_compliance_audit()
        self.assertEqual(audit["total_volumes"], 2)
        self.assertEqual(audit["protected_volumes"], 1)
        self.assertEqual(audit["unprotected_volumes"], 1)
        self.assertFalse(audit["overall_compliant"])

        # Alert triggered for Volume D
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["drive_letter"], "D:\\")

        # Event logged to database
        events = self.history_db.get_security_events()
        self.assertTrue(any(ev["event_type"] == "ENCRYPTION_NON_COMPLIANT" for ev in events))

    def test_engine_integration(self):
        """Verify engine initializes encryption sentinel properly."""
        engine = AntivirusEngine()
        self.assertIsNotNone(engine.encryption_sentinel)
        # Verify callback routes without error
        engine._on_encryption_alert({"details": "Test drive unencrypted"})


if __name__ == "__main__":
    unittest.main()
