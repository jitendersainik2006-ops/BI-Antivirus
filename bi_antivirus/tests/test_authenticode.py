import unittest
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from bi_antivirus.core.authenticode import AuthenticodeVerifier
from bi_antivirus.core.detector import ThreatDetector

class TestAuthenticodeAndPE(unittest.TestCase):

    def test_signed_windows_binary(self):
        # Explorer.exe is guaranteed to be digitally signed by Microsoft on Windows
        explorer_path = Path("C:/Windows/explorer.exe")
        if explorer_path.exists():
            res = AuthenticodeVerifier.verify_file_signature(explorer_path)
            self.assertTrue(res["is_signed"])
            self.assertTrue(res["is_trusted"])
            self.assertEqual(res["status"], "TRUSTED")
            self.assertEqual(res["status_code"], 0)

    def test_unsigned_or_nonexistent_file(self):
        nonexistent = Path("C:/Windows/NonExistentBinary12345.exe")
        res = AuthenticodeVerifier.verify_file_signature(nonexistent)
        self.assertFalse(res["is_signed"])
        self.assertFalse(res["is_trusted"])
        self.assertEqual(res["status"], "FILE_NOT_FOUND")

    def test_pe_packer_section_inspection(self):
        # Test synthetic PE header with UPX section
        fake_pe = bytearray(b"\x00" * 512)
        fake_pe[:2] = b"MZ"
        fake_pe[0x3C:0x40] = (64).to_bytes(4, "little")  # PE offset at 64
        fake_pe[64:68] = b"PE\x00\x00"
        fake_pe[64+6:64+8] = (1).to_bytes(2, "little")   # 1 section
        fake_pe[64+20:64+22] = (0).to_bytes(2, "little") # 0 opt header size
        sec_offset = 64 + 24
        fake_pe[sec_offset:sec_offset+5] = b".upx0"
        
        info = ThreatDetector.inspect_pe_header(bytes(fake_pe))
        self.assertTrue(info["is_pe"])
        self.assertTrue(info["is_packed"])
        self.assertIn(".upx0", info["sections"])

if __name__ == "__main__":
    unittest.main()
