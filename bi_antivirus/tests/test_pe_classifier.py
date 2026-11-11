"""
BI Antivirus - Test Suite for Local PE Security Classifier
Verifies:
- Shannon entropy calculation correctness
- Valid PE binary header parsing (PE32/PE32+)
- Non-PE and malformed binary handling without crashing
- RWX section permission detection
- Suspicious API identification and explainable heuristic scoring
- Database persistence of analysis records
"""

import os
import unittest
import struct
import secrets
from pathlib import Path

from bi_antivirus.core.pe_classifier import PEClassifier, calculate_entropy
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.config import SCRATCH_DIR


class TestPEClassifier(unittest.TestCase):
    """Test suite for PE static binary feature extraction and heuristic classification."""

    def setUp(self):
        self.scratch_dir = SCRATCH_DIR / "test_pe_scratch"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.scratch_dir / "test_pe_history.db"
        self.history_db = HistoryDatabase(db_path=self.db_path)
        self.classifier = PEClassifier(history_db=self.history_db)

    def tearDown(self):
        # Clean up scratch files
        for f in self.scratch_dir.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            self.scratch_dir.rmdir()
        except Exception:
            pass

    def test_shannon_entropy_calculation(self):
        """Verify Shannon entropy math on uniform, structured, and pseudo-random data."""
        # 1. Zero entropy for identical bytes
        uniform_data = b"A" * 1024
        self.assertEqual(calculate_entropy(uniform_data), 0.0)

        # 2. Moderate entropy for natural text (typically 3.0 to 4.5)
        text_data = b"The quick brown fox jumps over the lazy dog. Repetitive normal text string." * 20
        text_entropy = calculate_entropy(text_data)
        self.assertTrue(3.0 <= text_entropy <= 5.0, f"Unexpected text entropy: {text_entropy}")

        # 3. High entropy for cryptographic pseudorandom bytes (typically 7.8 to 8.0)
        random_data = secrets.token_bytes(2048)
        rand_entropy = calculate_entropy(random_data)
        self.assertTrue(rand_entropy >= 7.8, f"Unexpected random entropy: {rand_entropy}")

    def test_malformed_and_non_pe_files(self):
        """Verify that non-PE and truncated files are safely rejected without exceptions."""
        non_pe_path = self.scratch_dir / "plain_text.txt"
        non_pe_path.write_text("Hello, this is not a Portable Executable binary file.")

        report = self.classifier.analyze_file(non_pe_path)
        self.assertFalse(report["is_pe"])
        self.assertEqual(report["verdict"], "NOT_A_PE")
        self.assertEqual(report["suspicion_score"], 0)

        # Truncated DOS header (< 64 bytes)
        truncated_path = self.scratch_dir / "truncated.exe"
        truncated_path.write_bytes(b"MZ\x00\x00\x01\x02\x03")
        report2 = self.classifier.analyze_file(truncated_path)
        self.assertFalse(report2["is_pe"])
        self.assertEqual(report2["verdict"], "NOT_A_PE")

    def test_live_windows_binary_parsing(self):
        """Analyze a known Windows system executable (e.g., explorer.exe or cmd.exe)."""
        system_binaries = [
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "explorer.exe",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "cmd.exe",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe",
        ]
        target = next((b for b in system_binaries if b.exists()), None)
        if not target:
            self.skipTest("No standard Windows binary found for live test.")

        report = self.classifier.analyze_file(target)
        self.assertTrue(report["is_pe"])
        self.assertIn(report["architecture"], ("PE32+", "PE32"))
        self.assertGreater(len(report["sections"]), 0)
        self.assertIn(".text", [s["name"] for s in report["sections"]])
        # Standard signed Windows binaries should score low
        self.assertIn(report["verdict"], ("BENIGN_PROBABLE", "SUSPICIOUS_HEURISTIC"))
        self.assertLess(report["suspicion_score"], 60)

    def test_rwx_section_heuristic_scoring(self):
        """Verify that sections marked executable and writable increment the suspicion score."""
        # Synthesize a minimal PE with a section header having characteristics 0xE0000020 (RWX)
        pe_file = self.scratch_dir / "synthetic_rwx.exe"
        
        # Build minimal valid PE headers:
        # DOS Header (64 bytes)
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x40)  # e_lfanew = 0x40

        # PE Signature + COFF Header
        pe_sig = b"PE\x00\x00"
        # COFF: Machine=0x8664(x64), Sections=1, TimeDate=0, PtrSym=0, NumSym=0, OptHdrSize=240, Char=0x0022
        coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)

        # Optional Header 64-bit (240 bytes)
        opt_hdr = bytearray(240)
        struct.pack_into("<H", opt_hdr, 0, 0x020B)  # Magic = PE32+
        struct.pack_into("<I", opt_hdr, 16, 0x1000) # AddressOfEntryPoint
        struct.pack_into("<Q", opt_hdr, 24, 0x140000000) # ImageBase
        struct.pack_into("<I", opt_hdr, 32, 0x1000) # SectionAlignment
        struct.pack_into("<I", opt_hdr, 36, 0x200)  # FileAlignment
        struct.pack_into("<H", opt_hdr, 68, 2)      # Subsystem = Windows GUI
        struct.pack_into("<H", opt_hdr, 70, 0x0140) # DllCharacteristics = DYNAMIC_BASE | NX_COMPAT
        struct.pack_into("<I", opt_hdr, 108, 16)    # NumberOfRvaAndSizes

        # Section Header (40 bytes): Name, VirtualSize, VirtualAddress, RawSize, RawPtr, Reloc, Line, NumReloc, NumLine, Char
        # Char = 0xE0000020 (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | CODE)
        sect_name = b".rwxsec\x00"
        sect_hdr = struct.pack("<8sIIIIIIHHI", sect_name, 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000020)

        # Section raw payload (padded to 0x200 bytes)
        sec_payload = b"\x90" * 0x200  # NOP sled

        # Assemble binary
        binary_data = bytes(dos_header) + pe_sig + coff + bytes(opt_hdr) + sect_hdr
        # Pad to file alignment (0x200)
        binary_data += b"\x00" * (0x200 - (len(binary_data) % 0x200))
        binary_data += sec_payload

        pe_file.write_bytes(binary_data)

        report = self.classifier.analyze_file(pe_file)
        self.assertTrue(report["is_pe"])
        self.assertEqual(len(report["sections"]), 1)
        self.assertTrue(report["sections"][0]["is_rwx"])
        # RWX section should be flagged in reasons and add at least 30 to score
        self.assertTrue(any("RWX" in rea for rea in report["reasons"]))
        self.assertGreaterEqual(report["suspicion_score"], 30)

    def test_database_persistence_and_query(self):
        """Verify PE analysis reports are recorded and retrievable from HistoryDatabase."""
        # Use a live system PE or synthetic valid PE
        target = Path(os.environ.get("WINDIR", r"C:\Windows")) / "explorer.exe"
        if not target.exists():
            target = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "cmd.exe"

        if target.exists():
            report = self.classifier.analyze_file(target)
            recent = self.history_db.get_recent_pe_analyses(limit=5)
            self.assertGreater(len(recent), 0)
            matched = next((r for r in recent if r.get("sha256") == report["sha256"]), None)
            self.assertIsNotNone(matched)
            self.assertEqual(matched["file_path"], str(target))
        else:
            self.history_db.record_pe_analysis(
                file_path=r"D:\bit defender\test.exe",
                file_hash="dummyhash123",
                classification="BENIGN_PROBABLE",
                risk_score=10,
                confidence=0.8,
                is_pe64=1,
                sections_count=4,
                suspicious_imports_count=0,
                findings=["Normal binary"],
            )
            recent = self.history_db.get_recent_pe_analyses(limit=5)
            self.assertGreater(len(recent), 0)


if __name__ == "__main__":
    unittest.main()
