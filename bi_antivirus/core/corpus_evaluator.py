"""
BI Antivirus - Harmless Test Corpus & False-Positive Evaluator
Provides an automated, repeatable framework to benchmark detection accuracy,
false-positive resistance, malformed input resilience, and evaluation latency.
Strictly zero malware: uses only harmless, synthetic test artifacts.
"""

import os
import time
import zipfile
import struct
import base64
import secrets
import tracemalloc
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from bi_antivirus.config import SCRATCH_DIR
from bi_antivirus.core.pe_classifier import PEClassifier
from bi_antivirus.monitors.ransomware_shield import RansomwareShield, calculate_shannon_entropy

logger = logging.getLogger("BI_CorpusEvaluator")


class CorpusEvaluator:
    """Evaluates antivirus engines and classifiers against harmless benign and malformed test corpora."""

    def __init__(self, corpus_root: Optional[Path] = None):
        self.corpus_root = Path(corpus_root or (SCRATCH_DIR / "corpus_eval"))
        self.corpus_root.mkdir(parents=True, exist_ok=True)

    def generate_benign_pe(self, dest_path: Path) -> Path:
        """
        Synthesize a minimal, harmless valid PE32 executable binary structure.
        DOS Header + PE Header + Optional Header + .text Section.
        """
        # DOS Header (64 bytes)
        dos_hdr = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40))  # e_lfanew = 0x40 (64)
        
        # PE Signature (4 bytes)
        pe_sig = b"PE\x00\x00"
        
        # COFF File Header (20 bytes)
        # Machine=0x014C (x86), Sections=1, TimeDate=0x60000000, PtrSym=0, NumSym=0, OptHdrSz=224, Chars=0x0102
        coff_hdr = struct.pack("<HHIIIHH", 0x014C, 1, 0x60000000, 0, 0, 224, 0x0102)
        
        # Optional Header (224 bytes standard PE32)
        # Magic=0x010B (PE32), Linker=14.0, CodeSize=512, InitData=0, UninitData=0, Entry=0x1000, BaseCode=0x1000, BaseData=0x2000
        # ImageBase=0x00400000, SecAlign=0x1000, FileAlign=0x200, OS=6.0, Subsys=3 (CLI), DllChars=0x8140 (NX + DYNAMIC_BASE + TERMINAL)
        opt_hdr = bytearray(224)
        struct.pack_into("<HBBIIIIII", opt_hdr, 0, 0x010B, 14, 0, 512, 0, 0, 0x1000, 0x1000, 0x2000)
        struct.pack_into("<I", opt_hdr, 28, 0x00400000)  # ImageBase
        struct.pack_into("<II", opt_hdr, 32, 0x1000, 0x200)  # SectionAlign, FileAlign
        struct.pack_into("<HH", opt_hdr, 68, 3, 0x8140)     # Subsystem CLI, DllCharacteristics (DEP + ASLR)
        struct.pack_into("<I", opt_hdr, 108, 16)             # NumberOfRvaAndSizes = 16
        
        # Section Header: .text (40 bytes)
        # Name=".text\0\0\0", VSize=0x200, VAddr=0x1000, RawSize=0x200, RawPtr=0x200, Chars=0x60000020 (CODE | EXEC | READ)
        sec_hdr = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
        
        # Assemble headers up to 0x200 (padded with zeros)
        headers = dos_hdr + pe_sig + coff_hdr + opt_hdr + sec_hdr
        pad_size = 0x200 - len(headers)
        if pad_size > 0:
            headers += b"\x00" * pad_size
            
        # Section Payload (.text content): harmless NOP sled + RET (0x90... 0xC3)
        section_payload = b"\x90" * 511 + b"\xC3"
        
        complete_pe = bytes(headers + section_payload)
        dest_path.write_bytes(complete_pe)
        return dest_path

    def generate_benign_zip(self, dest_path: Path) -> Path:
        """Create a legitimate high-entropy compressed zip archive containing standard text."""
        with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("doc1.txt", "Legitimate corporate quarterly analysis data. " * 100)
            zf.writestr("config.json", '{"status": "active", "version": "2.4.0", "encryption": false}')
            zf.writestr("table.csv", "id,name,value\n1,alpha,100\n2,beta,200\n3,gamma,300\n")
        return dest_path

    def generate_benign_high_entropy_doc(self, dest_path: Path) -> Path:
        """Create a high-entropy ASCII document (base64 data) to test false-positive mitigation."""
        dense_base64 = base64.b64encode(secrets.token_bytes(2048)).decode("ascii")
        formatted_content = f"# Configuration Token Export\n\nTOKEN_DATA={dense_base64}\n\nEND OF FILE\n"
        dest_path.write_text(formatted_content, encoding="utf-8")
        return dest_path

    def generate_malformed_pes(self, base_dir: Path) -> List[Path]:
        """Generate a series of harmless malformed PE files to verify engine error resilience."""
        malformed_files = []

        # 1. Truncated DOS header (< 64 bytes)
        p1 = base_dir / "malformed_truncated_dos.bin"
        p1.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00")
        malformed_files.append(p1)

        # 2. Invalid e_lfanew pointing far beyond file bounds
        p2 = base_dir / "malformed_bad_lfanew.bin"
        bad_lfanew = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x10000000))
        p2.write_bytes(bad_lfanew)
        malformed_files.append(p2)

        # 3. Valid DOS header, corrupted PE signature
        p3 = base_dir / "malformed_bad_pe_sig.bin"
        bad_sig = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"XX\x00\x00" + b"\x00" * 100)
        p3.write_bytes(bad_sig)
        malformed_files.append(p3)

        # 4. Out-of-bounds section count (declared 500 sections vs 96 limit)
        p4 = base_dir / "malformed_massive_sections.bin"
        dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, 500, 0, 0, 0, 0, 0)
        p4.write_bytes(dos + coff)
        malformed_files.append(p4)

        # 5. Truncated COFF header
        p5 = base_dir / "malformed_truncated_coff.bin"
        p5.write_bytes(dos + b"PE\x00\x00\x4C\x01")
        malformed_files.append(p5)

        return malformed_files

    def setup_corpus(self) -> Dict[str, List[Path]]:
        """Construct all harmless test cases in scratch space."""
        benign_dir = self.corpus_root / "benign"
        malformed_dir = self.corpus_root / "malformed"
        benign_dir.mkdir(parents=True, exist_ok=True)
        malformed_dir.mkdir(parents=True, exist_ok=True)

        benign_samples = [
            self.generate_benign_pe(benign_dir / "benign_tool.exe"),
            self.generate_benign_zip(benign_dir / "benign_archive.zip"),
            self.generate_benign_high_entropy_doc(benign_dir / "benign_token.json"),
            self.generate_benign_high_entropy_doc(benign_dir / "benign_export.txt"),
        ]

        malformed_samples = self.generate_malformed_pes(malformed_dir)

        return {
            "benign": benign_samples,
            "malformed": malformed_samples,
        }

    def evaluate_false_positives(
        self,
        pe_classifier: Optional[PEClassifier] = None,
        ransomware_shield: Optional[RansomwareShield] = None,
    ) -> Dict[str, Any]:
        """
        Execute comprehensive evaluation of harmless corpus.
        Returns accuracy, false-positive counts, latency metrics, and memory usage.
        """
        classifier = pe_classifier or PEClassifier()
        shield = ransomware_shield or RansomwareShield(watch_dirs=[self.corpus_root])

        corpus = self.setup_corpus()
        benign_samples = corpus["benign"]
        malformed_samples = corpus["malformed"]

        latencies_ms: List[float] = []
        false_positives: List[Dict[str, Any]] = []
        malformed_results: List[Dict[str, Any]] = []
        crashes: List[str] = []

        tracemalloc.start()
        start_eval_time = time.time()

        # 1. Evaluate Benign Samples
        for path in benign_samples:
            t0 = time.perf_counter()
            try:
                # Test PE classification if binary
                if path.suffix.lower() in (".exe", ".dll"):
                    pe_res = classifier.inspect_pe_file(path)
                    if pe_res.get("verdict") in ("THREAT_SUSPICIOUS", "THREAT_MALICIOUS"):
                        false_positives.append({
                            "file": path.name,
                            "type": "PE_CLASSIFIER_FP",
                            "verdict": pe_res.get("verdict"),
                            "score": pe_res.get("risk_score"),
                        })

                # Test Ransomware Shield entropy evaluation
                entropy_alert = shield.record_file_entropy(path)
                if entropy_alert is not None:
                    false_positives.append({
                        "file": path.name,
                        "type": "RANSOMWARE_SHIELD_FP",
                        "alert": entropy_alert.get("type"),
                        "entropy": entropy_alert.get("current_entropy"),
                    })

            except Exception as e:
                crashes.append(f"Crash processing benign file {path.name}: {e}")
            finally:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies_ms.append(elapsed_ms)

        # 2. Evaluate Malformed Samples for crash resilience
        for path in malformed_samples:
            t0 = time.perf_counter()
            try:
                pe_res = classifier.inspect_pe_file(path)
                # Ensure malformed files are safely handled with error or SKIPPED
                malformed_results.append({
                    "file": path.name,
                    "is_pe": pe_res.get("is_pe", False),
                    "error": pe_res.get("error"),
                    "handled_safely": True,
                })
            except Exception as e:
                crashes.append(f"Crash processing malformed file {path.name}: {e}")
            finally:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies_ms.append(elapsed_ms)

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        total_tested = len(benign_samples) + len(malformed_samples)
        fp_rate = (len(false_positives) / len(benign_samples)) * 100.0 if benign_samples else 0.0

        latencies_ms.sort()
        mean_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        p95_index = int(len(latencies_ms) * 0.95)
        p95_latency = latencies_ms[min(p95_index, len(latencies_ms) - 1)] if latencies_ms else 0.0

        return {
            "evaluation_time_seconds": round(time.time() - start_eval_time, 4),
            "total_samples_evaluated": total_tested,
            "benign_samples_evaluated": len(benign_samples),
            "malformed_samples_evaluated": len(malformed_samples),
            "false_positives_count": len(false_positives),
            "false_positive_rate_percent": round(fp_rate, 2),
            "false_positives_details": false_positives,
            "crashes_count": len(crashes),
            "crashes_details": crashes,
            "all_malformed_handled_safely": len(crashes) == 0 and len(malformed_results) == len(malformed_samples),
            "performance": {
                "mean_latency_ms": round(mean_latency, 3),
                "p95_latency_ms": round(p95_latency, 3),
                "max_latency_ms": round(max(latencies_ms) if latencies_ms else 0.0, 3),
                "peak_memory_mb": round(peak_mem / (1024 * 1024), 3),
            },
        }

    def cleanup(self) -> None:
        """Safely remove temporary evaluation corpus from D: drive scratch."""
        try:
            for root, dirs, files in os.walk(self.corpus_root, topdown=False):
                for f in files:
                    try:
                        (Path(root) / f).unlink()
                    except Exception:
                        pass
                for d in dirs:
                    try:
                        (Path(root) / d).rmdir()
                    except Exception:
                        pass
            self.corpus_root.rmdir()
        except Exception:
            pass
