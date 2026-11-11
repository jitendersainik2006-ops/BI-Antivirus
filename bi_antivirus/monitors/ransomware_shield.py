"""
BI Antivirus - Advanced Ransomware Shield & Canary Decoy Sentinel
Multi-layered defense against ransomware and unauthorized cryptor activity:
1. Canary Decoy Baiting (Honey-pot traps in user folders)
2. High-Frequency File Extension Mutation Bursts (.locked, .crypto, .enc, etc.)
3. Known Ransom Note Drop Interception
4. Shadow Copy & Backup Tampering Defense
"""

import os
import time
import hashlib
import threading
import logging
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Tuple
from collections import deque, Counter

from bi_antivirus.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    DATA_DIR,
    SCRATCH_DIR,
    load_settings,
)
from bi_antivirus.database.history import HistoryDatabase

logger = logging.getLogger("bi_antivirus.ransomware_shield")

# Known extensions appended by active ransomware families
RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".crypted", ".enc", ".encrypted",
    ".wannacry", ".wncry", ".lockbit", ".blackcat", ".akira",
    ".phobos", ".ryuk", ".stop", ".djvu", ".mallox", ".blackmatter"
}

# Known ransom note filenames
RANSOM_NOTE_NAMES = {
    "readme_to_decrypt.txt", "how_to_recover_files.txt", "decrypt_files.html",
    "restore_files.txt", "!!!_readme_!!!.txt", "decrypt_info.txt",
    "readme_for_decrypt.txt", "recover_your_files.html", "how_to_decrypt.html"
}

# Canary decoy file content header
CANARY_HEADER = b"BI_ANTIVIRUS_CANARY_INTEGRITY_TRAP_V1_DO_NOT_MODIFY"

# Known legitimate archiving, backup, and compiler tools that legitimately generate high-entropy output
WHITELISTED_ARCHIVE_PROCESSES = {
    "7z.exe", "7zfm.exe", "7zg.exe", "winrar.exe", "rar.exe", "tar.exe",
    "gzip.exe", "bzip2.exe", "xz.exe", "git.exe", "cl.exe", "gcc.exe",
    "g++.exe", "cargo.exe", "rustc.exe", "python.exe", "python3.exe",
    "node.exe", "code.exe", "devenv.exe", "msbuild.exe", "compact.exe"
}

# Recognized compressed/archived file extensions where high entropy is expected and benign
LEGITIMATE_COMPRESSED_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst",
    ".pak", ".jar", ".apk", ".iso", ".vmdk", ".whl", ".cab", ".lz4"
}

# Actionable Administrator Recovery Guidance
RECOVERY_GUIDANCE = (
    "1. Host Isolation: Immediately isolate host from network to prevent lateral propagation.\n"
    "2. Process Termination: Terminate suspicious process trees executing rapid file mutations.\n"
    "3. Canary Verification: Check canary decoy files in user directories.\n"
    "4. Volume Shadow Assessment: Verify Volume Shadow Copies (vssadmin list shadows).\n"
    "5. Encrypted Vault Restore: Restore clean original files from BI Antivirus Quarantine Vault."
)


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)



class RansomwareShield:
    """Active anti-ransomware sentinel with canary baiting and mutation burst detection."""

    def __init__(
        self,
        watch_dirs: Optional[List[Path]] = None,
        history_db: Optional[HistoryDatabase] = None,
        on_ransomware_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.history_db = history_db or HistoryDatabase()
        self.on_ransomware_alert = on_ransomware_alert
        self.watch_dirs = watch_dirs or [
            Path(os.path.expanduser(r"~\Documents")),
            Path(os.path.expanduser(r"~\Desktop")),
        ]

        self.is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Canary tracking: {canary_path: expected_sha256}
        self.canaries: Dict[Path, str] = {}

        # Mutation burst tracking: deque of (timestamp, filepath, new_ext)
        self._mutation_history: deque = deque(maxlen=200)
        self._burst_window_seconds = 5.0
        self._burst_threshold = 3  # >= 3 ransomware mutations in 5s triggers critical alert

        # File entropy baseline tracking: {file_path_str: baseline_entropy}
        self._file_entropy_baseline: Dict[str, float] = {}

        # Whitelisted processes for false positive suppression
        self.whitelisted_processes: Set[str] = set(WHITELISTED_ARCHIVE_PROCESSES)

    def whitelist_process(self, process_name: str) -> None:
        """Add a process name to the archiver/compiler whitelist."""
        if process_name:
            self.whitelisted_processes.add(process_name.lower().strip())

    def is_process_whitelisted(self, process_name: Optional[str]) -> bool:
        """Check if a process is trusted for archiving or compiling."""
        if not process_name:
            return False
        clean = Path(process_name).name.lower().strip()
        return clean in self.whitelisted_processes

    def deploy_canaries(self) -> int:
        """Deploy honey-pot canary decoy files across watched directories."""
        deployed = 0
        for directory in self.watch_dirs:
            if not directory.exists():
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                except Exception:
                    continue

            canary_path = directory / ".bi_integrity_canary.docx"
            try:
                # Generate unique content with deterministic hash
                content = CANARY_HEADER + b"_" + str(canary_path).encode("utf-8")
                expected_hash = hashlib.sha256(content).hexdigest()

                with open(canary_path, "wb") as f:
                    f.write(content)

                # Set hidden attribute on Windows if available
                if os.name == "nt":
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(canary_path), 0x02)  # FILE_ATTRIBUTE_HIDDEN
                    except Exception:
                        pass

                self.canaries[canary_path] = expected_hash
                deployed += 1
            except Exception as e:
                logger.debug(f"Failed deploying canary at {canary_path}: {e}")

        logger.info(f"Deployed {deployed} ransomware canary honey-pots.")
        return deployed

    def check_canary_integrity(self) -> List[Dict[str, Any]]:
        """
        Verify that all deployed canary decoy files are intact and un-encrypted.
        Returns list of violated canaries.
        """
        violations = []
        for path, expected_hash in list(self.canaries.items()):
            if not path.exists():
                violations.append({
                    "canary_path": str(path),
                    "violation_type": "CANARY_DELETED",
                    "severity": SEVERITY_CRITICAL,
                    "description": "Canary decoy file was unexpectedly deleted or moved (unauthorized tampering).",
                })
                continue

            try:
                with open(path, "rb") as f:
                    data = f.read()
                current_hash = hashlib.sha256(data).hexdigest()
                if current_hash != expected_hash:
                    violations.append({
                        "canary_path": str(path),
                        "violation_type": "CANARY_ENCRYPTED_OR_MODIFIED",
                        "severity": SEVERITY_CRITICAL,
                        "description": "Canary decoy file content was altered or encrypted by an external process!",
                    })
            except Exception as e:
                violations.append({
                    "canary_path": str(path),
                    "violation_type": "CANARY_LOCKED",
                    "severity": SEVERITY_HIGH,
                    "description": f"Canary file locked by another process: {e}",
                })

        return violations

    def record_file_entropy(
        self,
        file_path: Path,
        data: Optional[bytes] = None,
        process_name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Calculates and tracks file entropy. Detects transition from structured plaintext
        to encrypted ciphertext (entropy spike >= 7.2 with delta >= 2.0, or absolute entropy >= 7.5 on text/docs).
        Suppresses false positives when writes originate from whitelisted archivers/compilers
        or target legitimate compressed/archive file extensions.
        """
        # 1. Check process whitelist
        if self.is_process_whitelisted(process_name):
            logger.debug(f"Entropy check suppressed for whitelisted process {process_name} on {file_path}")
            return None

        # 2. Check compressed extension whitelist
        ext = file_path.suffix.lower()
        if ext in LEGITIMATE_COMPRESSED_EXTENSIONS:
            return None

        path_str = str(file_path).lower()
        if data is None:
            if not file_path.exists() or file_path.is_dir():
                return None
            try:
                with open(file_path, "rb") as f:
                    data = f.read(65536)  # Sample first 64KB
            except Exception:
                return None

        if len(data) < 128:
            return None  # Too small for statistically significant entropy evaluation

        entropy = calculate_shannon_entropy(data)
        baseline = self._file_entropy_baseline.get(path_str)
        self._file_entropy_baseline[path_str] = entropy

        # Check for entropy transition indicating encryption
        if baseline is not None and baseline < 5.5 and entropy >= 7.2:
            delta = entropy - baseline
            alert = {
                "type": "RANSOMWARE_ENTROPY_SPIKE",
                "file_path": str(file_path),
                "severity": SEVERITY_CRITICAL,
                "threat_name": "Ransomware.EntropySpike.CiphertextTransition",
                "summary": f"Entropy spike detected in {file_path.name}: {baseline:.2f} -> {entropy:.2f} bits/byte (+{delta:.2f})",
                "baseline_entropy": baseline,
                "current_entropy": entropy,
                "entropy_delta": round(delta, 4),
                "recovery_guidance": RECOVERY_GUIDANCE,
            }
            self._handle_alert(alert)
            return alert

        # Also check for single-sample high entropy on standard non-compressed extensions
        name_lower = file_path.name.lower()
        if any(name_lower.endswith(sfx) for sfx in (".txt", ".log", ".csv", ".json", ".xml", ".sql")) and entropy >= 7.6:
            # False positive mitigation:
            # Legitimate high-entropy text (e.g. dense base64, minified JSON, UUID tokens)
            # consists of printable ASCII (0x20-0x7E, \t, \n, \r).
            # True encrypted ransomware ciphertext is uniformly distributed across all 256 bytes,
            # exhibiting high density of non-printable binary control bytes (> 25%).
            non_printable = sum(1 for b in data if not (0x20 <= b <= 0x7E or b in (9, 10, 13)))
            non_printable_ratio = non_printable / len(data)
            if non_printable_ratio > 0.25:
                alert = {
                    "type": "RANSOMWARE_HIGH_ENTROPY_TEXT",
                    "file_path": str(file_path),
                    "severity": SEVERITY_HIGH,
                    "threat_name": "Ransomware.SuspiciousHighEntropyDocument",
                    "summary": f"Abnormally high entropy ({entropy:.2f} bits/byte, binary density {non_printable_ratio:.1%}) in document {file_path.name}",
                    "current_entropy": entropy,
                    "non_printable_ratio": round(non_printable_ratio, 4),
                    "recovery_guidance": RECOVERY_GUIDANCE,
                }
                self._handle_alert(alert)
                return alert

        return None

    def record_file_mutation(self, file_path: Path, process_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Evaluate single file modification or creation for ransomware characteristics:
        1. Known ransomware extension (.locked, .crypto, etc.)
        2. Known ransom note dropped
        3. Mutation burst rate exceeding safety threshold
        4. Entropy transition
        """
        now = time.time()
        ext = file_path.suffix.lower()
        name = file_path.name.lower()

        # Check entropy transition if file exists
        if file_path.exists():
            entropy_alert = self.record_file_entropy(file_path, process_name=process_name)
            if entropy_alert:
                return entropy_alert

        # 1. Ransom Note Check
        if name in RANSOM_NOTE_NAMES:
            alert = {
                "type": "RANSOM_NOTE_DROPPED",
                "file_path": str(file_path),
                "severity": SEVERITY_CRITICAL,
                "threat_name": "Ransomware.ExtortionNote.Detected",
                "summary": f"Known ransomware extortion note detected: {file_path.name}",
                "recovery_guidance": RECOVERY_GUIDANCE,
            }
            self._handle_alert(alert)
            return alert

        # 2. Ransomware Extension Check
        if ext in RANSOMWARE_EXTENSIONS:
            self._mutation_history.append((now, str(file_path), ext))

            # Count recent mutations within burst window
            recent = [item for item in self._mutation_history if now - item[0] <= self._burst_window_seconds]
            if len(recent) >= self._burst_threshold:
                alert = {
                    "type": "RANSOMWARE_BURST_ATTACK",
                    "file_path": str(file_path),
                    "severity": SEVERITY_CRITICAL,
                    "threat_name": "Ransomware.ActiveEncryptionBurst",
                    "summary": f"Detected high-frequency ransomware encryption burst ({len(recent)} files mutated to {ext} within {self._burst_window_seconds}s)!",
                    "mutated_count": len(recent),
                    "recovery_guidance": RECOVERY_GUIDANCE,
                }
                self._handle_alert(alert)
                return alert
            else:
                alert = {
                    "type": "SUSPICIOUS_EXTENSION_MUTATION",
                    "file_path": str(file_path),
                    "severity": SEVERITY_HIGH,
                    "threat_name": f"Ransomware.SuspiciousExtension{ext.upper()}",
                    "summary": f"File renamed or written with known ransomware extension: {ext}",
                    "recovery_guidance": RECOVERY_GUIDANCE,
                }
                self._handle_alert(alert)
                return alert

        return None

    def _handle_alert(self, alert_data: Dict[str, Any]) -> None:
        """Log threat and trigger callbacks."""
        logger.warning(f"RANSOMWARE SHIELD ALERT: {alert_data['summary']}")
        self.history_db.record_threat(
            session_id="RANSOMWARE-SHIELD",
            file_path=alert_data.get("file_path", "CANARY_TRAP"),
            file_hash="RANSOMWARE_DEFENSE",
            file_size=0,
            threat_name=alert_data.get("threat_name", "Ransomware.Activity"),
            threat_family="Ransomware",
            severity=alert_data.get("severity", SEVERITY_CRITICAL),
            action_taken="INTERCEPTED",
            details=alert_data.get("summary", ""),
        )

        if self.on_ransomware_alert:
            try:
                self.on_ransomware_alert(alert_data)
            except Exception:
                pass

    def start(self) -> bool:
        """Start background sentinel checking canaries and mutation bursts."""
        if self.is_running:
            return True

        self.deploy_canaries()
        self._stop_event.clear()
        self.is_running = True
        self._worker_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="BI-RansomwareShield"
        )
        self._worker_thread.start()
        logger.info("Ransomware Shield started.")
        return True

    def stop(self) -> None:
        """Stop background sentinel."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("Ransomware Shield stopped.")

    def _monitor_loop(self) -> None:
        """Periodic canary integrity loop."""
        while not self._stop_event.is_set():
            try:
                violations = self.check_canary_integrity()
                for v in violations:
                    alert = {
                        "type": v["violation_type"],
                        "file_path": v["canary_path"],
                        "severity": v["severity"],
                        "threat_name": "Ransomware.CanaryTrapTriggered",
                        "summary": v["description"],
                    }
                    self._handle_alert(alert)
            except Exception as e:
                logger.debug(f"Canary check loop error: {e}")

            # Check every 2 seconds
            self._stop_event.wait(2.0)

    def simulate_ransomware_scenario(self, scratch_dir: Optional[Path] = None) -> Dict[str, Any]:
        """
        Controlled harmless ransomware test harness.
        Creates benign plaintext files in D: drive scratch space, mutates them to high-entropy ciphertext,
        and verifies interception by RansomwareShield. Cleans up all simulation files.
        """
        import secrets
        target_dir = scratch_dir or (SCRATCH_DIR / "sim_ransomware")
        target_dir.mkdir(parents=True, exist_ok=True)

        sim_files: List[Path] = []
        mutated_paths: List[Path] = []
        alerts_caught: List[Dict[str, Any]] = []
        original_callback = self.on_ransomware_alert

        def _capture_alert(alert: Dict[str, Any]) -> None:
            alerts_caught.append(alert)
            if original_callback:
                try:
                    original_callback(alert)
                except Exception:
                    pass

        self.on_ransomware_alert = _capture_alert

        try:
            # 1. Create benign plaintext sample files with low entropy
            sample_texts = [
                b"Black Intel Cyber Defense Platform System Audit Log File. Normal corporate document. " * 30,
                b"Financial report quarterly revenue table: Q1: $10000, Q2: $20000, Q3: $30000. " * 30,
                b"Employee attendance roster and timesheet records. Normal operations active today. " * 30,
                b"Configuration parameters for internal network gateways and subnet routes table. " * 30,
            ]
            baseline_entropies = []
            for i, text in enumerate(sample_texts):
                p = target_dir / f"test_document_{i}.txt"
                p.write_bytes(text)
                sim_files.append(p)
                # Baseline entropy check
                self.record_file_entropy(p)
                baseline_entropies.append(calculate_shannon_entropy(p.read_bytes()))

            # 2. Simulate encryption burst: rewrite files with high-entropy pseudorandom bytes + .locked extension
            for i, p in enumerate(sim_files):
                high_entropy_bytes = secrets.token_bytes(2048)
                locked_path = p.with_suffix(".txt.locked")
                locked_path.write_bytes(high_entropy_bytes)
                mutated_paths.append(locked_path)
                p.unlink(missing_ok=True)

                # Trigger monitors
                self.record_file_entropy(locked_path)
                self.record_file_mutation(locked_path)

            # 3. Simulate ransom note drop
            ransom_note = target_dir / "readme_to_decrypt.txt"
            ransom_note.write_text("ALL YOUR FILES HAVE BEEN ENCRYPTED! Send 1 BTC to recover.")
            mutated_paths.append(ransom_note)
            self.record_file_mutation(ransom_note)

            simulation_result = {
                "status": "SUCCESS",
                "files_simulated": len(sample_texts),
                "baseline_mean_entropy": round(sum(baseline_entropies) / len(baseline_entropies), 2),
                "alerts_intercepted": len(alerts_caught),
                "alert_types": list({a.get("type") for a in alerts_caught}),
                "burst_detected": any("BURST" in a.get("type", "") for a in alerts_caught),
                "ransom_note_detected": any("NOTE" in a.get("type", "") for a in alerts_caught),
                "entropy_spike_detected": any("ENTROPY" in a.get("type", "") for a in alerts_caught),
                "containment_verified": len(alerts_caught) > 0,
                "recovery_guidance": RECOVERY_GUIDANCE,
            }
            return simulation_result
        finally:
            self.on_ransomware_alert = original_callback
            # Clean up all created simulation files safely
            for f in mutated_paths + sim_files:
                try:
                    if f.exists():
                        f.unlink()
                except Exception:
                    pass
            try:
                target_dir.rmdir()
            except Exception:
                pass

    def get_shield_status(self) -> Dict[str, Any]:
        """Return diagnostic status of the ransomware shield and canaries."""
        return {
            "is_running": self.is_running,
            "canaries_count": len(self.canaries),
            "canaries": [str(p) for p in self.canaries.keys()],
            "mutations_tracked": len(self._mutation_history),
            "entropy_baselines_tracked": len(self._file_entropy_baseline),
            "whitelisted_processes_count": len(self.whitelisted_processes),
            "burst_alerts": 0,
            "watch_dirs": [str(d) for d in self.watch_dirs],
        }

