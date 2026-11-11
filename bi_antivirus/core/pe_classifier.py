"""
BI Antivirus - Local PE Security Classifier
Provides safe, static PE (Portable Executable) feature extraction, structural analysis,
and explainable risk classification for Windows binaries (.exe, .dll, .sys) without execution.

Analyzes:
1. DOS & COFF File Headers (Machine, Sections count, Timestamp, Characteristics)
2. Optional Header & Exploit Mitigations (DEP, ASLR, High-Entropy ASLR, CFG)
3. Data Directories (Exports, Imports, Security/Authenticode, Debug, Relocations)
4. Section Table (Names, Virtual/Raw sizes, RWX anomalies, Shannon Entropy per section)
5. Import Address Table (Suspicious API categories: Injection, C2, Ransomware, Evasion)
6. Overlay Detection (Payload appending beyond raw section boundaries)
7. Explainable risk classification with weighted scores and diagnostic reasons.

Completely safe and non-invasive: Zero execution of inspected binaries.
Handles truncated, malformed, or non-PE files safely with bounds checking.
"""

import os
import math
import struct
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("BI_PEClassifier")

# Machine Architecture Constants
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01C0
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# Optional Header Magic
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B

# DllCharacteristics Exploit Mitigations
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040      # ASLR
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100          # DEP
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000           # Control Flow Guard
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

# Section Characteristics
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Known Packer / Crypter Section Names
KNOWN_PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", "aspack", "themida", "vmp0", "vmp1",
    "mpress", "petite", "nsp0", "nsp1", "pack", "fsg", ".packed",
    "pebundle", "yoda", "mew", "telock"
}

# Suspicious API Categories
SUSPICIOUS_API_CATEGORIES = {
    "PROCESS_INJECTION": {
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "writeprocessmemory", "createremotethread", "queueuserapc",
        "ntmapviewofsection", "ntunmapviewofsection", "zwunmapviewofsection",
        "setthreadcontext", "getthreadcontext"
    },
    "PROCESS_CREATION": {
        "createprocessa", "createprocessw", "winexec", "shellexecutea",
        "shellexecutew", "createprocessasusera", "createprocessasuserw"
    },
    "EVASION_DEFENSE": {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstringa", "outputdebugstringw", "adjusttokenprivileges",
        "openprocesstoken", "lookupPrivilegeValuea", "lookupprivilegevaluew"
    },
    "NETWORK_C2": {
        "internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
        "urldownloadtofilea", "urldownloadtofilew", "httpsendrequesta",
        "httpsendrequestw", "wsastartup", "connect", "gethostbyname"
    },
    "ENCRYPTION_RANSOM": {
        "cryptencrypt", "cryptacquirecontexta", "cryptacquirecontextw",
        "bcryptencrypt", "cryptgenkey", "cryptderivekey", "cryptimportkey"
    },
    "KEYLOGGING_HOOK": {
        "setwindowshookexa", "setwindowshookexw", "getasynckeystate",
        "getkeystate", "registerhotkey"
    }
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a block of bytes (returns 0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


class PEClassifier:
    """Static PE structural parser and explainable risk classifier."""

    def __init__(self, history_db: Optional[Any] = None):
        self.history_db = history_db

    def inspect_pe_file(self, file_path: Path) -> Dict[str, Any]:
        """Alias for analyze_file."""
        return self.analyze_file(file_path)

    def analyze_bytes(self, raw_bytes: bytes, file_name: str = "in_memory.exe", file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a PE binary directly from raw bytes in memory.
        Returns a rich structural dictionary with headers, mitigations, sections,
        imports, overlay, risk score, and explainable classification.
        """
        base_result = {
            "file_path": file_path or f"memory://{file_name}",
            "file_name": file_name,
            "file_size": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else "",
            "is_pe": False,
            "format": "NON_PE",
            "is_pe64": False,
            "machine": "UNKNOWN",
            "compile_time": 0,
            "subsystem": "UNKNOWN",
            "mitigations": {
                "dep": False,
                "aslr": False,
                "high_entropy_aslr": False,
                "cfg": False,
                "force_integrity": False,
            },
            "authenticode_present": False,
            "data_directories": {
                "SECURITY": {"present": False}
            },
            "sections": [],
            "sections_count": 0,
            "rwx_sections": [],
            "high_entropy_sections": [],
            "packer_sections": [],
            "has_packer_sections": False,
            "imports": {},
            "suspicious_apis": [],
            "suspicious_categories": [],
            "suspicious_apis_by_category": {},
            "exports_count": 0,
            "overlay": {
                "present": False,
                "size": 0,
                "entropy": 0.0,
            },
            "overall_entropy": calculate_entropy(raw_bytes),
            "risk_score": 0,
            "suspicion_score": 0,
            "confidence": 0.5,
            "classification": "NOT_A_PE",
            "verdict": "NOT_A_PE",
            "architecture": "UNKNOWN",
            "suspicious_imports_found": [],
            "has_authenticode": False,
            "has_overlay": False,
            "reasons": [],
            "error": None,
        }

        if len(raw_bytes) < 64:
            base_result["error"] = "Data too small to contain a valid DOS header."
            return base_result

        try:
            # 1. DOS Header Check
            if raw_bytes[:2] != b"MZ":
                base_result["error"] = "Invalid DOS header magic (missing 'MZ')."
                return base_result

            e_lfanew = struct.unpack_from("<I", raw_bytes, 0x3C)[0]
            if e_lfanew + 4 > len(raw_bytes):
                base_result["error"] = "Malformed PE: e_lfanew points beyond data size."
                return base_result

            # 2. PE Signature Check
            if raw_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                base_result["error"] = "Missing PE signature (b'PE\\0\\0')."
                return base_result

            base_result["is_pe"] = True
            base_result["format"] = "PE"

            # 3. COFF File Header (20 bytes)
            coff_offset = e_lfanew + 4
            if coff_offset + 20 > len(raw_bytes):
                base_result["error"] = "Malformed COFF header: truncated."
                return base_result

            machine, num_sections, timedate, _, _, size_opt_hdr, characteristics = struct.unpack_from(
                "<HHIIIHH", raw_bytes, coff_offset
            )
            # Hard limit: Windows PE loader supports at most 96 sections
            num_sections = min(num_sections, 96)
            base_result["compile_time"] = timedate
            base_result["sections_count"] = num_sections

            if machine == IMAGE_FILE_MACHINE_I386:
                base_result["machine"] = "x86 (32-bit)"
            elif machine == IMAGE_FILE_MACHINE_AMD64:
                base_result["machine"] = "x64 (64-bit)"
            elif machine == IMAGE_FILE_MACHINE_ARM64:
                base_result["machine"] = "ARM64"
            else:
                base_result["machine"] = f"Machine_0x{machine:04X}"

            # 4. Optional Header
            opt_offset = coff_offset + 20
            if size_opt_hdr > 0 and opt_offset + size_opt_hdr <= len(raw_bytes):
                opt_magic = struct.unpack_from("<H", raw_bytes, opt_offset)[0]
                is_pe64 = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                base_result["is_pe64"] = is_pe64
                base_result["format"] = "PE32+ (64-bit)" if is_pe64 else "PE32 (32-bit)"

                # Parse Subsystem and DllCharacteristics
                if size_opt_hdr >= 72:
                    subsystem, dll_chars = struct.unpack_from("<HH", raw_bytes, opt_offset + 68)
                    base_result["subsystem"] = "GUI" if subsystem == 2 else ("CLI" if subsystem == 3 else f"Subsystem_{subsystem}")
                    base_result["mitigations"]["dep"] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                    base_result["mitigations"]["aslr"] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                    base_result["mitigations"]["high_entropy_aslr"] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
                    base_result["mitigations"]["cfg"] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
                    base_result["mitigations"]["force_integrity"] = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)

                # Data Directories offset
                data_dirs_offset = opt_offset + (112 if is_pe64 else 96)
                num_rva_and_sizes = struct.unpack_from("<I", raw_bytes, opt_offset + (108 if is_pe64 else 92))[0] if size_opt_hdr >= (112 if is_pe64 else 96) else 0

                data_dirs = []
                for i in range(min(num_rva_and_sizes, 16)):
                    entry_off = data_dirs_offset + (i * 8)
                    if entry_off + 8 <= len(raw_bytes):
                        va, sz = struct.unpack_from("<II", raw_bytes, entry_off)
                        data_dirs.append((va, sz))
                    else:
                        break

                # Security / Certificate directory is index 4
                if len(data_dirs) > 4 and data_dirs[4][1] > 0:
                    base_result["authenticode_present"] = True
                    base_result["has_authenticode"] = True
                    base_result["data_directories"]["SECURITY"]["present"] = True

                export_dir_rva = data_dirs[0][0] if len(data_dirs) > 0 else 0
                import_dir_rva = data_dirs[1][0] if len(data_dirs) > 1 else 0
            else:
                export_dir_rva = 0
                import_dir_rva = 0

            # 5. Section Table
            sec_table_offset = opt_offset + size_opt_hdr
            sections = []
            max_raw_end = 0

            for sec_idx in range(num_sections):
                sec_off = sec_table_offset + (sec_idx * 40)
                if sec_off + 40 > len(raw_bytes):
                    break

                raw_name = raw_bytes[sec_off:sec_off + 8].split(b"\x00")[0]
                name_str = raw_name.decode("latin1", errors="replace").strip()
                vsize, vaddr, raw_size, raw_ptr, _, _, _, _, chars = struct.unpack_from(
                    "<IIIIIIHHI", raw_bytes, sec_off + 8
                )

                # Extract section raw data for entropy analysis
                sec_data = b""
                if raw_ptr > 0 and raw_size > 0 and raw_ptr < len(raw_bytes):
                    sec_end = min(raw_ptr + raw_size, len(raw_bytes))
                    sec_data = raw_bytes[raw_ptr:sec_end]
                    if sec_end > max_raw_end:
                        max_raw_end = sec_end

                sec_entropy = calculate_entropy(sec_data)
                is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
                is_write = bool(chars & IMAGE_SCN_MEM_WRITE)
                is_rwx = is_exec and is_write

                sec_info = {
                    "name": name_str,
                    "virtual_size": vsize,
                    "virtual_address": vaddr,
                    "raw_size": raw_size,
                    "raw_pointer": raw_ptr,
                    "entropy": sec_entropy,
                    "is_executable": is_exec,
                    "is_writable": is_write,
                    "is_rwx": is_rwx,
                }
                sections.append(sec_info)

                if is_rwx:
                    base_result["rwx_sections"].append(name_str)
                if sec_entropy >= 7.0 and raw_size >= 512:
                    base_result["high_entropy_sections"].append(f"{name_str} (H={sec_entropy})")
                name_clean = name_str.lower().strip(".").strip()
                if name_clean in KNOWN_PACKER_SECTIONS or name_str.lower().startswith((".upx", "upx", ".vmp", ".aspack")):
                    base_result["packer_sections"].append(name_str)

            base_result["sections"] = sections
            base_result["has_packer_sections"] = bool(base_result["packer_sections"])

            # Helper function for RVA to raw file offset translation
            def rva_to_offset(rva: int) -> Optional[int]:
                for s in sections:
                    v_start = s["virtual_address"]
                    v_span = max(s["virtual_size"], s["raw_size"])
                    if v_start <= rva < v_start + v_span:
                        delta = rva - v_start
                        if delta < s["raw_size"]:
                            off = s["raw_pointer"] + delta
                            if 0 <= off < len(raw_bytes):
                                return off
                return None

            # 6. Parse Imports
            if import_dir_rva > 0:
                imp_off = rva_to_offset(import_dir_rva)
                if imp_off and imp_off + 20 <= len(raw_bytes):
                    imports_dict, suspicious_apis, categories, cat_map = self._parse_imports(
                        raw_bytes, imp_off, rva_to_offset, base_result["is_pe64"]
                    )
                    base_result["imports"] = imports_dict
                    base_result["suspicious_apis"] = suspicious_apis
                    base_result["suspicious_categories"] = list(categories)
                    base_result["suspicious_apis_by_category"] = cat_map

            # 7. Check for Overlay
            if max_raw_end > 0 and len(raw_bytes) > max_raw_end + 512:
                overlay_data = raw_bytes[max_raw_end:]
                base_result["overlay"]["present"] = True
                base_result["overlay"]["size"] = len(overlay_data)
                base_result["overlay"]["entropy"] = calculate_entropy(overlay_data)
                base_result["has_overlay"] = True

            # 8. Compute Risk Score & Classification
            self._evaluate_pe_risk(base_result)

            # Persist record in database if configured and file_path provided
            if self.history_db and file_path and hasattr(self.history_db, "record_pe_analysis"):
                try:
                    self.history_db.record_pe_analysis(
                        file_path=base_result["file_path"],
                        file_hash=base_result["sha256"],
                        classification=base_result["classification"],
                        risk_score=base_result["risk_score"],
                        confidence=base_result["confidence"],
                        is_pe64=1 if base_result["is_pe64"] else 0,
                        sections_count=len(sections),
                        suspicious_imports_count=len(base_result["suspicious_apis"]),
                        findings=base_result["reasons"],
                    )
                except Exception as e:
                    logger.debug(f"Failed persisting PE analysis record: {e}")

            return base_result

        except Exception as ex:
            logger.error(f"Error analyzing PE data: {ex}", exc_info=True)
            base_result["error"] = f"Internal parsing error: {str(ex)}"
            base_result["classification"] = "SUSPICIOUS"
            base_result["risk_score"] = 50
            base_result["reasons"].append(f"Parsing exception encountered: {str(ex)}")
            return base_result

    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze a local file statically.
        Returns a rich structural dictionary with headers, mitigations, sections,
        imports, overlay, risk score, and explainable classification.
        """
        path_obj = Path(file_path)
        base_result = {
            "file_path": str(path_obj),
            "file_name": path_obj.name,
            "file_size": 0,
            "sha256": "",
            "is_pe": False,
            "format": "NON_PE",
            "is_pe64": False,
            "machine": "UNKNOWN",
            "compile_time": 0,
            "subsystem": "UNKNOWN",
            "mitigations": {
                "dep": False,
                "aslr": False,
                "high_entropy_aslr": False,
                "cfg": False,
                "force_integrity": False,
            },
            "authenticode_present": False,
            "sections": [],
            "sections_count": 0,
            "rwx_sections": [],
            "high_entropy_sections": [],
            "packer_sections": [],
            "has_packer_sections": False,
            "imports": {},
            "suspicious_apis": [],
            "suspicious_categories": [],
            "suspicious_apis_by_category": {},
            "exports_count": 0,
            "overlay": {
                "present": False,
                "size": 0,
                "entropy": 0.0,
            },
            "overall_entropy": 0.0,
            "risk_score": 0,
            "suspicion_score": 0,
            "confidence": 0.5,
            "classification": "NOT_A_PE",
            "verdict": "NOT_A_PE",
            "architecture": "UNKNOWN",
            "suspicious_imports_found": [],
            "has_authenticode": False,
            "has_overlay": False,
            "reasons": [],
            "error": None,
        }

        if not path_obj.exists() or not path_obj.is_file():
            base_result["error"] = "File does not exist or is not a regular file."
            return base_result

        # Protect against unbounded memory consumption on oversized files (> 150MB)
        try:
            st_size = path_obj.stat().st_size
            if st_size > 150 * 1024 * 1024:
                base_result["error"] = f"File exceeds maximum analysis size (150MB): {st_size} bytes."
                base_result["verdict"] = "SKIPPED_OVERSIZED"
                base_result["classification"] = "SKIPPED_OVERSIZED"
                return base_result
            raw_bytes = path_obj.read_bytes()
            return self.analyze_bytes(raw_bytes, file_name=path_obj.name, file_path=str(path_obj))
        except Exception as e:
            base_result["error"] = f"Failed inspecting file: {e}"
            return base_result

    def _parse_imports(
        self,
        raw_bytes: bytes,
        import_desc_offset: int,
        rva_to_offset: Any,
        is_pe64: bool,
    ) -> Tuple[Dict[str, List[str]], List[str], set, Dict[str, List[str]]]:
        """Parse Import Directory Table descriptors and extract imported functions."""
        imports = {}
        suspicious_apis = []
        categories = set()
        cat_map: Dict[str, List[str]] = {cat: [] for cat in SUSPICIOUS_API_CATEGORIES}
        curr_desc = import_desc_offset

        # Bounded loop: inspect up to 50 imported DLL descriptors
        for _ in range(50):
            if curr_desc + 20 > len(raw_bytes):
                break

            orig_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", raw_bytes, curr_desc)
            if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break  # Null terminator descriptor

            curr_desc += 20

            # Read DLL name
            name_off = rva_to_offset(name_rva)
            if not name_off or name_off >= len(raw_bytes):
                continue

            dll_name_raw = raw_bytes[name_off:name_off + 128].split(b"\x00")[0]
            dll_name = dll_name_raw.decode("latin1", errors="replace").strip()
            if not dll_name:
                continue

            # Read thunk table (OriginalFirstThunk or fallback to FirstThunk)
            thunk_rva = orig_thunk if orig_thunk != 0 else first_thunk
            thunk_off = rva_to_offset(thunk_rva)
            if not thunk_off:
                continue

            func_names = []
            entry_size = 8 if is_pe64 else 4
            ordinal_mask = 0x8000000000000000 if is_pe64 else 0x80000000

            # Bounded loop: up to 100 functions per DLL
            for f_idx in range(100):
                thunk_entry_off = thunk_off + (f_idx * entry_size)
                if thunk_entry_off + entry_size > len(raw_bytes):
                    break

                entry_val = struct.unpack_from("<Q" if is_pe64 else "<I", raw_bytes, thunk_entry_off)[0]
                if entry_val == 0:
                    break

                if entry_val & ordinal_mask:
                    # Imported by ordinal
                    func_names.append(f"Ordinal_{entry_val & 0xFFFF}")
                else:
                    # Imported by name: RVA points to Hint (2 bytes) + ASCII name
                    name_entry_off = rva_to_offset(entry_val)
                    if name_entry_off and name_entry_off + 2 < len(raw_bytes):
                        fn_raw = raw_bytes[name_entry_off + 2:name_entry_off + 96].split(b"\x00")[0]
                        fn_name = fn_raw.decode("latin1", errors="replace").strip()
                        if fn_name:
                            func_names.append(fn_name)
                            # Check suspicious categories
                            fn_lower = fn_name.lower()
                            for cat, api_set in SUSPICIOUS_API_CATEGORIES.items():
                                if fn_lower in api_set:
                                    suspicious_apis.append(f"{fn_name} ({cat})")
                                    categories.add(cat)
                                    cat_map[cat].append(fn_name)

            imports[dll_name] = func_names

        return imports, suspicious_apis, categories, cat_map

    def _evaluate_pe_risk(self, result: Dict[str, Any]) -> None:
        """Evaluate explainable risk score and assign classification."""
        score = 0
        reasons = []

        # 1. Section RWX check (Critical indicator)
        if result["rwx_sections"]:
            score += 35
            reasons.append(f"CRITICAL ANOMALY: Detected {len(result['rwx_sections'])} RWX (Read-Write-Execute) section(s): {', '.join(result['rwx_sections'])}.")

        # 2. Known packer sections
        if result["packer_sections"]:
            score += 25
            reasons.append(f"PACKER SIGNATURE: Identified known runtime packer / crypter section(s): {', '.join(result['packer_sections'])}.")

        # 3. High entropy sections (Packing or encrypted payload)
        if result["high_entropy_sections"]:
            score += 20
            reasons.append(f"HIGH ENTROPY: {len(result['high_entropy_sections'])} section(s) exhibit compressed/encrypted characteristics ($H \\ge 7.0$): {', '.join(result['high_entropy_sections'])}.")

        # 4. Suspicious Import APIs
        num_susp = len(result["suspicious_apis"])
        cats = result["suspicious_categories"]
        if "PROCESS_INJECTION" in cats:
            score += 20
            reasons.append("SUSPICIOUS IMPORTS: Contains process memory injection / remote thread APIs (VirtualAlloc/WriteProcessMemory/CreateRemoteThread).")
        if "ENCRYPTION_RANSOM" in cats:
            score += 15
            reasons.append("SUSPICIOUS IMPORTS: Imports cryptographic encryption primitives (CryptEncrypt/BCryptEncrypt).")
        if "NETWORK_C2" in cats and ("PROCESS_INJECTION" in cats or "PROCESS_CREATION" in cats):
            score += 15
            reasons.append("SUSPICIOUS COMBINATION: Concurrently imports network connectivity and process creation/injection primitives.")
        elif num_susp > 0 and score < 20:
            score += min(num_susp * 5, 15)

        # 5. Exploit Mitigations
        if not result["mitigations"]["dep"]:
            score += 10
            reasons.append("MITIGATION WEAKNESS: DEP (Data Execution Prevention / NX) is not enabled in PE OptionalHeader.")
        if not result["mitigations"]["aslr"]:
            score += 10
            reasons.append("MITIGATION WEAKNESS: ASLR (DynamicBase) is not enabled in PE OptionalHeader.")

        # 6. Overlay Anomaly
        overlay = result["overlay"]
        if overlay["present"]:
            if overlay["size"] > 100 * 1024 and overlay["entropy"] > 7.2:
                score += 15
                reasons.append(f"SUSPICIOUS OVERLAY: Detected high-entropy payload appended beyond raw sections ({overlay['size']} bytes, $H = {overlay['entropy']}$).")
            else:
                score += 5
                reasons.append(f"OVERLAY DETECTED: Appended data beyond section table ({overlay['size']} bytes).")

        # Cap score between 0 and 100
        score = min(max(score, 0), 100)
        result["risk_score"] = score

        # Compute Confidence
        conf = 0.60
        if result["sections_count"] > 0:
            conf += 0.15
        if result["imports"]:
            conf += 0.15
        if result["file_size"] > 4096:
            conf += 0.05
        result["confidence"] = round(min(conf, 0.95), 2)

        # Classification label
        if score >= 70:
            result["classification"] = "MALICIOUS_SUSPECT"
        elif score >= 40:
            result["classification"] = "SUSPICIOUS"
        elif result["authenticode_present"] and score < 20:
            result["classification"] = "BENIGN_VERIFIED"
        else:
            result["classification"] = "BENIGN_PROBABLE"

        # Aliases for unified interface
        result["verdict"] = result["classification"]
        result["suspicion_score"] = result["risk_score"]
        result["architecture"] = "PE32+" if result.get("is_pe64") else "PE32"
        result["suspicious_imports_found"] = result.get("suspicious_apis", [])
        result["has_authenticode"] = result.get("authenticode_present", False)
        result["has_overlay"] = result.get("overlay", {}).get("present", False)

        mits = result.get("mitigations", {})
        mits["dep_nx_enabled"] = mits.get("dep", False)
        mits["aslr_enabled"] = mits.get("aslr", False)
        mits["cfg_enabled"] = mits.get("cfg", False)

        if not reasons:
            reasons.append("Standard PE structure. Valid section table, normal entropy, nominal exploit mitigations enabled.")

        result["reasons"] = reasons
