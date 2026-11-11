# BI ANTIVIRUS — TECHNICAL SPECIFICATION
## DEFENSIVE PROCESS MEMORY AUDITING & EXPLOIT MITIGATION SHIELD

**Module:** `bi_antivirus.monitors.exploit_shield`  
**Platform:** Windows 10 / 11 (64-bit user-mode)  
**Security Classification:** Defensive / Non-Invasive Endpoint Posture Assessment  
**Author:** BI Antivirus Development Team  

---

## 1. OBJECTIVE & SCOPE

The Memory Security Auditor (`MemoryExploitShield`) provides continuous, read-only defensive posture auditing of running Windows processes. It detects exploit-friendly process configurations and anomalous executable memory pages commonly leveraged by memory-corruption exploits, shellcode injection, reflective DLL loading, and process hollowing.

### Core Defensive Principles
1. **Zero Memory Modification:** The shield never calls `WriteProcessMemory`, `VirtualProtectEx`, or `VirtualAllocEx`. It performs purely observational telemetry.
2. **Zero Code Injection:** The shield never loads external DLLs or injects remote threads (`CreateRemoteThread`) into monitored processes.
3. **Zero Critical Process Termination:** Operating system critical binaries (`csrss.exe`, `smss.exe`, `services.exe`) are handled gracefully via access-denied safeguards and never forcibly terminated.
4. **Controlled Resource Utilization:** Memory map sweeps are bounded to a maximum of 500 committed regions per process and restricted to user-space boundaries (`0x7FFFFFFEFFFF`), preventing CPU or memory bottlenecks.

---

## 2. WIN32 PROCESS MITIGATION POLICIES

Windows provides hardware-enforced and software-enforced exploit mitigations managed by the OS kernel. The shield inspects these policies using the native Win32 API:

```c
BOOL GetProcessMitigationPolicy(
  HANDLE                    hProcess,
  PROCESS_MITIGATION_POLICY MitigationPolicy,
  PVOID                     lpBuffer,
  SIZE_T                    dwLength
);
```

### 2.1 Data Execution Prevention (DEP) — Policy `0`
- **Mechanism:** Enforces the CPU `NX` (No-Execute) / `XD` (Execute-Disable) bit on data pages (stack, heap, default data segments).
- **Structure Inspected:**
  ```python
  class DEP_POLICY(Structure):
      _fields_ = [("Flags", c_ulong), ("Permanent", c_ulong)]
  ```
- **Evaluation Criteria:**
  - `Flags & 0x1`: DEP is enabled for the process.
  - `Permanent == 1`: DEP cannot be disabled at runtime via `SetProcessDEPPolicy` (prevents in-process exploit downgrades).
  - **Defensive Alert:** If DEP is disabled, risk score increases by **+35 points**.

### 2.2 Address Space Layout Randomization (ASLR) — Policy `1`
- **Mechanism:** Randomizes the base addresses of executables, loaded modules, stacks, and heaps to prevent predictable return-oriented programming (ROP) gadget chains.
- **Structure Inspected:**
  ```python
  class ASLR_POLICY(Structure):
      _fields_ = [("Flags", c_ulong)]
  ```
- **Evaluation Criteria:**
  - `Flags & 0x1`: Bottom-up address space randomization enabled.
  - `(Flags >> 1) & 0x1`: Force relocate images enabled (forces ASLR on non-ASLR compiled DLLs).
  - `(Flags >> 2) & 0x1`: High-entropy 64-bit ASLR enabled (increases entropy from 8-16 bits to 24 bits).
  - **Defensive Alert:** If ASLR is completely disabled, risk score increases by **+30 points**; standard entropy without high-entropy increases risk by **+5 points**.

### 2.3 Control Flow Guard (CFG) — Policy `7`
- **Mechanism:** Compiler-driven and OS-enforced forward-edge control-flow integrity. Validates indirect call targets against a bitmap of compiler-approved function entries before dispatch, mitigating ROP/JOP attacks.
- **Structure Inspected:**
  ```python
  class CFG_POLICY(Structure):
      _fields_ = [("Flags", c_ulong)]
  ```
- **Evaluation Criteria:**
  - `Flags & 0x1`: Control Flow Guard enabled.
  - `(Flags >> 2) & 0x1`: Strict mode enabled (enforces dispatch checks on all indirect branches).

### 2.4 Dynamic Code Policy — Policy `2`
- **Mechanism:** Prohibits generation and modification of dynamic executable code in the process. Prevents `VirtualAlloc` or `VirtualProtect` with executable permissions.
- **Evaluation Criteria:**
  - `Flags & 0x1`: Prohibit dynamic code active. Useful for high-risk applications (e.g., browsers, office utilities) to prevent payload staging.

### 2.5 Binary Signature Policy — Policy `8`
- **Mechanism:** Restricts DLL loading to binaries signed exclusively by Microsoft or the Windows Store, preventing sideloading and DLL hijacking.

---

## 3. NON-INVASIVE MEMORY MAP AUDITING (`VirtualQueryEx`)

Attackers executing memory-corruption exploits (such as buffer overflows or use-after-free) frequently allocate or alter memory protections to execute injected shellcode. The shield sweeps committed user-space memory pages using `VirtualQueryEx`:

```python
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", c_ulong),
        ("__alignment1", c_ulong),
        ("RegionSize", c_size_t),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
        ("__alignment2", c_ulong),
    ]
```

### 3.1 RWX (Read-Write-Execute) Detection
- **Protection Constant:** `PAGE_EXECUTE_READWRITE = 0x40`
- **Anomaly Rationale:** Legitimate compiled native code is marked `PAGE_EXECUTE_READ` (`RX`). Writable code pages violate the W^X (Write XOR Execute) security paradigm. Attackers allocate RWX pages (`VirtualAlloc(..., PAGE_EXECUTE_READWRITE)`) to write shellcode and execute it directly without triggering additional API calls.
- **Scoring:** In non-JIT native binaries, each detected RWX region adds **+20 points** (up to +45 points max).

### 3.2 Unbacked Executable Memory Detection
- **Memory Type:** `MEM_PRIVATE = 0x20000` (vs `MEM_IMAGE = 0x1000000`)
- **Protection:** `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, or `PAGE_EXECUTE_READWRITE`
- **Anomaly Rationale:** Legitimate code execution typically originates from a file-backed executable image (`MEM_IMAGE`) mapped to disk. Executable private memory (`MEM_PRIVATE`) indicates code running in memory that has no corresponding file on disk — a signature hallmark of **Reflective DLL Injection**, **Process Hollowing**, or raw shellcode execution.
- **Scoring:** Adds **+15 points** per region (up to +35 points max).

### 3.3 Benign JIT Runtime Profiling
Certain runtime environments legitimately compile and execute code dynamically in private memory (Just-In-Time compilation):
- `node.exe` (V8 Engine)
- `python.exe` (Dynamic bytecode & C extensions)
- `java.exe` / `javaw.exe` (HotSpot JIT)
- `chrome.exe` / `msedge.exe` / `firefox.exe` (JavaScript Engines)

When evaluating a recognized JIT binary (`KNOWN_JIT_PROCESS_NAMES`), the shield discounts RWX and unbacked executable page weights to prevent false-positive alert fatigue while still reporting their presence in audit logs.

---

## 4. SAFE PROCESS ACCESS & OS PROTECTION HANDLING

In enterprise environments, system processes operate under Protected Process Light (PPL) or require `SeDebugPrivilege`. Attempting to open handles to these processes with high access masks fails with `ERROR_ACCESS_DENIED (5)`.

The shield implements a two-stage fallback:
1. First requests `PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION`.
2. If failed, falls back to `PROCESS_QUERY_LIMITED_INFORMATION`.
3. If both fail (or PID is $\le$ 4), the process is classified as `PROTECTED_SYSTEM_PROCESS` or `ACCESS_DENIED`.
4. No unhandled exceptions are raised; the audit log gracefully records the protection status without degrading monitoring uptime.

---

## 5. PERSISTENCE & SOC INTEGRATION

All memory audit findings are recorded in `HistoryDatabase`:
- Method: `record_memory_audit(...)`
- Query APIs: `get_recent_memory_audits()`, `get_high_risk_memory_audits(min_risk_score=40)`
- High-risk audits automatically emit an EDR alert event (`MEMORY_EXPLOIT_ALERT`), feeding directly into the EDR Incident Graph and correlating with corresponding process spawn and network socket telemetry.
