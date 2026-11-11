# BI Antivirus — Sprint 4 Security Findings & Threat Model

**Date:** November 11, 2026  
**Document:** Enterprise Threat Model & Production Security Evaluation  
**Subsystems Covered:** Enterprise Fleet, Policy Distribution, Quarantine Restoration, Update Pipelines, Heuristics  

---

## 1. Threat Model Overview

The transition to a distributed, local-first enterprise endpoint management platform introduces new threat surfaces:
1. **Rogue Endpoint Enrollment**: Unauthorized nodes attempting to register or forge telemetry.
2. **Policy Rollback / Downgrade Attacks**: Adversaries attempting to re-apply older, less restrictive security policies.
3. **Administrator Token Compromise / Replay**: Unauthorized modification of fleet policies or host isolation states.
4. **Denial-of-Service via Malformed Binaries**: Resource exhaustion through oversized files or crafted PE headers.
5. **False Positives on High-Entropy Documents**: Disruption of business operations through accidental blocking of valid documents.
6. **Quarantine Vault Tampering / Overwrite Hijacking**: Unauthorized modification of vaulted payloads or overwriting critical files during restore.

---

## 2. Security Analysis & Implemented Countermeasures

### 2.1 Rogue Endpoint Enrollment
- **Threat**: An adversary on the local subnet attempts to spoof an agent and flood the controller with bogus telemetry or receive confidential enterprise policy rules.
- **Countermeasure**:
  - Enrollment requires an HMAC-SHA256 derived master enrollment secret (`master_enrollment_key`).
  - Constant-time verification via `hmac.compare_digest` prevents timing attacks.
  - The database stores only a truncated SHA-256 fingerprint of the enrollment token, never the plaintext secret.

### 2.2 Policy Rollback & Downgrade Attacks
- **Threat**: An attacker who obtains an earlier valid policy file (e.g. from an unencrypted backup or cached file) attempts to re-apply it to re-enable disabled USB ports or relax firewall rules.
- **Countermeasure**:
  - Every policy enforces a strictly monotonic integer sequence number (`version`).
  - `FleetManager.create_or_update_policy()` evaluates:
    $$\text{Permitted} \iff \text{version}_{\text{new}} > \text{version}_{\text{current}}$$
  - Rollback attempts with $\le$ active version numbers are rejected immediately with security warning logs and immutable admin audit entries.

### 2.3 Administrator Authorization & Audit Integrity
- **Threat**: Malicious insider or local malware attempts to manipulate endpoint isolation or alter policies without credentials.
- **Countermeasure**:
  - All mutating administrative actions (`create_or_update_policy`, `assign_policy_to_endpoints`, `isolate_endpoint`, `unisolate_endpoint`) require a valid bearer authorization token (`admin_token`).
  - Every authorized action appends a record to the `fleet_audit_log` table containing `audit_id`, `admin_id`, `action`, `target_type`, `target_id`, `timestamp`, `details` (JSON), and the SHA-256 hash of the token used.
  - Audit logs are append-only.

### 2.4 Denial-of-Service & Parser Vulnerability
- **Threat**: Crafting PE files with massive headers, thousands of sections, or RVAs pointing outside file boundaries to trigger memory exhaustion or unhandled exceptions.
- **Countermeasure**:
  - Added a pre-read stat check refusing to process files larger than 150 MB into RAM (`SKIPPED_OVERSIZED`).
  - Section counts are clamped: `num_sections = min(num_sections, 96)` matching the Windows PE loader architectural limit.
  - `rva_to_offset()` bounds-checks mapped offsets against `len(raw_bytes)` before returning file offsets, preventing index errors.

### 2.5 False Positives on High-Entropy Documents
- **Threat**: Legitimate text files (minified JSON, base64 tokens, UUID logs) have high Shannon entropy ($H \ge 7.6$), risking false ransomware detection and disruption.
- **Countermeasure**:
  - `record_file_entropy()` was updated with a binary control byte density filter:
    $$\text{Non-Printable Ratio} = \frac{\sum [b \notin \{0x20..0x7E, \text{\\t, \\n, \\r}\}]}{\text{len}(data)}$$
  - Text files (`.txt`, `.log`, `.csv`, `.json`, `.xml`, `.sql`) are only flagged if entropy $\ge 7.6$ **and** non-printable binary byte density $> 25\%$.
  - Evaluation against our synthetic corpus confirmed **0.0% false-positive rate**.

### 2.6 Quarantine Restore Safety & Vault Integrity
- **Threat**: Restoring a quarantined file could inadvertently overwrite a newly created legitimate file, or a corrupted/tampered vault payload could be written to disk.
- **Countermeasure**:
  - `restore_file()` verifies destination existence: if the target file already exists and `overwrite=False`, restoration is aborted.
  - Verifies the cryptographic MAC of the vault file before decryption.
  - Computes the SHA-256 hash of restored bytes and validates against the original recorded file hash before replacing the target file atomically.
  - If MAC or SHA-256 verification fails, temporary files are removed and the vault payload is preserved.

### 2.7 Key Rotation & Cryptographic Transition
- **Threat**: A signing key compromise requires immediate retirement, but abruptly revoking the key invalidates previously deployed legitimate update bundles.
- **Countermeasure**:
  - `PolicyKeyManager` and `ThreatIntelEngine` implement `rotate_signing_key()`, which archives the retired key to `.prev` and generates a fresh 256-bit active key.
  - `verify_and_apply_bundle()` verifies incoming HMAC signatures against the active key first. If verification fails, it checks against `get_previous_signing_key()` for backward compatibility before rejecting.
  - Non-reentrant lock deadlocks were eliminated by implementing reentrant `threading.RLock()`.
