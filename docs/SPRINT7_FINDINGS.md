# BI ANTIVIRUS — SPRINT 7 SECURITY AUDIT FINDINGS CATALOG
**Project:** BI Antivirus  
**Audit Scope:** Sprints 1–6 Baseline Architecture & Implementation  
**Classification:** Defensive Security Assessment  
**Date:** November 11, 2026  

---

## 1. Findings Summary Table

| Finding ID | Severity | Category | Title | Affected Component | Status |
| :---: | :---: | :---: | :--- | :--- | :---: |
| **SEC-01** | **HIGH** | Cryptography | Static Salt in PBKDF2 Password Hashing | `bi_antivirus/enterprise/rbac_manager.py` | **RESOLVED** |
| **SEC-02** | **HIGH** | Authorization | Missing Session Invalidation on User Deactivation / Password Change | `bi_antivirus/enterprise/rbac_manager.py` | **RESOLVED** |
| **SEC-03** | **MEDIUM** | Input Validation | Quarantine File Restoration Path Traversal Potential | `bi_antivirus/core/quarantine.py` | **RESOLVED** |
| **SEC-04** | **MEDIUM** | Authorization | Revoked Session Token Fallthrough in `authorize_action` | `bi_antivirus/enterprise/rbac_manager.py` | **RESOLVED** |
| **SEC-05** | **LOW** | Enrollment | Potential Unlimited Re-Enrollment Window for Compromised Tokens | `bi_antivirus/enterprise/enrollment_manager.py` | **HARDENED** |
| **SEC-06** | **INFORMATIONAL**| Windows Security| Admin Privilege Rejection Graceful Notice | `bi_antivirus/monitors/firewall_monitor.py` | **VERIFIED** |

---

## 2. Detailed Vulnerability & Architecture Findings

### SEC-01: Static Salt in PBKDF2 Password Hashing
- **Severity:** HIGH
- **CWE:** CWE-760 (Use of a One-Way Hash with a Predictable Salt)
- **Description:** Previously, `RBACManager._hash_password()` applied a hardcoded static salt `b"BI_SALT_ENTERPRISE_2026"`. Consequently, identical passwords across different administrative accounts resulted in identical hashes, making them vulnerable to precomputed lookup attacks.
- **Exploit Scenario:** An adversary accessing a serialized credential backup could match precomputed tables against hashes across all default accounts.
- **Remediation:** Generated per-user 128-bit cryptographically secure random salts via `secrets.token_hex(16)`. Stored unique salts alongside user records, while preserving backward compatibility for legacy hashes.

### SEC-02: Missing Session Invalidation on User Deactivation / Password Change
- **Severity:** HIGH
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **Description:** Session tokens had an 8-hour expiration but were not revoked when a user was deactivated (`is_active = False`) or had their password changed. A compromised session remained authorized until the full 8-hour window lapsed.
- **Exploit Scenario:** An employee or operator terminated or demoted by an administrator could continue executing commands using an active session token issued prior to deactivation.
- **Remediation:** Implemented `revoke_session(session_id)`, `revoke_user_sessions(username)`, and integrated `is_active` validation into `validate_session()`. Deactivating a user immediately purges all active session tokens.

### SEC-03: Quarantine File Restoration Path Traversal Potential
- **Severity:** MEDIUM
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory - Path Traversal)
- **Description:** The `restore_file()` method accepted an optional `custom_target_path` without checking for parent directory traversal sequences (`..`).
- **Exploit Scenario:** A rogue script calling the restore API with a crafted path (e.g. `../../Windows/System32/evil.dll`) could attempt to place restored binaries into arbitrary directories.
- **Remediation:** Enforced path inspection rejecting any destination path containing `..` in its path components (`".." in target_path.parts`).

### SEC-04: Revoked Session Token Fallthrough in `authorize_action`
- **Severity:** MEDIUM
- **CWE:** CWE-285 (Improper Authorization)
- **Description:** In `authorize_action(role_or_session, permission)`, if the argument was not found in `self._sessions` (because it was revoked), the code fell back to treating the string as a role name (`role = role_or_session`).
- **Exploit Scenario:** If an invalid or revoked token happened to match a role name or caused misinterpretation, unexpected authorization state could occur.
- **Remediation:** Explicitly check for session token prefix (`BI-SESS-`), ensuring any token that is invalid or expired immediately produces an explicit rejection.
