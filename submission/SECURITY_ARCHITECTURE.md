# BI Antivirus Enterprise — Security Architecture Specification

**Product Name:** BI Antivirus Enterprise  
**Architecture Posture:** Sovereign Windows User-Space Defense-in-Depth  
**Storage Confinement:** 100% Confined to `D:\bit defender` (Zero writes to `C:\`)  
**Cryptography Standards:** AES-256-CBC / CNG, HMAC-SHA256, DPAPI, PBKDF2  

---

## 1. Threat Model & Security Boundaries

BI Antivirus Enterprise is engineered to deliver high-assurance endpoint security in Windows user space, providing real-time visibility, heuristic defense, and autonomous local response without relying on unverified external cloud connections or unsigned kernel drivers.

```
+-------------------------------------------------------------------------------+
|                        Windows User Desktop Session                           |
|  +------------------------------+           +------------------------------+  |
|  |   BI Antivirus GUI (Tkinter) |           |   BI Antivirus CLI Console   |  |
|  +--------------+---------------+           +--------------+---------------+  |
|                 |                                          |                  |
|  +--------------v------------------------------------------v---------------+  |
|  |                        AntivirusEngine Core                             |  |
|  |   - Multi-Layer Detector          - Threat Event Dispatcher             |  |
|  |   - Authenticode Verifier         - System Vulnerability Auditor        |  |
|  |   - Shannon Entropy Heuristics    - Software Inventory & CVE Auditor    |  |
|  +--------------+------------------------------------------+---------------+  |
|                 |                                          |                  |
|  +--------------v---------------+           +--------------v---------------+  |
|  |   Encrypted Quarantine Vault |           |   Loopback EDR REST API      |  |
|  |   AES-256-CBC + HMAC-SHA256  |           |   127.0.0.1:8765 (Auth Token)|  |
|  |   Windows DPAPI Key Store    |           |   Constant-time Auth Header  |  |
|  +------------------------------+           +--------------+---------------+  |
|                                                            |                  |
|  +---------------------------------------------------------v---------------+  |
|  |                        XDR Incident Graph Engine                        |  |
|  |   Nodes: Process, File, Network, Device, Memory, Identity, Cloud        |  |
|  |   Edges: SPAWNED, DROPPED, ACCESSED, AUTHENTICATED_AS, TRANSMITTED_TO   |  |
|  |   MITRE ATT&CK Mapping: T1059, T1055, T1110, T1567, T1486, T1078       |  |
|  +-------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Architecture

### 2.1 Authenticated Encryption (Encrypt-then-MAC)
Quarantined files are secured under the Encrypt-then-MAC (EtM) paradigm:
1. **IV Generation:** Cryptographically random 16-byte initialization vector via `secrets.token_bytes(16)`.
2. **AES-256 Encryption:** Plaintext bytes encrypted using AES-256-CBC via native Windows CNG (`bcrypt.dll`) with PKCS#7 padding.
3. **Authentication Tag:** An HMAC-SHA256 tag is computed over the authenticated header and ciphertext:
   $$\text{Tag} = \text{HMAC-SHA256}_{K_{\text{mac}}}(\text{Header} \parallel \text{IV} \parallel \text{Ciphertext})$$
4. **Decryption Verification:** Tags are validated using constant-time comparison (`hmac.compare_digest`) prior to any decryption.

### 2.2 Key Derivation & DPAPI Key Store
- Master key generated with 256 bits of cryptographically secure pseudo-random entropy.
- Derived sub-keys:
  - $K_{\text{enc}} = \text{HMAC-SHA256}(\text{MasterKey}, \text{b"BI_QUARANTINE_AES_KEY_v2"})$
  - $K_{\text{mac}} = \text{HMAC-SHA256}(\text{MasterKey}, \text{b"BI_QUARANTINE_HMAC_KEY_v2"})$
- Master key is persisted wrapped via Windows Data Protection API (`CryptProtectData`) using `CRYPTPROTECT_LOCAL_MACHINE` and custom entropy.

---

## 3. Defense-in-Depth Measures
- **NTFS ACL Hardening:** File permissions on `vault_master.dpapi` and authentication tokens are restricted to SYSTEM (`S-1-5-18`), Administrators (`S-1-5-32-544`), and the current logged-in user.
- **Strict IPv4 Loopback Binding:** Local REST APIs and webhooks reject all non-loopback connections (`!= 127.0.0.1`) with HTTP `403 Forbidden`.
- **Side-Channel Immunity:** All token, hash, and signature comparisons employ constant-time algorithms to eliminate timing attacks.
- **Fail-Safe Rollback:** Firewall modifications and quarantine operations employ pre-execution state caching and atomic temp-file swaps with automatic rollbacks on error.
