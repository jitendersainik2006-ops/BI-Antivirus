# BI Antivirus — Security Architecture Specification

## 1. Threat Model & Boundaries
BI Antivirus is designed to operate within a user-mode defense posture on Windows 10 and 11.

```
+-------------------------------------------------------------+
|                 Windows User Desktop Session                |
|  +-------------------------+     +-----------------------+  |
|  |  BI Antivirus GUI       |     |  BI Antivirus CLI     |  |
|  +------------+------------+     +-----------+-----------+  |
|               |                              |              |
|  +------------v------------------------------v-----------+  |
|  |               AntivirusEngine Core                    |  |
|  |   - Multi-Layer Detector   - Threat Event Dispatcher  |  |
|  |   - Authenticode Verifier  - Windows Baseline Auditor |  |
|  +------------+------------------------------+-----------+  |
|               |                              |              |
|  +------------v------------+     +-----------v-----------+  |
|  | Authenticated Vault     |     | Loopback REST API     |  |
|  | AES-256-CBC + HMAC-SHA256|     | 127.0.0.1:8765        |  |
|  | Windows DPAPI Key Mgmt  |     | Constant-time Auth    |  |
|  +-------------------------+     +-----------+-----------+  |
|                                              |              |
|                                  +-----------v-----------+  |
|                                  | n8n Community v2.46.5 |  |
|                                  | Inactive Workflow     |  |
|                                  +-----------------------+  |
+-------------------------------------------------------------+
```

---

## 2. Cryptographic Architecture

### 2.1 Authenticated Encryption (Encrypt-then-MAC)
Quarantined files are protected using the Encrypt-then-MAC (EtM) paradigm:
1. Generate a cryptographically random 16-byte IV via `secrets.token_bytes(16)`.
2. Encrypt file plaintext using AES-256 in CBC mode with PKCS#7 block padding.
3. Compute an HMAC-SHA256 tag over the concatenated authenticated header:
   $$\text{Tag} = \text{HMAC-SHA256}_{K_{\text{mac}}}(\text{Header} \parallel \text{IV} \parallel \text{Ciphertext})$$
4. Verify the MAC tag using constant-time comparison (`hmac.compare_digest`) before attempting decryption.

### 2.2 Key Derivation & DPAPI Wrapping
- A 256-bit random Master Key is generated at first run.
- Derived keys:
  - $K_{\text{enc}} = \text{SHA256}(\text{MasterKey} \parallel \text{b"AES256_ENC_KEY_V2"})$
  - $K_{\text{mac}} = \text{SHA256}(\text{MasterKey} \parallel \text{b"HMAC_SHA256_AUTH_KEY_V2"})$
- The Master Key is stored wrapped in Windows DPAPI (`crypt32.CryptProtectData`) using `CRYPTPROTECT_LOCAL_MACHINE` and custom entropy.

---

## 3. Defense-in-Depth Measures
- **NTFS Access Control Lists (ACLs):** File permissions on `vault_master.dpapi` and `api_key.txt` are restricted to SYSTEM (`S-1-5-18`), Administrators (`S-1-5-32-544`), and the current logged-in user.
- **Loopback Enforcement:** API and bridge daemons reject any connection originating outside IPv4 loopback (`127.0.0.1`) with HTTP `403 Forbidden`.
- **Constant-Time Verification:** API keys and HMAC tags are compared exclusively via constant-time routines to prevent timing side-channel attacks.
