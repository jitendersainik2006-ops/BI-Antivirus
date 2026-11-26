# BI Antivirus Enterprise — Universal User Manual
**Black Intel Cyber Defense Platform — Windows, Android & iOS**

**Document Version:** 1.0.0-PRO  
**Platform Coverage:** Windows 10/11 x64, Android 8.0+ (API 26–34), iOS 16.0+  
**Design Identity:** Black Intel Cyber Defense (Black & Gold)

---

## 1. Introduction & Philosophy

BI Antivirus Enterprise is engineered by **Black Intel Cyber Defense** to provide commercial-grade antivirus, anti-malware, and phishing protection across computers, smartphones, and tablets.

Unlike traditional antivirus programs that bombard users with complex technical jargon, slow down system performance, and harvest personal data, BI Antivirus is built on four core principles:
1. **Sovereign Privacy:** All file scanning, hashing, and entropy calculations run 100% locally on your device. Zero user documents or tracking telemetry are transmitted to the cloud.
2. **Mathematical Rigor:** Fast $O(1)$ signature lookups and high-precision Shannon entropy math calculate payload packing without guessing.
3. **Authenticated Vaulting:** Intercepted threats are neutralized using authenticated AES-256 encryption (`AES-256-CBC` + `HMAC-SHA256` on Windows, `AES-256-GCM` on Android, `CryptoKit AES.GCM` on iOS) to prevent accidental execution.
4. **Beginner-Friendly Clarity:** Clear security statuses, jargon-free explanations, and intuitive Black & Gold interfaces.

---

## 2. Navigating the Security Dashboard

Across Windows, Android, and iOS, the Dashboard serves as your central command center:

### Security Status Indicators
- 🟢 **DEVICE PROTECTED:** Real-time protection is active, threat definitions are current, and no malware has been detected.
- 🟡 **ATTENTION REQUIRED:** A setting is disabled (e.g. real-time shield turned off, or device lock PIN not set).
- 🔴 **THREAT DETECTED:** Malicious or high-risk files were discovered and require your review in the Quarantine Vault.

### Core Dashboard Controls
- **Quick Scan:** Inspects running memory, system startup locations, and active downloads in under 30 seconds.
- **Full System Scan (Windows):** Thoroughly examines every file and folder across your storage drives.
- **Scan Document (Android & iOS):** Opens the native system file picker to inspect any download, document, or archive.
- **Audit Posture:** Checks device health, encryption status, and configuration safeguards.

---

## 3. How Scanning Works

### Scan Verdicts Explained (Plain English)
When you scan a file, BI Antivirus evaluates it through multiple security layers and returns one of five explicit verdicts:
1. **`CLEAN`**: The file is completely benign. It matches no known virus signatures and contains no suspicious executable code.
2. **`THREAT_DETECTED`**: The file definitively matches a known virus, trojan, or ransomware signature. It should be quarantined immediately.
3. **`SUSPICIOUS`**: Anomaly detection triggered. For example, a file named `invoice.pdf.exe` (masquerading as a document), or an encrypted packed payload with high Shannon entropy ($H \ge 7.2$).
4. **`UNSUPPORTED`**: The file format is not supported for active inspection. *Guaranteed never reported as clean*.
5. **`SCAN_ERROR`**: The file is empty, corrupted, or unreadable. *Guaranteed never reported as clean*.

---

## 4. The Quarantine Vault & Safe Restoration

When a threat is discovered, BI Antivirus neutralizes it by moving it to the **Quarantine Vault**:
- **Why Quarantined Files Cannot Harm You:** Files in the vault are strongly encrypted. Even if malware attempts to execute, it is mathematically scrambled and inert.
- **Reviewing Vaulted Threats:** Open the **Quarantine Vault** screen to view the file name, original location, detection reason, and date.
- **Restoring a File (Safe Overwrite Protection):**
  - If you know a file is safe (a false alarm), you can select **Restore**.
  - The engine verifies the cryptographic integrity of the file before decrypting.
  - If a file with the same name already exists in the original folder, BI Antivirus will safely refuse to overwrite it unless you explicitly confirm, preventing accidental data loss.

---

## 5. Web & Phishing Defense

BI Antivirus includes **`WebReputationAuditor`** to protect you against deceptive websites:
- **Homoglyph & Punycode Defense:** Detects disguised domain names (such as spoofed banking websites using Cyrillic or special characters like `xn--`).
- **Raw IP Address Blocking:** Flags links that bypass legitimate domain name registration to connect directly to suspicious numeric IP addresses.
- **High-Risk TLD Filtering:** Alerts you when browsing top-level domains frequently abused by spammers and cybercriminals (`.top`, `.work`, `.click`).

---

## 6. Keeping Your Antivirus Updated

### Automated & One-Click Definition Updates
- **Windows:** Go to **Settings > Updates** and click **Verify & Refresh Definitions**. The application connects to the signed update channel and applies verified threat updates atomically.
- **Android:** Download and install the latest APK update. Your existing settings and quarantine vault remain completely intact.
- **iOS:** Update directly through Apple TestFlight or the App Store.

---

## 7. Troubleshooting & Safe Diagnostics

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| **"Python 3.10+ required" (Windows)** | Python runtime is not installed in system PATH | Run `winget install Python.Python.3.12` in PowerShell or use the portable package. |
| **App opens with blank or black screen** | Windows graphics driver incompatibility | Launch **BI Antivirus (Safe Mode Console)** from the Start Menu. |
| **"Install unknown apps" prompt (Android)** | Android security policy for manual APK installation | Go to Settings > Allow from this source for your file manager. |
| **Cannot scan system folders (iOS)** | Apple iOS sandboxing policy | Use the iOS Document Picker to select specific documents to inspect. |
| **Tampered Vault File Warning** | Quarantined file was edited or corrupted on disk | The vault automatically blocks restoration of tampered payloads. |

---

## 8. Summary of Product Integrity

BI Antivirus Enterprise is committed to 100% transparent cybersecurity. It contains zero backdoors, zero telemetry harvesting, and zero artificial software locks.
