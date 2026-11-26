# BI Antivirus Enterprise — Android Installation Guide
**Black Intel Cyber Defense Platform — Mobile Endpoint Protection**

## Overview
**BI Antivirus Enterprise for Android** protects your smartphone and tablet from malicious apps, high-entropy trojans, and phishing links with zero battery drain and complete privacy.

---

## 1. How to Install on Your Android Phone

### Step 1: Transfer or Download the APK
- Copy `BI_Antivirus_Enterprise_v1.0.0.apk` (Release) or `BI_Antivirus_Enterprise_v1.0.0_Debug.apk` to your phone's **Downloads** folder (via USB cable, Google Drive, local transfer, or via ADB: `adb install -r BI_Antivirus_Enterprise_v1.0.0.apk`).

### Step 2: Allow Installation from Your File Manager
Modern Android versions (Android 8.0 to 14+) require you to authorize your file manager or browser to install apps:
1. Open your phone's **Files** or **Downloads** app.
2. Tap `BI_Antivirus_Enterprise_v1.0.0.apk`.
3. If prompted with *"For your security, your phone is not allowed to install unknown apps from this source"*:
   - Tap **Settings**.
   - Turn **ON** the switch for **Allow from this source**.
   - Tap the back button to return to the installer.
4. Tap **Install**.

---

## 2. First-Launch Onboarding Experience

When you open BI Antivirus for the first time:
1. You will be greeted by the **Black Intel Cyber Defense** welcome screen.
2. The screen explains how your privacy is protected:
   - **Local Scanning:** All inspections run entirely on your phone. No documents are uploaded to the internet.
   - **No Invasive Permissions:** BI Antivirus does not ask for full storage snooping. It uses Android's **Storage Access Framework (SAF)**, meaning the app can only see files you explicitly pick to scan.
3. Tap **Activate Protection 🚀** to complete onboarding.

---

## 3. How to Use BI Antivirus on Android

### Scan a File or Download
1. On the main dashboard, tap **Scan Document**.
2. Select any file from your device (e.g. recent downloads, PDFs, APKs, or documents).
3. The app streams the file into its mathematical engine, checking hashes, Shannon entropy, and suspicious double extensions.
4. You will see an immediate verdict:
   - 🟢 **CLEAN:** File is safe.
   - 🔴 **THREAT DETECTED:** Known malware signature found.
   - 🟡 **SUSPICIOUS:** Anomaly detected (e.g. packed executable or spoofed extension).

### Quarantine Vault
- If an item is flagged, tap **Quarantine** to neutralize it.
- The file is encrypted using **AES-256-GCM** inside the app's private sandbox where other apps cannot access or run it.
- You can review and restore items from the **Quarantine Vault** screen at any time.

### Device Security Posture Audit
- Tap **Audit Posture** to check if your lock screen PIN is set, hardware encryption is active, and ensure no unauthorized root exploits exist.

---

## 4. How to Update the Android App

- Download the latest APK release package.
- Tap the new APK and select **Update**.
- Android will install the update over your existing installation. Your quarantined files, scan history, and custom settings are automatically preserved.

---

## 5. How to Uninstall

- Long-press the **BI Antivirus** icon on your home screen or app drawer.
- Tap **App info** (or drag to **Uninstall**).
- Tap **Uninstall** and confirm.
- All application cache and sandboxed data are removed cleanly.
