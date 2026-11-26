# BI Antivirus Enterprise — iPhone & iPad Installation Guide
**Black Intel Cyber Defense Platform — iOS Endpoint Security**

## Overview
**BI Antivirus Enterprise for iOS** is a native Swift and SwiftUI mobile endpoint security application engineered for iPhone and iPad (iOS 16.0 or higher). It provides cryptographic document inspection, Shannon entropy analysis, an authenticated Apple CryptoKit vault, and security posture auditing.

---

## 1. Supported Installation Methods for iPhone

Due to Apple's strict operating system security model, iOS applications must be distributed through Apple's verified channels:

### Method A: Apple TestFlight (Easiest for Beta & Enterprise Testing)
1. Install the official **TestFlight** app from the Apple App Store on your iPhone.
2. Tap the BI Antivirus TestFlight public invitation link provided by your organization.
3. Tap **Install** or **Update**.
4. The application will appear directly on your home screen with the official Black & Gold Cyber Shield icon.

### Method B: Direct Development Installation via Xcode (For Developers & Admins)
1. On a Mac running macOS Sonoma or newer with Xcode 15+:
2. Extract `releases/iOS/BI_Antivirus_iOS_v1.0.0_Source.zip`.
3. Open `BIAntivirus.xcodeproj` in Xcode.
4. Connect your iPhone via USB cable or select an **iOS Simulator** target (e.g. iPhone 15 Pro).
5. In Xcode, select your personal or team Apple Developer account under **Signing & Capabilities**.
6. Press **Cmd + R** to compile, install, and launch the app directly on your device.

### Method C: Enterprise MDM or Ad-Hoc IPA Deployment
Organizations with an Apple Developer Enterprise Account can deploy the compiled `.ipa` package using their Mobile Device Management (MDM) portal (such as Microsoft Intune or Jamf Pro).

---

## 2. First-Launch Onboarding Experience

1. Open **BI Antivirus** from your iPhone home screen.
2. The **Welcome Screen** introduces Black Intel's zero-telemetry endpoint defense:
   - **Zero Cloud Uploads:** File hashing and inspection are performed locally using Apple's native `CryptoKit` framework.
   - **Sandboxed Privacy:** In accordance with Apple iOS security policies, BI Antivirus only has access to documents you explicitly choose via the iOS Document Picker.
3. Tap **Activate Protection 🚀** to open your security dashboard.

---

## 3. How to Inspect Documents & Quarantine Threats

1. On the Dashboard, tap **Inspect File**.
2. The iOS Document Picker will open. Select any document, compressed archive, or download from your **Files** app, iCloud Drive, or local storage.
3. BI Antivirus calculates the file's SHA-256 and MD5 hashes, computes its Shannon entropy, and evaluates heuristic masquerading rules.
4. If a file is flagged as suspicious:
   - Tap **Isolate in Vault** to encrypt the payload with authenticated **AES-GCM** encryption inside the app's sandboxed storage.
   - Quarantined files are neutralized and cannot be opened by other apps.
   - You can view or restore quarantined items from the **Vault** tab.

---

## 4. How to Update on iOS

- **TestFlight Users:** TestFlight will automatically notify you when a new build is released. Tap **Update** in the TestFlight notification.
- **Enterprise / App Store:** Updates install seamlessly over the existing app, preserving all vaulted records and inspection history.

---

## 5. How to Uninstall

- Touch and hold the **BI Antivirus** app icon on your home screen.
- Tap **Remove App**, then tap **Delete App**.
- Confirm deletion to remove the app and its sandboxed storage.
