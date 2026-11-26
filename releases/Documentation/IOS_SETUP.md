# BI Antivirus Enterprise — iOS Native Setup & Deployment Guide

## Overview
**BI Antivirus Enterprise for iOS** is a native iPhone/iPad endpoint security application engineered in Swift 5.9 and SwiftUI. It features the official **Black Intel Cyber Defense** visual identity (`#0A0A0C` Deep Black, `#181A22` Charcoal, `#D4AF37` Metallic Gold, `#F3CF65` Bright Gold) with a dedicated Black Intel launch screen, Asset Catalogs, high-performance privacy-respecting file inspection, cryptographic hashing via Apple's CryptoKit, Shannon entropy analysis, heuristic pattern evaluation, on-device Web Reputation & Phishing URL auditing (`WebReputationAuditor`), an authenticated Apple CryptoKit AES.GCM document vault, explicit 5-state verdict classifications, and device security posture assessment using LocalAuthentication.

---

## 1. Prerequisites & System Requirements

| Component | Minimum Version | Recommended |
| :--- | :--- | :--- |
| **Operating System** | macOS Monterey (12.0+) | macOS Sonoma (14.0+) / Sequoia (15.0+) |
| **Integrated Development Environment** | Xcode 14.0+ | Xcode 15.2 or newer |
| **Language & Frameworks** | Swift 5.9, SwiftUI | Swift 5.9+, SwiftUI |
| **Base SDK** | iOS 16.0 | iOS 17.0+ |
| **Deployment Target** | iOS 16.0 or higher | iOS 16.0+ |
| **Device / Simulator** | iPhone 11 or newer / iOS Simulator | iPhone 15 Pro Simulator |
| **Apple Developer Account** | Optional for Simulator / Required for Device & TestFlight | Apple Developer Program ($99/year) |

---

## 2. Directory Structure

```
ios/
├── BIAntivirus.xcodeproj/          # Xcode project bundle
│   └── project.pbxproj             # Target, build phase, & code signing definitions
├── BIAntivirus/
│   ├── App/
│   │   ├── BIAntivirusApp.swift    # @main application entry point
│   │   └── ContentView.swift       # Root view router
│   ├── Theme/
│   │   └── CyberDarkGoldTheme.swift # Enterprise Cyber Dark & Gold design system
│   ├── Models/
│   │   ├── InspectionVerdict.swift  # Scan verdicts & severities
│   │   ├── ThreatRecord.swift       # Signature model
│   │   ├── FileInspectionResult.swift # Output report model
│   │   ├── iOSSecurityPosture.swift # Posture evaluation result
│   │   └── VaultedThreat.swift      # Quarantined file record
│   ├── Core/
│   │   ├── HashCalculator.swift     # CryptoKit SHA-256 + CommonCrypto MD5
│   │   ├── EntropyAnalyzer.swift    # Shannon entropy math
│   │   ├── ThreatCatalog.swift      # Thread-safe in-memory signature catalog
│   │   ├── HeuristicScanner.swift   # Double-extension, entropy & profile rules
│   │   ├── IsolatedVaultManager.swift # Apple CryptoKit AES.GCM authenticated vault
│   │   ├── FileInspectionEngine.swift # Security-scoped URL inspector
│   │   └── WebReputationAuditor.swift # On-device Phishing & URL reputation analyzer
│   ├── Posture/
│   │   └── iOSDevicePostureChecker.swift # Biometrics, passcode & iOS checks
│   ├── Storage/
│   │   ├── InspectionHistoryStore.swift # JSON file store
│   │   ├── SecurityPreferences.swift    # UserDefaults wrapper
│   │   └── ScanReportExporter.swift     # Markdown and JSON report generator
│   ├── Views/                      # SwiftUI screens
│   │   ├── DashboardView.swift
│   │   ├── PostureAuditView.swift
│   │   ├── VaultView.swift
│   │   ├── HistoryView.swift
│   │   └── SettingsView.swift
│   └── Resources/
│       ├── Info.plist               # App metadata, bundle ID, & security declarations
│       ├── LaunchScreen.storyboard  # Black Intel Cyber Shield launch screen
│       ├── Assets.xcassets/         # App icons & AccentColor asset catalog
│       └── mobile_threat_signatures.json # Synchronized signature catalog
└── BIAntivirusTests/               # XCTest unit test suites
    ├── HashCalculatorTests.swift
    ├── EntropyAnalyzerTests.swift
    ├── ThreatCatalogTests.swift
    ├── HeuristicScannerTests.swift
    ├── FileInspectionEngineTests.swift
    ├── FileTypeInspectorTests.swift
    ├── IsolatedVaultManagerTests.swift
    ├── ScanReportExporterTests.swift
    └── WebReputationAuditorTests.swift
```

---

## 3. Building and Running in Xcode

### Opening the Project
1. On a macOS development workstation, open Terminal.
2. Open the project in Xcode:
   ```bash
   open "ios/BIAntivirus.xcodeproj"
   ```

### Running on iOS Simulator
1. Select the **BIAntivirus** scheme.
2. Select target device: e.g. **iPhone 15 (iOS 17.0)**.
3. Press **Cmd+R** or click the **Play** button to build and launch.

### Executing Unit Tests
1. Press **Cmd+U** in Xcode, or run via `xcodebuild`:
   ```bash
   xcodebuild test \
     -project ios/BIAntivirus.xcodeproj \
     -scheme BIAntivirusTests \
     -destination 'platform=iOS Simulator,name=iPhone 15'
   ```

---

## 4. Production Release Archive & IPA Distribution

To generate an enterprise distribution IPA or TestFlight build on macOS:

### Step 1: Configure Code Signing in Xcode
1. Open `BIAntivirus.xcodeproj` in Xcode.
2. In **Signing & Capabilities**:
   - Check **Automatically manage signing** (or select manual Enterprise Provisioning Profile).
   - Select your **Apple Developer Team**.
   - Bundle Identifier: `com.biantivirus.security`.

### Step 2: Create Archive via Command Line
```bash
xcodebuild archive \
  -project "ios/BIAntivirus.xcodeproj" \
  -scheme "BIAntivirus" \
  -configuration Release \
  -archivePath "releases/iOS/BIAntivirus.xcarchive"
```

### Step 3: Export IPA Package
Using an `ExportOptions.plist` configured for App Store, Ad-Hoc, or Enterprise:
```bash
xcodebuild -exportArchive \
  -archivePath "releases/iOS/BIAntivirus.xcarchive" \
  -exportPath "releases/iOS/IPA" \
  -exportOptionsPlist "releases/iOS/ExportOptions.plist"
```

### Step 4: TestFlight & App Store Connect Validation
- **Encryption Exemption**: BI Antivirus uses standard Apple CryptoKit AES-GCM for file vaulting. In `Info.plist`, `ITSAppUsesNonExemptEncryption` is set to `NO`.
- **Privacy Nutrition Labels**:
  - Data Collected: None.
  - Data Linked to Identity: None.
  - Data Kept On-Device: Inspection history and vaulted threats stored purely in private sandboxed `Application Support`.

---

## 5. Privacy & Apple Sandbox Compliance

BI Antivirus Enterprise iOS is engineered to fully comply with Apple's strict sandboxing (`sandbox_init`) and App Store Review Guidelines:

1. **Document Picker (`UIDocumentPickerViewController`):**
   - In accordance with iOS sandboxing, third-party apps cannot traverse other apps' files or system directories.
   - The user explicitly grants access to files via the system file picker using security-scoped URLs (`startAccessingSecurityScopedResource()`).
2. **Cryptographic Protection:**
   - Hashing is performed directly in memory using Apple's native `CryptoKit` framework.
   - Quarantined items are stored inside the app's sandboxed `Application Support/IsolatedVault/` container with authenticated AES-GCM encryption.
3. **No Jailbreak Required:**
   - The app operates entirely within Apple's user-space sandbox.
   - It performs passive security posture checks (passcode enabled, Face ID/Touch ID status, iOS version compliance) without requiring kernel exploitation.

---

## 6. Testing with Safe Test Vectors

1. Open the Files app on your iPhone or Simulator.
2. Save test vectors from `shared/test_vectors/` into the Files app (e.g., iCloud Drive or On My iPhone).
3. Open **BI Antivirus**, navigate to **Inspect File**, and select the vector:
   - `clean_document.txt` $\rightarrow$ **Clean**
   - `suspicious_double_extension.pdf.apk` $\rightarrow$ **Suspicious Heuristic**
   - `high_entropy_packed_sample.bin` $\rightarrow$ **Suspicious Heuristic**
