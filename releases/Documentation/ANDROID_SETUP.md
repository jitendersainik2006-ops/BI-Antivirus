# BI Antivirus Enterprise — Android Native Setup & Deployment Guide

## Overview
**BI Antivirus Enterprise for Android** is a native mobile endpoint protection solution engineered with Kotlin, Android Jetpack Compose, and modern Android architecture. It features the official **Black Intel Cyber Defense** visual identity (`#0A0A0C` Deep Black, `#181A22` Charcoal, `#D4AF37` Metallic Gold, `#F3CF65` Bright Gold) with adaptive gold shield launcher icons, high-performance streaming signature matching (SHA-256 / MD5), Shannon entropy calculation, heuristic double-extension detection, on-device Web Reputation & Phishing URL auditing (`WebReputationAuditor`), AES-256-GCM authenticated threat vaulting, explicit 5-state verdict classifications, and device security posture auditing.

---

## 1. Prerequisites & System Requirements

| Component | Minimum Version | Recommended |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11 x64, macOS 13+, or Linux x64 | Windows 11 x64 / macOS Sonoma |
| **Android Studio** | Android Studio Hedgehog (2023.1.1) | Android Studio Iguana / Ladybug |
| **JDK (Java Development Kit)** | OpenJDK 17 | Eclipse Temurin JDK 17 (or Amazon Corretto 17) |
| **Android SDK Platform** | API Level 34 (Android 14) | API Level 34 |
| **Android Build Tools** | 34.0.0 | 34.0.0 |
| **Android NDK** | Optional (pure Kotlin implementation) | N/A |
| **Target Device / Emulator** | Android 8.0 (API 26) or higher | Android 12+ (API 31+) |

---

## 2. Directory Structure

```
android/
├── build.gradle.kts                # Project-level build configuration (AGP 8.2+, Kotlin 1.9+)
├── settings.gradle.kts             # Module definitions & repositories (Google, MavenCentral)
├── gradle.properties               # JVM memory allocations & AndroidX flags
└── app/
    ├── build.gradle.kts            # App module dependencies, SDK targets, & ProGuard
    ├── proguard-rules.pro          # Code shrinking, optimization, & obfuscation rules
    └── src/
        ├── main/
        │   ├── AndroidManifest.xml # Permissions, Application, and Activity declarations
        │   ├── assets/
        │   │   └── mobile_threat_signatures.json # Synchronized threat catalog
        │   ├── java/com/biantivirus/security/
        │   │   ├── BIAntivirusApp.kt        # Application lifecycle & DB init
        │   │   ├── core/
        │   │   │   ├── HashEngine.kt         # SHA-256 / MD5 streaming
        │   │   │   ├── EntropyCalculator.kt  # Shannon entropy math
        │   │   │   ├── SignatureDatabase.kt  # Fast memory lookup
        │   │   │   ├── HeuristicEngine.kt    # Suspicious pattern detector
        │   │   │   ├── ScannerEngine.kt      # Stream analysis orchestrator
        │   │   │   ├── QuarantineManager.kt  # AES-256-GCM authenticated vault
        │   │   │   └── WebReputationAuditor.kt # On-device Phishing & URL reputation analyzer
        │   │   ├── model/                  # Data classes & ScanVerdict
        │   │   ├── posture/                # DevicePostureAuditor
        │   │   ├── storage/                # SQLite & SharedPreferences
        │   │   └── ui/                     # Jetpack Compose UI & screens
        │   │       └── theme/              # Black Intel Theme & Palette
        │   └── res/                        # Themes, colors, strings, drawables
        │       ├── mipmap-anydpi-v26/      # Adaptive launcher icons (Gold Cyber Shield)
        │       ├── drawable/               # Icon backgrounds and foreground vectors
        │       └── values/                 # Black Intel color definitions
        └── test/                           # JUnit 4 & Kotlin unit tests
            ├── ScannerEngineTest.kt
            ├── HeuristicEngineTest.kt
            ├── QuarantineManagerTest.kt
            ├── DevicePostureAuditorTest.kt
            └── WebReputationAuditorTest.kt
```

---

## 3. Building the Project

### Using Android Studio
1. Open Android Studio.
2. Select **File > Open** and browse to `D:\bit defender\android`.
3. Allow Gradle to synchronize project dependencies.
4. Select build variant: **Debug** or **Release**.
5. Click **Build > Make Project** (or press `Ctrl+F9` / `Cmd+F9`).

### Using Command Line (Gradle)
```bash
# Navigate to the Android root directory
cd "D:\bit defender\android"

# Run all unit tests
./gradlew testDebugUnitTest

# Build Debug APK
./gradlew assembleDebug

# Output APK path:
# android/app/build/outputs/apk/debug/app-debug.apk
```

---

## 4. Production Release Build & APK Signing

To generate an optimized, signed release APK ready for deployment or Google Play:

### Step 1: Generate a Production Keystore
Generate a cryptographically secure 2048-bit RSA release signing key:
```bash
keytool -genkey -v \
  -keystore "D:\bit defender\releases\Android\biantivirus-release.jks" \
  -alias "biantivirus-release" \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -dname "CN=BI Antivirus Release, OU=Cyber Defense, O=Black Intel, L=City, ST=State, C=US"
```

### Step 2: Configure Release Signing in `app/build.gradle.kts`
Set the signing configuration using environment variables or a secure properties file (never check raw passwords into Git):
```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file(System.getenv("KEYSTORE_PATH") ?: "../releases/Android/biantivirus-release.jks")
            storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
            keyAlias = System.getenv("KEY_ALIAS") ?: "biantivirus-release"
            keyPassword = System.getenv("KEY_PASSWORD") ?: ""
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

### Step 3: Execute Release Assembly
```bash
./gradlew assembleRelease
# Output: android/app/build/outputs/apk/release/app-release.apk

# Verify signature with apksigner:
apksigner verify --verbose android/app/build/outputs/apk/release/app-release.apk
```

---

## 5. Security & Permission Architecture

BI Antivirus Enterprise Android strictly adheres to Google Play Core Policy and privacy-preserving zero-trust mobile architecture:

### Declared Permissions Analysis

| Permission | Purpose | Protection Level |
| :--- | :--- | :--- |
| `android.permission.INTERNET` | Threat signature updates and optional webhook alerts | Normal (automatic grant) |
| `android.permission.ACCESS_NETWORK_STATE` | Check connectivity status before downloading definition updates | Normal (automatic grant) |
| `android.permission.POST_NOTIFICATIONS` | Alert user when malware or phishing threat is intercepted (Android 13+) | Dangerous (Runtime prompt) |

### Zero Dangerous Permissions
- **No `MANAGE_EXTERNAL_STORAGE`**: Prevents broad device surveillance or Play Store policy violations.
- **Storage Access Framework (SAF)**: Uses user-guided `OpenDocument` intent for scanning arbitrary user files.
- **Zero Root Execution**: Uses pure unprivileged Java/Kotlin user-space APIs.
- **Private Sandbox Storage**: Quarantined items are stored strictly in `context.filesDir/quarantine/` with `AES-256-GCM` encryption.

---

## 6. Device Compatibility & Hardware Support

| Dimension | Specification |
| :--- | :--- |
| **Minimum API Level** | API 26 (Android 8.0 Oreo) |
| **Target API Level** | API 34 (Android 14 UpsideDownCake) |
| **Supported ABIs** | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |
| **Form Factors** | Smartphones, Tablets, Foldable devices, ChromeOS Android container |
| **Memory Footprint** | Peak heap < 48 MB during active 64 KB streaming inspection |

---

## 7. Testing with Safe Test Vectors

You can transfer the safe test vectors located in `shared/test_vectors/` to your test device to verify detection:

```bash
# Push safe test vectors to Downloads directory
adb push shared/test_vectors/clean_document.txt /sdcard/Download/
adb push shared/test_vectors/suspicious_double_extension.pdf.apk /sdcard/Download/
adb push shared/test_vectors/high_entropy_packed_sample.bin /sdcard/Download/
```

- Open **BI Antivirus**, navigate to **File Scanner**, tap **Choose File to Scan**, and select each test vector:
  - `clean_document.txt` $\rightarrow$ **Clean** (Emerald badge)
  - `suspicious_double_extension.pdf.apk` $\rightarrow$ **Suspicious** (Heuristic double extension trigger)
  - `high_entropy_packed_sample.bin` $\rightarrow$ **Suspicious** (Entropy $\ge 7.2$)
