# BI Antivirus Enterprise — Android Native Build & Signing Guide

## Prerequisites
- JDK 17+ (Eclipse Temurin or OpenJDK 17)
- Android Studio Hedgehog (2023.1.1) or higher
- Android SDK Platform API 34 (Android 14) and Build-Tools 34.0.0

## Directory Contents
- `app/src/main/java/com/biantivirus/security/`: Complete Kotlin source code
  - `core/`: HashEngine, EntropyCalculator, SignatureDatabase, HeuristicEngine, ScannerEngine, QuarantineManager, WebReputationAuditor
  - `model/`: ScanVerdict, ThreatRecord, HeuristicAnomaly, AuditLog
  - `posture/`: DevicePostureAuditor
  - `storage/`: SQLite scan history database and SharedPreferences
  - `ui/`: Jetpack Compose UI screens with official Black Intel Cyber Defense design system
- `app/src/main/res/`: Resources, adaptive Gold Shield icons, themes, colors, strings
- `app/src/main/assets/`: Packaged `mobile_threat_signatures.json`
- `app/src/test/`: Complete JUnit 4 unit tests (ScannerEngineTest, HeuristicEngineTest, QuarantineManagerTest, DevicePostureAuditorTest, WebReputationAuditorTest)
- `build.gradle.kts` & `app/build.gradle.kts`: Gradle build configuration with ProGuard/R8 rules

## Building via Gradle CLI
```bash
# Run unit tests
./gradlew testDebugUnitTest

# Build Debug APK
./gradlew assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk

# Build ProGuard-Optimized Release APK
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

## Keystore Generation
```bash
keytool -genkey -v -keystore biantivirus-release.jks -alias biantivirus-release -keyalg RSA -keysize 2048 -validity 10000
```
