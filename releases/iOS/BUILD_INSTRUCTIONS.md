# BI Antivirus Enterprise — iOS Native Build & Distribution Guide

## Prerequisites
- macOS Monterey (12.0+) or macOS Sonoma (14.0+) / Sequoia (15.0+)
- Xcode 14.0+ (Xcode 15.2+ recommended)
- Swift 5.9+, SwiftUI, Apple CryptoKit
- Apple Developer Account (for device testing, TestFlight, or App Store release)

## Directory Contents
- `BIAntivirus.xcodeproj/project.pbxproj`: Complete Xcode project configuration
- `BIAntivirus/App/`: BIAntivirusApp.swift (@main) and ContentView router
- `BIAntivirus/Theme/`: CyberDarkGoldTheme (Black Intel official palette)
- `BIAntivirus/Core/`: HashCalculator, EntropyAnalyzer, ThreatCatalog, HeuristicScanner, IsolatedVaultManager, FileInspectionEngine, WebReputationAuditor
- `BIAntivirus/Models/`: InspectionVerdict, ThreatRecord, FileInspectionResult, iOSSecurityPosture, VaultedThreat
- `BIAntivirus/Posture/`: iOSDevicePostureChecker
- `BIAntivirus/Storage/`: InspectionHistoryStore, SecurityPreferences, ScanReportExporter
- `BIAntivirus/Views/`: DashboardView, PostureAuditView, VaultView, HistoryView, SettingsView
- `BIAntivirus/Resources/`: Info.plist, LaunchScreen.storyboard, Assets.xcassets, mobile_threat_signatures.json
- `BIAntivirusTests/`: Complete XCTest unit test suites

## Building via Xcode CLI
```bash
# Execute unit tests in iOS Simulator
xcodebuild test \
  -project BIAntivirus.xcodeproj \
  -scheme BIAntivirusTests \
  -destination 'platform=iOS Simulator,name=iPhone 15'

# Create Production Archive
xcodebuild archive \
  -project BIAntivirus.xcodeproj \
  -scheme BIAntivirus \
  -configuration Release \
  -archivePath BIAntivirus.xcarchive

# Export Distribution IPA
xcodebuild -exportArchive \
  -archivePath BIAntivirus.xcarchive \
  -exportPath IPA \
  -exportOptionsPlist ExportOptions.plist
```
