import SwiftUI

public struct SettingsView: View {
    @ObservedObject private var prefs = SecurityPreferences.shared

    public init() {}

    public var body: some View {
        ZStack {
            CyberTheme.bgDarkest.ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("SECURITY CONTROLS")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(CyberTheme.textSecondary)

                    VStack(spacing: 14) {
                        Toggle(isOn: $prefs.isHeuristicEnabled) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Heuristic Analysis")
                                    .font(.system(size: 14, weight: .semibold))
                                    .foregroundColor(CyberTheme.textPrimary)
                                Text("Detects double extensions and Shannon entropy anomalies")
                                    .font(.system(size: 11))
                                    .foregroundColor(CyberTheme.textSecondary)
                            }
                        }
                        .tint(CyberTheme.goldAccent)

                        Divider().background(CyberTheme.borderSubtle)

                        Toggle(isOn: $prefs.isAutoQuarantine) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Auto-Quarantine Threats")
                                    .font(.system(size: 14, weight: .semibold))
                                    .foregroundColor(CyberTheme.textPrimary)
                                Text("Disabled by default for user safety and approval")
                                    .font(.system(size: 11))
                                    .foregroundColor(CyberTheme.textSecondary)
                            }
                        }
                        .tint(CyberTheme.goldAccent)
                    }
                    .padding(16)
                    .background(CyberTheme.bgCard)
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(CyberTheme.borderSubtle, lineWidth: 1))

                    Text("SOVEREIGN PRIVACY COMMITMENT")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(CyberTheme.textSecondary)

                    VStack(alignment: .leading, spacing: 8) {
                        Text("100% On-Device Processing")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(CyberTheme.goldAccent)
                        Text("BI Antivirus on iOS strictly adheres to Apple's sandbox architecture. Zero files, hashes, file names, or user data are uploaded to cloud servers. All cryptographic hash calculations and signature checks occur locally on your device.")
                            .font(.system(size: 12))
                            .foregroundColor(CyberTheme.textSecondary)
                            .lineSpacing(3)
                    }
                    .padding(16)
                    .background(CyberTheme.bgCard)
                    .cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(CyberTheme.borderSubtle, lineWidth: 1))
                }
                .padding(16)
            }
        }
        .navigationTitle("Settings & Privacy")
        .navigationBarTitleDisplayMode(.inline)
    }
}
