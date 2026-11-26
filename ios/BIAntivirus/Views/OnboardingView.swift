import SwiftUI

public struct OnboardingView: View {
    private let onComplete: () -> Void

    public init(onComplete: @escaping () -> Void) {
        self.onComplete = onComplete
    }

    public var body: some View {
        ZStack {
            CyberTheme.bgDarkest.ignoresSafeArea()

            VStack(spacing: 24) {
                Spacer()

                // Brand Emblem
                ZStack {
                    RoundedRectangle(cornerRadius: 24)
                        .fill(CyberTheme.bgCard)
                        .frame(width: 90, height: 90)
                        .overlay(
                            RoundedRectangle(cornerRadius: 24)
                                .stroke(CyberTheme.goldAccent, lineWidth: 2)
                        )

                    Image(systemName: "shield.fill")
                        .font(.system(size: 46))
                        .foregroundColor(CyberTheme.goldAccent)
                }

                VStack(spacing: 6) {
                    Text("BI ANTIVIRUS")
                        .font(.system(size: 26, weight: .bold))
                        .foregroundColor(CyberTheme.goldAccent)
                        .tracking(1.5)

                    Text("BLACK INTEL CYBER DEFENSE")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(CyberTheme.textSecondary)
                        .tracking(2.0)
                }

                VStack(spacing: 8) {
                    Text("Enterprise iOS Endpoint Defense")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(CyberTheme.textPrimary)

                    Text("High-performance file inspection, cryptographic vaulting, and privacy posture evaluation with zero telemetry.")
                        .font(.system(size: 13))
                        .foregroundColor(CyberTheme.textSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }

                // Value Highlights
                VStack(spacing: 12) {
                    featureCard(
                        icon: "lock.shield.fill",
                        title: "Apple CryptoKit AES.GCM Vault",
                        desc: "Quarantined threats are isolated with authenticated on-device encryption."
                    )
                    featureCard(
                        icon: "hand.raised.fill",
                        title: "100% Sandboxed Privacy",
                        desc: "Inspects only files you explicitly select via the iOS Document Picker."
                    )
                    featureCard(
                        icon: "bolt.shield.fill",
                        title: "Shannon Entropy Analysis",
                        desc: "Calculates entropy and detects disguised malicious payloads."
                    )
                }
                .padding(.horizontal, 16)

                Spacer()

                Button(action: onComplete) {
                    Text("Activate Protection 🚀")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(CyberTheme.bgDarkest)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 16)
                        .background(CyberTheme.goldAccent)
                        .cornerRadius(14)
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 20)
            }
        }
    }

    private func featureCard(icon: String, title: String, desc: String) -> some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(CyberTheme.bgCardHover)
                    .frame(width: 38, height: 38)
                Image(systemName: icon)
                    .foregroundColor(CyberTheme.goldAccent)
                    .font(.system(size: 18))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text(desc)
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }
            Spacer()
        }
        .padding(14)
        .background(CyberTheme.bgCard)
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(CyberTheme.borderSubtle, lineWidth: 1)
        )
    }
}
