import SwiftUI

public struct PostureAuditView: View {
    @State private var posture: iOSSecurityPosture

    public init() {
        _posture = State(initialValue: iOSDevicePostureChecker.shared.auditPosture())
    }

    public var body: some View {
        ZStack {
            CyberTheme.bgDarkest.ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    // Score Card
                    let scoreColor = posture.overallScore >= 85 ? CyberTheme.statusSafe : (posture.overallScore >= 60 ? CyberTheme.statusWarning : CyberTheme.statusThreat)

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("SECURITY SCORE")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(CyberTheme.textSecondary)
                                Text("\(posture.overallScore) / 100")
                                    .font(.system(size: 32, weight: .heavy))
                                    .foregroundColor(scoreColor)
                                Text("Status: \(posture.statusText)")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(scoreColor)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text(posture.deviceModel)
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(CyberTheme.textPrimary)
                                Text(posture.osVersion)
                                    .font(.system(size: 11))
                                    .foregroundColor(CyberTheme.textSecondary)
                            }
                        }
                    }
                    .padding(18)
                    .background(CyberTheme.bgCard)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(scoreColor, lineWidth: 1))

                    Text("SECURITY BASELINE AUDIT CONTROLS")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(CyberTheme.textSecondary)

                    // Check Items
                    ForEach(posture.checks) { check in
                        let statusColor: Color = {
                            switch check.status {
                            case .pass: return CyberTheme.statusSafe
                            case .warn: return CyberTheme.statusWarning
                            case .fail: return CyberTheme.statusThreat
                            case .notApplicable: return CyberTheme.textSecondary
                            }
                        }()

                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(check.name)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(CyberTheme.textPrimary)
                                Spacer()
                                Text(check.status.rawValue)
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(statusColor)
                            }

                            Text(check.details)
                                .font(.system(size: 12))
                                .foregroundColor(CyberTheme.textSecondary)

                            if check.status != .pass {
                                Text("Recommendation: \(check.recommendation)")
                                    .font(.system(size: 11))
                                    .foregroundColor(CyberTheme.goldBright)
                            }
                        }
                        .padding(14)
                        .background(CyberTheme.bgCard)
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(CyberTheme.borderSubtle, lineWidth: 1))
                    }
                }
                .padding(16)
            }
        }
        .navigationTitle("Device Security Posture")
        .navigationBarTitleDisplayMode(.inline)
    }
}
