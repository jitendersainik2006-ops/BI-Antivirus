import SwiftUI

public struct DashboardView: View {
    @State private var showingFileImporter = false
    @State private var inspectionResult: FileInspectionResult?
    @State private var isInspecting = false
    @State private var posture: iOSSecurityPosture?

    public init() {}

    public var body: some View {
        NavigationStack {
            ZStack {
                CyberTheme.bgDarkest.ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // Header
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("BI ANTIVIRUS")
                                    .font(.system(size: 22, weight: .bold))
                                    .foregroundColor(CyberTheme.goldAccent)
                                Text("iOS Enterprise Endpoint Security")
                                    .font(.system(size: 13))
                                    .foregroundColor(CyberTheme.textSecondary)
                            }
                            Spacer()
                            NavigationLink(destination: SettingsView()) {
                                Image(systemName: "gearshape.fill")
                                    .foregroundColor(CyberTheme.goldAccent)
                                    .font(.system(size: 20))
                            }
                        }
                        .padding(.top, 8)

                        // Hero Status Card
                        VStack(alignment: .leading, spacing: 14) {
                            HStack(spacing: 14) {
                                Image(systemName: "shield.lefthalf.filled")
                                    .font(.system(size: 38))
                                    .foregroundColor(CyberTheme.statusSafe)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text("DEVICE PROTECTED")
                                        .font(.system(size: 17, weight: .bold))
                                        .foregroundColor(CyberTheme.statusSafe)
                                    Text("Apple Secure Enclave & local heuristics active")
                                        .font(.system(size: 12))
                                        .foregroundColor(CyberTheme.textSecondary)
                                }
                            }

                            Divider().background(CyberTheme.borderSubtle)

                            HStack {
                                VStack(alignment: .leading) {
                                    Text("Signatures").font(.system(size: 11)).foregroundColor(CyberTheme.textSecondary)
                                    Text("OFFLINE DB").font(.system(size: 13, weight: .semibold)).foregroundColor(CyberTheme.textPrimary)
                                }
                                Spacer()
                                VStack(alignment: .leading) {
                                    Text("Integrity").font(.system(size: 11)).foregroundColor(CyberTheme.textSecondary)
                                    Text("CryptoKit").font(.system(size: 13, weight: .semibold)).foregroundColor(CyberTheme.textPrimary)
                                }
                                Spacer()
                                VStack(alignment: .leading) {
                                    Text("Isolation").font(.system(size: 11)).foregroundColor(CyberTheme.textSecondary)
                                    Text("App Sandbox").font(.system(size: 13, weight: .semibold)).foregroundColor(CyberTheme.goldAccent)
                                }
                            }
                        }
                        .padding(18)
                        .background(CyberTheme.bgCard)
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(CyberTheme.borderSubtle, lineWidth: 1)
                        )

                        // Actions Section
                        Text("SECURITY OPERATIONS")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(CyberTheme.textSecondary)

                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                            // File Inspector Action
                            Button(action: { showingFileImporter = true }) {
                                ActionTile(
                                    title: "Inspect File",
                                    subtitle: "User-selected document",
                                    iconName: "doc.text.magnifyingglass"
                                )
                            }

                            // Device Posture Action
                            NavigationLink(destination: PostureAuditView()) {
                                ActionTile(
                                    title: "Device Posture",
                                    subtitle: "Biometrics & lock check",
                                    iconName: "lock.shield.fill"
                                )
                            }

                            // Quarantine Vault Action
                            NavigationLink(destination: VaultView()) {
                                ActionTile(
                                    title: "Threat Vault",
                                    subtitle: "Isolated storage",
                                    iconName: "archivebox.fill"
                                )
                            }

                            // History Action
                            NavigationLink(destination: HistoryView()) {
                                ActionTile(
                                    title: "Audit History",
                                    subtitle: "Inspection logs",
                                    iconName: "clock.arrow.circlepath"
                                )
                            }
                        }

                        // Last Inspection Quick Card
                        if let result = inspectionResult {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("LATEST INSPECTION VERDICT")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(CyberTheme.textSecondary)

                                HStack {
                                    Text(result.fileName)
                                        .font(.system(size: 14, weight: .semibold))
                                        .foregroundColor(CyberTheme.textPrimary)
                                    Spacer()
                                    Text(result.verdict.rawValue)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(result.verdict == .clean ? CyberTheme.statusSafe : CyberTheme.statusThreat)
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
            .fileImporter(
                isPresented: $showingFileImporter,
                allowedContentTypes: [.item],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    if let selectedURL = urls.first {
                        isInspecting = true
                        DispatchQueue.global(qos: .userInitiated).async {
                            let res = FileInspectionEngine.shared.inspect(securityScopedURL: selectedURL)
                            InspectionHistoryStore.shared.save(result: res)
                            DispatchQueue.main.async {
                                self.inspectionResult = res
                                self.isInspecting = false
                            }
                        }
                    }
                case .failure(let error):
                    print("File picker error: \(error.localizedDescription)")
                }
            }
        }
    }
}

struct ActionTile: View {
    let title: String
    let subtitle: String
    let iconName: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: iconName)
                .font(.system(size: 26))
                .foregroundColor(CyberTheme.goldAccent)

            Spacer()

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(CyberTheme.textPrimary)
                Text(subtitle)
                    .font(.system(size: 11))
                    .foregroundColor(CyberTheme.textSecondary)
            }
        }
        .frame(minHeight: 110)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(CyberTheme.bgCard)
        .cornerRadius(10)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(CyberTheme.borderSubtle, lineWidth: 1))
    }
}
