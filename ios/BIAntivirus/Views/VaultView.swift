import SwiftUI

public struct VaultView: View {
    @State private var vaultFiles: [URL] = []

    public init() {}

    public var body: some View {
        ZStack {
            CyberTheme.bgDarkest.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 16) {
                Text("ISOLATED THREAT VAULT")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(CyberTheme.textSecondary)
                    .padding(.horizontal, 16)
                    .padding(.top, 16)

                if vaultFiles.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 42))
                            .foregroundColor(CyberTheme.statusSafe)
                        Text("Threat Vault is Empty")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundColor(CyberTheme.textPrimary)
                        Text("No malicious files or quarantined items are isolated.")
                            .font(.system(size: 12))
                            .foregroundColor(CyberTheme.textSecondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(20)
                } else {
                    List {
                        ForEach(vaultFiles, id: \.self) { url in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(url.lastPathComponent)
                                        .font(.system(size: 14, weight: .semibold))
                                        .foregroundColor(CyberTheme.textPrimary)
                                    Text("Encrypted Quarantine Record (.biq)")
                                        .font(.system(size: 11))
                                        .foregroundColor(CyberTheme.goldBright)
                                }
                                Spacer()
                                Button(action: {
                                    _ = IsolatedVaultManager.shared.deleteVaultFile(at: url)
                                    reloadVault()
                                }) {
                                    Image(systemName: "trash")
                                        .foregroundColor(CyberTheme.statusThreat)
                                }
                            }
                            .listRowBackground(CyberTheme.bgCard)
                        }
                    }
                    .scrollContentBackground(.hidden)
                }
            }
        }
        .navigationTitle("Threat Vault")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { reloadVault() }
    }

    private func reloadVault() {
        vaultFiles = IsolatedVaultManager.shared.listVaultFiles()
    }
}
