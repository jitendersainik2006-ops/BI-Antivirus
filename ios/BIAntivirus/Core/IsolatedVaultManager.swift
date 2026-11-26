import Foundation
import CryptoKit

public enum VaultItemStatus: String, Codable {
    case quarantined = "QUARANTINED"
    case restored = "RESTORED"
    case deleted = "DELETED"
}

public struct VaultLedgerItem: Codable {
    public let id: String
    public let originalFileName: String
    public let originalPath: String
    public let quarantinedTimestamp: TimeInterval
    public let sha256: String
    public let threatName: String
    public let vaultFilePath: String
    public let fileSize: Int64
    public var status: VaultItemStatus
    public var restoredTimestamp: TimeInterval?
}

public enum VaultRestoreResult {
    case success(restoredURL: URL, verifiedSha256: String)
    case tamperDetected(reason: String)
    case destinationExists(path: String)
    case recordNotFound(id: String)
    case failure(reason: String)
}

/**
 * Hardened iOS Isolated Vault utilizing Apple CryptoKit AES.GCM Authenticated Encryption with Associated Data (AEAD).
 * Guarantees cryptographic confidentiality, authentication, tamper detection, and overwrite safety.
 */
public final class IsolatedVaultManager {

    public static let shared = IsolatedVaultManager()

    public let vaultDirectory: URL
    private let ledgerURL: URL
    private let keyURL: URL

    private var ledger: [VaultLedgerItem] = []
    private let queue = DispatchQueue(label: "com.biantivirus.isolatedvault", attributes: .concurrent)
    private var symmetricKey: SymmetricKey!

    public init(customVaultDirectory: URL? = nil) {
        if let custom = customVaultDirectory {
            self.vaultDirectory = custom
        } else {
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            self.vaultDirectory = docs.appendingPathComponent("QuarantineVault", isDirectory: true)
        }

        self.ledgerURL = vaultDirectory.appendingPathComponent("vault_ledger.json")
        self.keyURL = vaultDirectory.appendingPathComponent("vault_master.key")

        if !FileManager.default.fileExists(atPath: vaultDirectory.path) {
            try? FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        }

        self.symmetricKey = getOrCreateVaultKey()
        loadLedger()
    }

    private func getOrCreateVaultKey() -> SymmetricKey {
        if let keyData = try? Data(contentsOf: keyURL), keyData.count == 32 {
            return SymmetricKey(data: keyData)
        }
        let freshKey = SymmetricKey(size: .bits256)
        let keyData = freshKey.withUnsafeBytes { Data($0) }
        try? keyData.write(to: keyURL)
        return freshKey
    }

    private func loadLedger() {
        guard let data = try? Data(contentsOf: ledgerURL) else { return }
        if let decoded = try? JSONDecoder().decode([VaultLedgerItem].self, from: data) {
            self.ledger = decoded
        }
    }

    private func saveLedger() {
        guard let data = try? JSONEncoder().encode(ledger) else { return }
        try? data.write(to: ledgerURL)
    }

    private func computeSha256(data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public func quarantine(
        fileName: String,
        originalPath: String,
        data: Data,
        threatName: String,
        sha256: String
    ) throws -> VaultLedgerItem {
        let id = "Q-" + UUID().uuidString.prefix(8).uppercased()
        let vaultFileUrl = vaultDirectory.appendingPathComponent("\(id).biq")

        // 1. Generate unique 12-byte nonce for AES-GCM encryption
        let nonce = AES.GCM.Nonce()

        // 2. Encrypt with Apple CryptoKit AES.GCM with AAD bound to quarantine ID
        guard let aad = id.data(using: .utf8) else {
            throw NSError(domain: "IsolatedVaultManager", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to encode AAD"])
        }
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce, authenticating: aad)

        // 3. Write sealed box (Nonce + Ciphertext + Tag) atomically
        guard let combined = sealedBox.combined else {
            throw NSError(domain: "IsolatedVaultManager", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to construct combined sealed box"])
        }
        let tempURL = vaultDirectory.appendingPathComponent("\(id).tmp")
        try combined.write(to: tempURL)
        if FileManager.default.fileExists(atPath: vaultFileUrl.path) {
            try? FileManager.default.removeItem(at: vaultFileUrl)
        }
        try FileManager.default.moveItem(at: tempURL, to: vaultFileUrl)

        let record = VaultLedgerItem(
            id: String(id),
            originalFileName: fileName,
            originalPath: originalPath,
            quarantinedTimestamp: Date().timeIntervalSince1970,
            sha256: sha256.lowercased(),
            threatName: threatName,
            vaultFilePath: vaultFileUrl.path,
            fileSize: Int64(data.count),
            status: .quarantined,
            restoredTimestamp: nil
        )

        queue.async(flags: .barrier) {
            self.ledger.append(record)
            self.saveLedger()
        }

        return record
    }

    public func restoreItem(
        id: String,
        destinationDirectory: URL,
        allowOverwrite: Bool = false
    ) -> VaultRestoreResult {
        var targetRecord: VaultLedgerItem?
        queue.sync {
            targetRecord = self.ledger.first { $0.id == id }
        }

        guard let record = targetRecord else {
            return .recordNotFound(id: id)
        }

        let vaultURL = URL(fileURLWithPath: record.vaultFilePath)
        guard FileManager.default.fileExists(atPath: vaultURL.path) else {
            return .failure(reason: "Vault file not found on disk")
        }

        do {
            let combinedData = try Data(contentsOf: vaultURL)
            guard let sealedBox = try? AES.GCM.SealedBox(combined: combinedData) else {
                return .tamperDetected(reason: "Malformed sealed box structure or truncated vault file.")
            }

            guard let aad = id.data(using: .utf8) else {
                return .failure(reason: "Failed to encode AAD")
            }

            // Authenticated decryption
            let restoredData: Data
            do {
                restoredData = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
            } catch {
                return .tamperDetected(reason: "AES-GCM authentication tag verification failed. Payload or authentication tag was modified.")
            }

            // Pre-restoration SHA-256 integrity verification
            let calculatedHash = computeSha256(data: restoredData).lowercased()
            if calculatedHash != record.sha256.lowercased() {
                return .tamperDetected(
                    reason: "Cryptographic SHA-256 mismatch: expected \(record.sha256), got \(calculatedHash)"
                )
            }

            // Overwrite safety check
            let targetURL = destinationDirectory.appendingPathComponent(record.originalFileName)
            if FileManager.default.fileExists(atPath: targetURL.path) && !allowOverwrite {
                return .destinationExists(path: targetURL.path)
            }

            // Atomic restore via temporary file
            let tempRestoreURL = destinationDirectory.appendingPathComponent(".restoring_\(UUID().uuidString).tmp")
            try restoredData.write(to: tempRestoreURL)
            if FileManager.default.fileExists(atPath: targetURL.path) && allowOverwrite {
                try? FileManager.default.removeItem(at: targetURL)
            }
            try FileManager.default.moveItem(at: tempRestoreURL, to: targetURL)

            queue.async(flags: .barrier) {
                if let index = self.ledger.firstIndex(where: { $0.id == id }) {
                    self.ledger[index].status = .restored
                    self.ledger[index].restoredTimestamp = Date().timeIntervalSince1970
                    self.saveLedger()
                }
            }

            return .success(restoredURL: targetURL, verifiedSha256: calculatedHash)
        } catch {
            return .failure(reason: error.localizedDescription)
        }
    }

    public func deleteItem(id: String) -> Bool {
        var found = false
        queue.sync(flags: .barrier) {
            if let index = self.ledger.firstIndex(where: { $0.id == id }) {
                let path = self.ledger[index].vaultFilePath
                try? FileManager.default.removeItem(atPath: path)
                self.ledger[index].status = .deleted
                self.saveLedger()
                found = true
            }
        }
        return found
    }

    public func getLedgerHistory() -> [VaultLedgerItem] {
        queue.sync { self.ledger }
    }

    public func getActiveQuarantinedItems() -> [VaultLedgerItem] {
        queue.sync { self.ledger.filter { $0.status == .quarantined } }
    }
}
