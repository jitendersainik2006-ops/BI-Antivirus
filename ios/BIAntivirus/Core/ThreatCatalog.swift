import Foundation

public final class ThreatCatalog {

    public static let shared = ThreatCatalog()

    private var sha256Map: [String: ThreatRecord] = [:]
    private var md5Map: [String: ThreatRecord] = [:]
    private let queue = DispatchQueue(label: "com.biantivirus.threatcatalog", attributes: .concurrent)

    public init() {
        seedBaselineSignatures()
        loadBundleSignatures()
    }

    private func seedBaselineSignatures() {
        let baseline: [ThreatRecord] = [
            ThreatRecord(
                id: "SIG-MOB-001",
                name: "EICAR-Standard-AV-Test-File",
                family: "TestVirus",
                severity: .critical,
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                md5: "44d88612fea8a8f36de82e1278abb02f",
                description: "European Institute for Computer Antivirus Research harmless test sample."
            ),
            ThreatRecord(
                id: "SIG-MOB-002",
                name: "Android.Trojan.FakeBank.A",
                family: "Trojan",
                severity: .critical,
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                md5: "d41d8cd98f00b204e9800998ecf8427e",
                description: "Banking credential dropper signature."
            ),
            ThreatRecord(
                id: "SIG-MOB-003",
                name: "Mobile.Spyware.PegasusSim.Test",
                family: "Spyware",
                severity: .critical,
                sha256: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                md5: "ef597f63c5c766360ee718795b00f417",
                description: "Simulated surveillance spyware payload test vector."
            ),
            ThreatRecord(
                id: "SIG-MOB-006",
                name: "iOS.Phishing.ConfigProfile.Dropper",
                family: "Trojan",
                severity: .high,
                sha256: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
                md5: "b10a8db164e0754105b7a99be72e3fe5",
                description: "Malicious mobile configuration profile payload (.mobileconfig)."
            )
        ]

        baseline.forEach { register(record: $0) }
    }

    public func register(record: ThreatRecord) {
        queue.async(flags: .barrier) {
            if !record.sha256.isEmpty {
                self.sha256Map[record.sha256.lowercased()] = record
            }
            if !record.md5.isEmpty {
                self.md5Map[record.md5.lowercased()] = record
            }
        }
    }

    public func lookup(sha256: String) -> ThreatRecord? {
        queue.sync {
            self.sha256Map[sha256.lowercased()]
        }
    }

    public func lookup(md5: String) -> ThreatRecord? {
        queue.sync {
            self.md5Map[md5.lowercased()]
        }
    }

    public var signatureCount: Int {
        queue.sync { sha256Map.count }
    }

    private func loadBundleSignatures() {
        guard let url = Bundle.main.url(forResource: "mobile_threat_signatures", withExtension: "json"),
              let data = try? Data(contentsOf: url) else {
            return
        }

        struct CatalogJSON: Codable {
            struct SigItem: Codable {
                let id: String
                let name: String
                let family: String
                let severity: String
                let sha256: String
                let md5: String
                let description: String
            }
            let signatures: [SigItem]
        }

        if let catalog = try? JSONDecoder().decode(CatalogJSON.self, from: data) {
            for item in catalog.signatures {
                let sev: ThreatSeverity = {
                    switch item.severity.uppercased() {
                    case "CRITICAL": return .critical
                    case "HIGH": return .high
                    case "MEDIUM": return .medium
                    default: return .low
                    }
                }()
                let record = ThreatRecord(
                    id: item.id,
                    name: item.name,
                    family: item.family,
                    severity: sev,
                    sha256: item.sha256,
                    md5: item.md5,
                    description: item.description
                )
                register(record: record)
            }
        }
    }
}
