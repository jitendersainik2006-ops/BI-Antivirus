import Foundation

public final class InspectionHistoryStore {

    public static let shared = InspectionHistoryStore()

    private let historyFileUrl: URL
    private let queue = DispatchQueue(label: "com.biantivirus.historystore", attributes: .concurrent)

    public init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        if !FileManager.default.fileExists(atPath: appSupport.path) {
            try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
        }
        self.historyFileUrl = appSupport.appendingPathComponent("inspection_history.json")
    }

    public func save(result: FileInspectionResult) {
        queue.async(flags: .barrier) {
            var current = self.loadInternal()
            current.insert(result, at: 0)
            if current.count > 100 {
                current = Array(current.prefix(100))
            }
            if let data = try? JSONEncoder().encode(current) {
                try? data.write(to: self.historyFileUrl)
            }
        }
    }

    public func getRecent(limit: Int = 50) -> [FileInspectionResult] {
        queue.sync {
            let items = self.loadInternal()
            return Array(items.prefix(limit))
        }
    }

    public func clear() {
        queue.async(flags: .barrier) {
            try? FileManager.default.removeItem(at: self.historyFileUrl)
        }
    }

    private func loadInternal() -> [FileInspectionResult] {
        guard let data = try? Data(contentsOf: historyFileUrl),
              let items = try? JSONDecoder().decode([FileInspectionResult].self, from: data) else {
            return []
        }
        return items
    }
}
