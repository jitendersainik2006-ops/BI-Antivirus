import Foundation

public final class SecurityPreferences: ObservableObject {

    public static let shared = SecurityPreferences()

    private enum Keys {
        static let heuristicEnabled = "bi_heuristic_enabled"
        static let autoQuarantine = "bi_auto_quarantine"
        static let notifyThreatsOnly = "bi_notify_threats_only"
    }

    @Published public var isHeuristicEnabled: Bool {
        didSet { UserDefaults.standard.set(isHeuristicEnabled, forKey: Keys.heuristicEnabled) }
    }

    @Published public var isAutoQuarantine: Bool {
        didSet { UserDefaults.standard.set(isAutoQuarantine, forKey: Keys.autoQuarantine) }
    }

    @Published public var notifyThreatsOnly: Bool {
        didSet { UserDefaults.standard.set(notifyThreatsOnly, forKey: Keys.notifyThreatsOnly) }
    }

    public init() {
        self.isHeuristicEnabled = UserDefaults.standard.object(forKey: Keys.heuristicEnabled) as? Bool ?? true
        self.isAutoQuarantine = UserDefaults.standard.object(forKey: Keys.autoQuarantine) as? Bool ?? false
        self.notifyThreatsOnly = UserDefaults.standard.object(forKey: Keys.notifyThreatsOnly) as? Bool ?? false
    }
}
