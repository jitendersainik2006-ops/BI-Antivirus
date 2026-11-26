//
//  BIAntivirusApp.swift
//  BIAntivirus
//
//  Main application entry point for BI Antivirus Enterprise iOS.
//  Created for BI Antivirus Enterprise Cross-Platform Security.
//

import SwiftUI

@main
public struct BIAntivirusApp: App {
    @StateObject private var historyStore = InspectionHistoryStore.shared
    @StateObject private var preferences = SecurityPreferences.shared

    public init() {
        // Configure global navigation/tab bar appearance for Cyber Dark & Gold
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = UIColor(CyberDarkGoldTheme.surface)
        appearance.titleTextAttributes = [.foregroundColor: UIColor(CyberDarkGoldTheme.primary)]
        appearance.largeTitleTextAttributes = [.foregroundColor: UIColor(CyberDarkGoldTheme.primary)]
        
        UINavigationBar.appearance().standardAppearance = appearance
        UINavigationBar.appearance().scrollEdgeAppearance = appearance
        UINavigationBar.appearance().compactAppearance = appearance
    }

    public var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(historyStore)
                .environmentObject(preferences)
                .preferredColorScheme(.dark)
        }
    }
}
