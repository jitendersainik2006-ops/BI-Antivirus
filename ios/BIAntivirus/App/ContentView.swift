import SwiftUI

public struct ContentView: View {
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding: Bool = false

    public init() {}

    public var body: some View {
        if hasCompletedOnboarding {
            DashboardView()
        } else {
            OnboardingView(onComplete: {
                hasCompletedOnboarding = true
            })
        }
    }
}
