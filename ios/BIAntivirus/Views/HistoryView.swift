import SwiftUI

public struct HistoryView: View {
    @State private var items: [FileInspectionResult] = []

    public init() {}

    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f
    }()

    public var body: some View {
        ZStack {
            CyberTheme.bgDarkest.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("INSPECTION AUDIT LOG")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(CyberTheme.textSecondary)
                    Spacer()
                    if !items.isEmpty {
                        Button(action: {
                            InspectionHistoryStore.shared.clear()
                            items = []
                        }) {
                            Text("Clear")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundColor(CyberTheme.goldAccent)
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 16)

                if items.isEmpty {
                    VStack(spacing: 8) {
                        Text("No inspection records.")
                            .font(.system(size: 14))
                            .foregroundColor(CyberTheme.textSecondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        ForEach(items) { item in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(item.fileName)
                                        .font(.system(size: 14, weight: .semibold))
                                        .foregroundColor(CyberTheme.textPrimary)
                                    Spacer()
                                    Text(item.verdict.rawValue)
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(item.verdict == .clean ? CyberTheme.statusSafe : CyberTheme.statusThreat)
                                }
                                HStack {
                                    Text(dateFormatter.string(from: item.timestamp))
                                        .font(.system(size: 11))
                                        .foregroundColor(CyberTheme.textSecondary)
                                    Spacer()
                                    Text("\(item.fileSize) bytes")
                                        .font(.system(size: 11))
                                        .foregroundColor(CyberTheme.textSecondary)
                                }
                            }
                            .padding(.vertical, 4)
                            .listRowBackground(CyberTheme.bgCard)
                        }
                    }
                    .scrollContentBackground(.hidden)
                }
            }
        }
        .navigationTitle("Inspection History")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            items = InspectionHistoryStore.shared.getRecent()
        }
    }
}
