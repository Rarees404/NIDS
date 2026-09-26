import Charts
import SwiftUI
import WidgetKit

// MARK: - Timeline

struct Entry: TimelineEntry {
    let date: Date
    let snapshot: WidgetSnapshot?
}

struct Provider: TimelineProvider {
    func placeholder(in context: Context) -> Entry { Entry(date: .now, snapshot: nil) }

    func getSnapshot(in context: Context, completion: @escaping (Entry) -> Void) {
        Task { completion(Entry(date: .now, snapshot: try? await PyNIDSClient.widgetSnapshot())) }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<Entry>) -> Void) {
        Task {
            let snap = try? await PyNIDSClient.widgetSnapshot()
            // The menu bar app also asks WidgetKit to reload whenever new events arrive.
            let next = Calendar.current.date(byAdding: .minute, value: snap == nil ? 2 : 5, to: .now)!
            completion(Timeline(entries: [Entry(date: .now, snapshot: snap)], policy: .after(next)))
        }
    }
}

// MARK: - Root

struct PyNIDSWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: Entry

    var body: some View {
        Group {
            if let s = entry.snapshot {
                switch family {
                case .systemSmall: SmallView(s: s, date: entry.date)
                case .systemLarge: LargeView(s: s, date: entry.date)
                default: MediumView(s: s, date: entry.date)
                }
            } else {
                OfflineView(date: entry.date)
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
        .widgetURL(URL(string: "pynids://events"))
    }
}

// MARK: - Status model

/// What the widget headlines: capture state first, then whether anything
/// notable happened in the last hour.
struct Status {
    let symbol: String
    let color: Color
    let title: String
    let detail: String
    let count: Int?

    init(_ s: WidgetSnapshot) {
        if s.needsRoot {
            symbol = "shield.slash"
            color = .secondary
            title = "Capture off"
            detail = "Run: sudo pynids daemon install"
            count = nil
        } else if s.attention == 0 {
            symbol = "checkmark.shield.fill"
            color = Palette.good
            title = "All clear"
            detail = "Nothing notable in the last hour"
            count = nil
        } else {
            let level = Level(s.level)
            symbol = level == .ok ? Level.notice.symbol : level.symbol
            color = level == .ok ? Palette.warning : level.color
            title = (s.recentHigh ?? 0) > 0 ? "Needs attention" : "Worth a look"
            let high = s.recentHigh ?? 0
            detail = high > 0 ? "\(high) high-severity in the last hour" : "alerts in the last hour"
            count = s.attention
        }
    }
}

// MARK: - Building blocks

struct Header: View {
    let status: Status

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: status.symbol)
                .foregroundStyle(status.color)
                .font(.system(size: 13, weight: .semibold))
            Text("PyNIDS").font(.system(size: 13, weight: .semibold))
            Spacer(minLength: 4)
        }
    }
}

struct Hero: View {
    let status: Status
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let count = status.count {
                Text(Format.count(count))
                    .font(.system(size: compact ? 34 : 38, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(status.color)
                    .contentTransition(.numericText())
                Text(status.title)
                    .font(.system(size: 12, weight: .semibold))
            } else {
                Image(systemName: status.symbol)
                    .font(.system(size: compact ? 30 : 34, weight: .medium))
                    .foregroundStyle(status.color)
                    .padding(.bottom, 2)
                Text(status.title)
                    .font(.system(size: 15, weight: .semibold))
            }
            Text(status.detail)
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .minimumScaleFactor(0.85)
        }
    }
}

struct Metric: View {
    let label: String
    let value: Int
    let symbol: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .frame(width: 14)
            Text(label).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 2)
            Text(Format.count(value)).font(.system(size: 11.5, weight: .semibold)).monospacedDigit()
        }
    }
}

struct Throughput: View {
    let s: WidgetSnapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 4) {
                Text("Throughput").font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer(minLength: 2)
                Text(Format.bits(s.bps)).font(.system(size: 10, weight: .semibold)).monospacedDigit()
            }
            Chart {
                ForEach(Array(s.seriesBps.enumerated()), id: \.offset) { i, v in
                    AreaMark(x: .value("t", i), y: .value("bps", v))
                        .foregroundStyle(Palette.series.opacity(0.14))
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("t", i), y: .value("bps", v))
                        .foregroundStyle(Palette.series)
                        .lineStyle(StrokeStyle(lineWidth: 1.6, lineCap: .round, lineJoin: .round))
                        .interpolationMethod(.monotone)
                }
            }
            .chartXAxis(.hidden)
            .chartYAxis(.hidden)
            .chartYScale(domain: 0...max(1, (s.seriesBps.max() ?? 1) * 1.15))
        }
    }
}

struct Updated: View {
    let date: Date

    var body: some View {
        (Text("Updated ") + Text(date, style: .time))
            .font(.system(size: 9.5))
            .foregroundStyle(.tertiary)
    }
}

struct SectionTitle: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 9.5, weight: .semibold))
            .tracking(0.4)
            .foregroundStyle(.secondary)
    }
}

// MARK: - Sizes

struct SmallView: View {
    let s: WidgetSnapshot
    let date: Date

    var body: some View {
        let status = Status(s)
        VStack(alignment: .leading, spacing: 0) {
            Header(status: status)
            Spacer(minLength: 4)
            Hero(status: status, compact: true)
            Spacer(minLength: 6)
            HStack(spacing: 10) {
                Label(Format.count(s.trackers), systemImage: "eye")
                Label(Format.count(s.leaks), systemImage: "network.badge.shield.half.filled")
                Label(Format.count(s.encryptedDns), systemImage: "lock.shield")
            }
            .font(.system(size: 10.5, weight: .medium))
            .monospacedDigit()
            .foregroundStyle(.secondary)
            .labelStyle(TightLabel())
        }
    }
}

struct TightLabel: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 3) { configuration.icon; configuration.title }
    }
}

struct MediumView: View {
    let s: WidgetSnapshot
    let date: Date

    var body: some View {
        let status = Status(s)
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 0) {
                Header(status: status)
                Spacer(minLength: 4)
                Hero(status: status)
                Spacer(minLength: 4)
                Updated(date: date)
            }
            .frame(width: 128, alignment: .leading)

            VStack(alignment: .leading, spacing: 5) {
                SectionTitle(text: "This session")
                Metric(label: "Trackers", value: s.trackers, symbol: "eye")
                Metric(label: "Leaks & probes", value: s.leaks, symbol: "network.badge.shield.half.filled")
                Metric(label: "Encrypted DNS", value: s.encryptedDns, symbol: "lock.shield")
                Metric(label: "Countries", value: s.countries, symbol: "globe")
                Throughput(s: s).padding(.top, 2)
            }
        }
    }
}

struct LargeView: View {
    let s: WidgetSnapshot
    let date: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            MediumView(s: s, date: date).frame(height: 136)
            Divider()
            attention
            apps
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private var attention: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionTitle(text: "Needs attention")
            let alerts = s.notableAlerts ?? []
            if alerts.isEmpty {
                Label("Nothing notable in the last hour", systemImage: "checkmark.circle")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(alerts.enumerated()), id: \.offset) { _, a in
                    HStack(alignment: .top, spacing: 7) {
                        Image(systemName: Severity.symbol(a.severity ?? "LOW"))
                            .font(.system(size: 11))
                            .foregroundStyle(Severity.color(a.severity ?? "LOW"))
                            .frame(width: 14)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(a.message ?? "").font(.system(size: 11.5)).lineLimit(2)
                            Text([a.severity.map(Severity.label), a.app, Format.ago(a.timestamp)]
                                .compactMap { $0 }.joined(separator: " · "))
                                .font(.system(size: 10)).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var apps: some View {
        if !s.topApps.isEmpty {
            let total = max(s.totalBytes ?? s.topApps.reduce(0) { $0 + $1.bytes }, 1)
            VStack(alignment: .leading, spacing: 6) {
                SectionTitle(text: "Busiest apps")
                ForEach(s.topApps.prefix(4)) { app in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(app.app).font(.system(size: 11.5, weight: .medium)).lineLimit(1)
                            if app.alerts > 0 {
                                Text("\(app.alerts) alert\(app.alerts == 1 ? "" : "s")")
                                    .font(.system(size: 9.5)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(Format.bytes(app.bytes)).font(.system(size: 11)).monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                Capsule().fill(Palette.series.opacity(0.14))
                                Capsule().fill(Palette.series)
                                    .frame(width: max(3, geo.size.width * min(1, app.bytes / total)))
                            }
                        }
                        .frame(height: 4)
                    }
                }
            }
        }
    }
}

struct OfflineView: View {
    let date: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 5) {
                Image(systemName: "shield.slash").foregroundStyle(.secondary)
                Text("PyNIDS").font(.system(size: 13, weight: .semibold))
            }
            Spacer(minLength: 0)
            Text("Not running").font(.system(size: 15, weight: .semibold))
            Text("Start the monitor in Terminal:")
                .font(.system(size: 10.5)).foregroundStyle(.secondary)
            Text("sudo pynids daemon install")
                .font(.system(size: 9.5, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Spacer(minLength: 0)
            Updated(date: date)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Widget

struct PyNIDSStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "PyNIDSStatus", provider: Provider()) { entry in
            PyNIDSWidgetView(entry: entry)
        }
        .configurationDisplayName("PyNIDS")
        .description("What needs your attention on the network, plus trackers, leaks, and throughput.")
        .supportedFamilies([.systemSmall, .systemMedium, .systemLarge])
    }
}

@main
struct PyNIDSWidgets: WidgetBundle {
    var body: some Widget {
        PyNIDSStatusWidget()
    }
}
