import AppKit
import Charts
import ServiceManagement
import SwiftUI
import WidgetKit

@main
struct PyNIDSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var monitor = Monitor()

    var body: some Scene {
        MenuBarExtra {
            MenuContent(monitor: monitor)
        } label: {
            MenuBarLabel(monitor: monitor)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Handles `pynids://` links from the desktop widget.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls where url.scheme == "pynids" {
            let anchor = url.host.map { "#\($0)" } ?? ""
            if let target = URL(string: PyNIDSClient.dashboard.absoluteString + anchor) {
                NSWorkspace.shared.open(target)
            }
        }
    }
}

// MARK: - Live model

@MainActor
final class Monitor: ObservableObject {
    @Published var summary: Summary?
    @Published var snapshot: WidgetSnapshot?
    @Published var alerts: [AlertItem] = []
    @Published var error: String?
    @Published var launchAtLogin: Bool = SMAppService.mainApp.status == .enabled

    private var timer: Timer?
    private var lastEventTotal = -1
    private var lastWidgetReload = Date.distantPast

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    var level: Level { Level(summary?.level ?? "ok") }
    /// High-severity alerts in the last hour — what the menu bar badge shows.
    var threats: Int { snapshot?.recentHigh ?? 0 }
    var needsRoot: Bool { summary?.status.state == "needs-root" }

    func refresh() {
        Task {
            do {
                let s = try await PyNIDSClient.get("/api/summary", as: Summary.self)
                let a = try await PyNIDSClient.get("/api/alerts?limit=8&min_severity=MEDIUM", as: [AlertItem].self)
                snapshot = try? await PyNIDSClient.widgetSnapshot()
                summary = s
                alerts = a
                error = nil
                // Keep the desktop widget in step, without burning its refresh budget.
                if s.eventsTotal != lastEventTotal, Date().timeIntervalSince(lastWidgetReload) > 60 {
                    lastEventTotal = s.eventsTotal
                    lastWidgetReload = Date()
                    WidgetCenter.shared.reloadAllTimelines()
                }
            } catch {
                summary = nil
                alerts = []
                self.error = error.localizedDescription
            }
        }
    }

    func setNotifications(_ enabled: Bool) {
        Task {
            _ = try? await PyNIDSClient.request("/api/notifications", method: "POST", body: ["enabled": enabled])
            refresh()
        }
    }

    func block(_ ip: String, reason: String) {
        Task {
            _ = try? await PyNIDSClient.request(
                "/api/blocks", method: "POST", body: ["ip": ip, "reason": reason, "ttl": 3600])
            refresh()
        }
    }

    func toggleLaunchAtLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            self.error = "Launch at login: \(error.localizedDescription)"
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func openDashboard(_ anchor: String = "") {
        NSWorkspace.shared.open(URL(string: PyNIDSClient.dashboard.absoluteString + anchor)!)
    }
}

// MARK: - Menu bar icon

struct MenuBarLabel: View {
    @ObservedObject var monitor: Monitor

    var body: some View {
        let symbol = monitor.summary == nil ? "shield.slash" : monitor.level.symbol
        HStack(spacing: 3) {
            Image(systemName: symbol)
            if monitor.threats > 0 {
                Text("\(monitor.threats)").monospacedDigit()
            }
        }
        .accessibilityLabel("PyNIDS: \(monitor.summary == nil ? "offline" : monitor.level.title)")
    }
}

// MARK: - Popover

struct MenuContent: View {
    @ObservedObject var monitor: Monitor

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if let s = monitor.summary {
                if monitor.needsRoot {
                    Notice(text: "Packet capture needs root. Run: sudo pynids daemon install")
                }
                stats(s)
                throughput(s)
                alertList
                apps(s)
            } else {
                offline
            }
            Divider()
            footer
        }
        .padding(14)
        .frame(width: 380)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: monitor.summary == nil ? "shield.slash" : monitor.level.symbol)
                .font(.system(size: 26))
                .foregroundStyle(monitor.summary == nil ? Color.secondary : monitor.level.color)
            VStack(alignment: .leading, spacing: 1) {
                Text("PyNIDS").font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Button { monitor.refresh() } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless)
                .help("Refresh")
        }
    }

    private var subtitle: String {
        guard let s = monitor.summary else { return "Daemon offline" }
        let ifaces = (s.status.interfaces ?? []).joined(separator: " + ")
        return "\(monitor.level.title) · \(ifaces.isEmpty ? "—" : ifaces) · \(Format.bits(s.rates.bps))"
    }

    private func stats(_ s: Summary) -> some View {
        Grid(horizontalSpacing: 8, verticalSpacing: 8) {
            GridRow {
                StatTile(title: "Notable · last hour", value: monitor.snapshot?.attention ?? 0,
                         symbol: "exclamationmark.shield",
                         tint: (monitor.snapshot?.recentHigh ?? 0) > 0 ? Palette.critical : .secondary)
                StatTile(title: "Trackers & beacons", value: s.count("tracker", "beacon"), symbol: "eye", tint: .secondary)
            }
            GridRow {
                StatTile(title: "IP leaks & probes", value: s.count("webrtc", "localhost"),
                         symbol: "network.badge.shield.half.filled", tint: .secondary)
                StatTile(title: "Encrypted DNS", value: s.count("doh"), symbol: "lock.shield", tint: .secondary)
            }
        }
    }

    private func throughput(_ s: Summary) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Throughput").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("\(Format.bits(s.rates.bps)) · \(Int(s.rates.pps)) pkt/s")
                    .font(.caption).monospacedDigit().foregroundStyle(.secondary)
            }
            Chart {
                ForEach(Array(s.rates.seriesBps.enumerated()), id: \.offset) { i, v in
                    AreaMark(x: .value("s", i), y: .value("bps", v))
                        .foregroundStyle(Palette.series.opacity(0.12))
                    LineMark(x: .value("s", i), y: .value("bps", v))
                        .foregroundStyle(Palette.series)
                        .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                }
            }
            .chartXAxis(.hidden)
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                    AxisGridLine().foregroundStyle(.quaternary)
                    AxisValueLabel {
                        if let v = value.as(Double.self) { Text(Format.bits(v)).font(.system(size: 9)) }
                    }
                }
            }
            .frame(height: 64)
            .accessibilityLabel("Throughput over the last minute, now \(Format.bits(s.rates.bps))")
        }
    }

    @ViewBuilder
    private var alertList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Recent alerts").font(.caption).foregroundStyle(.secondary)
            if monitor.alerts.isEmpty {
                Text("Nothing notable yet.").font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(monitor.alerts.prefix(5)) { a in
                    AlertRow(alert: a, onBlock: { ip in monitor.block(ip, reason: a.message) })
                        .onTapGesture { monitor.openDashboard("#events") }
                }
            }
        }
    }

    @ViewBuilder
    private func apps(_ s: Summary) -> some View {
        if !s.topApps.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("Busiest apps").font(.caption).foregroundStyle(.secondary)
                ForEach(s.topApps.prefix(4)) { app in
                    HStack {
                        Text(app.app).lineLimit(1)
                        if app.alerts > 0 {
                            Text("\(app.alerts) alerts").font(.caption2).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(Format.bytes(app.bytes)).monospacedDigit().foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
            }
        }
    }

    private var offline: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("The PyNIDS daemon isn't running.").font(.callout)
            Text("Start it in Terminal:").font(.caption).foregroundStyle(.secondary)
            Text("sudo pynids daemon install")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(6)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Button {
                monitor.openDashboard()
            } label: {
                Label("Open Dashboard", systemImage: "chart.bar.xaxis")
            }
            .keyboardShortcut("d")
            .disabled(monitor.summary == nil)
            Spacer()
            if let s = monitor.summary {
                let on = s.status.notifications ?? false
                Button { monitor.setNotifications(!on) } label: {
                    Image(systemName: on ? "bell.fill" : "bell.slash")
                }
                .buttonStyle(.borderless)
                .help(on ? "Pause notifications" : "Resume notifications")
            }
            Menu {
                Toggle("Launch at login", isOn: Binding(
                    get: { monitor.launchAtLogin },
                    set: { _ in monitor.toggleLaunchAtLogin() }))
                Divider()
                Button("Quit PyNIDS menu") { NSApp.terminate(nil) }
            } label: {
                Image(systemName: "gearshape")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }
}

struct StatTile: View {
    let title: String
    let value: Int
    let symbol: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: symbol)
                .font(.caption)
                .foregroundStyle(tint)
                .lineLimit(1)
            Text(Format.count(value))
                .font(.system(size: 22, weight: .semibold))
                .monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// Hover state as an observable object: the command-line-tools SDK lacks the
/// compiler plugin behind SwiftUI's `@State` macro, so `@State` can't be used
/// when building without Xcode.
final class HoverState: ObservableObject {
    @Published var on = false
}

struct AlertRow: View {
    let alert: AlertItem
    let onBlock: (String) -> Void
    @StateObject private var hover = HoverState()

    private var hovering: Bool { hover.on }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: Severity.symbol(alert.severity))
                .foregroundStyle(Severity.color(alert.severity))
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(alert.message).font(.callout).lineLimit(2)
                Text([Severity.label(alert.severity), alert.context?.app, Format.ago(alert.timestamp)]
                    .compactMap { $0 }.joined(separator: " · "))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if hovering, ["HIGH", "CRITICAL"].contains(alert.severity),
               let ip = alert.context?.remoteIp ?? alert.dstIp {
                Button { onBlock(ip) } label: { Image(systemName: "hand.raised") }
                    .buttonStyle(.borderless)
                    .help("Block \(ip) for 1 hour")
            }
        }
        .padding(.vertical, 3)
        .padding(.horizontal, 4)
        .background(hovering ? Color.primary.opacity(0.06) : .clear, in: RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onHover { hover.on = $0 }
    }
}

struct Notice: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.caption)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.warning.opacity(0.18), in: RoundedRectangle(cornerRadius: 8))
    }
}
