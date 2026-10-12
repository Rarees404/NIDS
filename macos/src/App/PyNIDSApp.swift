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
    @Published var attention: AttentionResponse?
    @Published var error: String?
    @Published var launchAtLogin: Bool = SMAppService.mainApp.status == .enabled
    @Published var busy = false

    private var timer: Timer?
    private var ticks = 0
    private var lastEventTotal = -1
    private var lastWidgetReload = Date.distantPast

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    var level: Level { Level(summary?.level ?? "ok") }
    /// High-severity alerts in the last hour plus untrusted programs — the menu bar badge.
    var threats: Int { (snapshot?.recentHigh ?? 0) + (attention?.host?.flaggedPrograms ?? 0) }
    var host: HostSummary? { attention?.host }
    var needsRoot: Bool { summary?.status.state == "needs-root" }
    var paused: Bool { summary?.status.paused ?? false }
    var daemonInstalled: Bool { FileManager.default.fileExists(atPath: Daemon.plist) }

    func refresh(full: Bool = false) {
        ticks += 1
        // The attention summary reads the live socket table; every ~15 s is plenty.
        let wantAttention = full || attention == nil || ticks % 5 == 0
        Task {
            do {
                let s = try await PyNIDSClient.get("/api/summary", as: Summary.self)
                let a = try await PyNIDSClient.get("/api/alerts?limit=8&min_severity=MEDIUM", as: [AlertItem].self)
                snapshot = try? await PyNIDSClient.widgetSnapshot()
                if wantAttention {
                    attention = try? await PyNIDSClient.get("/api/attention", as: AttentionResponse.self)
                }
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
                attention = nil
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

    /// Stop: the daemon keeps running but stops capturing, so nothing is
    /// detected and no alerts pop up.  Persists across restarts until resumed.
    func setDetection(_ enabled: Bool) {
        busy = true
        Task {
            do {
                _ = try await PyNIDSClient.request("/api/detection", method: "POST", body: ["enabled": enabled])
            } catch {
                self.error = error.localizedDescription
            }
            busy = false
            refresh(full: true)
            // The widget should say "Stopped" / come back right away, not in 5 minutes.
            WidgetCenter.shared.reloadAllTimelines()
        }
    }

    /// Quit: unload the root daemon (and keep launchd from restarting it at
    /// boot), then quit the menu bar app.  Needs an administrator password.
    func quitEverything() {
        let alert = NSAlert()
        alert.messageText = "Quit PyNIDS completely?"
        alert.informativeText = "This shuts down the background daemon and the menu bar app. "
            + "Nothing will be monitored until you open PyNIDS again and start it."
        alert.addButton(withTitle: "Quit PyNIDS")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        // disable: launchd won't start it at boot.  bootout: stop it now (launchd
        // waits for a clean exit, then kills the whole process group, so no
        // helper — nettop, codesign, nmap — survives).  pkill: a daemon started
        // by hand with `sudo pynids daemon run`.
        runPrivileged("/bin/launchctl disable \(Daemon.target); "
                      + "/bin/launchctl bootout \(Daemon.target) 2>/dev/null; "
                      + "/usr/bin/pkill -TERM -f '\(Daemon.manualPattern)'; true") { [weak self] ok in
            guard ok, let self else { return }
            Task { @MainActor in
                if await self.waitUntilStopped() {
                    self.timer?.invalidate()
                    // Repaint the widget as "Not running" before we disappear.
                    WidgetCenter.shared.reloadAllTimelines()
                    NSApp.terminate(nil)
                } else {
                    self.error = "PyNIDS is still running. Try again, or run: sudo pynids daemon uninstall"
                    self.refresh(full: true)
                }
            }
        }
    }

    /// True once the daemon's API stops answering (up to ~10 s).
    private func waitUntilStopped() async -> Bool {
        for _ in 0..<20 {
            if (try? await PyNIDSClient.request("/api/health", authenticated: false)) == nil { return true }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return false
    }

    /// Start the daemon again after a Quit.
    func startDaemon() {
        runPrivileged("/bin/launchctl enable \(Daemon.target); "
                      + "/bin/launchctl bootstrap system '\(Daemon.plist)' || "
                      + "/bin/launchctl kickstart \(Daemon.target)") { [weak self] _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                self?.refresh(full: true)
                WidgetCenter.shared.reloadAllTimelines()
            }
        }
    }

    /// Run a shell command as root through the standard macOS password prompt.
    private func runPrivileged(_ command: String, completion: @escaping @MainActor (Bool) -> Void) {
        busy = true
        let script = "do shell script \"\(command)\" with administrator privileges"
        Task.detached {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            proc.arguments = ["-e", script]
            let errPipe = Pipe()
            proc.standardError = errPipe
            var ok = false
            var message = ""
            do {
                try proc.run()
                proc.waitUntilExit()
                ok = proc.terminationStatus == 0
                message = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            } catch {
                message = error.localizedDescription
            }
            let (succeeded, output) = (ok, message)
            await MainActor.run {
                self.busy = false
                // -128 is the user pressing Cancel on the password prompt.
                if !succeeded && !output.contains("-128") {
                    self.error = output.trimmingCharacters(in: .whitespacesAndNewlines)
                }
                completion(succeeded)
            }
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

enum Daemon {
    static let label = "com.pynids.daemon"
    static let target = "system/\(label)"
    static let plist = "/Library/LaunchDaemons/\(label).plist"
    /// `pkill -f` pattern for a daemon started by hand (`pynids daemon run`).
    /// "[p]" keeps the pattern from matching the shell that runs pkill, whose
    /// own command line contains this text.
    static let manualPattern = "[p]ynids.* daemon run"
}

// MARK: - Menu bar icon

struct MenuBarLabel: View {
    @ObservedObject var monitor: Monitor

    var body: some View {
        let symbol = monitor.summary == nil ? "shield.slash"
            : monitor.paused ? "pause.circle" : monitor.level.symbol
        HStack(spacing: 3) {
            Image(systemName: symbol)
            if monitor.threats > 0 && !monitor.paused {
                Text("\(monitor.threats)").monospacedDigit()
            }
        }
        .accessibilityLabel("PyNIDS: \(monitor.summary == nil ? "offline" : monitor.paused ? "stopped" : monitor.level.title)")
    }
}

// MARK: - Popover

struct MenuContent: View {
    @ObservedObject var monitor: Monitor

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if let s = monitor.summary {
                if monitor.paused {
                    Notice(text: "Detection is stopped — no traffic is analysed and no alerts are shown.")
                } else if monitor.needsRoot {
                    Notice(text: "Packet capture needs root. Run: sudo pynids daemon install")
                }
                stats(s)
                attentionList
                throughput(s)
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
            Image(systemName: monitor.summary == nil ? "shield.slash"
                  : monitor.paused ? "pause.circle" : monitor.level.symbol)
                .font(.system(size: 26))
                .foregroundStyle(monitor.summary == nil || monitor.paused ? Color.secondary : monitor.level.color)
            VStack(alignment: .leading, spacing: 1) {
                Text("PyNIDS").font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Button { monitor.refresh(full: true) } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless)
                .help("Refresh")
            powerMenu
        }
    }

    private var powerMenu: some View {
        Menu {
            if monitor.summary != nil {
                if monitor.paused {
                    Button("Resume Detection") { monitor.setDetection(true) }
                } else {
                    // Pause: capture and every scan stop; the daemon stays up so Resume is instant.
                    Button("Stop Detection (pause)") { monitor.setDetection(false) }
                }
            } else if monitor.daemonInstalled {
                Button("Start PyNIDS…") { monitor.startDaemon() }
            }
            Divider()
            Button("Quit PyNIDS Completely…") { monitor.quitEverything() }
                .disabled(!monitor.daemonInstalled)
            Button("Quit Menu Bar App Only") { NSApp.terminate(nil) }
        } label: {
            Image(systemName: "power")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .disabled(monitor.busy)
        .help("Stop or quit PyNIDS")
    }

    private var subtitle: String {
        guard let s = monitor.summary else { return "Daemon offline" }
        if monitor.paused { return "Stopped · not detecting" }
        let ifaces = (s.status.interfaces ?? []).joined(separator: " + ")
        return "\(monitor.level.title) · \(ifaces.isEmpty ? "—" : ifaces) · \(Format.bits(s.rates.bps))"
    }

    private func stats(_ s: Summary) -> some View {
        let flagged = monitor.host?.flaggedPrograms ?? 0
        return Grid(horizontalSpacing: 8, verticalSpacing: 8) {
            GridRow {
                StatTile(title: "Notable · last hour", value: monitor.snapshot?.attention ?? 0,
                         symbol: "exclamationmark.shield",
                         tint: (monitor.snapshot?.recentHigh ?? 0) > 0 ? Palette.critical : .secondary)
                    .onTapGesture { monitor.openDashboard("#events") }
                StatTile(title: "Untrusted programs", value: flagged, symbol: "app.badge.checkmark",
                         tint: flagged > 0 ? Palette.serious : .secondary,
                         placeholder: monitor.host == nil)
                    .onTapGesture { monitor.openDashboard("#connections") }
            }
            GridRow {
                StatTile(title: "Exposed ports", value: monitor.host?.exposedPorts ?? 0,
                         symbol: "door.left.hand.open", tint: .secondary, placeholder: monitor.host == nil)
                    .onTapGesture { monitor.openDashboard("#connections") }
                StatTile(title: "Trackers & beacons", value: s.count("tracker", "beacon"), symbol: "eye", tint: .secondary)
                    .onTapGesture { monitor.openDashboard("#events") }
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

    /// "Needs your attention" — the same list as the dashboard's Overview:
    /// serious alerts from the last hour, untrusted programs, exposed ports,
    /// new LAN devices.  Alerts keep their hover-to-block button.
    @ViewBuilder
    private var attentionList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Needs your attention").font(.caption).foregroundStyle(.secondary)
            if monitor.paused {
                Text("Nothing is checked while detection is stopped.").font(.callout).foregroundStyle(.secondary)
            } else if let items = monitor.attention?.items, !items.isEmpty {
                ForEach(items.prefix(4)) { item in
                    if item.action?.type == "alert", let a = monitor.alerts.first(where: { $0.alertId == item.action?.id }) {
                        AlertRow(alert: a, onBlock: { ip in monitor.block(ip, reason: a.message) })
                            .onTapGesture { monitor.openDashboard("#events") }
                    } else {
                        AttentionRow(item: item)
                            .onTapGesture { monitor.openDashboard(item.anchor) }
                    }
                }
            } else if monitor.attention == nil && !monitor.alerts.isEmpty {
                // Older daemon without /api/attention: fall back to recent alerts.
                ForEach(monitor.alerts.prefix(4)) { a in
                    AlertRow(alert: a, onBlock: { ip in monitor.block(ip, reason: a.message) })
                        .onTapGesture { monitor.openDashboard("#events") }
                }
            } else {
                Label("All clear — nothing needs a look right now.", systemImage: "checkmark.circle")
                    .font(.callout).foregroundStyle(.secondary)
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

    @ViewBuilder
    private var offline: some View {
        if monitor.daemonInstalled {
            VStack(alignment: .leading, spacing: 8) {
                Text("PyNIDS is shut down.").font(.callout)
                Button {
                    monitor.startDaemon()
                } label: {
                    Label("Start PyNIDS", systemImage: "play.fill")
                }
                .disabled(monitor.busy)
                if let error = monitor.error, !error.contains("not running") {
                    Text(error).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                }
            }
        } else {
            notInstalled
        }
    }

    private var notInstalled: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("The PyNIDS daemon isn't installed.").font(.callout)
            Text("Install it in Terminal:").font(.caption).foregroundStyle(.secondary)
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
            Button { monitor.openDashboard("#overview") } label: { Image(systemName: "sparkles") }
                .buttonStyle(.borderless)
                .disabled(monitor.summary == nil)
                .help("Ask Claude about your Mac (opens the dashboard)")
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
                Button("Refresh widget") { WidgetCenter.shared.reloadAllTimelines() }
                Divider()
                Toggle("Launch at login", isOn: Binding(
                    get: { monitor.launchAtLogin },
                    set: { _ in monitor.toggleLaunchAtLogin() }))
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
    var placeholder = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: symbol)
                .font(.caption)
                .foregroundStyle(tint)
                .lineLimit(1)
            Text(placeholder ? "—" : Format.count(value))
                .font(.system(size: 22, weight: .semibold))
                .monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .contentShape(Rectangle())
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
                Text(alert.headline).font(.callout).lineLimit(2)
                Text([alert.about?.verdict ?? Severity.label(alert.severity), alert.context?.app,
                      Format.ago(alert.timestamp)]
                    .compactMap { $0 }.joined(separator: " · "))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .help(alert.about.map { "\($0.meaning)\n\nWhat to do: " + ($0.nextSteps ?? []).joined(separator: " ") }
                  ?? alert.message)
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

/// A non-alert attention item (untrusted program, exposed ports, new device).
struct AttentionRow: View {
    let item: AttentionItem
    @StateObject private var hover = HoverState()

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: Severity.symbol(item.level))
                .foregroundStyle(Severity.color(item.level))
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title).font(.callout).lineLimit(2)
                if let detail = item.detail, !detail.isEmpty {
                    Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                }
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                .opacity(hover.on ? 1 : 0)
        }
        .padding(.vertical, 3)
        .padding(.horizontal, 4)
        .background(hover.on ? Color.primary.opacity(0.06) : .clear, in: RoundedRectangle(cornerRadius: 6))
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
