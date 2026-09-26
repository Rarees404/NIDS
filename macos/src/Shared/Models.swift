import Foundation
import SwiftUI

// MARK: - API payloads (mirror pynids/service/api.py)

struct TopApp: Codable, Hashable, Identifiable {
    let app: String
    let bytes: Double
    let alerts: Int
    var id: String { app }
}

struct BriefAlert: Codable, Hashable {
    let alertId: String?
    let timestamp: Double?
    let severity: String?
    let kind: String?
    let title: String?
    let subject: String?
    let message: String?
    let app: String?
}

/// `/api/widget` — unauthenticated, counts only (the sandboxed widget can't read the token).
struct WidgetSnapshot: Codable, Hashable {
    let level: String
    let eventsTotal: Int
    let threats: Int
    let trackers: Int
    let leaks: Int
    let encryptedDns: Int
    let blocked: Int
    let pps: Double
    let bps: Double
    let seriesBps: [Double]
    let topApps: [TopApp]
    let countries: Int
    let lastAlert: BriefAlert?
    let uptime: Int
    let status: String
    // Added in 2.0.1 — optional so an older daemon still decodes.
    let recentNotable: Int?
    let recentHigh: Int?
    let notableAlerts: [BriefAlert]?
    let totalBytes: Double?

    var needsRoot: Bool { status == "needs-root" }
    var attention: Int { recentNotable ?? 0 }
}

struct Rates: Codable, Hashable {
    let pps: Double
    let bps: Double
    let seriesBps: [Double]
}

struct DaemonStatus: Codable, Hashable {
    let state: String?
    let interfaces: [String]?
    let notifications: Bool?
    let autoBlock: Bool?
    let ai: Bool?
    let geoip: Bool?
    let version: String?
}

/// `/api/summary`
struct Summary: Codable, Hashable {
    let uptime: Int
    let packets: Int
    let bytes: Double
    let eventsTotal: Int
    let kinds: [String: Int]
    let lastAlert: BriefAlert?
    let topApps: [TopApp]
    let remoteCount: Int
    let countryCount: Int
    let rates: Rates
    let status: DaemonStatus
    let level: String
    let blocked: Int

    func count(_ keys: String...) -> Int { keys.reduce(0) { $0 + (kinds[$1] ?? 0) } }
}

struct AlertContext: Codable, Hashable {
    let app: String?
    let remoteHost: String?
    let remoteIp: String?
    let country: String?
}

struct AlertItem: Codable, Hashable, Identifiable {
    let alertId: String
    let timestamp: Double
    let severity: String
    let kind: String?
    let message: String
    let ruleId: String?
    let dstIp: String?
    let context: AlertContext?
    var id: String { alertId }
}

// MARK: - Presentation helpers shared by the app and the widget

enum Level: String {
    case ok, notice, warning, critical

    init(_ raw: String) { self = Level(rawValue: raw) ?? .ok }

    var symbol: String {
        switch self {
        case .ok: return "checkmark.shield.fill"
        case .notice: return "shield.lefthalf.filled"
        case .warning: return "exclamationmark.shield.fill"
        case .critical: return "xmark.shield.fill"
        }
    }

    var color: Color {
        switch self {
        case .ok: return Palette.good
        case .notice: return Palette.warning
        case .warning: return Palette.serious
        case .critical: return Palette.critical
        }
    }

    var title: String {
        switch self {
        case .ok: return "All clear"
        case .notice: return "Notable activity"
        case .warning: return "High-severity activity"
        case .critical: return "Critical activity"
        }
    }
}

enum Palette {
    static let good = Color(red: 0x0c / 255, green: 0xa3 / 255, blue: 0x0c / 255)
    static let warning = Color(red: 0xfa / 255, green: 0xb2 / 255, blue: 0x19 / 255)
    static let serious = Color(red: 0xec / 255, green: 0x83 / 255, blue: 0x5a / 255)
    static let critical = Color(red: 0xd0 / 255, green: 0x3b / 255, blue: 0x3b / 255)
    static let series = Color(red: 0x3a / 255, green: 0x82 / 255, blue: 0xde / 255)
}

enum Severity {
    static func symbol(_ s: String) -> String {
        switch s {
        case "CRITICAL": return "xmark.octagon.fill"
        case "HIGH": return "exclamationmark.circle.fill"
        case "MEDIUM": return "exclamationmark.triangle.fill"
        default: return "info.circle"
        }
    }

    static func color(_ s: String) -> Color {
        switch s {
        case "CRITICAL": return Palette.critical
        case "HIGH": return Palette.serious
        case "MEDIUM": return Palette.warning
        default: return .secondary
        }
    }

    static func label(_ s: String) -> String { s.prefix(1) + s.dropFirst().lowercased() }
}

enum Format {
    static func bytes(_ value: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .decimal)
    }

    static func bits(_ value: Double) -> String {
        let units = ["bps", "Kbps", "Mbps", "Gbps"]
        var v = value
        var i = 0
        while v >= 1000 && i < units.count - 1 { v /= 1000; i += 1 }
        return i == 0 ? "\(Int(v)) \(units[i])" : String(format: v < 10 ? "%.1f %@" : "%.0f %@", v, units[i])
    }

    static func count(_ n: Int) -> String {
        if n >= 1_000_000 { return String(format: "%.1fM", Double(n) / 1_000_000) }
        if n >= 10_000 { return String(format: "%.1fK", Double(n) / 1_000) }
        return NumberFormatter.localizedString(from: NSNumber(value: n), number: .decimal)
    }

    static func ago(_ ts: Double?) -> String {
        guard let ts else { return "" }
        let s = max(0, Date().timeIntervalSince1970 - ts)
        if s < 60 { return "just now" }
        if s < 3600 { return "\(Int(s / 60)) min ago" }
        if s < 86400 { return "\(Int(s / 3600)) h ago" }
        return "\(Int(s / 86400)) d ago"
    }
}
