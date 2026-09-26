import Foundation

/// Talks to the PyNIDS daemon's local API on 127.0.0.1.
enum PyNIDSClient {
    static let base = URL(string: "http://127.0.0.1:8787")!
    static let dashboard = URL(string: "http://127.0.0.1:8787/")!

    enum ClientError: LocalizedError {
        case offline
        case http(Int, String)

        var errorDescription: String? {
            switch self {
            case .offline: return "The PyNIDS daemon is not running."
            case .http(let code, let message): return "API error \(code): \(message)"
            }
        }
    }

    /// The daemon writes a random token here (mode 0644) for local clients.
    static func token() -> String {
        var paths = ["/Library/Application Support/PyNIDS/api-token"]
        if let home = ProcessInfo.processInfo.environment["PYNIDS_HOME"] {
            paths.insert(home + "/api-token", at: 0)
        }
        paths.append(NSHomeDirectory() + "/Library/Application Support/PyNIDS/api-token")
        for path in paths {
            if let value = try? String(contentsOfFile: path, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
                return value
            }
        }
        return ""
    }

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 4
        config.timeoutIntervalForResource = 8
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: config)
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    static func request(_ path: String, method: String = "GET", body: [String: Any]? = nil,
                        authenticated: Bool = true) async throws -> Data {
        var req = URLRequest(url: URL(string: path, relativeTo: base)!)
        req.httpMethod = method
        if authenticated { req.setValue(token(), forHTTPHeaderField: "X-PyNIDS-Token") }
        if let body {
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw ClientError.offline
        }
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw ClientError.http(http.statusCode, message ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode))
        }
        return data
    }

    static func get<T: Decodable>(_ path: String, as type: T.Type, authenticated: Bool = true) async throws -> T {
        try decoder.decode(T.self, from: try await request(path, authenticated: authenticated))
    }

    static func widgetSnapshot() async throws -> WidgetSnapshot {
        try await get("/api/widget", as: WidgetSnapshot.self, authenticated: false)
    }
}
