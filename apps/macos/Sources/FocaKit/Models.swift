import Foundation

// What the app reads from foca's JSON: only the fields it shows. Unknown
// fields are ignored, as design §8.4 asks of readers. client.reported is
// never decoded: nothing the app shows may come from it (design §8.7).

public struct Resource: Decodable, Equatable, Hashable {
    public let kind: String
    public let id: String
}

public struct Realm: Decodable, Equatable {
    public let kind: String
    public let name: String
}

public struct VerifiedPeer: Decodable, Equatable {
    public let name: String?
    public let realm: Realm?
}

public struct Peer: Decodable, Equatable {
    public let verified: VerifiedPeer?
}

public struct Approval: Decodable, Equatable {
    public let id: String?
    public let mode: String?
    /// Set when the host's config made the grant quiet (notify = false).
    public let quiet: Bool?
}

/// One line of `foca events query` or `follow` (design §8.1).
public struct AuditEvent: Decodable, Equatable {
    public let seq: UInt64
    public let ts: String
    public let instance: String?
    public let type: String
    public let outcome: String
    public let reason: String?
    public let resource: Resource?
    public let resources: [Resource]?
    public let params: [String: String]?
    public let approval: Approval?
    public let peer: Peer?
    public let count: Int?
    /// Shared by the events of one request: its approval and each read or run.
    public let requestID: String?

    enum CodingKeys: String, CodingKey {
        case seq, ts, instance, type, outcome, reason, resource, resources, params, approval, peer, count
        case requestID = "request_id"
    }

    public var date: Date? { GoTime.parse(ts) }
}

/// A line of `foca events query`: an event, or the last line saying where
/// the next page starts.
public enum QueryLine: Equatable {
    case event(AuditEvent)
    case next(afterSeq: UInt64)

    private struct NextPage: Decodable {
        let next_after_seq: UInt64
    }

    public static func parse(_ line: Data) -> QueryLine? {
        let d = JSONDecoder()
        if let e = try? d.decode(AuditEvent.self, from: line) {
            return .event(e)
        }
        if let n = try? d.decode(NextPage.self, from: line) {
            return .next(afterSeq: n.next_after_seq)
        }
        return nil
    }
}

public struct KeyPart: Decodable, Equatable, Hashable {
    public let value: String
    public let by: String
}

public struct ScopeKey: Decodable, Equatable, Hashable {
    public let instance: String
    public let connection: KeyPart?
    public let peerSession: KeyPart?

    enum CodingKeys: String, CodingKey {
        case instance, connection
        case peerSession = "peer_session"
    }
}

/// One live grant in `foca grants --host -f json` (design §8.6).
public struct Grant: Decodable, Equatable, Hashable, Identifiable {
    public let kind: String
    public let name: String
    public let params: [String: String]?
    public let scope: String
    public let scopeKey: ScopeKey?
    public let approvalID: String
    public let grantedAt: String
    public let expiresAt: String
    /// Set when the host's config made the grant quiet (notify = false).
    public let quiet: Bool?

    enum CodingKeys: String, CodingKey {
        case kind, name, params, scope, quiet
        case scopeKey = "scope_key"
        case approvalID = "approval_id"
        case grantedAt = "granted_at"
        case expiresAt = "expires_at"
    }

    public var id: String { approvalID + "|" + kind + ":" + name }
    public var expires: Date? { GoTime.parse(expiresAt) }
    public var isQuiet: Bool { quiet ?? false }
}

/// One instance in `foca grants --host -f json`.
public struct InstanceGrants: Decodable, Equatable, Identifiable {
    public let instance: String
    public let running: Bool
    public let reuse: Bool
    public let writtenAt: String?
    public let grants: [Grant]
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case instance, running, reuse, grants, error
        case writtenAt = "written_at"
    }

    public var id: String { instance }

    /// Worth a place in the menu: it holds grants, or its service runs but
    /// its grants can't be read. An instance with nothing to say is left out.
    public var isWorthShowing: Bool { !grants.isEmpty || (running && error != nil) }

    /// Parses the command's output, one object per line. Lines that don't
    /// parse are skipped; the caller tells an empty result from an error by
    /// the exit status.
    public static func parse(_ output: Data) -> [InstanceGrants] {
        let d = JSONDecoder()
        return output.split(separator: UInt8(ascii: "\n")).compactMap { try? d.decode(InstanceGrants.self, from: Data($0)) }
    }
}

/// Times as Go writes them: RFC 3339 with zero to nine fractional digits.
public enum GoTime {
    private static let plain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    public static func parse(_ s: String) -> Date? {
        var base = s
        var fraction = 0.0
        if let dot = s.firstIndex(of: ".") {
            let rest = s[s.index(after: dot)...]
            let digits = rest.prefix(while: { $0.isASCII && $0.isNumber })
            guard !digits.isEmpty, let f = Double("0." + digits) else {
                return nil
            }
            fraction = f
            base = String(s[..<dot]) + String(rest.dropFirst(digits.count))
        }
        return plain.date(from: base)?.addingTimeInterval(fraction)
    }
}
