import Foundation

/// Reuses grouped by approval (design §8.7). `credential_process` can reuse a
/// grant on every AWS call, so the first reuse of an approval notifies at
/// once, and later ones within the window update that one notification with
/// a count instead of adding more.
public struct ReuseBursts {
    public struct Burst: Equatable {
        public let approvalID: String
        public let first: Date
        public var count: Int
        /// What was reused, in the order first seen.
        public var resources: [String]
        /// Who reused it last, as ReuseText.peer words it.
        public var peer: String
    }

    public let window: TimeInterval
    private var bursts: [String: Burst] = [:]

    public init(window: TimeInterval = 60) {
        self.window = window
    }

    /// Records one reuse and returns the burst to show for it.
    public mutating func add(approvalID: String, resource: String, peer: String, at: Date) -> Burst {
        bursts = bursts.filter { at.timeIntervalSince($0.value.first) < window }
        if var b = bursts[approvalID] {
            b.count += 1
            if !b.resources.contains(resource) {
                b.resources.append(resource)
            }
            b.peer = peer
            bursts[approvalID] = b
            return b
        }
        let b = Burst(approvalID: approvalID, first: at, count: 1, resources: [resource], peer: peer)
        bursts[approvalID] = b
        return b
    }
}

/// The words of a reuse notification. Every part comes from fields the
/// host filled: the resource, its validated params, the instance, and the
/// peer as the kernel identified it. Never from client.reported, which a
/// notification can't mark as unverified the way the prompt does.
public enum ReuseText {
    public static func resource(_ r: Resource, params: [String: String]?) -> String {
        var s = Names.text(r.id)
        if r.kind == "action" {
            s = "action " + s
            if let p = params, !p.isEmpty {
                let pairs = p.keys.sorted().map { Names.text($0, max: Names.maxName) + "=" + Names.text(p[$0] ?? "", max: Names.maxName) }
                s += " (" + pairs.joined(separator: ", ") + ")"
            }
        }
        return s
    }

    /// "ssh (vm dev)": the verified program and the realm it was admitted
    /// for.
    public static func peer(_ p: Peer?, instance: String?) -> String {
        var name = Names.program(p?.verified?.name ?? "")
        if name.isEmpty {
            name = "an unnamed program"
        }
        if let r = p?.verified?.realm {
            let kind = Names.program(r.kind), realm = Names.program(r.name)
            if kind == "host" {
                return name + " (host)"
            }
            return name + " (" + kind + " " + realm + ")"
        }
        if let i = instance {
            return name + " (instance " + Names.program(i) + ")"
        }
        return name
    }

    public static func body(_ b: ReuseBursts.Burst) -> String {
        let what = b.resources.joined(separator: ", ")
        if b.count == 1 {
            return what + " reused by " + b.peer
        }
        return what + " reused \(b.count)× by " + b.peer + " in the last minute"
    }

    public static func missed(_ n: Int, capped: Bool) -> String {
        let count = capped ? "\(n)+" : "\(n)"
        return count + (n == 1 && !capped ? " grant was" : " grants were") + " reused while Foca wasn't running"
    }

    /// A grant in the menu: its name, an action's params, and what it is
    /// keyed on.
    public static func grant(_ g: Grant) -> String {
        resource(Resource(kind: g.kind, id: g.name), params: g.params)
    }
}

/// One line of recent activity.
public enum ActivityText {
    public static func describe(_ e: AuditEvent) -> String {
        var parts = [Names.text(e.type, max: Names.maxName)]
        if let r = e.resource {
            parts.append(ReuseText.resource(r, params: e.params))
        } else if let rs = e.resources, !rs.isEmpty {
            parts.append(rs.map { Names.text($0.id) }.joined(separator: ", "))
        }
        if e.type == "lock", let reason = e.reason {
            parts.append(Names.text(reason, max: Names.maxName) + (e.count.map { ", \($0) dropped" } ?? ""))
        }
        if e.outcome != "ok" {
            parts.append(Names.text(e.outcome, max: Names.maxName))
        }
        if e.peer?.verified != nil {
            parts.append("· " + ReuseText.peer(e.peer, instance: e.instance))
        }
        return parts.joined(separator: " ")
    }
}
