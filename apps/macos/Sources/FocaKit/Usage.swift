import Foundation

/// How often each live grant has been used, and when last (design §8.7): the
/// access it was approved for and each reuse, as the activity row folds them.
/// Each is a secret.read or action.run that was served under the grant's
/// approval. A grant and its uses share the approval ID and the resource;
/// Grant.id is that pair.
public struct GrantUsage: Equatable {
    public struct Use: Equatable {
        public var count = 0
        public var last: Date?
        /// The latest uses, newest first, at most keptEntries of them.
        public var entries: [Entry] = []
    }

    /// One use, for the list a grant opens to.
    public struct Entry: Equatable, Identifiable {
        public let seq: UInt64
        public let date: Date?
        /// "approved" for the access the grant was made for, else "reused".
        public let how: String
        /// The program, as ReuseText.peer words it; "" if it wasn't verified.
        public let by: String

        public var id: UInt64 { seq }
    }

    /// How many uses a grant keeps to list; its count goes on past them.
    public static let keptEntries = 50

    private var uses: [String: Use] = [:]

    public init() {}

    /// The grant an event names, as Grant.id names it.
    public static func key(_ e: AuditEvent) -> String? {
        guard let id = e.approval?.id, let r = e.resource else { return nil }
        return id + "|" + r.kind + ":" + r.id
    }

    /// Counts e if it is a use of a grant: an access served under an approval
    /// made with a prompt or reused.
    public mutating func add(_ e: AuditEvent) {
        guard e.type == "secret.read" || e.type == "action.run", e.outcome == "ok",
              e.approval?.mode == "fresh" || e.approval?.mode == "reused", let k = Self.key(e) else { return }
        var u = uses[k] ?? Use()
        u.count += 1
        if let d = e.date, u.last.map({ d > $0 }) ?? true {
            u.last = d
        }
        let entry = Entry(seq: e.seq, date: e.date, how: e.approval?.mode == "fresh" ? "approved" : "reused",
                          by: e.peer?.verified != nil ? ReuseText.peer(e.peer, instance: e.instance) : "")
        // Events come oldest first when read back and as they happen, so a
        // new one almost always goes first; seq keeps the order either way.
        let at = u.entries.firstIndex { $0.seq < e.seq } ?? u.entries.count
        u.entries.insert(entry, at: at)
        if u.entries.count > Self.keptEntries {
            u.entries.removeLast(u.entries.count - Self.keptEntries)
        }
        uses[k] = u
    }

    public func of(_ g: Grant) -> Use { uses[g.id] ?? Use() }

    /// Forgets grants last used longer ago than any grant lasts: they have
    /// ended.
    public mutating func prune(now: Date) {
        uses = uses.filter { ($0.value.last ?? now) > now - maxGrantWindow }
    }

    /// "Used 3× · last 2m ago", "Used 14× · last just now"; "Not used yet" if
    /// its first access is older than the events read.
    public static func text(_ u: Use, now: Date) -> String {
        guard u.count > 0 else { return "Not used yet" }
        var when = u.last.map { ActivityStyle.ago($0, now: now) } ?? ""
        if when == "now" {
            when = "just now"
        }
        return "Used \(u.count)×" + (when.isEmpty ? "" : " · last " + when)
    }
}

/// The longest a grant can last (policy.MaxReuseWindow).
public let maxGrantWindow: TimeInterval = 8 * 3600

/// What the bell on each grant was set to in the menu, until that grant ends: a
/// grant muted, or a quiet one (notify = false) to be heard after all. A choice
/// names one grant (Grant.id), so a new approval of the same secret starts
/// from the config again.
public struct BellChoices: Equatable {
    private(set) var muted: [String: Date] = [:]
    private(set) var heard: [String: Date] = [:]

    public init() {}

    /// From what was saved. Choices already over are kept until prune: they
    /// still cover the reuses Foca missed while it wasn't running.
    public init(muted: [String: Double], heard: [String: Double]) {
        self.muted = muted.mapValues { Date(timeIntervalSince1970: $0) }
        self.heard = heard.mapValues { Date(timeIntervalSince1970: $0) }
    }

    public var storedMuted: [String: Double] { muted.mapValues(\.timeIntervalSince1970) }
    public var storedHeard: [String: Double] { heard.mapValues(\.timeIntervalSince1970) }

    /// Whether reuses of the grant named key are announced at now: a quiet
    /// grant only if it was turned on, any other unless it was muted.
    public func notifies(_ key: String, quiet: Bool, now: Date) -> Bool {
        if quiet {
            return heard[key].map { $0 > now } ?? false
        }
        return !(muted[key].map { $0 > now } ?? false)
    }

    /// Flips g's bell, until g ends.
    public mutating func toggle(_ g: Grant, now: Date) {
        guard let end = g.expires else { return }
        let on = notifies(g.id, quiet: g.isQuiet, now: now)
        if g.isQuiet {
            heard[g.id] = on ? nil : end
        } else {
            muted[g.id] = on ? end : nil
        }
    }

    public mutating func prune(now: Date) {
        muted = muted.filter { $0.value > now }
        heard = heard.filter { $0.value > now }
    }
}

/// Whether a reuse is announced: as the host's config says (quiet when
/// notify = false), unless the grant's bell was set otherwise in the menu. It
/// is recorded and shown in the activity either way.
public enum ReuseNotice {
    /// The bell is checked as of the reuse, so one Foca missed while it
    /// wasn't running counts as the bell was then.
    public static func notifies(_ e: AuditEvent, bells: BellChoices) -> Bool {
        guard e.type == "approval.reused" else { return false }
        let quiet = e.approval?.quiet == true
        guard let k = GrantUsage.key(e) else { return !quiet }
        return bells.notifies(k, quiet: quiet, now: e.date ?? Date())
    }
}

