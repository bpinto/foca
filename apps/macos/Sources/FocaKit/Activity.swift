import Foundation

/// One row of recent activity (design §8.7). A request writes its approval
/// (approval.granted, reused, denied or timeout) and then a secret.read or
/// action.run per resource, all with one request_id; they make one item,
/// saying what was accessed, by whom, and how it was approved. Any other
/// event is an item of its own.
public struct ActivityItem: Equatable, Identifiable {
    public let id: String
    /// The request's newest event: where the item sits, and its time.
    public let seq: UInt64
    public let date: Date?
    public let text: String
    /// "approved", "reused", "denied", "timed out", an outcome such as
    /// "error", or "" for events that aren't accesses.
    public let how: String
    /// An SF Symbol name.
    public let symbol: String
    public let tone: Tone
    /// The grant a request was allowed under, approved or reused: requests
    /// under one grant fold together. Never set for one refused or failed.
    public var approvalID: String? = nil

    /// Merges events given newest first. An item sits where its newest event
    /// is.
    public static func items(_ newestFirst: [AuditEvent]) -> [ActivityItem] {
        var order: [String] = []
        var byKey: [String: [AuditEvent]] = [:]
        for e in newestFirst {
            var k = "seq:\(e.seq)"
            if let r = e.requestID, !r.isEmpty, isRequestPart(e.type) {
                k = "req:" + r
            }
            if byKey[k] == nil {
                order.append(k)
            }
            byKey[k, default: []].append(e)
        }
        return order.map { k in
            let es = byKey[k]!
            if k.hasPrefix("req:") {
                return request(id: k, newestFirst: es)
            }
            let e = es[0]
            let style = ActivityStyle.symbol(e)
            return ActivityItem(id: k, seq: e.seq, date: e.date, text: ActivityText.describe(e), how: "", symbol: style.name, tone: style.tone)
        }
    }

    static func isRequestPart(_ type: String) -> Bool {
        type.hasPrefix("approval.") || type == "secret.read" || type == "action.run"
    }

    private static func request(id: String, newestFirst es: [AuditEvent]) -> ActivityItem {
        let inOrder = Array(es.reversed())
        let access = inOrder.filter { $0.type == "secret.read" || $0.type == "action.run" }
        let approvals = inOrder.filter { $0.type.hasPrefix("approval.") }

        // What was accessed: each read or run, else what the approval named
        // (its access may be older than the events read, or not written yet).
        var what: [String] = []
        let add = { (s: String) in
            if !what.contains(s) {
                what.append(s)
            }
        }
        for e in access {
            if let r = e.resource {
                add(ReuseText.resource(r, params: e.params))
            }
        }
        if what.isEmpty {
            for e in approvals {
                if let r = e.resource {
                    add(ReuseText.resource(r, params: e.params))
                }
                for r in e.resources ?? [] {
                    add(ReuseText.resource(r, params: e.params))
                }
            }
        }
        var text = what.joined(separator: ", ")
        if let p = inOrder.first(where: { $0.peer?.verified != nil }) {
            text += " · " + ReuseText.peer(p.peer, instance: p.instance)
        }

        let how = Self.how(access: access, approvals: approvals)
        let isAction = access.contains { $0.type == "action.run" } || approvals.contains { $0.resource?.kind == "action" || ($0.resources ?? []).contains { $0.kind == "action" } }
        var grant: String?
        if how.word == "approved" || how.word == "reused" {
            grant = inOrder.compactMap { $0.approval?.id }.first
        }
        return ActivityItem(id: id, seq: es[0].seq, date: es[0].date, text: text, how: how.word,
                            symbol: how.symbol ?? (isAction ? "terminal.fill" : "key.fill"), tone: how.tone, approvalID: grant)
    }

    /// The worst thing that happened to the request, else how it was approved.
    private static func how(access: [AuditEvent], approvals: [AuditEvent]) -> (word: String, symbol: String?, tone: Tone) {
        let all = access + approvals
        if all.contains(where: { $0.type == "approval.denied" || $0.outcome == "denied" }) {
            return ("denied", "xmark.circle.fill", .bad)
        }
        if all.contains(where: { $0.type == "approval.timeout" || $0.outcome == "timeout" }) {
            return ("timed out", "clock.fill", .warning)
        }
        if let bad = access.first(where: { $0.outcome != "ok" }) {
            return (Names.text(bad.outcome.replacingOccurrences(of: "_", with: " "), max: Names.maxName), "exclamationmark.circle.fill", .bad)
        }
        let modes = all.compactMap { $0.approval?.mode }
        if modes.contains("fresh") || approvals.contains(where: { $0.type == "approval.granted" }) {
            return ("approved", "checkmark.circle.fill", .good)
        }
        if modes.contains("reused") {
            return ("reused", "arrow.triangle.2.circlepath", .info)
        }
        return ("", nil, .neutral)
    }
}

/// Repeats in recent activity, folded into one row ("5×"): the requests
/// allowed under one grant (its approval, then its reuses) by the same
/// program, and otherwise items that read the same and ended the same way.
/// Allowed and refused requests never share a row.
public struct ActivityGroup: Identifiable, Equatable {
    public let id: String
    /// Newest first; never empty.
    public let items: [ActivityItem]

    public var newest: ActivityItem { items[0] }

    /// What the row shows: a grant by its approval, when that is among the
    /// items, else the newest; the time is always the newest's.
    public var summary: ActivityItem { items.first { $0.how == "approved" } ?? items[0] }

    /// Groups items given newest first. A group sits where its newest item
    /// is, and keeps its items newest first.
    public static func group(_ newestFirst: [ActivityItem]) -> [ActivityGroup] {
        var order: [String] = []
        var byKey: [String: [ActivityItem]] = [:]
        for i in newestFirst {
            var k = i.symbol + "\u{0}" + i.how + "\u{0}" + i.text
            if let ap = i.approvalID {
                k = "grant\u{0}" + ap + "\u{0}" + i.text
            }
            if byKey[k] == nil {
                order.append(k)
            }
            byKey[k, default: []].append(i)
        }
        return order.map { ActivityGroup(id: $0, items: byKey[$0]!) }
    }

    /// Events given newest first, merged into items and folded.
    public static func of(_ newestFirst: [AuditEvent]) -> [ActivityGroup] {
        group(ActivityItem.items(newestFirst))
    }
}
