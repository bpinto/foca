import Foundation

/// What a row's colour says; the app maps it to a colour.
public enum Tone: Equatable {
    case good, info, warning, bad, neutral
}

/// The icon (an SF Symbol name) and tone of an event in the activity list.
public enum ActivityStyle {
    public static func symbol(_ e: AuditEvent) -> (name: String, tone: Tone) {
        let failed = e.outcome != "ok"
        switch e.type {
        case "approval.reused":
            return ("arrow.triangle.2.circlepath", .info)
        case "approval.granted":
            return ("checkmark.circle.fill", .good)
        case "approval.denied":
            return ("xmark.circle.fill", .bad)
        case "approval.timeout":
            return ("clock.fill", .warning)
        case "secret.read":
            return ("key.fill", failed ? .bad : .neutral)
        case "action.run":
            return ("terminal.fill", failed ? .bad : .neutral)
        case "secret.list", "action.list":
            return ("list.bullet", failed ? .warning : .neutral)
        case "lock":
            return ("lock.fill", .neutral)
        case "grants.drop":
            return ("minus.circle.fill", .neutral)
        case "request.rejected":
            return ("hand.raised.fill", .warning)
        case "server.start", "server.stop", "config.load", "config.reload":
            return ("power", failed ? .bad : .neutral)
        default:
            return ("tray.full.fill", failed ? .bad : .neutral)
        }
    }

    /// "now", "5m ago", "3h ago", or the day.
    public static func ago(_ date: Date, now: Date) -> String {
        let s = Int(now.timeIntervalSince(date))
        switch s {
        case ..<60:
            return "now"
        case ..<3600:
            return "\(s / 60)m ago"
        case ..<86400:
            return "\(s / 3600)h ago"
        default:
            return "\(s / 86400)d ago"
        }
    }
}

/// How much of a grant's window is left.
public struct TimeLeft: Equatable {
    public let text: String
    /// Of the whole window, 0 to 1.
    public let fraction: Double

    public static func of(_ g: Grant, now: Date) -> TimeLeft? {
        guard let end = g.expires else { return nil }
        let left = end.timeIntervalSince(now)
        let total = GoTime.parse(g.grantedAt).map { end.timeIntervalSince($0) } ?? 0
        let fraction = total > 0 ? min(1, max(0, left / total)) : 0
        let s = Int(left)
        let text: String
        switch s {
        case ..<1:
            text = "ending"
        case ..<60:
            text = "<1m"
        case ..<3600:
            text = "\(s / 60)m"
        default:
            text = s % 3600 / 60 == 0 ? "\(s / 3600)h" : "\(s / 3600)h \(s % 3600 / 60)m"
        }
        return TimeLeft(text: text, fraction: fraction)
    }
}
