import Foundation

/// Text the app shows comes from foca's JSON, and some of it was chosen by
/// the process that connected: a program can name itself with terminal
/// controls or bidi overrides. foca escapes those in JSON (design §8.5), and
/// decoding turns them back into real characters, so they are dropped again
/// here before anything reaches a notification or the menu.
public enum Names {
    public static let maxName = 32
    public static let maxText = 64

    /// A program name as foca's prompt shows it (identity.DisplayName): the
    /// base name, a Nix wrapper's `.name-wrapped` undone, only
    /// `[A-Za-z0-9._+-]`, at most 32 characters.
    public static func program(_ s: String) -> String {
        var base = basename(text(s, max: 4096))
        if base == "." || base == "/" {
            return ""
        }
        while base.hasPrefix("."), base.hasSuffix("-wrapped"), base.count > ".-wrapped".count {
            base = String(base.dropFirst().dropLast("-wrapped".count))
        }
        var out = String.UnicodeScalarView()
        for u in base.unicodeScalars where isNameChar(u) {
            if out.count == maxName {
                break
            }
            out.append(u)
        }
        return String(out)
    }

    /// Any other text: characters that don't print dropped, and cut to max
    /// with an ellipsis.
    public static func text(_ s: String, max: Int = maxText) -> String {
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars where printable(u) {
            out.append(u)
        }
        let str = String(out)
        if str.count > max {
            return String(str.prefix(max - 1)) + "…"
        }
        return str
    }

    static func printable(_ u: Unicode.Scalar) -> Bool {
        switch u.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned:
            return false
        default:
            return true
        }
    }

    static func isNameChar(_ u: Unicode.Scalar) -> Bool {
        switch u {
        case "a"..."z", "A"..."Z", "0"..."9", ".", "_", "+", "-":
            return true
        default:
            return false
        }
    }

    /// The last path element, as Go's filepath.Base gives it.
    static func basename(_ s: String) -> String {
        if s.isEmpty {
            return "."
        }
        var t = Substring(s)
        while t.hasSuffix("/") {
            t = t.dropLast()
        }
        if t.isEmpty {
            return "/"
        }
        if let slash = t.lastIndex(of: "/") {
            return String(t[t.index(after: slash)...])
        }
        return String(t)
    }
}
