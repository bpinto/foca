import Foundation

/// Where the app looks for foca (design §8.7).
public enum Locator {
    /// The paths to try, in order. FOCA_BIN, when set, is the only one: a
    /// path the user named that doesn't work should say so, not be passed
    /// over for another foca.
    public static func candidates(environment: [String: String], bundleURL: URL) -> [String] {
        if let bin = environment["FOCA_BIN"], !bin.isEmpty {
            return [bin]
        }
        let parent = bundleURL.deletingLastPathComponent()
        return [
            // The release archive: Foca.app next to foca.
            parent.appendingPathComponent("foca").path,
            // The Nix package: $out/Applications/Foca.app and $out/bin/foca.
            parent.deletingLastPathComponent().appendingPathComponent("bin").appendingPathComponent("foca").path,
        ]
    }

    public static func find(environment: [String: String], bundleURL: URL, isExecutable: (String) -> Bool) -> String? {
        candidates(environment: environment, bundleURL: bundleURL).first(where: isExecutable)
    }
}
