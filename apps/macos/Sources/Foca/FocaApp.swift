// Foca: the menu-bar app (design §8.7). It shows live grants and recent
// activity, and notifies when a grant is reused, since a reuse shows no Touch
// ID prompt. It is a viewer: it runs foca's host commands and holds no keys.

import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Monitor.shared.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        Monitor.shared.stop()
    }
}

@main
struct FocaApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var monitor = Monitor.shared

    var body: some Scene {
        MenuBarExtra {
            MenuView(monitor: monitor)
        } label: {
            MenuBarLabel(warning: !monitor.warnings.isEmpty)
        }
        .menuBarExtraStyle(.window)
    }
}

/// The pixel-art seal (scripts/pixelart), with a "!" while the menu has a
/// warning. Template images, so macOS tints them for the menu bar.
struct MenuBarLabel: View {
    let warning: Bool

    var body: some View {
        if let image = NSImage(named: warning ? "MenuBarIconWarning" : "MenuBarIcon") {
            Image(nsImage: Self.template(image))
        } else {
            Image(systemName: warning ? "exclamationmark.triangle.fill" : "key.fill")
        }
    }

    private static func template(_ image: NSImage) -> NSImage {
        image.isTemplate = true
        return image
    }
}
