import AppKit
import FocaKit
import Foundation
import UserNotifications

/// Posts reuse notifications (design §8.7). They come after the fact and
/// protect nothing: they are there so a reuse, which shows no Touch ID
/// prompt, doesn't go unseen.
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    private let center = UNUserNotificationCenter.current()
    private var bursts = ReuseBursts(window: 60)

    /// Called on the main queue with whether notifications can be shown.
    var onState: ((NotificationState) -> Void)?

    /// Asks for permission on the first launch; macOS shows its prompt once.
    func setUp() {
        center.delegate = self
        checkSettings(askIfNew: true)
    }

    /// Checks again, since the user can turn notifications off at any time.
    func checkSettings(askIfNew: Bool = false) {
        center.getNotificationSettings { [weak self] s in
            let state: NotificationState
            switch s.authorizationStatus {
            case .notDetermined:
                state = .notAsked
            case .denied:
                state = .denied
            default:
                state = s.alertSetting == .disabled ? .alertsOff : .on
            }
            DispatchQueue.main.async {
                if state == .notAsked && askIfNew {
                    self?.ask()
                } else {
                    self?.onState?(state)
                }
            }
        }
    }

    /// Shows macOS's prompt if it hasn't been shown; after a denial it does
    /// nothing, and only System Settings can turn notifications on.
    func ask() {
        center.requestAuthorization(options: [.alert, .sound]) { [weak self] _, error in
            DispatchQueue.main.async {
                if let error {
                    self?.onState?(.failed(error.localizedDescription))
                } else {
                    self?.checkSettings()
                }
            }
        }
    }

    /// Opens Foca's page in System Settings → Notifications.
    func openSettings() {
        let id = Bundle.main.bundleIdentifier ?? "io.github.bpinto.foca"
        if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=" + id) {
            NSWorkspace.shared.open(url)
        }
    }

    func reuse(_ e: AuditEvent) {
        guard let r = e.resource, let id = e.approval?.id else { return }
        let b = bursts.add(approvalID: id, resource: ReuseText.resource(r, params: e.params),
                           peer: ReuseText.peer(e.peer, instance: e.instance), at: e.date ?? Date())
        // One identifier per approval, so a later reuse replaces the
        // notification instead of adding another.
        post(id: "reuse-" + id, title: "Grant reused", body: ReuseText.body(b))
    }

    func missed(_ n: Int, capped: Bool) {
        post(id: "missed", title: "Grants reused", body: ReuseText.missed(n, capped: capped))
    }

    private func post(id: String, title: String, body: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        c.threadIdentifier = "reuse"
        center.add(UNNotificationRequest(identifier: id, content: c, trigger: nil))
    }

    // Shown even while the menu is open.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list])
    }
}
