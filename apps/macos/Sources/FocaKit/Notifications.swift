import Foundation

/// Whether macOS will show Foca's notifications.
public enum NotificationState: Equatable {
    case on
    /// Never asked, so macOS hasn't shown its prompt yet.
    case notAsked
    /// Turned off, in the prompt or in System Settings.
    case denied
    /// Allowed, but with the alert style "None": nothing appears on screen.
    case alertsOff
    /// macOS refused the request with this error.
    case failed(String)
}

public enum NotificationFix: Equatable {
    /// Ask macOS again; it shows its prompt if it hasn't before.
    case ask
    /// Open Foca's page in System Settings → Notifications.
    case openSettings
}

/// What the menu says when notifications are off, and the button that fixes
/// it. After a denial macOS never shows its prompt again, so only System
/// Settings can turn them back on.
public struct NotificationAdvice: Equatable {
    public let text: String
    public let fixTitle: String
    public let fix: NotificationFix

    public static func advice(_ state: NotificationState) -> NotificationAdvice? {
        switch state {
        case .on:
            return nil
        case .notAsked:
            return NotificationAdvice(
                text: "Foca isn't allowed to notify yet, so reuses go unseen.",
                fixTitle: "Allow Notifications…", fix: .ask)
        case .denied:
            return NotificationAdvice(
                text: "Notifications are off for Foca, so reuses go unseen. Turn on \"Allow notifications\" for Foca in System Settings.",
                fixTitle: "Open Notification Settings", fix: .openSettings)
        case .alertsOff:
            return NotificationAdvice(
                text: "Foca's notifications are set to show no alerts, so reuses go unseen. Choose Banners or Alerts for Foca in System Settings.",
                fixTitle: "Open Notification Settings", fix: .openSettings)
        case .failed(let error):
            return NotificationAdvice(
                text: "macOS refused Foca's request to notify (" + Names.text(error, max: 120) + "), so reuses go unseen.",
                fixTitle: "Try Again", fix: .ask)
        }
    }
}
