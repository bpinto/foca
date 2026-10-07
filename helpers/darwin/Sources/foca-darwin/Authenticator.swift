// The authenticator kind: Touch ID through LocalAuthentication.
//
// The reason text comes from the foca core, built from trusted templates.
// macOS shows it after "<name> is trying to", so it is a verb phrase.

import Foundation
import LocalAuthentication

enum Authenticator {
    static func run() -> Never {
        let req: Request
        do {
            req = try readRequest()
        } catch let f as Failure {
            fail(f)
        } catch {
            fail(Failure("internal", "\(error)"))
        }
        do {
            switch req.op {
            case "available":
                try available(req.params)
            case "approve":
                try approve(req.params)
            default:
                throw Failure.badRequest("unknown op \(req.op) for authenticator")
            }
        } catch let f as Failure {
            fail(f)
        } catch {
            fail(Failure("internal", "\(error)"))
        }
    }

    /// Biometry only, unless config allows the device password as well.
    static func policy(_ fallback: Bool) -> LAPolicy {
        fallback ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
    }

    static func available(_ p: Params) throws -> Never {
        try p.only(["allow_password_fallback"])
        let fallback = try p.bool("allow_password_fallback")
        var error: NSError?
        if LAContext().canEvaluatePolicy(policy(fallback), error: &error) {
            respond(["available": true])
        }
        respond(["available": false, "reason": error?.localizedDescription ?? "Touch ID can't be used"])
    }

    // State below is only touched on the main queue.
    static var terminated = false
    static var timedOut = false

    static func approve(_ p: Params) throws -> Never {
        try p.only(["reason", "timeout_ms", "allow_password_fallback"])
        let reason = try p.string("reason")
        let timeoutMS = try p.int("timeout_ms")
        let fallback = try p.bool("allow_password_fallback")
        guard !reason.isEmpty, reason.utf8.count <= 4096 else { throw Failure.badRequest("reason must be 1..4096 bytes") }
        guard timeoutMS > 0, timeoutMS <= 600_000 else { throw Failure.badRequest("timeout_ms must be 1..600000") }

        // macOS ends the reason with its own full stop; the core's ends with
        // one too, which would show twice.
        let shown = reason.hasSuffix(".") ? String(reason.dropLast()) : reason

        let ctx = LAContext()
        // Never reuse an earlier unlock: each prompt needs its own touch.
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        ctx.localizedCancelTitle = "Deny"
        if !fallback {
            // Hides "Use Password…".
            ctx.localizedFallbackTitle = ""
        }

        // SIGTERM from the service: take the dialog down, answer cancelled.
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler {
            Authenticator.terminated = true
            ctx.invalidate()
            // If LocalAuthentication doesn't call back promptly, answer anyway.
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(500)) { fail(Failure("cancelled", "terminated")) }
        }
        term.resume()

        // Our own deadline, in case the service's SIGTERM never comes.
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(timeoutMS)) {
            Authenticator.timedOut = true
            ctx.invalidate()
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(500)) { fail(Failure("timeout")) }
        }

        ctx.evaluatePolicy(policy(fallback), localizedReason: shown) { ok, error in
            DispatchQueue.main.async {
                if ok {
                    respond(["approved": true, "method": fallback ? "biometry-or-password" : "biometry"])
                }
                fail(Authenticator.failure(error))
            }
        }
        dispatchMain()
    }

    /// Maps LocalAuthentication errors to protocol codes. A user cancel (-2)
    /// is a denial; an app cancel (-9) is our own invalidate(), so a
    /// timeout or SIGTERM. The audit log can tell the two apart.
    static func failure(_ error: Error?) -> Failure {
        if terminated { return Failure("cancelled", "terminated") }
        if timedOut { return Failure("timeout") }
        guard let e = error as NSError?, e.domain == LAErrorDomain else {
            return Failure("internal", error.map { "\($0)" } ?? "no error")
        }
        let msg = e.localizedDescription
        switch e.code {
        case -1, -2, -3: // authenticationFailed, userCancel, userFallback
            return Failure("denied", msg)
        case -4, -9, -10: // systemCancel, appCancel, invalidContext
            return Failure("cancelled", msg)
        case -5, -6, -7, -8, -11, -12, -13, -1004:
            // passcodeNotSet, biometryNotAvailable, biometryNotEnrolled,
            // biometryLockout, watchNotAvailable, biometryNotPaired,
            // biometryDisconnected, notInteractive
            return Failure("unavailable", msg)
        default:
            return Failure("internal", "LAError \(e.code): \(msg)")
        }
    }
}
