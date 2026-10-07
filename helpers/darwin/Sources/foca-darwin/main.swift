// foca-darwin: the macOS helper for foca. It wraps the APIs Go can't reach
// without cgo: Touch ID (LocalAuthentication), the Keychain, and sleep and
// screen-lock events. The foca service runs it as `foca-darwin <kind>`.

import Foundation

let kinds = ["authenticator", "key-protector", "events"]

if let v = ProcessInfo.processInfo.environment["FOCA_HELPER_PROTOCOL"], v != String(protocolVersion) {
    fail(Failure.badRequest("protocol version \(v) is not supported (want \(protocolVersion))"))
}

guard CommandLine.arguments.count == 2 else {
    fail(Failure.badRequest("usage: foca-darwin info | authenticator | key-protector | events"))
}

switch CommandLine.arguments[1] {
case "info":
    oneShot { req in
        guard req.op == "info" else { throw Failure.badRequest("unknown op \(req.op) for info") }
        try req.params.only([])
        return ["kinds": kinds, "version": helperVersion]
    }
case "authenticator":
    Authenticator.run()
case "key-protector":
    KeyProtector.run()
case "events":
    Events.run()
default:
    fail(Failure.badRequest("unknown kind \(CommandLine.arguments[1])"))
}
