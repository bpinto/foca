// The events kind: long-lived. After a {"op":"subscribe"} line on stdin it
// writes one JSON object per line on stdout:
//
//   {"v":1,"seq":1,"event":"ready"}
//   {"v":1,"seq":2,"event":"sleep"}
//
// - sleep: IOKit's system-will-sleep. The machine is let sleep once the
//   service acks the event ({"op":"ack","params":{"seq":2}}), or after
//   ackLimit, so the wipe isn't raced by sleep.
// - screen-lock: the com.apple.screenIsLocked distributed notification, and
//   a fast-user-switch away from this session.
// - session-end: log out, restart or shut down.
//
// Waking and unlocking are not reported: they restore nothing. Any process
// can post a distributed notification, but a forged one only causes a wipe.
// The helper exits when stdin closes (the service is gone) or on SIGTERM.

import AppKit
import Foundation
import IOKit
import IOKit.pwr_mgt

enum Events {
    // IOKit power messages. They are C macros Swift doesn't import:
    // iokit_common_msg(x) = sys_iokit (0xE0000000) | sub_iokit_common (0) | x.
    static let canSystemSleep: UInt32 = 0xE000_0270
    static let systemWillSleep: UInt32 = 0xE000_0280

    static let ackLimit = DispatchTimeInterval.seconds(5)

    // State below is only touched on the main thread.
    static var seq: UInt64 = 0
    static var rootPort: io_connect_t = 0
    /// Sleep notifications waiting for their ack, by event seq.
    static var pendingSleep: [UInt64: Int] = [:]
    static var observers: [NSObjectProtocol] = []

    @discardableResult
    static func emit(_ event: String) -> UInt64 {
        seq += 1
        writeLine(["v": protocolVersion, "seq": seq, "event": event])
        return seq
    }

    static func allowSleep(_ s: UInt64) {
        if let id = pendingSleep.removeValue(forKey: s) {
            IOAllowPowerChange(rootPort, id)
        }
    }

    static func run() -> Never {
        signal(SIGPIPE, SIG_IGN)
        guard let first = readLine(strippingNewline: true) else { exit(0) }
        do {
            let req = try parseRequest(Data(first.utf8))
            guard req.op == "subscribe" else { throw Failure.badRequest("expected subscribe, got \(req.op)") }
        } catch let f as Failure {
            fail(f)
        } catch {
            fail(Failure("internal", "\(error)"))
        }

        // Acks arrive on stdin; EOF means the service has gone.
        Thread {
            while let line = readLine(strippingNewline: true) {
                guard let req = try? parseRequest(Data(line.utf8)), req.op == "ack",
                      let s = try? req.params.int("seq"), s > 0 else {
                    log("ignoring a malformed line on stdin")
                    continue
                }
                DispatchQueue.main.async { Events.allowSleep(UInt64(s)) }
            }
            DispatchQueue.main.async { exit(0) }
        }.start()

        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler { exit(0) }
        term.resume()

        var notifier: io_object_t = 0
        var port: IONotificationPortRef?
        rootPort = IORegisterForSystemPower(nil, &port, { _, _, messageType, argument in
            let id = Int(bitPattern: argument)
            switch messageType {
            case Events.canSystemSleep:
                // Idle sleep asks first; never veto it.
                IOAllowPowerChange(Events.rootPort, id)
            case Events.systemWillSleep:
                let s = Events.emit("sleep")
                Events.pendingSleep[s] = id
                DispatchQueue.main.asyncAfter(deadline: .now() + Events.ackLimit) { Events.allowSleep(s) }
            default:
                break
            }
        }, &notifier)
        guard rootPort != 0, let port else {
            log("IORegisterForSystemPower failed")
            exit(1)
        }
        CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(port).takeUnretainedValue(), .defaultMode)

        let distributed = DistributedNotificationCenter.default()
        observers.append(distributed.addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            Events.emit("screen-lock")
        })
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append(workspace.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main) { _ in
            Events.emit("screen-lock")
        })
        observers.append(workspace.addObserver(forName: NSWorkspace.willPowerOffNotification, object: nil, queue: .main) { _ in
            Events.emit("session-end")
        })

        emit("ready")
        CFRunLoopRun()
        exit(0)
    }
}
