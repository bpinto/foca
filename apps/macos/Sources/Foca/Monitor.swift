import FocaKit
import Foundation

/// What the menu shows, kept current from foca's own commands (design §8.7).
final class Monitor: ObservableObject {
    static let shared = Monitor()

    @Published private(set) var focaPath: String?
    @Published private(set) var instances: [InstanceGrants] = []
    @Published private(set) var grantsError: String?
    /// Newest first.
    @Published private(set) var recent: [AuditEvent] = []
    @Published private(set) var followError: String?
    /// Why the last revoke from the menu failed, until the next one works.
    @Published private(set) var revokeError: String?
    @Published private(set) var notifications: NotificationState = .on
    @Published private(set) var now = Date()
    /// Reuses of each live grant, from the log.
    @Published private(set) var usage = GrantUsage()
    /// Each grant's bell as set in the menu, kept across launches until the
    /// grant ends.
    @Published private(set) var bells = BellChoices(
        muted: UserDefaults.standard.dictionary(forKey: "mutes") as? [String: Double] ?? [:],
        heard: UserDefaults.standard.dictionary(forKey: "heard") as? [String: Double] ?? [:])

    private var cli: FocaCLI?
    private let follower = Follower()
    private let notifier = Notifier()
    private var timer: Timer?
    private var restart: DispatchWorkItem?

    // Repeats fold into one row, so this is more than the menu shows.
    private let recentLimit = 300
    private let pageLimit = 500
    private let maxPages = 20

    /// The last seq the app has shown, kept across launches so the reuses
    /// it missed can be summed up.
    private var lastSeq: UInt64 {
        get { UInt64(UserDefaults.standard.string(forKey: "lastSeq") ?? "") ?? 0 }
        set { UserDefaults.standard.set(String(newValue), forKey: "lastSeq") }
    }

    /// A reason the menu-bar icon shows a warning, and the button that fixes
    /// it, if one can.
    struct Warning: Identifiable {
        let text: String
        var fixTitle: String?
        var fix: (() -> Void)?
        var id: String { text }
    }

    var warnings: [Warning] {
        var w: [Warning] = []
        if focaPath == nil {
            w.append(Warning(text: "foca not found: set FOCA_BIN, or keep Foca.app next to foca"))
        }
        if let e = followError {
            w.append(Warning(text: "Activity stopped: " + e))
        }
        if let e = revokeError {
            w.append(Warning(text: "Couldn't revoke: " + e))
        }
        if let a = NotificationAdvice.advice(notifications) {
            w.append(Warning(text: a.text, fixTitle: a.fixTitle, fix: { [weak self] in self?.fixNotifications(a.fix) }))
        }
        return w
    }

    func start() {
        let env = ProcessInfo.processInfo.environment
        guard let path = Locator.find(environment: env, bundleURL: Bundle.main.bundleURL,
                                      isExecutable: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            focaPath = nil
            return
        }
        focaPath = path
        cli = FocaCLI(path: path)
        notifier.onState = { [weak self] state in self?.notifications = state }
        notifier.setUp()
        Task { await self.catchUp() }
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.now = Date()
            self.usage.prune(now: self.now)
            self.bells.prune(now: self.now)
            self.saveBells()
            self.notifier.checkSettings()
            Task { await self.refreshGrants() }
        }
    }

    /// Checks now, as the menu opens: the user may have just changed them in
    /// System Settings.
    func checkNotifications() {
        notifier.checkSettings()
    }

    private func fixNotifications(_ fix: NotificationFix) {
        switch fix {
        case .ask:
            notifier.ask()
        case .openSettings:
            notifier.openSettings()
        }
    }

    func stop() {
        timer?.invalidate()
        restart?.cancel()
        follower.stop()
    }

    /// Flips a grant's bell until it ends: mutes a grant, or turns on a quiet
    /// one (notify = false).
    func toggleBell(_ g: Grant) {
        bells.toggle(g, now: Date())
        saveBells()
    }

    private func saveBells() {
        UserDefaults.standard.set(bells.storedMuted, forKey: "mutes")
        UserDefaults.standard.set(bells.storedHeard, forKey: "heard")
    }

    /// Drops one grant (foca grants --host --drop, design §8.6): the next
    /// access asks again.
    func revoke(_ g: Grant) {
        guard let cli else { return }
        Task {
            let r = await cli.run(["grants", "--host", "--drop", g.approvalID + "/" + g.name])
            let err = r.status == 0 ? nil : Names.text(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "foca: ", with: ""), max: 200)
            await MainActor.run { self.revokeError = err }
            await self.refreshGrants()
        }
    }

    /// foca lock: every grant dropped now (design §6.2).
    func lock() {
        guard let cli else { return }
        Task {
            _ = await cli.run(["lock"])
            await self.refreshGrants()
        }
    }

    /// Fills recent activity, sums up the reuses missed since lastSeq, then
    /// follows from the next event, so nothing falls between the two.
    private func catchUp() async {
        guard let cli else { return }
        var since = lastSeq
        var events: [AuditEvent] = []
        var usage = GrantUsage()
        var after: UInt64?
        for _ in 0..<maxPages {
            var args = ["events", "query", "--since", "24h", "--limit", String(pageLimit)]
            if let a = after {
                args += ["--after-seq", String(a)]
            }
            let r = await cli.run(args)
            guard r.status == 0 else {
                await MainActor.run { self.followError = Names.text(r.stderr, max: 200) }
                break
            }
            after = nil
            for line in r.stdout.split(separator: UInt8(ascii: "\n")) {
                switch QueryLine.parse(Data(line)) {
                case .event(let e):
                    usage.add(e)
                    events.append(e)
                    if events.count > recentLimit {
                        events.removeFirst(events.count - recentLimit)
                    }
                case .next(let a):
                    after = a
                case nil:
                    break
                }
            }
            if after == nil {
                break
            }
        }
        // A log that starts over (a new data directory) has no seq this high.
        if let last = events.last?.seq, since > last {
            since = 0
        }
        let newest = max(events.last?.seq ?? 0, since)
        let shown = Array(events.reversed())
        if since > 0 && newest > since {
            let (n, capped) = await countReuses(after: since, through: newest)
            if n > 0 {
                await MainActor.run { self.notifier.missed(n, capped: capped) }
            }
        }
        await MainActor.run {
            self.recent = shown
            self.usage = usage
            self.lastSeq = newest
            self.follow(from: newest > 0 ? newest + 1 : nil)
        }
        await refreshGrants()
    }

    private func countReuses(after: UInt64, through: UInt64) async -> (Int, Bool) {
        guard let cli else { return (0, false) }
        let bells = await MainActor.run { self.bells }
        var n = 0
        var from = after
        for _ in 0..<maxPages {
            let r = await cli.run(["events", "query", "--type", "approval.reused", "--after-seq", String(from), "--limit", String(pageLimit)])
            guard r.status == 0 else { return (n, false) }
            var next: UInt64?
            for line in r.stdout.split(separator: UInt8(ascii: "\n")) {
                switch QueryLine.parse(Data(line)) {
                case .event(let e) where e.seq <= through:
                    if ReuseNotice.notifies(e, bells: bells) {
                        n += 1
                    }
                case .next(let a) where a < through:
                    next = a
                default:
                    break
                }
            }
            guard let a = next else { return (n, false) }
            from = a
        }
        return (n, true)
    }

    /// Follows the log live, from seq when given, else from the next new
    /// event. An error (rotation removed files it hadn't read, design §8.5)
    /// is shown, and following starts again from the newest event.
    private func follow(from seq: UInt64?) {
        guard let cli else { return }
        var args = ["events", "follow"]
        if let s = seq {
            args += ["--from-seq", String(s)]
        }
        follower.start(cli, args, onLine: { [weak self] line in
            guard let self, case .event(let e) = QueryLine.parse(line) else { return }
            self.handle(e)
        }, onExit: { [weak self] status, stderr in
            guard let self else { return }
            self.followError = Names.text(stderr.isEmpty ? "foca exited with status \(status)" : stderr, max: 200)
            let work = DispatchWorkItem { [weak self] in self?.follow(from: nil) }
            self.restart = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: work)
        })
    }

    private func handle(_ e: AuditEvent) {
        followError = nil
        if e.seq > lastSeq {
            lastSeq = e.seq
        }
        recent.insert(e, at: 0)
        if recent.count > recentLimit {
            recent.removeLast(recent.count - recentLimit)
        }
        usage.add(e)
        switch e.type {
        case "approval.reused":
            if ReuseNotice.notifies(e, bells: bells) {
                notifier.reuse(e)
            }
        case "approval.granted", "grants.drop", "lock", "server.start", "server.stop", "config.reload":
            Task { await self.refreshGrants() }
        default:
            break
        }
    }

    private func refreshGrants() async {
        guard let cli else { return }
        let r = await cli.run(["grants", "--host", "-f", "json"])
        let parsed = InstanceGrants.parse(r.stdout)
        await MainActor.run {
            self.now = Date()
            self.instances = parsed
            if parsed.isEmpty && r.status != 0 {
                self.grantsError = Names.text(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "foca: ", with: ""), max: 200)
            } else {
                self.grantsError = nil
            }
        }
    }
}
