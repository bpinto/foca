import XCTest
@testable import FocaKit

final class NamesTests: XCTestCase {
    func testProgramNamesFollowThePromptRules() {
        XCTAssertEqual(Names.program("/nix/store/abc-gh/bin/.gh-wrapped"), "gh")
        XCTAssertEqual(Names.program("/usr/bin/ssh"), "ssh")
        XCTAssertEqual(Names.program("evil\u{202E}txt.exe"), "eviltxt.exe")
        XCTAssertEqual(Names.program("a b\u{1B}[31m"), "ab31m")
        XCTAssertEqual(Names.program(String(repeating: "x", count: 100)).count, Names.maxName)
        XCTAssertEqual(Names.program("/"), "")
        XCTAssertEqual(Names.program(""), "")
    }

    func testTextDropsWhatDoesntPrintAndIsShortened() {
        XCTAssertEqual(Names.text("\u{1B}[2Jred\u{2028}\u{202E}line\u{9B}"), "[2Jredline")
        let long = Names.text(String(repeating: "é", count: 100))
        XCTAssertEqual(long.count, Names.maxText)
        XCTAssertTrue(long.hasSuffix("…"))
        XCTAssertEqual(Names.text("profile=dev admin"), "profile=dev admin")
    }
}

// An event as foca writes it, with a client.reported block the app must never
// show and a field it doesn't know.
let reusedEvent = """
{"v":1,"seq":1042,"id":"e1","ts":"2026-10-01T17:02:11.482Z","instance":"dev","vault":"common",\
"type":"approval.reused","outcome":"ok","request_id":"r1","origin":"client-socket",\
"resource":{"kind":"secret","id":"common:github-pat"},\
"approval":{"id":"ap1","mode":"reused","scope":"peer-session","expires_at":"2026-10-01T18:00:00Z"},\
"peer":{"verified":{"source":"LOCAL_PEERCRED","uid":501,"gid":20,"pid":4711,"name":"ssh","exe_sealed":true,\
"pid_stable":true,"opaque":true,"realm":{"kind":"vm","name":"dev","peers":"opaque"}}},\
"client":{"reported":{"name":"trusted-tool","exe":"/usr/bin/trusted-tool"}},"future_field":[1,2]}
"""

final class ModelTests: XCTestCase {
    func testDecodesAnEventAndIgnoresUnknownFields() throws {
        guard case .event(let e) = QueryLine.parse(Data(reusedEvent.utf8)) else {
            return XCTFail("not an event")
        }
        XCTAssertEqual(e.seq, 1042)
        XCTAssertEqual(e.type, "approval.reused")
        XCTAssertEqual(e.approval?.id, "ap1")
        XCTAssertEqual(e.peer?.verified?.name, "ssh")
        XCTAssertEqual(e.date, GoTime.parse("2026-10-01T17:02:11.482Z"))
    }

    func testDecodesTheNextPageLine() {
        XCTAssertEqual(QueryLine.parse(Data(#"{"next_after_seq":1100}"#.utf8)), .next(afterSeq: 1100))
        XCTAssertNil(QueryLine.parse(Data("not json".utf8)))
    }

    func testDecodesGrantsHostOutput() {
        let out = """
        {"instance":"dev","running":true,"reuse":true,"written_at":"2026-10-10T01:31:49.123Z","grants":[\
        {"kind":"action","name":"aws-creds","params":{"my_profile":"dev-admin"},"scope":"peer-session",\
        "scope_key":{"instance":"dev","peer_session":{"value":"ssh:4711","by":"host"}},"approval_id":"ap1",\
        "granted_at":"2026-10-10T01:31:49.123456789Z","expires_at":"2026-10-10T02:01:49.123456789Z"}]}
        {"instance":"work","running":false,"reuse":false,"grants":[],"error":"service not running (no pid file)"}

        """
        let got = InstanceGrants.parse(Data(out.utf8))
        XCTAssertEqual(got.count, 2)
        XCTAssertEqual(got[0].grants.first?.params?["my_profile"], "dev-admin", "param names are kept as foca wrote them")
        XCTAssertEqual(got[0].grants.first?.scopeKey?.peerSession?.value, "ssh:4711")
        XCTAssertNotNil(got[0].grants.first?.expires)
        XCTAssertFalse(got[1].running)
        XCTAssertEqual(ReuseText.grant(got[0].grants[0]), "action aws-creds (my_profile=dev-admin)")
    }

    func testParsesTimesAsGoWritesThem() {
        let whole = GoTime.parse("2026-10-10T01:31:49Z")
        XCTAssertNotNil(whole)
        XCTAssertEqual(GoTime.parse("2026-10-10T01:31:49.5Z")!.timeIntervalSince(whole!), 0.5, accuracy: 1e-6)
        XCTAssertEqual(GoTime.parse("2026-10-10T01:31:49.123456789Z")!.timeIntervalSince(whole!), 0.123456789, accuracy: 1e-6)
        XCTAssertEqual(GoTime.parse("2026-10-10T11:31:49+10:00"), whole)
        XCTAssertNil(GoTime.parse("2026-10-10T01:31:49.Z"))
        XCTAssertNil(GoTime.parse("yesterday"))
    }
}

final class ReuseTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_000_000)

    func testReusesOfOneApprovalWithinAMinuteShareOneNotification() {
        var b = ReuseBursts(window: 60)
        XCTAssertEqual(b.add(approvalID: "ap1", resource: "aws-creds", peer: "ssh (vm dev)", at: t0).count, 1)
        XCTAssertEqual(b.add(approvalID: "ap2", resource: "common:github-pat", peer: "ssh (vm dev)", at: t0).count, 1, "another approval starts its own")
        var last = b.add(approvalID: "ap1", resource: "aws-creds", peer: "ssh (vm dev)", at: t0 + 10)
        for i in 0..<12 {
            last = b.add(approvalID: "ap1", resource: "aws-creds", peer: "ssh (vm dev)", at: t0 + 20 + Double(i))
        }
        XCTAssertEqual(last.count, 14)
        XCTAssertEqual(last.first, t0)
        XCTAssertEqual(ReuseText.body(last), "aws-creds reused 14× by ssh (vm dev) in the last minute")
        // After the window, the next reuse notifies afresh.
        let later = b.add(approvalID: "ap1", resource: "aws-creds", peer: "ssh (vm dev)", at: t0 + 61)
        XCTAssertEqual(later.count, 1)
        XCTAssertEqual(ReuseText.body(later), "aws-creds reused by ssh (vm dev)")
    }

    func testNotificationTextComesOnlyFromHostFields() throws {
        guard case .event(let e) = QueryLine.parse(Data(reusedEvent.utf8)) else {
            return XCTFail("not an event")
        }
        var b = ReuseBursts()
        let burst = b.add(approvalID: e.approval!.id!, resource: ReuseText.resource(e.resource!, params: e.params),
                          peer: ReuseText.peer(e.peer, instance: e.instance), at: e.date!)
        let body = ReuseText.body(burst)
        XCTAssertEqual(body, "common:github-pat reused by ssh (vm dev)")
        XCTAssertFalse(body.contains("trusted-tool"), "client.reported reached a notification")
    }

    func testPeerWordingSanitisesWhatTheProcessChose() {
        let p = Peer(verified: VerifiedPeer(name: "/tmp/.x\u{202E}gh-wrapped", realm: Realm(kind: "host", name: "host")))
        XCTAssertEqual(ReuseText.peer(p, instance: "host"), "xgh (host)")
        XCTAssertEqual(ReuseText.peer(nil, instance: "dev"), "an unnamed program (instance dev)")
    }

    func testMissedSummary() {
        XCTAssertEqual(ReuseText.missed(1, capped: false), "1 grant was reused while Foca wasn't running")
        XCTAssertEqual(ReuseText.missed(6, capped: false), "6 grants were reused while Foca wasn't running")
        XCTAssertEqual(ReuseText.missed(10000, capped: true), "10000+ grants were reused while Foca wasn't running")
    }
}

final class LocatorTests: XCTestCase {
    let bundle = URL(fileURLWithPath: "/nix/store/abc-foca/Applications/Foca.app")

    func testFocaBinIsTheOnlyCandidateWhenSet() {
        XCTAssertEqual(Locator.candidates(environment: ["FOCA_BIN": "/opt/foca"], bundleURL: bundle), ["/opt/foca"])
        XCTAssertNil(Locator.find(environment: ["FOCA_BIN": "/opt/foca"], bundleURL: bundle, isExecutable: { $0 != "/opt/foca" }))
    }

    func testBundleNeighboursForTheArchiveAndTheNixPackage() {
        XCTAssertEqual(Locator.candidates(environment: [:], bundleURL: bundle),
                       ["/nix/store/abc-foca/Applications/foca", "/nix/store/abc-foca/bin/foca"])
        XCTAssertEqual(Locator.find(environment: [:], bundleURL: bundle, isExecutable: { $0.hasSuffix("/bin/foca") }),
                       "/nix/store/abc-foca/bin/foca")
    }
}

final class NotificationAdviceTests: XCTestCase {
    func testEveryWayOfBeingOffSaysHowToFixIt() {
        XCTAssertNil(NotificationAdvice.advice(.on))
        XCTAssertEqual(NotificationAdvice.advice(.notAsked)?.fix, .ask)
        // After a denial macOS never prompts again: only System Settings helps.
        XCTAssertEqual(NotificationAdvice.advice(.denied)?.fix, .openSettings)
        XCTAssertEqual(NotificationAdvice.advice(.alertsOff)?.fix, .openSettings)
        XCTAssertEqual(NotificationAdvice.advice(.failed("boom"))?.fix, .ask)
        for s in [NotificationState.notAsked, .denied, .alertsOff, .failed("boom")] {
            let a = NotificationAdvice.advice(s)!
            XCTAssertFalse(a.fixTitle.isEmpty)
            XCTAssertTrue(a.text.contains("reuses go unseen"), a.text)
        }
        XCTAssertTrue(NotificationAdvice.advice(.denied)!.text.contains("Allow notifications"))
        XCTAssertTrue(NotificationAdvice.advice(.failed("boom"))!.text.contains("boom"))
    }
}

final class GrantsViewTests: XCTestCase {
    func testOnlyInstancesWithSomethingToSayAreShown() {
        let out = """
        {"instance":"idle","running":true,"reuse":true,"grants":[]}
        {"instance":"no-reuse","running":true,"reuse":false,"grants":[]}
        {"instance":"stopped","running":false,"reuse":false,"grants":[],"error":"service not running (stale pid file)"}
        {"instance":"broken","running":true,"reuse":false,"grants":[],"error":"grants.json is malformed"}
        {"instance":"dev","running":true,"reuse":true,"grants":[{"kind":"secret","name":"common:github-pat","scope":"connection","approval_id":"ap1","granted_at":"2026-10-10T01:31:49Z","expires_at":"2026-10-10T02:01:49Z"}]}
        """
        let shown = InstanceGrants.parse(Data(out.utf8)).filter(\.isWorthShowing).map(\.instance)
        XCTAssertEqual(shown, ["broken", "dev"])
    }
}

final class StyleTests: XCTestCase {
    func grant(granted: String, expires: String) -> Grant {
        let json = """
        {"kind":"secret","name":"dev:x","scope":"connection","approval_id":"a","granted_at":"\(granted)","expires_at":"\(expires)"}
        """
        return try! JSONDecoder().decode(Grant.self, from: Data(json.utf8))
    }

    func testTimeLeftWordsAndFraction() {
        let now = GoTime.parse("2026-10-10T01:00:00Z")!
        let long = TimeLeft.of(grant(granted: "2026-10-10T00:00:00Z", expires: "2026-10-10T08:00:00Z"), now: now)!
        XCTAssertEqual(long.text, "7h")
        XCTAssertEqual(long.fraction, 7.0 / 8.0, accuracy: 1e-9)
        XCTAssertEqual(TimeLeft.of(grant(granted: "2026-10-10T00:30:00Z", expires: "2026-10-10T02:15:00Z"), now: now)!.text, "1h 15m")
        XCTAssertEqual(TimeLeft.of(grant(granted: "2026-10-10T00:50:00Z", expires: "2026-10-10T01:10:00Z"), now: now)!.text, "10m")
        XCTAssertEqual(TimeLeft.of(grant(granted: "2026-10-10T00:00:00Z", expires: "2026-10-10T00:59:00Z"), now: now)!.text, "ending")
    }

    func testEveryEventTypeHasAnIcon() {
        for t in ["approval.reused", "approval.granted", "approval.denied", "approval.timeout", "secret.read", "action.run",
                  "secret.list", "lock", "grants.drop", "request.rejected", "server.start", "vault.init", "something.new"] {
            let e = try! JSONDecoder().decode(AuditEvent.self, from: Data(#"{"seq":1,"ts":"2026-10-10T01:00:00Z","type":"\#(t)","outcome":"ok"}"#.utf8))
            XCTAssertFalse(ActivityStyle.symbol(e).name.isEmpty, t)
        }
        let denied = try! JSONDecoder().decode(AuditEvent.self, from: Data(#"{"seq":1,"ts":"2026-10-10T01:00:00Z","type":"secret.read","outcome":"denied"}"#.utf8))
        XCTAssertEqual(ActivityStyle.symbol(denied).tone, .bad)
    }

    func testAgo() {
        let now = Date(timeIntervalSince1970: 100_000)
        XCTAssertEqual(ActivityStyle.ago(now - 30, now: now), "now")
        XCTAssertEqual(ActivityStyle.ago(now - 300, now: now), "5m ago")
        XCTAssertEqual(ActivityStyle.ago(now - 7200, now: now), "2h ago")
        XCTAssertEqual(ActivityStyle.ago(now - 200_000, now: now), "2d ago")
    }
}

final class UsageTests: XCTestCase {
    func event(seq: UInt64, ts: String, type: String = "approval.reused", approval: String = "ap1", id: String = "dev:x",
               quiet: Bool = false, outcome: String = "ok", mode: String = "reused") -> AuditEvent {
        let json = """
        {"seq":\(seq),"ts":"\(ts)","type":"\(type)","outcome":"\(outcome)","resource":{"kind":"secret","id":"\(id)"},\
        "approval":{"id":"\(approval)","mode":"\(mode)"\(quiet ? #","quiet":true"# : "")}}
        """
        return try! JSONDecoder().decode(AuditEvent.self, from: Data(json.utf8))
    }

    func grant(approval: String = "ap1", name: String = "dev:x", expires: String = "2026-10-10T02:00:00Z", quiet: Bool = false) -> Grant {
        let json = """
        {"kind":"secret","name":"\(name)","scope":"peer-session","approval_id":"\(approval)",\
        "granted_at":"2026-10-10T01:00:00Z","expires_at":"\(expires)"\(quiet ? #","quiet":true"# : "")}
        """
        return try! JSONDecoder().decode(Grant.self, from: Data(json.utf8))
    }

    // A grant's uses are the access it was approved for and each reuse,
    // counted as the activity row folds them: the reads served under it.
    func testUsageCountsEveryReadServedUnderAGrant() {
        var u = GrantUsage()
        u.add(event(seq: 1, ts: "2026-10-10T01:10:00Z", type: "approval.granted", mode: "fresh"))
        u.add(event(seq: 2, ts: "2026-10-10T01:10:00Z", type: "secret.read", mode: "fresh"))
        u.add(event(seq: 3, ts: "2026-10-10T01:15:00Z", type: "approval.reused"))
        u.add(event(seq: 4, ts: "2026-10-10T01:15:00Z", type: "secret.read"))
        u.add(event(seq: 5, ts: "2026-10-10T01:20:00Z", type: "secret.read"))
        u.add(event(seq: 6, ts: "2026-10-10T01:21:00Z", type: "secret.read", outcome: "error"))
        u.add(event(seq: 7, ts: "2026-10-10T01:15:00Z", type: "secret.read", approval: "ap2"))
        u.add(event(seq: 8, ts: "2026-10-10T01:16:00Z", type: "secret.read", approval: "ap3", outcome: "denied", mode: "fresh"))
        let now = GoTime.parse("2026-10-10T01:22:00Z")!
        XCTAssertEqual(GrantUsage.text(u.of(grant()), now: now), "Used 3× · last 2m ago", "the approved read and two reuses; not the failed one")
        XCTAssertEqual(GrantUsage.text(u.of(grant(approval: "ap2")), now: now), "Used 1× · last 7m ago")
        XCTAssertEqual(GrantUsage.text(u.of(grant(approval: "ap3")), now: now), "Not used yet", "a denial is no use")
        XCTAssertEqual(GrantUsage.text(u.of(grant(name: "dev:y")), now: now), "Not used yet", "another resource of the same approval")
        u.prune(now: now + maxGrantWindow + 1)
        XCTAssertEqual(u.of(grant()).count, 0, "ended grants are forgotten")
    }

    // An open grant lists its uses newest first, the approved one apart from
    // its reuses; it keeps the latest ones and counts the rest.
    func testAGrantListsItsUses() {
        var u = GrantUsage()
        u.add(event(seq: 1, ts: "2026-10-10T01:10:00Z", type: "secret.read", mode: "fresh"))
        u.add(event(seq: 3, ts: "2026-10-10T01:12:00Z", type: "secret.read"))
        u.add(event(seq: 2, ts: "2026-10-10T01:11:00Z", type: "secret.read"))
        let use = u.of(grant())
        XCTAssertEqual(use.entries.map(\.seq), [3, 2, 1])
        XCTAssertEqual(use.entries.map(\.how), ["reused", "reused", "approved"])
        for i in 0..<60 {
            u.add(event(seq: 100 + UInt64(i), ts: "2026-10-10T01:20:00Z", type: "secret.read"))
        }
        let many = u.of(grant())
        XCTAssertEqual(many.count, 63)
        XCTAssertEqual(many.entries.count, GrantUsage.keptEntries)
        XCTAssertEqual(many.entries.first?.seq, 159, "the newest are kept")
    }

    func testAQuietGrantIsReadAsQuiet() {
        XCTAssertTrue(grant(quiet: true).isQuiet, "notify = false, as foca grants --host -f json writes it")
        XCTAssertFalse(grant().isQuiet, "foca leaves quiet out of any other grant")
    }

    func testQuietAndMutedReusesDontNotify() {
        let g = grant()
        let now = GoTime.parse("2026-10-10T01:05:00Z")!
        var b = BellChoices()
        XCTAssertTrue(ReuseNotice.notifies(event(seq: 1, ts: "2026-10-10T01:10:00Z"), bells: b))
        XCTAssertFalse(ReuseNotice.notifies(event(seq: 2, ts: "2026-10-10T01:10:00Z", quiet: true), bells: b), "notify = false in the config")
        XCTAssertFalse(ReuseNotice.notifies(event(seq: 3, ts: "2026-10-10T01:10:00Z", type: "secret.read"), bells: b))
        b.toggle(g, now: now)
        XCTAssertFalse(ReuseNotice.notifies(event(seq: 4, ts: "2026-10-10T01:10:00Z"), bells: b), "muted grant")
        XCTAssertTrue(ReuseNotice.notifies(event(seq: 5, ts: "2026-10-10T01:10:00Z", approval: "ap2"), bells: b),
                      "a new approval of the same secret notifies again")
        // Saved and loaded, as across a relaunch: it still covers reuses made
        // while Foca wasn't running, until it's pruned.
        let loaded = BellChoices(muted: b.storedMuted, heard: b.storedHeard)
        XCTAssertFalse(ReuseNotice.notifies(event(seq: 6, ts: "2026-10-10T01:59:00Z"), bells: loaded))
        var pruned = loaded
        pruned.prune(now: GoTime.parse("2026-10-10T02:00:01Z")!)
        XCTAssertEqual(pruned, BellChoices())
        b.toggle(g, now: now)
        XCTAssertTrue(ReuseNotice.notifies(event(seq: 7, ts: "2026-10-10T01:10:00Z"), bells: b), "unmuted")
    }

    // notify = false is where a grant starts; the bell can turn it on, and
    // off again, as for any other grant.
    func testAQuietGrantCanBeTurnedOnFromTheMenu() {
        let g = grant(quiet: true)
        let now = GoTime.parse("2026-10-10T01:05:00Z")!
        var b = BellChoices()
        XCTAssertFalse(b.notifies(g.id, quiet: true, now: now))
        b.toggle(g, now: now)
        XCTAssertTrue(b.notifies(g.id, quiet: true, now: now))
        XCTAssertTrue(ReuseNotice.notifies(event(seq: 1, ts: "2026-10-10T01:10:00Z", quiet: true), bells: b), "turned on")
        XCTAssertFalse(ReuseNotice.notifies(event(seq: 2, ts: "2026-10-10T01:10:00Z", approval: "ap2", quiet: true), bells: b),
                       "another quiet grant stays quiet")
        let loaded = BellChoices(muted: b.storedMuted, heard: b.storedHeard)
        XCTAssertTrue(ReuseNotice.notifies(event(seq: 3, ts: "2026-10-10T01:59:00Z", quiet: true), bells: loaded), "kept across a relaunch")
        XCTAssertFalse(ReuseNotice.notifies(event(seq: 4, ts: "2026-10-10T02:00:01Z", quiet: true), bells: loaded), "ends with the grant")
        b.toggle(g, now: now)
        XCTAssertFalse(b.notifies(g.id, quiet: true, now: now), "and off again")
    }

    func testOnlyARunOfRepeatsFoldsIntoOneRow() {
        let newestFirst = [
            event(seq: 6, ts: "2026-10-10T01:06:00Z"),
            event(seq: 5, ts: "2026-10-10T01:05:00Z"),
            event(seq: 4, ts: "2026-10-10T01:04:00Z", id: "dev:y"),
            event(seq: 3, ts: "2026-10-10T01:03:00Z"),
            event(seq: 2, ts: "2026-10-10T01:02:00Z", outcome: "denied"),
            event(seq: 1, ts: "2026-10-10T01:01:00Z"),
        ]
        let groups = ActivityGroup.of(newestFirst)
        XCTAssertEqual(groups.map { $0.items.map(\.seq) }, [[6, 5], [4], [3], [2], [1]], "x 2, y, x, x denied, x: never x 4")
        XCTAssertEqual(groups.map(\.id), ["seq:5", "seq:4", "seq:3", "seq:2", "seq:1"], "a row is known by its oldest item")
    }
}

final class ActivityTests: XCTestCase {
    /// An event of one request, as foca writes them.
    func ev(_ seq: UInt64, _ type: String, req: String, outcome: String = "ok", secret: String? = "common:github-pat",
            secrets: [String]? = nil, mode: String? = nil, ap: String = "ap", peer: String = "ssh") -> AuditEvent {
        var fields = [#""seq":\#(seq)"#, #""ts":"2026-10-10T01:00:\#(seq < 10 ? "0\(seq)" : "\(seq)")Z""#, #""type":"\#(type)""#,
                      #""outcome":"\#(outcome)""#, #""request_id":"\#(req)""#, #""instance":"dev""#,
                      #""peer":{"verified":{"name":"\#(peer)","realm":{"kind":"vm","name":"dev"}}}"#]
        if let s = secret {
            fields.append(#""resource":{"kind":"secret","id":"\#(s)"}"#)
        }
        if let ss = secrets {
            fields.append(#""resources":["# + ss.map { #"{"kind":"secret","id":"\#($0)"}"# }.joined(separator: ",") + "]")
        }
        if let m = mode {
            fields.append(#""approval":{"id":"\#(ap)","mode":"\#(m)"}"#)
        }
        return try! JSONDecoder().decode(AuditEvent.self, from: Data(("{" + fields.joined(separator: ",") + "}").utf8))
    }

    func testARequestIsOneRow() {
        // Newest first, as the menu holds them: a batch approved with a
        // prompt, then a reuse, then a denial, then an unrelated lock.
        let lock = try! JSONDecoder().decode(AuditEvent.self, from: Data(#"{"seq":1,"ts":"2026-10-10T01:00:01Z","type":"lock","outcome":"ok","reason":"manual","count":2}"#.utf8))
        let events = [
            ev(9, "secret.read", req: "r3", secret: "common:npm-token", mode: "fresh"),
            ev(8, "secret.read", req: "r3", mode: "fresh"),
            ev(7, "approval.granted", req: "r3", secret: nil, secrets: ["common:github-pat", "common:npm-token"], mode: "fresh"),
            ev(6, "secret.read", req: "r2", mode: "reused"),
            ev(5, "approval.reused", req: "r2", mode: "reused"),
            ev(4, "secret.read", req: "r1", outcome: "denied", mode: "fresh"),
            ev(3, "approval.denied", req: "r1", outcome: "denied", secret: nil, secrets: ["common:github-pat"], mode: "fresh"),
            lock,
        ]
        let items = ActivityItem.items(events)
        XCTAssertEqual(items.map(\.seq), [9, 6, 4, 1])
        XCTAssertEqual(items[0].text, "common:github-pat, common:npm-token · ssh (vm dev)", "a batch is one row, in the order read")
        XCTAssertEqual(items[0].how, "approved")
        XCTAssertEqual(items[1].text, "common:github-pat · ssh (vm dev)")
        XCTAssertEqual(items[1].how, "reused")
        XCTAssertEqual(items[2].how, "denied")
        XCTAssertEqual(items[2].tone, .bad, "a denial is red")
        XCTAssertEqual(items[3].how, "")
        XCTAssertEqual(items[3].text, ActivityText.describe(lock))
        XCTAssertEqual(items[3].tone, .neutral, "a lock is routine: no colour")
    }

    func testRequestsThatEndedDifferentlyNeverFold() {
        let events = [
            ev(6, "secret.read", req: "r3", mode: "reused"),
            ev(5, "approval.reused", req: "r3", mode: "reused"),
            ev(4, "secret.read", req: "r2", outcome: "denied", mode: "fresh"),
            ev(3, "approval.denied", req: "r2", outcome: "denied", secret: nil, secrets: ["common:github-pat"]),
            ev(2, "secret.read", req: "r1", mode: "reused"),
            ev(1, "approval.reused", req: "r1", mode: "reused"),
        ]
        let groups = ActivityGroup.of(events)
        XCTAssertEqual(groups.map { $0.items.map(\.seq) }, [[6], [4], [2]], "the denial stays apart, and parts the reuses")
        XCTAssertEqual(groups[1].newest.how, "denied")
    }

    func testOneGrantIsOneRowFromItsApprovalThroughItsReuses() {
        let events = [
            ev(8, "secret.read", req: "r4", mode: "reused", ap: "ap2"),
            ev(7, "approval.reused", req: "r4", mode: "reused", ap: "ap2"),
            ev(6, "secret.read", req: "r3", mode: "reused", ap: "ap1"),
            ev(5, "approval.reused", req: "r3", mode: "reused", ap: "ap1"),
            ev(4, "secret.read", req: "r2", mode: "reused", ap: "ap1"),
            ev(3, "approval.reused", req: "r2", mode: "reused", ap: "ap1"),
            ev(2, "secret.read", req: "r1", mode: "fresh", ap: "ap1"),
            ev(1, "approval.granted", req: "r1", mode: "fresh", ap: "ap1"),
        ]
        let groups = ActivityGroup.of(events)
        XCTAssertEqual(groups.map { $0.items.map(\.seq) }, [[8], [6, 4, 2]], "another grant of the same secret is its own row")
        XCTAssertEqual(groups[1].summary.how, "approved", "the row says how the grant was made")
        XCTAssertEqual(groups[1].newest.seq, 6, "and when it was last used")
        XCTAssertEqual(groups[0].summary.how, "reused")
    }

    func plain(_ seq: UInt64, _ type: String, outcome: String = "ok", reason: String? = nil) -> AuditEvent {
        let r = reason.map { #","reason":"\#($0)""# } ?? ""
        let json = #"{"seq":\#(seq),"ts":"2026-10-10T01:00:0\#(seq)Z","type":"\#(type)","outcome":"\#(outcome)"\#(r)}"#
        return try! JSONDecoder().decode(AuditEvent.self, from: Data(json.utf8))
    }

    func testActivityStartsAtTheNewestStartOrWipe() {
        let events = [
            ev(9, "secret.read", req: "r3", mode: "reused"),
            ev(8, "approval.reused", req: "r3", mode: "reused"),
            plain(7, "lock", reason: "expired"),
            plain(6, "lock", reason: "screen-lock"),
            ev(5, "secret.read", req: "r2", mode: "reused"),
            ev(4, "approval.reused", req: "r2", mode: "reused"),
            plain(3, "server.start"),
            ev(2, "secret.read", req: "r1", mode: "fresh"),
            ev(1, "approval.granted", req: "r1", mode: "fresh"),
        ]
        XCTAssertEqual(ActivityGroup.of(events).map(\.id), ["req:r3", "seq:7", "seq:6"],
                       "a wipe starts it, and is shown; grants that expired are no reset")
        XCTAssertEqual(ActivityGroup.of(Array(events[4...])).map(\.id), ["req:r2", "seq:3"], "so does a start")
        XCTAssertEqual(ActivityGroup.of(Array(events[7...])).map(\.id), ["req:r1"], "with neither, everything read is shown")
        XCTAssertEqual(ActivityGroup.of(events, sinceReset: false).map(\.id), ["req:r3", "seq:7", "seq:6", "req:r2", "seq:3", "req:r1"],
                       "turned off, everything read is shown")
    }

    func testImportantOnlyLeavesOutRoutineEventsAndFoldsWhatTheyParted() {
        let events = [
            ev(8, "secret.read", req: "r3", mode: "reused"),
            ev(7, "approval.reused", req: "r3", mode: "reused"),
            plain(6, "secret.list"),
            plain(5, "lock", reason: "expired"),
            plain(4, "request.rejected", outcome: "rejected"),
            ev(3, "secret.read", req: "r2", mode: "reused"),
            ev(2, "approval.reused", req: "r2", mode: "reused"),
            plain(1, "config.reload"),
        ]
        XCTAssertEqual(ActivityGroup.of(events).map { $0.items.map(\.seq) }, [[8], [6], [5], [4], [3], [1]])
        XCTAssertEqual(ActivityGroup.of(events, importantOnly: true).map { $0.items.map(\.seq) }, [[8], [4], [3]],
                       "a rejected request is kept, and still parts the reuses")
        XCTAssertEqual(ActivityGroup.of(Array(events[..<4]), importantOnly: true).map { $0.items.map(\.seq) }, [[8]])
        let parted = Array(events[..<4]) + Array(events[5...])
        XCTAssertEqual(ActivityGroup.of(parted, importantOnly: true).map { $0.items.map(\.seq) }, [[8, 3]],
                       "reuses parted only by routine events fold")
    }

    func testAFailedServeIsNotShownAsApproved() {
        let items = ActivityItem.items([
            ev(2, "secret.read", req: "r1", outcome: "error", mode: "fresh"),
            ev(1, "approval.granted", req: "r1", mode: "fresh"),
        ])
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].how, "error")
        XCTAssertEqual(items[0].tone, .bad)
    }
}
