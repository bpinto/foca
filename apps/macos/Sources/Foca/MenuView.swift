import AppKit
import FocaKit
import SwiftUI

extension Tone {
    var color: Color {
        switch self {
        case .good: return .green
        case .info: return .accentColor
        case .warning: return .orange
        case .bad: return .red
        case .neutral: return .secondary
        }
    }
}

struct MenuView: View {
    @ObservedObject var monitor: Monitor
    private let visibleActivity = 5
    // Recent activity's two filters, kept across launches: only what came
    // since the service started or last wiped its grants, and only what was
    // read or run, or refused or failed (no locks, starts or lists).
    @AppStorage("activitySinceReset") private var sinceReset = true
    @AppStorage("activityImportantOnly") private var importantOnly = true

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header

            ForEach(monitor.warnings) { w in
                WarningCard(warning: w)
            }

            Divider()

            section("Live grants") {
                let shown = monitor.instances.filter(\.isWorthShowing)
                if shown.isEmpty {
                    Label(monitor.instances.isEmpty ? (monitor.grantsError ?? "No service is running")
                                                    : "None: every access asks",
                          systemImage: monitor.instances.isEmpty ? "moon.zzz.fill" : "checkmark.shield.fill")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                ForEach(shown) { inst in
                    InstanceView(inst: inst, monitor: monitor)
                }
            }

            Divider()

            section("Recent activity", accessory: { activityFilters }) {
                let groups = ActivityGroup.of(monitor.recent, sinceReset: sinceReset, importantOnly: importantOnly)
                if groups.isEmpty {
                    Label(emptyActivity, systemImage: "tray")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                        .foregroundStyle(.secondary)
                } else {
                    ActivityList(groups: groups, now: monitor.now, visibleRows: visibleActivity)
                }
            }

            Divider()

            // Menu-style rows, like "Wi-Fi Settings…" at the foot of the Wi-Fi menu.
            VStack(spacing: 0) {
                Button("Revoke all grants") { monitor.lock() }
                    .help("Drop every reuse grant, so the next access asks again (foca lock)")
                    .disabled(monitor.focaPath == nil)
                Button("Quit Foca") { NSApp.terminate(nil) }
            }
            .buttonStyle(MenuRowStyle())
            .padding(.horizontal, -8)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .frame(width: 360)
        .onAppear { monitor.checkNotifications() }
    }

    private var header: some View {
        // Like the Battery menu's title: a bold name, its state on the right.
        HStack(spacing: 6) {
            Text("Foca").font(.body.bold())
            Spacer()
            let s = status
            Circle()
                .fill(s.tone.color)
                .frame(width: 7, height: 7)
            Text(s.text)
                .foregroundStyle(.secondary)
        }
    }

    private var status: (text: String, tone: Tone) {
        if !monitor.warnings.isEmpty {
            return ("Needs attention", .warning)
        }
        if monitor.instances.isEmpty {
            return ("Not running", .neutral)
        }
        return ("Watching", .good)
    }

    private var activityFilters: some View {
        HStack(spacing: 6) {
            FilterToggle(on: $sinceReset, symbol: "lock.rotation", onSymbol: "lock.rotation",
                         help: sinceReset ? "Showing activity since foca started or last locked. Click to show the last 24 hours"
                                          : "Showing the last 24 hours. Click to show only activity since foca started or last locked")
            FilterToggle(on: $importantOnly, symbol: "line.3.horizontal.decrease.circle", onSymbol: "line.3.horizontal.decrease.circle.fill",
                         help: importantOnly ? "Showing what was read or run, and anything refused or failed. Click to show locks, starts and lists too"
                                             : "Showing every event. Click to show only what was read or run, and anything refused or failed")
        }
        .font(.subheadline)
    }

    private var emptyActivity: String {
        if monitor.recent.isEmpty {
            return "Nothing in the last 24 hours"
        }
        if importantOnly {
            return sinceReset ? "No accesses since the last start or lock" : "No accesses in the last 24 hours"
        }
        return "Nothing since the last start or lock"
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        section(title, accessory: { EmptyView() }, content: content)
    }

    private func section<Accessory: View, Content: View>(_ title: String, @ViewBuilder accessory: () -> Accessory,
                                                         @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                accessory()
            }
            VStack(alignment: .leading, spacing: 6, content: content)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// Recent activity with repeats folded into one row ("5×"), which opens to
/// list when each happened.
struct ActivityList: View {
    let groups: [ActivityGroup]
    let now: Date
    let visibleRows: Int
    @State private var expanded: Set<String> = []

    private let rowHeight: CGFloat = 22

    var body: some View {
        let rows = groups.reduce(0) { $0 + 1 + (expanded.contains($1.id) ? $1.items.count : 0) }
        if rows <= visibleRows {
            list
        } else {
            // About visibleRows rows; the rest scroll.
            ScrollView {
                list
            }
            .frame(height: CGFloat(visibleRows) * rowHeight)
        }
    }

    private var list: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(groups) { g in
                row(g)
                if expanded.contains(g.id) {
                    ForEach(g.items) { i in
                        HStack(spacing: 6) {
                            Text(i.date.map { $0.formatted(date: .omitted, time: .standard) } ?? "")
                            Text(i.how)
                            Spacer(minLength: 4)
                            Text(i.date.map { ActivityStyle.ago($0, now: now) } ?? "")
                        }
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .padding(.leading, 22)
                        .frame(height: 18)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func row(_ g: ActivityGroup) -> some View {
        let i = g.summary
        let open = expanded.contains(g.id)
        // Refused and failed requests stand out: the whole row is red.
        let alarm = i.tone == .bad
        let line = HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: i.symbol)
                .foregroundStyle(i.tone.color)
                .frame(width: 16)
            Text(i.text)
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(alarm ? Color.red : Color.primary)
            Spacer(minLength: 4)
            if g.items.count > 1 {
                Text("\(g.items.count)×")
                    .font(.caption2.weight(.semibold))
                    .monospacedDigit()
                    .padding(.horizontal, 5)
                    .background(Color.primary.opacity(0.08), in: Capsule())
                    .foregroundStyle(.secondary)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .rotationEffect(.degrees(open ? 90 : 0))
                    .foregroundStyle(.secondary)
            }
            if !i.how.isEmpty {
                Text(i.how)
                    .foregroundStyle(alarm ? Color.red : i.tone == .warning ? Color.orange : Color.secondary)
            }
            Text(g.newest.date.map { ActivityStyle.ago($0, now: now) } ?? "")
                .monospacedDigit()
                .foregroundStyle(.secondary)
        }
        .font(.caption)
        .frame(height: 18)
        .padding(.horizontal, 4)
        .background(alarm ? Color.red.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
        .contentShape(Rectangle())
        .help(i.how.isEmpty ? i.text : i.text + " (" + i.how + ")")

        if g.items.count > 1 {
            Button {
                if open {
                    expanded.remove(g.id)
                } else {
                    expanded.insert(g.id)
                }
            } label: {
                line
            }
            .buttonStyle(.plain)
        } else {
            line
        }
    }
}

/// A filter in a section's title: an icon, in the accent colour (and filled,
/// when its symbol has a filled form) while it filters, grey while it doesn't.
struct FilterToggle: View {
    @Binding var on: Bool
    let symbol: String
    let onSymbol: String
    let help: String

    var body: some View {
        Button {
            on.toggle()
        } label: {
            Image(systemName: on ? onSymbol : symbol)
                .foregroundStyle(on ? Color.accentColor : Color.secondary)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(help)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

/// A full-width row that highlights under the pointer, as items do in the system's menu-bar menus.
struct MenuRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        MenuRow(configuration: configuration)
    }

    private struct MenuRow: View {
        let configuration: Configuration
        @Environment(\.isEnabled) private var isEnabled
        @State private var hovering = false

        var body: some View {
            configuration.label
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .foregroundStyle(isEnabled ? HierarchicalShapeStyle.primary : .tertiary)
                .background(
                    RoundedRectangle(cornerRadius: 5)
                        .fill(Color.primary.opacity(highlight))
                )
                .contentShape(Rectangle())
                .onHover { hovering = $0 }
        }

        private var highlight: Double {
            if !isEnabled { return 0 }
            if configuration.isPressed { return 0.16 }
            return hovering ? 0.08 : 0
        }
    }
}

struct WarningCard: View {
    let warning: Monitor.Warning

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(warning.text, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            if let title = warning.fixTitle, let fix = warning.fix {
                Button(title, action: fix)
                    .buttonStyle(.borderedProminent)
                    .tint(.orange)
                    .controlSize(.small)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.orange.opacity(0.35)))
    }
}

struct InstanceView: View {
    let inst: InstanceGrants
    @ObservedObject var monitor: Monitor

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let e = inst.error {
                Label(Names.program(inst.instance) + ": " + Names.text(e, max: 200), systemImage: "exclamationmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            ForEach(inst.grants) { g in
                GrantRow(grant: g, instance: inst.instance, now: monitor.now, use: monitor.usage.of(g),
                         notifies: monitor.bells.notifies(g.id, quiet: g.isQuiet, now: monitor.now), toggleBell: { monitor.toggleBell(g) },
                         revoke: { monitor.revoke(g) })
            }
        }
    }
}

struct GrantRow: View {
    let grant: Grant
    let instance: String
    let now: Date
    let use: GrantUsage.Use
    let notifies: Bool
    let toggleBell: () -> Void
    let revoke: () -> Void

    var body: some View {
        let left = TimeLeft.of(grant, now: now)
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Image(systemName: grant.kind == "action" ? "terminal.fill" : "key.fill")
                    .foregroundStyle(.secondary)
                    .frame(width: 16)
                Text(ReuseText.grant(grant))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(Names.program(instance))
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Color.primary.opacity(0.08), in: Capsule())
                    .foregroundStyle(.secondary)
                Spacer(minLength: 4)
                Button(action: toggleBell) {
                    Image(systemName: notifies ? "bell" : "bell.slash.fill")
                        .foregroundStyle(notifies ? Color.secondary : Color.orange)
                }
                .buttonStyle(.borderless)
                .help(bellHelp)
                Button(action: revoke) {
                    Image(systemName: "xmark.circle")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help("Revoke this grant: the next access asks again (foca grants --host --drop)")
            }
            .font(.callout)
            // Its use, then how long it has left: one line, which opens to
            // list the uses.
            HStack(spacing: 6) {
                if use.entries.isEmpty {
                    Text(GrantUsage.text(use, now: now))
                        .lineLimit(1)
                } else {
                    Button {
                        open.toggle()
                    } label: {
                        HStack(spacing: 4) {
                            Text(GrantUsage.text(use, now: now))
                                .lineLimit(1)
                            Image(systemName: "chevron.right")
                                .font(.caption2.weight(.semibold))
                                .rotationEffect(.degrees(open ? 90 : 0))
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(open ? "Hide its uses" : "List its uses")
                }
                Spacer(minLength: 8)
                if let left {
                    ProgressView(value: left.fraction)
                        .progressViewStyle(.linear)
                        .tint(.secondary)
                        .scaleEffect(x: 1, y: 0.5, anchor: .center)
                        .frame(width: 60)
                    Text(left.text)
                        .monospacedDigit()
                        .frame(minWidth: 34, alignment: .trailing)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.leading, 22)
            if open {
                ForEach(use.entries.prefix(Self.listedUses)) { u in
                    HStack(spacing: 6) {
                        Text(u.date.map { $0.formatted(date: .omitted, time: .standard) } ?? "")
                        Text(u.how)
                        Text(u.by)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: 4)
                        Text(u.date.map { ActivityStyle.ago($0, now: now) } ?? "")
                    }
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .padding(.leading, 34)
                }
                if use.count > min(use.entries.count, Self.listedUses) {
                    Text("and \(use.count - min(use.entries.count, Self.listedUses)) earlier")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .padding(.leading, 34)
                }
            }
        }
        .help(holder)
    }

    @State private var open = false
    // The newest uses an open grant lists; the rest are counted.
    private static let listedUses = 10

    private var bellHelp: String {
        switch (grant.isQuiet, notifies) {
        case (true, false):
            return "Not notified: notify = false in foca's config. Click to be notified of this grant's reuses until it ends"
        case (true, true):
            return "Notified until this grant ends, though foca's config says notify = false. Click to stop"
        case (false, false):
            return "Muted until this grant ends. Click to be notified of its reuses again"
        case (false, true):
            return "Click to stop notifications of this grant's reuses until it ends"
        }
    }

    private var holder: String {
        if let p = grant.scopeKey?.peerSession {
            return "For session " + Names.text(p.value) + ", until it expires or the Mac sleeps or locks"
        }
        if let c = grant.scopeKey?.connection {
            return "For connection " + Names.text(c.value) + " only"
        }
        return Names.text(grant.scope)
    }
}
