import AppKit
import SwiftUI

enum ViewMode: String, Hashable { case list, graph }

struct ContentView: View {
    @EnvironmentObject var store: Store
    @State private var selection: String?
    @State private var query = ""
    @State private var showSettings = false
    @State private var showSchedule = false
    @State private var bandFilter: Band?
    @State private var mode: ViewMode = .list
    @AppStorage("grouping") private var grouping = "urgency"
    @State private var collapsed: Set<String> = []
    @State private var hovered: String?
    @AppStorage("scheduleEnabled") private var scheduleOn = false
    @AppStorage("scheduleHour") private var scheduleHour = 9
    @AppStorage("scheduleMinute") private var scheduleMinute = 0
    @AppStorage("ageFilter") private var ageFilter = "all"

    /// Projects after the age filter, used by the list, the detail and the overview
    /// so every count on screen agrees.
    private var scoped: [ProjectGroup] {
        store.projects.compactMap { $0.filtered(age: ageFilter) }
    }

    /// Built once per render rather than inside the ForEach: a Section produced by a
    /// conditional inside a lazy stack keeps a stale layout when the filter empties and
    /// refills it, and the rows stop drawing.
    private var bandSections: [(band: Band, projects: [ProjectGroup])] {
        Band.allCases.compactMap { band in
            let group = visible.filter { $0.band == band }
            return group.isEmpty ? nil : (band, group)
        }
    }

    private var visible: [ProjectGroup] {
        var list = scoped
        if let bandFilter { list = list.filter { $0.band == bandFilter } }
        guard !query.isEmpty else { return list }
        let needle = query.lowercased()
        return list.filter {
            $0.name.lowercased().contains(needle) || $0.path.lowercased().contains(needle)
                || $0.items.contains { $0.package.lowercased().contains(needle) }
        }
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 268)
            Divider().overlay(Theme.hairline)
            VStack(spacing: 0) {
                toolbar
                contentPanel
            }
            .frame(maxWidth: .infinity)
        }
        .background(VisualEffect(material: .underWindowBackground).ignoresSafeArea())
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showSettings) { SettingsView() }
        .onAppear { store.loadFromDisk() }
        .onReceive(NotificationCenter.default.publisher(for: .selectProject)) { note in
            if let path = note.object as? String {
                bandFilter = nil
                mode = .list
                selection = path
            }
        }
    }

    // MARK: toolbar — sits in the title bar strip, one primary action

    private var toolbar: some View {
        HStack(spacing: Space.s) {
            Segmented(options: [(ViewMode.list, "List", "list.bullet.indent"),
                                (ViewMode.graph, "Graph",
                                 "point.3.connected.trianglepath.dotted")],
                      selection: $mode)

            if store.isScanning {
                Text(store.progress.isEmpty ? "Scanning…" : store.progress)
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                    .lineLimit(1).truncationMode(.middle)
            } else if let error = store.lastError {
                HStack(spacing: 5) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 9)).foregroundStyle(Band.p1.tint)
                    Text(error).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                        .lineLimit(1).truncationMode(.middle).frame(maxWidth: 300)
                }
            }

            Spacer(minLength: Space.s)

            scheduleButton
            if store.isScanning {
                Button("Stop") { store.cancelScan() }
                    .buttonStyle(.plain)
                    .pointerCursor()
                    .font(TypeScale.strong).foregroundStyle(Band.p0.tint)
            } else {
                PrimaryButton(title: "Scan", symbol: "arrow.clockwise") { store.scan() }
                    .keyboardShortcut("r", modifiers: .command)
            }
            IconButton(symbol: "doc.text", help: "Open the report  ⌘D") {
                store.open(store.reportURL)
            }
            .keyboardShortcut("d", modifiers: .command)
            IconButton(symbol: "arrow.up.forward.app", help: "Open the graph in a browser  ⌘G") {
                store.open(store.graphURL)
            }
            .keyboardShortcut("g", modifiers: .command)
            IconButton(symbol: "gearshape", help: "Settings  ⌘,") { showSettings = true }
                .keyboardShortcut(",", modifiers: .command)
        }
        .padding(.horizontal, Space.l)
        .frame(height: Theme.toolbarHeight)
    }

    // MARK: content — one inset panel, Sonoma style

    private var contentPanel: some View {
        RoundedRectangle(cornerRadius: Theme.panelRadius, style: .continuous)
            .fill(Theme.contentPanel)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.panelRadius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.07), lineWidth: 0.5)
            )
            .overlay(
                Group {
                    if mode == .graph {
                        GraphPane(focus: selection)
                    } else if let path = selection,
                              let project = scoped.first(where: { $0.path == path }) {
                        ProjectDetail(project: project)
                    } else {
                        Overview(selection: $selection, bandFilter: $bandFilter,
                                 projects: scoped, ageFilter: ageFilter)
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: Theme.panelRadius, style: .continuous))
            )
            .shadow(color: .black.opacity(0.28), radius: 2, y: 1)
            .padding(.leading, Space.m - 1)
            .padding(.trailing, 14)
            .padding(.bottom, 14)
    }

    // MARK: sidebar — material, search, list, standing state at the foot

    private var sidebar: some View {
        VStack(spacing: 0) {
            // Clear strip the traffic lights sit on.
            Color.clear.frame(height: Theme.toolbarHeight - 6)

            VStack(spacing: Space.s) {
                searchField
                Segmented(options: [("urgency", "Urgency", nil), ("folder", "Folder", nil)],
                          selection: $grouping)
                Segmented(options: [("all", "All", nil), ("recent", "Recent", nil),
                                    ("backlog", "Backlog", nil)],
                          selection: $ageFilter)
            }
            .padding(.horizontal, Space.m)
            .padding(.bottom, Space.s)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1, pinnedViews: [.sectionHeaders]) {
                    if grouping == "folder" {
                        ForEach(FolderGroup.build(from: visible)) { folder in
                            Section {
                                if !collapsed.contains(folder.path) {
                                    ForEach(folder.projects) { projectRow($0) }
                                }
                            } header: {
                                folderHeader(folder, holdsSelection: holds(folder.projects))
                            }
                        }
                    } else {
                        ForEach(bandSections, id: \.band) { section in
                            Section {
                                ForEach(section.projects) { projectRow($0) }
                            } header: {
                                bandHeader(section.band, count: section.projects.count,
                                           holdsSelection: holds(section.projects))
                            }
                        }
                    }
                    if visible.isEmpty { emptyList }
                }
                .padding(.bottom, Space.m)
            }

            Divider().overlay(Theme.hairline)
            sidebarFooter
        }
        .background(VisualEffect(material: .sidebar).ignoresSafeArea())
    }

    private var sidebarFooter: some View {
        HStack(spacing: Space.s) {
            GlowDot(color: headlineTint, size: 7)
            Text(store.headline).font(TypeScale.strong).foregroundStyle(Theme.text)
                .lineLimit(1)
            Spacer(minLength: Space.xs)
            if let last = store.lastScan {
                Text(last.formatted(.relative(presentation: .numeric)))
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary).lineLimit(1)
            }
        }
        .padding(.horizontal, Space.m + 2)
        .frame(height: 38)
    }

    /// Scheduled scans sit beside the manual one: "run it now" and "run it on a clock"
    /// are the same decision, so they belong together.
    private var scheduleButton: some View {
        Button { showSchedule.toggle() } label: {
            HStack(spacing: 5) {
                Image(systemName: scheduleOn ? "clock.fill" : "clock")
                    .font(.system(size: 11, weight: .medium))
                Text(scheduleOn ? String(format: "%02d:%02d", scheduleHour, scheduleMinute)
                                : "Schedule")
                    .font(.system(size: 12, weight: .medium))
            }
            .foregroundStyle(scheduleOn ? Theme.accent : Theme.secondary)
            .fixedSize()
            .padding(.horizontal, Space.m)
            .padding(.vertical, 5)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(scheduleOn ? Theme.accent.opacity(0.14) : Color.white.opacity(0.05)))
            .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                .strokeBorder(scheduleOn ? Theme.accent.opacity(0.35)
                                         : Color.white.opacity(0.09), lineWidth: 0.5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .help(ScanSchedule.summary)
        .popover(isPresented: $showSchedule, arrowEdge: .bottom) {
            SchedulePopover().environmentObject(store)
        }
    }

    private var emptyList: some View {
        Text(store.findings == nil ? "No scan yet" : "Nothing matches")
            .font(TypeScale.body).foregroundStyle(Theme.tertiary)
            .padding(.horizontal, Space.m).padding(.top, Space.l)
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11)).foregroundStyle(Theme.tertiary)
            TextField("Search", text: $query)
                .textFieldStyle(.plain).font(TypeScale.body).foregroundStyle(Theme.text)
            if !query.isEmpty {
                Button { query = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 10)).foregroundStyle(Theme.tertiary)
                }
                .buttonStyle(.plain)
                .pointerCursor()
            }
        }
        .padding(.horizontal, Space.s + 2)
        .frame(height: 26)
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.sunken))
        .overlay(RoundedRectangle(cornerRadius: 7)
            .strokeBorder(Color.white.opacity(0.08), lineWidth: 0.5))
    }

    private func bandHeader(_ band: Band, count: Int, holdsSelection: Bool) -> some View {
        HStack {
            SectionLabel(text: band.title, tint: holdsSelection ? Theme.accent : nil)
            Spacer()
            Text("\(count)").font(TypeScale.micro).foregroundStyle(Theme.tertiary.opacity(0.8))
        }
        .padding(.horizontal, Space.m + 3)
        .padding(.top, Space.m).padding(.bottom, Space.xs)
        .background(.ultraThinMaterial)
        .overlay(alignment: .leading) { sectionMarker(holdsSelection) }
    }

    private func folderHeader(_ folder: FolderGroup, holdsSelection: Bool) -> some View {
        let isCollapsed = collapsed.contains(folder.path)
        return Button {
            if isCollapsed { collapsed.remove(folder.path) } else { collapsed.insert(folder.path) }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 8, weight: .bold)).foregroundStyle(Theme.tertiary)
                    .rotationEffect(.degrees(isCollapsed ? 0 : 90))
                GlowDot(color: folder.band.tint, size: 5, glow: false)
                Text(folder.name).font(TypeScale.micro).tracking(0.5)
                    .foregroundStyle(holdsSelection ? Theme.accent : Theme.tertiary)
                    .lineLimit(1).truncationMode(.head)
                Spacer()
                Text("\(folder.projects.count)")
                    .font(TypeScale.micro).foregroundStyle(Theme.tertiary.opacity(0.8))
            }
            .padding(.horizontal, Space.m + 3)
            .padding(.top, Space.m).padding(.bottom, Space.xs)
            .background(.ultraThinMaterial)
            .overlay(alignment: .leading) { sectionMarker(holdsSelection) }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .pointerCursor()
    }

    /// The accent rail that ties a pinned header to the row selected inside it.
    private func sectionMarker(_ on: Bool) -> some View {
        Rectangle().fill(Theme.accent).frame(width: 2)
            .padding(.vertical, 4)
            .opacity(on ? 1 : 0)
    }

    private func holds(_ projects: [ProjectGroup]) -> Bool {
        guard let selection else { return false }
        return projects.contains { $0.path == selection }
    }

    private func projectRow(_ project: ProjectGroup) -> some View {
        let active = selection == project.path
        // Selecting stays in whichever view you are in: the list shows the detail,
        // the graph focuses that project's cluster.
        return Button { selection = project.path } label: {
            HStack(spacing: Space.s + 2) {
                GlowDot(color: project.band.tint, size: 7, glow: active && project.band <= .p1)
                Text(project.name)
                    .font(active ? Font.system(size: 13, weight: .semibold) : TypeScale.body)
                    .foregroundStyle(active ? .white : Theme.text.opacity(0.84))
                    .lineLimit(1)
                Spacer(minLength: Space.xs)
                if project.kev {
                    Image(systemName: "flame.fill")
                        .font(.system(size: 8)).foregroundStyle(Band.p0.tint)
                }
                Text("\(project.items.count)")
                    .font(TypeScale.mono).foregroundStyle(Theme.tertiary).monospacedDigit()
            }
            .padding(.horizontal, Space.s + 1)
            .frame(height: 28)
            .background(RoundedRectangle(cornerRadius: 6)
                .fill(active ? Theme.accent : (hovered == project.path
                                               ? Color.white.opacity(0.06) : .clear)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .onHover { hovered = $0 ? project.path : (hovered == project.path ? nil : hovered) }
        .padding(.horizontal, Space.s + 1)
        .id(project.path)
    }

    private var headlineTint: Color {
        guard let findings = store.findings else { return Theme.tertiary }
        if findings.count(.p0) > 0 { return Band.p0.tint }
        if findings.count(.p1) > 0 { return Band.p1.tint }
        return Theme.good
    }
}

// MARK: - Overview

struct Overview: View {
    @EnvironmentObject var store: Store
    @Binding var selection: String?
    @Binding var bandFilter: Band?
    let projects: [ProjectGroup]
    let ageFilter: String

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xl) {
                if store.findings == nil {
                    emptyState
                } else {
                    malwareBanner
                    header
                    tiles
                    if !topRisks.isEmpty { risks }
                    if let leads = store.findings?.leads, !leads.isEmpty { leadsPanel(leads) }
                    scanPanel
                }
            }
            .padding(.horizontal, 26)
            .padding(.vertical, 22)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var emptyState: some View {
        VStack(spacing: Space.m) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 38, weight: .light)).foregroundStyle(Theme.tertiary)
            Text("No scan yet").font(TypeScale.title).foregroundStyle(Theme.text)
            Text("Builds a dependency graph of your projects and matches it against "
                 + "advisories published in the last two weeks.")
                .font(TypeScale.body).foregroundStyle(Theme.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 360)
            PrimaryButton(title: "Run first scan", symbol: "play.fill") { store.scan() }
                .padding(.top, Space.xs)
        }
        .frame(maxWidth: .infinity).padding(.top, 90)
    }

    /// Known-malicious packages and suspicious install hooks are a different class of
    /// problem from an out-of-date dependency, so they lead rather than queue.
    @ViewBuilder
    private var malwareBanner: some View {
        let malware = store.findings?.malware ?? []
        let alerts = store.findings?.alerts ?? []
        if !malware.isEmpty || !alerts.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 7) {
                    Image(systemName: "exclamationmark.octagon.fill")
                        .font(.system(size: 13)).foregroundStyle(Band.p0.tint)
                    Text(malware.isEmpty
                         ? "\(alerts.count) suspicious install hook(s)"
                         : malware.contains { $0.installedOnDisk == true }
                           ? "\(malware.count) known-malicious package(s) unpacked on disk"
                           : "\(malware.count) known-malicious package(s) pinned in a lockfile")
                        .font(TypeScale.title).foregroundStyle(Theme.text)
                }
                Text(malware.isEmpty
                     ? "Lifecycle scripts run automatically on install. Read each one "
                       + "before running a build in these projects."
                     : malware.contains { $0.installedOnDisk == true }
                       ? "A MAL-* advisory marks the package itself as malicious, and it "
                         + "is unpacked here. Treat it as a compromise: quarantine the "
                         + "project, do not install or build, and rotate any credential "
                         + "reachable from it."
                       : "A MAL-* advisory marks the package itself as malicious. Nothing "
                         + "is unpacked on disk — it is pinned in a lockfile nothing has "
                         + "installed, so the risk lands only if someone runs an install "
                         + "there. Bump or remove the pin first.")
                    .font(TypeScale.body).foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(malware.prefix(4), id: \.self) { item in
                    Text("· \(item.package) \(item.installed) — \(item.advisory ?? "")")
                        .font(TypeScale.mono).foregroundStyle(Band.p0.tint)
                }
                ForEach(Array(alerts.prefix(4).enumerated()), id: \.offset) { _, alert in
                    Text("· \(alert.name ?? "") — \(alert.hook ?? "") \(alert.why ?? "")")
                        .font(TypeScale.mono).foregroundStyle(Band.p0.tint)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Band.p0.tint.opacity(0.12)))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Band.p0.tint.opacity(0.45), lineWidth: 1))
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(store.headline).font(TypeScale.heading).tracking(-0.3)
                .foregroundStyle(Theme.text)
            Text(store.subhead).font(TypeScale.body).foregroundStyle(Theme.secondary)
            if ageFilter != "all" {
                Text(ageFilter == "recent"
                     ? "Showing only advisories disclosed inside the window."
                     : "Showing only older advisories found by osv-scanner.")
                    .font(TypeScale.caption).foregroundStyle(Band.p1.tint)
            }
        }
    }

    /// The stat tiles double as the band filter — one control, not two.
    private var tiles: some View {
        HStack(spacing: Space.s + 2) {
            ForEach(Band.allCases, id: \.self) { band in
                let count = ageFilter == "all"
                    ? (store.findings?.count(band) ?? 0)
                    : projects.reduce(0) { $0 + $1.count(band) }
                let active = bandFilter == band
                Button {
                    bandFilter = active ? nil : band
                    selection = nil
                } label: {
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            GlowDot(color: band.tint, size: 6, glow: count > 0 && band <= .p1)
                            Text(band.rawValue).font(TypeScale.micro).tracking(0.5)
                                .foregroundStyle(band.tint)
                            Spacer()
                        }
                        Text("\(count)").font(TypeScale.stat).tracking(-0.5)
                            .foregroundStyle(count > 0 ? Theme.text : Theme.tertiary)
                            .monospacedDigit()
                        Text(band.title).font(TypeScale.caption)
                            .foregroundStyle(Theme.tertiary)
                    }
                    .padding(.horizontal, 14).padding(.vertical, 13)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(Color.white.opacity(active ? 0.075 : 0.035)))
                    .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .strokeBorder(active ? band.tint.opacity(0.45)
                                             : Color.white.opacity(0.05), lineWidth: 0.5))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .pointerCursor()
                .help("\(band.rawValue) — \(band.blurb)")
            }
        }
    }

    private var topRisks: [ProjectGroup] {
        Array(projects.filter { $0.band <= .p1 }.prefix(7))
    }

    private var risks: some View {
        VStack(alignment: .leading, spacing: Space.s + 2) {
            SectionLabel(text: "Needs action")
            Panel(padding: 0) {
                VStack(spacing: 0) {
                    ForEach(Array(topRisks.enumerated()), id: \.element.id) { index, project in
                        Button { selection = project.path } label: {
                            HStack(spacing: Space.s + 3) {
                                GlowDot(color: project.band.tint, size: 7, glow: false)
                                Text(project.name).font(TypeScale.strong)
                                    .foregroundStyle(Theme.text)
                                if project.kev {
                                    Text("KEV").font(.system(size: 9, weight: .bold))
                                        .tracking(0.4)
                                        .foregroundStyle(Band.p0.tint)
                                        .padding(.horizontal, 5).padding(.vertical, 2.5)
                                        .background(Band.p0.tint.opacity(0.16),
                                                    in: RoundedRectangle(cornerRadius: 4))
                                }
                                Spacer()
                                Text(project.items.prefix(3).map(\.package)
                                    .joined(separator: ", "))
                                    .font(TypeScale.mono).foregroundStyle(Theme.tertiary)
                                    .lineLimit(1).truncationMode(.tail)
                                    .frame(maxWidth: 260, alignment: .trailing)
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 9, weight: .semibold))
                                    .foregroundStyle(Theme.tertiary.opacity(0.8))
                            }
                            .padding(.horizontal, 15).padding(.vertical, 11)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .pointerCursor()
                        if index < topRisks.count - 1 {
                            Divider().overlay(Color.white.opacity(0.055))
                                .padding(.leading, 15)
                        }
                    }
                }
            }
        }
    }

    private func leadsPanel(_ leads: [Lead]) -> some View {
        VStack(alignment: .leading, spacing: Space.s + 2) {
            SectionLabel(text: "Host leads — confirm your version")
            Panel {
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(leads.prefix(5), id: \.cve) { lead in
                        HStack(spacing: Space.s + 2) {
                            Text(lead.cve).font(TypeScale.mono).foregroundStyle(Theme.text)
                            Text("\(lead.vendor ?? "") / \(lead.product ?? "")")
                                .font(TypeScale.caption).foregroundStyle(Theme.secondary)
                            Spacer()
                            if let url = lead.url, let link = URL(string: url) {
                                Link("advisory", destination: link)
                                    .font(TypeScale.caption).foregroundStyle(Theme.accent)
                                    .pointerCursor()
                                    .pointerCursor()
                            }
                        }
                    }
                    Text("CISA KEV publishes no version ranges — these name software "
                         + "installed here, nothing more.")
                        .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                        .padding(.top, 2)
                }
            }
        }
    }

    private var scanPanel: some View {
        VStack(alignment: .leading, spacing: Space.s + 2) {
            SectionLabel(text: "Scan")
            Panel {
                VStack(spacing: 7) {
                    if let intel = store.findings?.intel {
                        meta("Advisory window",
                             "\(intel.windowDays ?? 0)d · since \(intel.publishedSince ?? "—")")
                        meta("KEV catalog", intel.kevCatalog ?? "—")
                    }
                    meta("Packages scanned", "\(store.findings?.graphStats?.packages ?? 0)")
                    meta("Projects scanned", "\(store.findings?.graphStats?.projects ?? 0)")
                    meta("Schedule", ScanSchedule.summary)
                    if let last = store.lastScan {
                        meta("Last scan", last.formatted(date: .abbreviated, time: .shortened))
                    }
                }
            }
        }
    }

    private func meta(_ key: String, _ value: String) -> some View {
        HStack {
            Text(key).font(TypeScale.body).foregroundStyle(Theme.secondary)
            Spacer()
            Text(value).font(TypeScale.mono).foregroundStyle(Theme.text)
        }
    }
}

// MARK: - Project detail

enum FixMode: String, CaseIterable, Hashable {
    case commands, ai

    var title: String { self == .commands ? "Commands" : "Fix with AI" }
    var symbol: String { self == .commands ? "terminal" : "sparkles" }
    var hint: String {
        self == .commands
            ? "Review before running. Nothing here runs on its own."
            : "Paste into a coding agent in this repo. It carries the advisory evidence and "
              + "asks the agent to judge whether a fix is warranted before changing anything."
    }
}

struct ProjectDetail: View {
    @EnvironmentObject var store: Store
    let project: ProjectGroup
    @State private var copied = false
    @State private var fixMode: FixMode = .commands

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.l) {
                header
                Text("Dependabot raises these only for repos on GitHub, and only if it "
                     + "is switched on for that repo.")
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(spacing: Space.s) {
                    ForEach(project.items) { PackageCard(item: $0) }
                }
                fixBlock
            }
            .padding(.horizontal, 26)
            .padding(.vertical, 22)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: Space.s + 3) {
                GlowDot(color: project.band.tint, size: 9)
                Text(project.name).font(TypeScale.heading).tracking(-0.3)
                    .foregroundStyle(Theme.text)
                if project.kev {
                    Text("EXPLOITED IN THE WILD").font(.system(size: 9, weight: .bold))
                        .tracking(0.6)
                        .foregroundStyle(Band.p0.tint)
                        .padding(.horizontal, 6).padding(.vertical, 3.5)
                        .background(Band.p0.tint.opacity(0.16),
                                    in: RoundedRectangle(cornerRadius: 4))
                }
                Spacer()
            }
            HStack(spacing: 6) {
                Text(displayPath).font(TypeScale.mono).foregroundStyle(Theme.tertiary)
                    .textSelection(.enabled)
                Button { store.reveal(path: project.path) } label: {
                    Image(systemName: "folder")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Theme.accent)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .pointerCursor()
                .help("Open this folder in Finder")
                if let stale = project.staleDays {
                    Text("· last commit \(stale)d ago").font(TypeScale.caption)
                        .foregroundStyle(Theme.tertiary)
                }
                if project.newCount > 0 {
                    Text("· \(project.newCount) new").font(TypeScale.caption)
                        .foregroundStyle(Theme.accent)
                }
            }
        }
    }

    private var displayPath: String {
        let home = NSHomeDirectory()
        return project.path.hasPrefix(home)
            ? "~" + project.path.dropFirst(home.count) : project.path
    }

    private var fixBlock: some View {
        VStack(alignment: .leading, spacing: Space.s + 2) {
            HStack(spacing: Space.s) {
                Segmented(options: FixMode.allCases.map { ($0, $0.title, $0.symbol) },
                          selection: $fixMode)
                Spacer()
                Button {
                    store.copy(fixMode == .commands ? project.fixScript : project.aiPrompt)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { copied = false }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 10, weight: .semibold))
                        Text(copied ? "Copied" : "Copy").font(TypeScale.caption)
                    }
                    .foregroundStyle(copied ? Theme.good : Theme.secondary)
                }
                .buttonStyle(.plain)
                .pointerCursor()
                Button { store.reveal(path: project.path) } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "folder").font(.system(size: 10, weight: .semibold))
                        Text("Reveal").font(TypeScale.caption)
                    }
                    .foregroundStyle(Theme.secondary)
                }
                .buttonStyle(.plain)
                .pointerCursor()
            }
            Text(fixMode == .commands ? project.fixScript : project.aiPrompt)
                .font(TypeScale.mono).foregroundStyle(Theme.text.opacity(0.88))
                .textSelection(.enabled)
                .lineSpacing(3)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Theme.sunken))
                .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.05), lineWidth: 0.5))
            Text(fixMode.hint).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
        }
    }
}

struct PackageCard: View {
    let item: PackageItem
    @State private var expanded = false

    var body: some View {
        Panel(padding: 14, hoverable: true) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: Space.s + 2) {
                    BandPill(band: item.band)
                    Text(item.package).font(Font.system(size: 14, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    VersionJump(from: item.installed, to: item.target)
                    if item.kev {
                        Image(systemName: "flame.fill")
                            .font(.system(size: 9)).foregroundStyle(Band.p0.tint)
                    }
                    if item.isNew {
                        Text("NEW").font(.system(size: 9, weight: .bold)).tracking(0.4)
                            .foregroundStyle(Theme.accent)
                    }
                    Text(item.dependabotCovered ? "DEPENDABOT" : "NO DEPENDABOT")
                        .font(.system(size: 8.5, weight: .bold)).tracking(0.5)
                        .foregroundStyle(item.dependabotCovered ? Theme.accent
                                                                : Band.p1.tint)
                        .padding(.horizontal, 4).padding(.vertical, 1.5)
                        .background((item.dependabotCovered ? Theme.accent : Band.p1.tint)
                            .opacity(0.14), in: RoundedRectangle(cornerRadius: 3))
                        .help(item.dependabotCovered
                              ? "This repo is on GitHub, so Dependabot can raise it"
                              : "Not a GitHub repo — Dependabot will never raise this")
                    if let origin = item.originLabel {
                        Text(origin)
                            .font(.system(size: 8.5, weight: .bold)).tracking(0.5)
                            .foregroundStyle(item.viaWindow ? Band.p1.tint : Theme.tertiary)
                            .padding(.horizontal, 4).padding(.vertical, 1.5)
                            .background((item.viaWindow ? Band.p1.tint : Theme.tertiary)
                                .opacity(0.14), in: RoundedRectangle(cornerRadius: 3))
                            .help(item.viaWindow
                                  ? "Disclosed inside the advisory window"
                                  : "Older advisory, found by osv-scanner")
                    }
                    Spacer()
                    Button {
                        withAnimation(.easeOut(duration: 0.14)) { expanded.toggle() }
                    } label: {
                        HStack(spacing: 4) {
                            Text(advisoryLabel).font(TypeScale.caption)
                            Image(systemName: "chevron.down")
                                .font(.system(size: 8, weight: .bold))
                                .rotationEffect(.degrees(expanded ? 180 : 0))
                        }
                        .foregroundStyle(Theme.accent)
                    }
                    .buttonStyle(.plain)
                    .pointerCursor()
                }
                Text(exposure).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                if expanded {
                    Divider().overlay(Color.white.opacity(0.07)).padding(.vertical, 2)
                    VStack(alignment: .leading, spacing: 9) {
                        ForEach(item.advisories, id: \.self) { advisoryRow($0) }
                    }
                }
            }
        }
    }

    private func advisoryRow(_ adv: Finding) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 7) {
                if let url = adv.url, let link = URL(string: url) {
                    Link(adv.advisory ?? adv.cve ?? "advisory", destination: link)
                        .font(TypeScale.mono).foregroundStyle(Theme.accent)
                        .pointerCursor()
                        .pointerCursor()
                } else {
                    Text(adv.advisory ?? "advisory").font(TypeScale.mono)
                        .foregroundStyle(Theme.secondary)
                }
                Text((adv.severity ?? "").uppercased())
                    .font(.system(size: 9.5, weight: .bold)).tracking(0.4)
                    .foregroundStyle(severityTint(adv.severity))
                if let cvss = adv.cvss {
                    Text("CVSS \(cvss, specifier: "%.1f")").font(TypeScale.caption)
                        .foregroundStyle(Theme.tertiary)
                }
                if adv.kev == true {
                    Text("KEV").font(.system(size: 9.5, weight: .bold))
                        .foregroundStyle(Band.p0.tint)
                }
                if adv.fromOSV {
                    Text("osv").font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Theme.tertiary)
                }
                Spacer()
            }
            Text(adv.summary ?? "").font(TypeScale.body).foregroundStyle(Theme.secondary)
                .lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func severityTint(_ severity: String?) -> Color {
        switch (severity ?? "").lowercased() {
        case "critical": return Band.p0.tint
        case "high": return Band.p1.tint
        case "medium": return Band.p2.tint
        default: return Theme.tertiary
        }
    }

    private var advisoryLabel: String {
        item.advisories.count == 1 ? "1 advisory" : "\(item.advisories.count) advisories"
    }

    private var exposure: String {
        var bits = [item.direct ? "direct" : "transitive"]
        if item.rel == "dev" { bits.append("dev dependency") }
        if item.rel == "ci_uses" { bits.append("CI workflow") }
        bits.append(item.ecosystem)
        return bits.joined(separator: " · ")
    }
}
