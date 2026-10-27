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

    private var visible: [ProjectGroup] {
        var list = store.projects
        if let bandFilter { list = list.filter { $0.band == bandFilter } }
        guard !query.isEmpty else { return list }
        let needle = query.lowercased()
        return list.filter {
            $0.name.lowercased().contains(needle) || $0.path.lowercased().contains(needle)
                || $0.items.contains { $0.package.lowercased().contains(needle) }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider().overlay(Theme.hairline)
            HSplitView {
                sidebar.frame(minWidth: 230, idealWidth: 252, maxWidth: 340)
                content.frame(minWidth: 560)
            }
            Divider().overlay(Theme.hairline)
            statusBar
        }
        .background(Theme.bg)
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

    // MARK: toolbar — one primary action, everything else quiet

    private var toolbar: some View {
        HStack(spacing: Space.m) {
            Segmented(options: [(ViewMode.list, "List", "list.bullet.indent"),
                                (ViewMode.graph, "Graph",
                                 "point.3.connected.trianglepath.dotted")],
                      selection: $mode)

            if store.isScanning {
                Text(store.progress.isEmpty ? "Scanning…" : store.progress)
                    .font(TypeScale.caption).foregroundStyle(Theme.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }

            Spacer(minLength: Space.s)

            if store.isScanning {
                Button("Stop") { store.cancelScan() }
                    .buttonStyle(.plain)
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
        .padding(.horizontal, Space.m)
        .padding(.vertical, Space.s)
        .background(Theme.bg)
    }

    // MARK: content

    @ViewBuilder
    private var content: some View {
        if mode == .graph {
            GraphPane()
        } else if let path = selection,
                  let project = store.projects.first(where: { $0.path == path }) {
            ProjectDetail(project: project)
        } else {
            Overview(selection: $selection)
        }
    }

    // MARK: sidebar — search, grouping, list. Nothing else.

    private var sidebar: some View {
        VStack(spacing: 0) {
            VStack(spacing: Space.s) {
                searchField
                Segmented(options: [("urgency", "Urgency", nil), ("folder", "Folder", nil)],
                          selection: $grouping)
            }
            .padding(Space.s)

            Divider().overlay(Theme.hairline)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1, pinnedViews: [.sectionHeaders]) {
                    if grouping == "folder" {
                        ForEach(FolderGroup.build(from: visible)) { folder in
                            Section {
                                if !collapsed.contains(folder.path) {
                                    ForEach(folder.projects) { projectRow($0) }
                                }
                            } header: { folderHeader(folder) }
                        }
                    } else {
                        ForEach(Band.allCases, id: \.self) { band in
                            let group = visible.filter { $0.band == band }
                            if !group.isEmpty {
                                Section {
                                    ForEach(group) { projectRow($0) }
                                } header: { bandHeader(band, count: group.count) }
                            }
                        }
                    }
                    if visible.isEmpty { emptyList }
                }
                .padding(.bottom, Space.m)
            }
        }
        .background(Theme.sidebar)
    }

    private var emptyList: some View {
        Text(store.findings == nil ? "No scan yet" : "Nothing matches")
            .font(TypeScale.small).foregroundStyle(Theme.tertiary)
            .padding(.horizontal, Space.m).padding(.top, Space.l)
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11)).foregroundStyle(Theme.tertiary)
            TextField("Search", text: $query)
                .textFieldStyle(.plain).font(TypeScale.small).foregroundStyle(Theme.text)
            if !query.isEmpty {
                Button { query = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 10)).foregroundStyle(Theme.tertiary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, Space.s).padding(.vertical, 5)
        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.surface))
    }

    private func bandHeader(_ band: Band, count: Int) -> some View {
        HStack {
            SectionLabel(text: "\(band.rawValue) · \(band.title)")
            Spacer()
            Text("\(count)").font(TypeScale.micro).foregroundStyle(Theme.tertiary)
        }
        .padding(.horizontal, Space.m)
        .padding(.top, Space.m).padding(.bottom, Space.xs)
        .background(Theme.sidebar)
    }

    private func folderHeader(_ folder: FolderGroup) -> some View {
        let isCollapsed = collapsed.contains(folder.path)
        return Button {
            if isCollapsed { collapsed.remove(folder.path) } else { collapsed.insert(folder.path) }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 8, weight: .bold)).foregroundStyle(Theme.tertiary)
                    .rotationEffect(.degrees(isCollapsed ? 0 : 90))
                GlowDot(color: folder.band.tint, size: 5, glow: false)
                Text(folder.name).font(TypeScale.micro).tracking(0.3)
                    .foregroundStyle(Theme.secondary).lineLimit(1).truncationMode(.head)
                Spacer()
                Text("\(folder.projects.count)")
                    .font(TypeScale.micro).foregroundStyle(Theme.tertiary)
            }
            .padding(.horizontal, Space.m)
            .padding(.top, Space.m).padding(.bottom, Space.xs)
            .background(Theme.sidebar)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func projectRow(_ project: ProjectGroup) -> some View {
        let active = selection == project.path
        return Button { selection = project.path; mode = .list } label: {
            HStack(spacing: Space.s) {
                GlowDot(color: project.band.tint, size: 6, glow: project.band <= .p1)
                Text(project.name)
                    .font(active ? TypeScale.strong : TypeScale.body)
                    .foregroundStyle(active ? Theme.text : Theme.text.opacity(0.85))
                    .lineLimit(1)
                Spacer(minLength: Space.xs)
                if project.kev {
                    Image(systemName: "flame.fill")
                        .font(.system(size: 8)).foregroundStyle(Band.p0.tint)
                }
                Text("\(project.items.count)")
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary).monospacedDigit()
            }
            .padding(.horizontal, Space.s).padding(.vertical, 5)
            .background(RoundedRectangle(cornerRadius: 6)
                .fill(active ? Theme.accent.opacity(0.15) : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 6)
    }

    // MARK: status bar — standing state lives here, not stacked in the sidebar

    private var statusBar: some View {
        HStack(spacing: Space.m) {
            HStack(spacing: 6) {
                GlowDot(color: headlineTint, size: 7)
                Text(store.headline).font(TypeScale.small).foregroundStyle(Theme.text)
            }

            if store.findings != nil {
                DistributionBar(counts: bandCounts).frame(width: 84)
                HStack(spacing: Space.xs) {
                    ForEach(Band.allCases, id: \.self) { bandFilterChip($0) }
                }
            }

            Spacer(minLength: Space.s)

            if let error = store.lastError {
                HStack(spacing: 5) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 9)).foregroundStyle(Band.p1.tint)
                    Text(error).font(TypeScale.caption).foregroundStyle(Theme.secondary)
                        .lineLimit(1).truncationMode(.middle).frame(maxWidth: 260)
                }
            }

            scheduleChip

            if let last = store.lastScan {
                Text(last.formatted(.relative(presentation: .numeric)))
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, Space.m)
        .padding(.vertical, 6)
        .background(Theme.sidebar)
    }

    private var scheduleChip: some View {
        Button { showSchedule.toggle() } label: {
            HStack(spacing: 5) {
                Image(systemName: ScanSchedule.enabled ? "clock.fill" : "clock")
                    .font(.system(size: 9))
                Text(store.nextScanText ?? "No schedule").font(TypeScale.caption)
            }
            .foregroundStyle(ScanSchedule.enabled ? Theme.accent : Theme.tertiary)
            .fixedSize()
            .padding(.horizontal, Space.s).padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 6)
                .fill(ScanSchedule.enabled ? Theme.accent.opacity(0.12) : Theme.surface))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .popover(isPresented: $showSchedule, arrowEdge: .top) {
            SchedulePopover().environmentObject(store)
        }
    }

    private func bandFilterChip(_ band: Band) -> some View {
        let count = store.findings?.count(band) ?? 0
        let active = bandFilter == band
        return Button {
            bandFilter = active ? nil : band
            selection = nil
        } label: {
            HStack(spacing: 3) {
                GlowDot(color: band.tint, size: 5, glow: active)
                Text("\(count)").font(TypeScale.caption)
                    .foregroundStyle(active ? band.tint : Theme.secondary).monospacedDigit()
            }
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 5)
                .fill(active ? band.tint.opacity(0.15) : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("\(band.rawValue) — \(band.blurb)")
    }

    private var headlineTint: Color {
        guard let findings = store.findings else { return Theme.tertiary }
        if findings.count(.p0) > 0 { return Band.p0.tint }
        if findings.count(.p1) > 0 { return Band.p1.tint }
        return Theme.good
    }

    private var bandCounts: [Band: Int] {
        Dictionary(uniqueKeysWithValues: Band.allCases.map {
            ($0, store.findings?.count($0) ?? 0)
        })
    }
}

// MARK: - Overview

struct Overview: View {
    @EnvironmentObject var store: Store
    @Binding var selection: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xl) {
                if store.findings == nil {
                    emptyState
                } else {
                    header
                    tiles
                    if !topRisks.isEmpty { risks }
                    if let leads = store.findings?.leads, !leads.isEmpty { leadsPanel(leads) }
                    scanPanel
                }
            }
            .padding(Space.xl)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.bg)
    }

    private var emptyState: some View {
        VStack(spacing: Space.m) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 38, weight: .light)).foregroundStyle(Theme.tertiary)
            Text("No scan yet").font(TypeScale.title).foregroundStyle(Theme.text)
            Text("Builds a dependency graph of your projects and matches it against "
                 + "advisories published in the last two weeks.")
                .font(TypeScale.small).foregroundStyle(Theme.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 360)
            PrimaryButton(title: "Run first scan", symbol: "play.fill") { store.scan() }
                .padding(.top, Space.xs)
        }
        .frame(maxWidth: .infinity).padding(.top, 80)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(store.headline).font(TypeScale.heading).foregroundStyle(Theme.text)
            Text(store.subhead).font(TypeScale.body).foregroundStyle(Theme.secondary)
        }
    }

    private var tiles: some View {
        HStack(spacing: Space.s) {
            ForEach(Band.allCases, id: \.self) { band in
                let count = store.findings?.count(band) ?? 0
                Panel(padding: Space.m) {
                    VStack(alignment: .leading, spacing: Space.xs) {
                        HStack(spacing: 5) {
                            GlowDot(color: band.tint, size: 6, glow: count > 0 && band <= .p1)
                            Text(band.rawValue).font(TypeScale.micro)
                                .foregroundStyle(band.tint)
                        }
                        Text("\(count)").font(TypeScale.stat)
                            .foregroundStyle(count > 0 ? Theme.text : Theme.tertiary)
                            .monospacedDigit()
                        Text(band.title).font(TypeScale.caption)
                            .foregroundStyle(Theme.secondary)
                    }
                }
            }
        }
    }

    private var topRisks: [ProjectGroup] {
        Array(store.projects.filter { $0.band <= .p1 }.prefix(7))
    }

    private var risks: some View {
        VStack(alignment: .leading, spacing: Space.s) {
            SectionLabel(text: "Needs action")
            Panel(padding: 0) {
                VStack(spacing: 0) {
                    ForEach(Array(topRisks.enumerated()), id: \.element.id) { index, project in
                        Button { selection = project.path } label: {
                            HStack(spacing: Space.s) {
                                GlowDot(color: project.band.tint, size: 6)
                                Text(project.name).font(TypeScale.strong)
                                    .foregroundStyle(Theme.text)
                                if project.kev {
                                    Text("KEV").font(TypeScale.micro)
                                        .foregroundStyle(Band.p0.tint)
                                        .padding(.horizontal, 4).padding(.vertical, 1)
                                        .background(Band.p0.tint.opacity(0.15),
                                                    in: RoundedRectangle(cornerRadius: 3))
                                }
                                Spacer()
                                Text(project.items.prefix(3).map(\.package)
                                    .joined(separator: ", "))
                                    .font(TypeScale.mono).foregroundStyle(Theme.tertiary)
                                    .lineLimit(1)
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 9, weight: .semibold))
                                    .foregroundStyle(Theme.tertiary)
                            }
                            .padding(.horizontal, Space.m).padding(.vertical, Space.s)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if index < topRisks.count - 1 {
                            Divider().overlay(Theme.hairline).padding(.leading, Space.m)
                        }
                    }
                }
            }
        }
    }

    private func leadsPanel(_ leads: [Lead]) -> some View {
        VStack(alignment: .leading, spacing: Space.s) {
            SectionLabel(text: "Host leads — confirm your version")
            Panel {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(leads.prefix(5), id: \.cve) { lead in
                        HStack(spacing: Space.s) {
                            Text(lead.cve).font(TypeScale.mono).foregroundStyle(Theme.text)
                            Text("\(lead.vendor ?? "") / \(lead.product ?? "")")
                                .font(TypeScale.caption).foregroundStyle(Theme.secondary)
                            Spacer()
                            if let url = lead.url, let link = URL(string: url) {
                                Link("advisory", destination: link)
                                    .font(TypeScale.caption).foregroundStyle(Theme.accent)
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
        VStack(alignment: .leading, spacing: Space.s) {
            SectionLabel(text: "Scan")
            Panel {
                VStack(spacing: 6) {
                    if let intel = store.findings?.intel {
                        meta("Advisory window",
                             "\(intel.windowDays ?? 0)d · since \(intel.publishedSince ?? "—")")
                        meta("KEV catalog", intel.kevCatalog ?? "—")
                    }
                    meta("Packages scanned", "\(store.findings?.graphStats?.packages ?? 0)")
                    meta("Projects scanned", "\(store.findings?.graphStats?.projects ?? 0)")
                    meta("Schedule", ScanSchedule.summary)
                }
            }
        }
    }

    private func meta(_ key: String, _ value: String) -> some View {
        HStack {
            Text(key).font(TypeScale.small).foregroundStyle(Theme.secondary)
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
                VStack(spacing: 6) {
                    ForEach(project.items) { PackageCard(item: $0) }
                }
                fixBlock
            }
            .padding(Space.xl)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.bg)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: Space.s) {
                GlowDot(color: project.band.tint, size: 9)
                Text(project.name).font(TypeScale.heading).foregroundStyle(Theme.text)
                if project.kev {
                    Text("EXPLOITED IN THE WILD").font(TypeScale.micro).tracking(0.4)
                        .foregroundStyle(Band.p0.tint)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Band.p0.tint.opacity(0.14),
                                    in: RoundedRectangle(cornerRadius: 4))
                }
                Spacer()
            }
            Text(project.path).font(TypeScale.mono).foregroundStyle(Theme.tertiary)
                .textSelection(.enabled)
            HStack(spacing: 6) {
                ForEach(Band.allCases, id: \.self) { band in
                    if project.count(band) > 0 {
                        HStack(spacing: 3) {
                            BandPill(band: band)
                            Text("\(project.count(band))").font(TypeScale.caption)
                                .foregroundStyle(Theme.secondary)
                        }
                    }
                }
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

    private var fixBlock: some View {
        VStack(alignment: .leading, spacing: Space.s) {
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
                Button { store.reveal(path: project.path) } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "folder").font(.system(size: 10, weight: .semibold))
                        Text("Reveal").font(TypeScale.caption)
                    }
                    .foregroundStyle(Theme.secondary)
                }
                .buttonStyle(.plain)
            }
            Text(fixMode.hint).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
            Panel {
                Text(fixMode == .commands ? project.fixScript : project.aiPrompt)
                    .font(TypeScale.mono).foregroundStyle(Theme.text.opacity(0.9))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

struct PackageCard: View {
    let item: PackageItem
    @State private var expanded = false

    var body: some View {
        Panel(padding: Space.m, hoverable: true) {
            VStack(alignment: .leading, spacing: Space.s) {
                HStack(spacing: Space.s) {
                    BandPill(band: item.band)
                    Text(item.package).font(TypeScale.title).foregroundStyle(Theme.text)
                    VersionJump(from: item.installed, to: item.target)
                    if item.kev {
                        Image(systemName: "flame.fill")
                            .font(.system(size: 9)).foregroundStyle(Band.p0.tint)
                    }
                    if item.isNew {
                        Text("NEW").font(TypeScale.micro).foregroundStyle(Theme.accent)
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
                }
                Text(exposure).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                if expanded {
                    Divider().overlay(Theme.hairline)
                    VStack(alignment: .leading, spacing: Space.s) {
                        ForEach(item.advisories, id: \.self) { advisoryRow($0) }
                    }
                }
            }
        }
    }

    private func advisoryRow(_ adv: Finding) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                if let url = adv.url, let link = URL(string: url) {
                    Link(adv.advisory ?? adv.cve ?? "advisory", destination: link)
                        .font(TypeScale.mono).foregroundStyle(Theme.accent)
                } else {
                    Text(adv.advisory ?? "advisory").font(TypeScale.mono)
                        .foregroundStyle(Theme.secondary)
                }
                Text((adv.severity ?? "").uppercased()).font(TypeScale.micro)
                    .foregroundStyle(severityTint(adv.severity))
                if let cvss = adv.cvss {
                    Text("CVSS \(cvss, specifier: "%.1f")").font(TypeScale.caption)
                        .foregroundStyle(Theme.tertiary)
                }
                if adv.kev == true {
                    Text("KEV").font(TypeScale.micro).foregroundStyle(Band.p0.tint)
                }
                Spacer()
            }
            Text(adv.summary ?? "").font(TypeScale.small).foregroundStyle(Theme.secondary)
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
