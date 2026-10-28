import AppKit
import SwiftUI

// MARK: - Building blocks

/// A rounded group of rows, as in macOS System Settings: one panel, hairlines between
/// rows, rather than a box around every individual control.
struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s) {
            SectionLabel(text: title)
            VStack(spacing: 0) { content }
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.white.opacity(0.035)))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.05), lineWidth: 0.5))
        }
    }
}

struct SettingsRow<Trailing: View, Extra: View>: View {
    let title: String
    var detail: String? = nil
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var extra: Extra

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s) {
            HStack(alignment: .firstTextBaseline, spacing: Space.m) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(TypeScale.strong).foregroundStyle(Theme.text)
                    if let detail {
                        Text(detail).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: Space.m)
                trailing
            }
            extra
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }
}

extension SettingsRow where Extra == EmptyView {
    init(title: String, detail: String? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.init(title: title, detail: detail, trailing: trailing, extra: { EmptyView() })
    }
}

private struct RowDivider: View {
    var body: some View {
        Divider().overlay(Color.white.opacity(0.055)).padding(.leading, 14)
    }
}

private struct ChoiceRow: View {
    let title: String
    let detail: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: Space.m) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .font(.system(size: 14))
                    .foregroundStyle(selected ? Theme.accent : Theme.tertiary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(TypeScale.strong).foregroundStyle(Theme.text)
                    Text(detail).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .pointerCursor()
    }
}

// MARK: - Settings

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var store: Store

    @AppStorage("scriptPath") private var scriptPath = ""
    @AppStorage("outputDir") private var outputDir = ""
    @AppStorage("roots") private var roots = ""
    @AppStorage("scanScope") private var scanScope = "home"
    @AppStorage("ignored") private var ignored = ""
    @AppStorage("windowDays") private var windowDays = 14
    @AppStorage("deepScan") private var deepScan = false

    private var folders: [String] { lines(roots) }
    private var ignoredFolders: [String] { lines(ignored) }

    private func lines(_ value: String) -> [String] {
        value.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            ScrollView {
                VStack(alignment: .leading, spacing: Space.l + 2) {
                    scopeGroup
                    lookGroup
                    pathsGroup
                }
                .padding(.horizontal, Space.l + 2)
                .padding(.vertical, Space.l)
            }
            Divider().overlay(Theme.hairline)
            footer
        }
        .frame(width: 520, height: 596)
        .background(VisualEffect(material: .underWindowBackground).ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    private var header: some View {
        HStack {
            Text("Settings").font(TypeScale.ui(17, .semibold)).foregroundStyle(Theme.text)
            Spacer()
            PrimaryButton(title: "Done", symbol: "checkmark") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, Space.l + 2)
        .frame(height: 54)
    }

    private var footer: some View {
        HStack(spacing: 6) {
            Image(systemName: "lock.shield").font(.system(size: 11))
            Text("Scans are read-only. Fix commands are never run for you.")
                .font(TypeScale.caption)
            Spacer()
        }
        .foregroundStyle(Theme.tertiary)
        .padding(.horizontal, Space.l + 2)
        .frame(height: 40)
    }

    // MARK: where

    private var scopeGroup: some View {
        SettingsGroup(title: "Where to scan") {
            ChoiceRow(title: "My whole home folder",
                      detail: "Finds every project you have, wherever it lives. "
                            + "Slower, nothing missed.",
                      selected: scanScope == "home") { scanScope = "home" }
            RowDivider()
            ChoiceRow(title: "Specific folders",
                      detail: "Point it at where your code lives. Faster, and the report "
                            + "stays focused.",
                      selected: scanScope == "folders") { scanScope = "folders" }
            if scanScope == "folders" {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(folders, id: \.self) { folderChip($0) }
                    if folders.isEmpty {
                        Text("No folders chosen — the scan falls back to your home folder.")
                            .font(TypeScale.caption).foregroundStyle(Band.p1.tint)
                    }
                    Button { chooseFolder() } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "plus").font(.system(size: 10, weight: .bold))
                            Text("Add folder…").font(TypeScale.caption)
                        }
                        .foregroundStyle(Theme.accent)
                    }
                    .buttonStyle(.plain)
                    .pointerCursor()
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 40)
                .padding(.trailing, 14)
                .padding(.bottom, 13)
            }
            RowDivider()
            ignoreRow
        }
    }

    private var ignoreRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Skip these").font(TypeScale.ui(13, .medium)).foregroundStyle(Theme.text)
                Text("Old clients, archives, anything you no longer work on. Applies "
                     + "whichever scope you picked above.")
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(ignoredFolders, id: \.self) { ignoreChip($0) }
            Button { chooseIgnored() } label: {
                HStack(spacing: 5) {
                    Image(systemName: "plus").font(.system(size: 10, weight: .bold))
                    Text("Add folder to skip…").font(TypeScale.caption)
                }
                .foregroundStyle(Theme.accent)
            }
            .buttonStyle(.plain)
            .pointerCursor()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }

    private func ignoreChip(_ folder: String) -> some View {
        HStack(spacing: Space.s) {
            Image(systemName: "nosign")
                .font(.system(size: 10)).foregroundStyle(Theme.tertiary)
            Text(displayPath(folder)).font(TypeScale.mono).foregroundStyle(Theme.secondary)
                .lineLimit(1).truncationMode(.head)
            Spacer()
            Button { ignored = ignoredFolders.filter { $0 != folder }
                                             .joined(separator: "\n") } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 9, weight: .bold)).foregroundStyle(Theme.tertiary)
            }
            .buttonStyle(.plain)
            .pointerCursor()
        }
        .padding(.horizontal, Space.m)
        .frame(height: 30)
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.sunken))
    }

    private func chooseIgnored() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Skip this folder"
        panel.message = "Choose a folder the scan should leave alone"
        guard panel.runModal() == .OK else { return }
        var list = ignoredFolders
        for url in panel.urls where !list.contains(url.path) { list.append(url.path) }
        ignored = list.joined(separator: "\n")
    }

    private func folderChip(_ folder: String) -> some View {
        HStack(spacing: Space.s) {
            Image(systemName: "folder.fill")
                .font(.system(size: 10)).foregroundStyle(Theme.accent)
            Text(displayPath(folder)).font(TypeScale.mono).foregroundStyle(Theme.text)
                .lineLimit(1).truncationMode(.head)
            Spacer()
            Button { remove(folder) } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 9, weight: .bold)).foregroundStyle(Theme.tertiary)
            }
            .buttonStyle(.plain)
            .pointerCursor()
        }
        .padding(.horizontal, Space.m)
        .frame(height: 30)
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.sunken))
    }

    // MARK: what

    private var lookGroup: some View {
        SettingsGroup(title: "What to look for") {
            SettingsRow(title: "Advisory window",
                        detail: "How far back to pull newly published advisories.") {
                Text("\(windowDays) days").font(TypeScale.mono).foregroundStyle(Theme.text)
            } extra: {
                Slider(value: Binding(get: { Double(windowDays) },
                                      set: { windowDays = Int($0) }), in: 1...90, step: 1)
                    .tint(Theme.accent)
                    .controlSize(.small)
                    .pointerCursor()
            }
            RowDivider()
            SettingsRow(title: "Deep scan",
                        detail: "Adds osv-scanner for the full advisory history. Slower, "
                              + "but it catches anything disclosed before the window.") {
                Toggle("", isOn: $deepScan).toggleStyle(.switch).labelsHidden()
                    .tint(Theme.accent)
                    .pointerCursor()
            }
        }
    }

    // MARK: paths

    private var pathsGroup: some View {
        SettingsGroup(title: "Advanced") {
            pathRow("Scan script", text: $scriptPath, placeholder: Settings.resolvedScript)
            RowDivider()
            pathRow("Output folder", text: $outputDir, placeholder: Settings.resolvedOutput)
        }
    }

    private func pathRow(_ title: String, text: Binding<String>,
                         placeholder: String) -> some View {
        SettingsRow(title: title) {
            EmptyView()
        } extra: {
            TextField(displayPath(placeholder), text: text)
                .textFieldStyle(.plain)
                .font(TypeScale.mono)
                .foregroundStyle(Theme.text)
                .padding(.horizontal, Space.s + 2)
                .frame(height: 26)
                .background(RoundedRectangle(cornerRadius: 7).fill(Theme.sunken))
                .overlay(RoundedRectangle(cornerRadius: 7)
                    .strokeBorder(Color.white.opacity(0.06), lineWidth: 0.5))
        }
    }

    // MARK: actions

    private func displayPath(_ path: String) -> String {
        path.hasPrefix(NSHomeDirectory())
            ? "~" + path.dropFirst(NSHomeDirectory().count) : path
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Scan this folder"
        panel.message = "Choose the folder your code lives in"
        guard panel.runModal() == .OK else { return }
        var list = folders
        for url in panel.urls where !list.contains(url.path) { list.append(url.path) }
        roots = list.joined(separator: "\n")
    }

    private func remove(_ folder: String) {
        roots = folders.filter { $0 != folder }.joined(separator: "\n")
    }
}

// MARK: - Schedule

/// Reachable in one click from the sidebar footer, not buried in a settings sheet.
struct SchedulePopover: View {
    @EnvironmentObject var store: Store
    @AppStorage("scheduleEnabled") private var enabled = false
    @AppStorage("scheduleHour") private var hour = 9
    @AppStorage("scheduleMinute") private var minute = 0
    @AppStorage("scheduleDays") private var days = 0b1111111
    @AppStorage("scheduleAgent") private var useAgent = false
    @State private var note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.m) {
            HStack {
                Text("Scheduled scan").font(TypeScale.title).foregroundStyle(Theme.text)
                Spacer()
                Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                    .tint(Theme.accent)
                    .pointerCursor()
                    .onChange(of: enabled) { _ in apply() }
            }

            if enabled {
                HStack(spacing: Space.m) {
                    Text("Run at").font(TypeScale.body).foregroundStyle(Theme.secondary)
                    TimeField(hour: $hour, minute: $minute)
                        .onChange(of: hour) { _ in apply() }
                        .onChange(of: minute) { _ in apply() }
                    Spacer()
                }

                HStack(spacing: Space.xs + 1) {
                    ForEach(0..<7, id: \.self) { dayChip($0) }
                }

                HStack(spacing: Space.xs + 1) {
                    presetButton("Daily", 0b1111111)
                    presetButton("Weekdays", 0b0111110)
                    presetButton("Weekly", 1 << 1)
                    Spacer()
                }

                Divider().overlay(Theme.hairline)

                Toggle(isOn: $useAgent) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Run when the app is closed").font(TypeScale.strong)
                            .foregroundStyle(Theme.text)
                        Text("Installs a launchd agent, so the report is ready when you look.")
                            .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(.switch)
                .tint(Theme.accent)
                .pointerCursor()
                .onChange(of: useAgent) { _ in apply() }

                HStack(spacing: 5) {
                    Image(systemName: "clock").font(.system(size: 10))
                    Text(store.nextScanText.map { "Next run \($0)" } ?? ScanSchedule.summary)
                        .font(TypeScale.caption)
                }
                .foregroundStyle(Theme.accent)

                if let note {
                    Text(note).font(TypeScale.caption).foregroundStyle(Band.p1.tint)
                }
            } else {
                Text("Scans run only when you press Scan.")
                    .font(TypeScale.body).foregroundStyle(Theme.tertiary)
            }
        }
        .padding(Space.l + 2)
        .frame(width: 330)
        .background(VisualEffect(material: .popover).ignoresSafeArea())
    }

    private func dayChip(_ index: Int) -> some View {
        let on = days & (1 << index) != 0
        return Button {
            let next = days ^ (1 << index)
            if next != 0 { days = next; apply() }
        } label: {
            Text(ScanSchedule.dayNames[index].prefix(1))
                .font(TypeScale.ui(10.5, .semibold))
                .foregroundStyle(on ? Color.white : Theme.secondary)
                .frame(width: 27, height: 25)
                .background(RoundedRectangle(cornerRadius: 6)
                    .fill(on ? Theme.accent : Color.white.opacity(0.06)))
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .help(ScanSchedule.dayNames[index])
    }

    private func presetButton(_ title: String, _ mask: Int) -> some View {
        Button { days = mask; apply() } label: {
            Text(title).font(TypeScale.caption)
                .foregroundStyle(days == mask ? Theme.accent : Theme.secondary)
                .padding(.horizontal, Space.s + 1).padding(.vertical, 4)
                .background(RoundedRectangle(cornerRadius: 6)
                    .fill(days == mask ? Theme.accent.opacity(0.15)
                                       : Color.white.opacity(0.06)))
        }
        .buttonStyle(.plain)
        .pointerCursor()
    }

    private func apply() {
        store.scheduleAutoScan()
        if enabled && useAgent {
            note = Scheduler.installAgent()
        } else {
            Scheduler.removeAgent()
            note = nil
        }
    }
}
