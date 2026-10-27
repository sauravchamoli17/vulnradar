import AppKit
import SwiftUI

/// Scheduling reachable in one click from the status bar, not buried in a settings sheet.
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
                    .onChange(of: enabled) { _ in apply() }
            }

            if enabled {
                HStack(spacing: Space.s) {
                    Text("at").font(TypeScale.small).foregroundStyle(Theme.secondary)
                    DatePicker("", selection: timeBinding, displayedComponents: .hourAndMinute)
                        .datePickerStyle(.stepperField).labelsHidden().frame(width: 86)
                        .onChange(of: hour) { _ in apply() }
                        .onChange(of: minute) { _ in apply() }
                    Spacer()
                }

                HStack(spacing: Space.xs) {
                    ForEach(0..<7, id: \.self) { dayChip($0) }
                }

                HStack(spacing: Space.xs) {
                    presetButton("Daily", 0b1111111)
                    presetButton("Weekdays", 0b0111110)
                    presetButton("Weekly", 1 << 1)
                }

                Divider().overlay(Theme.hairline)

                Toggle(isOn: $useAgent) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Run when the app is closed").font(TypeScale.strong)
                            .foregroundStyle(Theme.text)
                        Text("installs a launchd agent, so the report is ready when you look")
                            .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                    }
                }
                .toggleStyle(.switch)
                .onChange(of: useAgent) { _ in apply() }

                HStack(spacing: 5) {
                    Image(systemName: "clock").font(.system(size: 9))
                    Text(store.nextScanText.map { "Next run \($0)" } ?? ScanSchedule.summary)
                        .font(TypeScale.caption)
                }
                .foregroundStyle(Theme.secondary)

                if let note {
                    Text(note).font(TypeScale.caption).foregroundStyle(Band.p1.tint)
                }
            } else {
                Text("Scans run only when you press Scan.")
                    .font(TypeScale.small).foregroundStyle(Theme.tertiary)
            }
        }
        .padding(Space.l)
        .frame(width: 320)
        .background(Theme.surface)
    }

    private var timeBinding: Binding<Date> {
        Binding(
            get: {
                Calendar.current.date(from: DateComponents(hour: hour, minute: minute)) ?? Date()
            },
            set: { date in
                let parts = Calendar.current.dateComponents([.hour, .minute], from: date)
                hour = parts.hour ?? 9
                minute = parts.minute ?? 0
            })
    }

    private func dayChip(_ index: Int) -> some View {
        let on = days & (1 << index) != 0
        return Button {
            let next = days ^ (1 << index)
            if next != 0 { days = next; apply() }
        } label: {
            Text(ScanSchedule.dayNames[index].prefix(1))
                .font(.system(size: 10, weight: .semibold, design: .rounded))
                .foregroundStyle(on ? Color.white : Theme.secondary)
                .frame(width: 26, height: 24)
                .background(RoundedRectangle(cornerRadius: 6)
                    .fill(on ? Theme.accent : Theme.raised))
        }
        .buttonStyle(.plain)
        .help(ScanSchedule.dayNames[index])
    }

    private func presetButton(_ title: String, _ mask: Int) -> some View {
        Button { days = mask; apply() } label: {
            Text(title).font(TypeScale.caption)
                .foregroundStyle(days == mask ? Theme.accent : Theme.secondary)
                .padding(.horizontal, Space.s).padding(.vertical, 3)
                .background(RoundedRectangle(cornerRadius: 5)
                    .fill(days == mask ? Theme.accent.opacity(0.14) : Theme.raised))
        }
        .buttonStyle(.plain)
    }

    private func apply() {
        store.scheduleAutoScan()
        note = (enabled && useAgent) ? Scheduler.installAgent() : {
            Scheduler.removeAgent(); return nil
        }()
    }
}

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var store: Store

    @AppStorage("scriptPath") private var scriptPath = ""
    @AppStorage("outputDir") private var outputDir = ""
    @AppStorage("roots") private var roots = ""
    @AppStorage("scanScope") private var scanScope = "home"
    @AppStorage("windowDays") private var windowDays = 14
    @AppStorage("deepScan") private var deepScan = false

    private var folders: [String] {
        roots.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Settings").font(TypeScale.title).foregroundStyle(Theme.text)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, Space.l).padding(.vertical, Space.m)
            Divider().overlay(Theme.hairline)

            ScrollView {
                VStack(alignment: .leading, spacing: Space.xl) {
                    scopeSection
                    depthSection
                    pathsSection
                }
                .padding(Space.l)
            }

            Divider().overlay(Theme.hairline)
            HStack(spacing: 5) {
                Image(systemName: "lock.shield").font(.system(size: 10))
                Text("Scans are read-only. Fix commands are never run for you.")
                    .font(TypeScale.caption)
                Spacer()
            }
            .foregroundStyle(Theme.tertiary)
            .padding(.horizontal, Space.l).padding(.vertical, Space.s)
        }
        .frame(width: 500, height: 540)
        .background(Theme.bg)
        .preferredColorScheme(.dark)
    }

    private var scopeSection: some View {
        VStack(alignment: .leading, spacing: Space.s) {
            SectionLabel(text: "Where to scan")
            scopeOption("home", "My whole home folder",
                        "Finds every project you have, wherever it lives. Slower, nothing missed.")
            scopeOption("folders", "Specific folders",
                        "Point it at where your code lives. Faster, and the report stays focused.")

            if scanScope == "folders" {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(folders, id: \.self) { folder in
                        HStack(spacing: Space.s) {
                            Image(systemName: "folder.fill")
                                .font(.system(size: 10)).foregroundStyle(Theme.accent)
                            Text(displayPath(folder)).font(TypeScale.mono)
                                .foregroundStyle(Theme.text)
                                .lineLimit(1).truncationMode(.head)
                            Spacer()
                            Button { remove(folder) } label: {
                                Image(systemName: "xmark")
                                    .font(.system(size: 9, weight: .bold))
                                    .foregroundStyle(Theme.tertiary)
                            }
                            .buttonStyle(.plain)
                        }
                        .padding(.horizontal, Space.s).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.surface))
                    }
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
                }
                .padding(.leading, Space.xl)
            }
        }
    }

    private func scopeOption(_ value: String, _ title: String, _ detail: String) -> some View {
        Button { scanScope = value } label: {
            HStack(alignment: .top, spacing: Space.s) {
                Image(systemName: scanScope == value ? "largecircle.fill.circle" : "circle")
                    .font(.system(size: 13))
                    .foregroundStyle(scanScope == value ? Theme.accent : Theme.tertiary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(TypeScale.strong).foregroundStyle(Theme.text)
                    Text(detail).font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var depthSection: some View {
        VStack(alignment: .leading, spacing: Space.s) {
            SectionLabel(text: "What to look for")
            VStack(alignment: .leading, spacing: Space.xs) {
                HStack {
                    Text("Advisory window").font(TypeScale.strong).foregroundStyle(Theme.text)
                    Spacer()
                    Text("\(windowDays) days").font(TypeScale.mono).foregroundStyle(Theme.text)
                }
                Slider(value: Binding(get: { Double(windowDays) },
                                      set: { windowDays = Int($0) }), in: 1...90, step: 1)
                Text("How far back to pull newly published advisories.")
                    .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
            }
            Toggle(isOn: $deepScan) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Deep scan").font(TypeScale.strong).foregroundStyle(Theme.text)
                    Text("adds osv-scanner for the full advisory history — slower")
                        .font(TypeScale.caption).foregroundStyle(Theme.tertiary)
                }
            }
            .toggleStyle(.switch)
        }
    }

    private var pathsSection: some View {
        DisclosureGroup {
            VStack(spacing: Space.s) {
                TextField(Settings.resolvedScript, text: $scriptPath)
                TextField(Settings.resolvedOutput, text: $outputDir)
            }
            .textFieldStyle(.roundedBorder).font(TypeScale.mono).padding(.top, Space.s)
        } label: {
            SectionLabel(text: "Advanced paths")
        }
    }

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
