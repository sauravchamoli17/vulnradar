import AppKit
import Foundation
import SwiftUI

struct Settings {
    @AppStorage("scriptPath") static var scriptPath = ""
    @AppStorage("outputDir") static var outputDir = ""
    @AppStorage("roots") static var roots = ""
    @AppStorage("scanScope") static var scanScope = "home"
    @AppStorage("ignored") static var ignored = ""
    @AppStorage("windowDays") static var windowDays = 14
    @AppStorage("deepScan") static var deepScan = false

    /// The scanner shipped inside the app, falling back to a skill checkout.
    ///
    /// The bundled copy is what a downloaded build runs; the checkout path is what a
    /// clone of this repo runs, so working on the scripts does not mean rebuilding the
    /// app to see the change. An explicit path in Settings beats both.
    static var resolvedScript: String {
        if !scriptPath.isEmpty { return scriptPath }
        let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("scripts/radar.sh").path
        if let bundled, FileManager.default.isReadableFile(atPath: bundled) {
            return bundled
        }
        return NSHomeDirectory() + "/.claude/skills/vuln-radar/scripts/radar.sh"
    }
    static var resolvedOutput: String {
        outputDir.isEmpty ? NSHomeDirectory() + "/.claude/vuln-radar/latest" : outputDir
    }
    static var folders: [String] {
        lines(roots)
    }
    /// Applies whichever scope is in force: you can sweep home and still skip the
    /// folder full of clients you stopped working for.
    static var ignoredFolders: [String] {
        lines(ignored)
    }

    private static func lines(_ value: String) -> [String] {
        value.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Scope "folders" means the user picked their code directories; anything else
    /// (or an empty list) falls back to sweeping the whole home folder.
    /// The same list resolvedRoots joins, kept as an array for comparing against the
    /// scope a finished scan recorded.
    static var folderRoots: [String] {
        scanScope == "folders" && !folders.isEmpty ? folders : [NSHomeDirectory()]
    }
    static var resolvedRoots: String {
        scanScope == "folders" && !folders.isEmpty ? folders.joined(separator: "\n")
                                                   : NSHomeDirectory()
    }
}

@MainActor
final class Store: ObservableObject {
    @Published private(set) var findings: Findings?
    @Published private(set) var projects: [ProjectGroup] = []
    @Published private(set) var isScanning = false
    @Published private(set) var progress = ""
    @Published private(set) var lastError: String?
    @Published private(set) var lastScan: Date?

    private var process: Process?
    private lazy var scheduler = Scheduler(store: self)

    var outputDir: URL { URL(fileURLWithPath: Settings.resolvedOutput) }
    var reportURL: URL { outputDir.appendingPathComponent("report.md") }
    var graphURL: URL { outputDir.appendingPathComponent("graph.html") }
    var findingsURL: URL { outputDir.appendingPathComponent("findings.json") }

    var headline: String {
        guard let findings else { return "No scan yet" }
        let p0 = findings.count(.p0), p1 = findings.count(.p1)
        if p0 == 0 && p1 == 0 { return "Nothing needs action" }
        return "\(p0) act now · \(p1) this week"
    }

    var subhead: String {
        guard let findings else { return "Run a scan to begin" }
        let projectCount = projects.count
        let scanned = findings.graphStats?.projects ?? 0
        return "\(projectCount) of \(scanned) projects affected"
    }

    func loadFromDisk() {
        guard FileManager.default.fileExists(atPath: findingsURL.path) else { return }
        do {
            let loaded = try Findings.load(from: findingsURL)
            findings = loaded
            projects = ProjectGroup.build(from: loaded.findings)
            lastError = nil
            let attrs = try? FileManager.default.attributesOfItem(atPath: findingsURL.path)
            lastScan = attrs?[.modificationDate] as? Date
        } catch {
            lastError = "Could not read findings.json: \(error.localizedDescription)"
        }
    }

    func scheduleAutoScan() {
        scheduler.reschedule()
    }

    var scheduleSummary: String { ScanSchedule.summary }

    var nextScanText: String? {
        guard let next = ScanSchedule.nextFireDate() else { return nil }
        return next.formatted(date: .omitted, time: .shortened)
            + " · " + next.formatted(.relative(presentation: .numeric))
    }

    func scan() {
        guard !isScanning else { return }
        let script = Settings.resolvedScript
        guard FileManager.default.fileExists(atPath: script) else {
            lastError = "radar.sh not found at \(script) — set it in Settings."
            return
        }
        let previousP0 = findings?.count(.p0) ?? 0
        isScanning = true
        progress = "Starting…"
        lastError = nil

        var args = [script,
                    "--days", String(Settings.windowDays),
                    "--out", Settings.resolvedOutput,
                    "--title", "Vulnerability radar — by project"]
        for root in Settings.resolvedRoots.split(separator: "\n") {
            let trimmed = root.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { args.append(contentsOf: ["--roots", trimmed]) }
        }
        for pattern in Settings.ignoredFolders {
            args.append(contentsOf: ["--ignore", pattern])
        }
        if Settings.deepScan { args.append("--deep") }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = args
        // The scan shells out to git, gh, brew and python; give it a real login PATH.
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        task.environment = env

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        process = task

        pipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty, let text = String(data: chunk, encoding: .utf8) else { return }
            let lines = text.split(separator: "\n").map(String.init)
                .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            guard let last = lines.last else { return }
            Task { @MainActor in self.progress = last }
        }

        task.terminationHandler = { [weak self] finished in
            Task { @MainActor in
                guard let self else { return }
                pipe.fileHandleForReading.readabilityHandler = nil
                self.isScanning = false
                self.process = nil
                self.progress = ""
                // radar.sh exits 2 when it finds P0s; that is a result, not a failure.
                if finished.terminationStatus > 2 {
                    self.lastError = "Scan failed (exit \(finished.terminationStatus))"
                }
                self.loadFromDisk()
                let now = self.findings?.count(.p0) ?? 0
                if now > previousP0 {
                    Notifier.post(title: "New critical findings",
                                  body: "\(now - previousP0) new P0 since the last scan.")
                }
                AppMenu.shared?.refresh()
            }
        }

        do {
            try task.run()
        } catch {
            isScanning = false
            lastError = "Could not start scan: \(error.localizedDescription)"
        }
    }

    func cancelScan() {
        process?.terminate()
        process = nil
        isScanning = false
        progress = ""
    }

    func open(_ url: URL) {
        guard FileManager.default.fileExists(atPath: url.path) else {
            lastError = "\(url.lastPathComponent) does not exist yet — run a scan."
            return
        }
        NSWorkspace.shared.open(url)
    }

    func reveal(path: String) {
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
    }

    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
