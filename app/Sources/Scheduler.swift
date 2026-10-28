import Foundation
import SwiftUI

/// Scan on a clock, not a stopwatch: "every day at 09:00", not "every 24 hours from launch".
///
/// Two independent mechanisms, because they answer different questions:
///   in-app timer  — fires while the menu bar app is running, updates the badge live
///   launchd agent — fires even when the app is closed, so the report is ready when you look
struct ScanSchedule {
    @AppStorage("scheduleEnabled") static var enabled = false
    @AppStorage("scheduleHour") static var hour = 9
    @AppStorage("scheduleMinute") static var minute = 0
    @AppStorage("scheduleDays") static var daysMask = 0b1111111
    @AppStorage("scheduleAgent") static var useAgent = false

    static let dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

    static var selectedWeekdays: [Int] {
        (0..<7).filter { daysMask & (1 << $0) != 0 }
    }

    static func toggleDay(_ index: Int) {
        let next = daysMask ^ (1 << index)
        // Never let the schedule become unreachable.
        daysMask = next == 0 ? daysMask : next
    }

    static func isOn(_ index: Int) -> Bool { daysMask & (1 << index) != 0 }

    /// Just the time, for the sidebar footer where space is tight.
    static var clockLabel: String {
        String(format: "%02d:%02d", hour, minute)
    }

    static var summary: String {
        guard enabled else { return "Off" }
        let time = String(format: "%02d:%02d", hour, minute)
        let days = selectedWeekdays
        if days.count == 7 { return "Daily at \(time)" }
        if days == [1, 2, 3, 4, 5] { return "Weekdays at \(time)" }
        return days.map { dayNames[$0] }.joined(separator: " ") + " at \(time)"
    }

    static func nextFireDate(after date: Date = Date()) -> Date? {
        guard enabled else { return nil }
        var components = DateComponents()
        components.hour = hour
        components.minute = minute
        let calendar = Calendar.current
        var candidate = date
        for _ in 0..<8 {
            guard let next = calendar.nextDate(after: candidate, matching: components,
                                               matchingPolicy: .nextTime) else { return nil }
            // Calendar weekday is 1-based from Sunday; the mask is 0-based.
            let weekday = calendar.component(.weekday, from: next) - 1
            if isOn(weekday) { return next }
            candidate = next
        }
        return nil
    }
}

@MainActor
final class Scheduler {
    static let label = "dev.local.vulnradar.scan"
    private var timer: Timer?
    private weak var store: Store?

    init(store: Store) { self.store = store }

    func reschedule() {
        timer?.invalidate()
        timer = nil
        guard let fire = ScanSchedule.nextFireDate() else { return }
        let interval = max(30, fire.timeIntervalSinceNow)
        let timer = Timer(timeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor in
                self?.store?.scan()
                // Arm the next occurrence once this one has started.
                self?.reschedule()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    // MARK: launchd agent

    static var agentURL: URL {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static var agentInstalled: Bool {
        FileManager.default.fileExists(atPath: agentURL.path)
    }

    /// Writes a LaunchAgent that runs the scan headlessly at the chosen times.
    @discardableResult
    static func installAgent() -> String? {
        let intervals = ScanSchedule.selectedWeekdays.map { day in
            """
                <dict>
                  <key>Weekday</key><integer>\(day)</integer>
                  <key>Hour</key><integer>\(ScanSchedule.hour)</integer>
                  <key>Minute</key><integer>\(ScanSchedule.minute)</integer>
                </dict>
            """
        }.joined(separator: "\n")

        var args = ["/bin/bash", Settings.resolvedScript,
                    "--days", String(Settings.windowDays),
                    "--out", Settings.resolvedOutput,
                    "--title", "Vulnerability radar — by project"]
        for root in Settings.resolvedRoots.split(separator: "\n") {
            let trimmed = root.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { args.append(contentsOf: ["--roots", trimmed]) }
        }
        if Settings.deepScan { args.append("--deep") }
        let argXML = args.map { "    <string>\($0)</string>" }.joined(separator: "\n")
        let logPath = Settings.resolvedOutput + "/scheduled-scan.log"

        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key>
          <array>
        \(argXML)
          </array>
          <key>StartCalendarInterval</key>
          <array>
        \(intervals)
          </array>
          <key>RunAtLoad</key><false/>
          <key>StandardOutPath</key><string>\(logPath)</string>
          <key>StandardErrorPath</key><string>\(logPath)</string>
          <key>EnvironmentVariables</key>
          <dict>
            <key>PATH</key>
            <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
          </dict>
        </dict>
        </plist>
        """

        do {
            try FileManager.default.createDirectory(
                at: agentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.createDirectory(
                atPath: Settings.resolvedOutput, withIntermediateDirectories: true)
            try plist.write(to: agentURL, atomically: true, encoding: .utf8)
        } catch {
            return "Could not write the agent: \(error.localizedDescription)"
        }
        _ = launchctl(["bootout", "gui/\(getuid())/\(label)"])
        let result = launchctl(["bootstrap", "gui/\(getuid())", agentURL.path])
        if result != 0 && launchctl(["load", "-w", agentURL.path]) != 0 {
            return "Agent written, but launchctl would not load it."
        }
        return nil
    }

    @discardableResult
    static func removeAgent() -> String? {
        _ = launchctl(["bootout", "gui/\(getuid())/\(label)"])
        _ = launchctl(["unload", agentURL.path])
        try? FileManager.default.removeItem(at: agentURL)
        return nil
    }

    private static func launchctl(_ args: [String]) -> Int32 {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = args
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus
        } catch {
            return -1
        }
    }
}
