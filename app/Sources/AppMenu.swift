import AppKit
import SwiftUI
import UserNotifications

enum Notifier {
    private static var authorized = false

    static func prepare() {
        guard Bundle.main.bundleIdentifier != nil else { return }
        UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound]) { granted, _ in
                authorized = granted
            }
    }

    /// Best effort: an unsigned or unapproved build simply shows nothing.
    static func post(title: String, body: String) {
        guard authorized, Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}

@MainActor
final class AppMenu: NSObject, NSMenuDelegate {
    static var shared: AppMenu?

    private let store: Store
    private let statusItem: NSStatusItem
    private var window: NSWindow?

    init(store: Store) {
        self.store = store
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        AppMenu.shared = self
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        refresh()
    }

    func refresh() {
        guard let button = statusItem.button else { return }
        let p0 = store.findings?.count(.p0) ?? 0
        let p1 = store.findings?.count(.p1) ?? 0
        let symbol = store.isScanning ? "arrow.triangle.2.circlepath"
            : p0 > 0 ? "exclamationmark.shield.fill"
            : p1 > 0 ? "shield.lefthalf.filled" : "checkmark.shield.fill"

        let config = NSImage.SymbolConfiguration(pointSize: 14.5, weight: .regular)
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "Vulnerability radar")?
            .withSymbolConfiguration(config)
        // Template rendering is what lets the icon invert with the menu bar instead of
        // sitting on it as a dark blob.
        image?.isTemplate = true
        button.image = image
        button.imagePosition = p0 > 0 ? .imageLeading : .imageOnly
        button.attributedTitle = NSAttributedString(
            string: p0 > 0 ? " \(p0)" : "",
            attributes: [.font: NSFont.monospacedDigitSystemFont(ofSize: 11.5,
                                                                 weight: .semibold)])
        button.toolTip = store.isScanning ? "Scanning…" : store.headline
        rebuildMenu()
    }

    private func item(_ title: String, _ action: Selector?, key: String = "") -> NSMenuItem {
        let entry = NSMenuItem(title: title, action: action, keyEquivalent: key)
        entry.target = self
        return entry
    }

    private func rebuildMenu() {
        guard let menu = statusItem.menu else { return }
        menu.removeAllItems()

        let status = NSMenuItem(title: store.isScanning
            ? (store.progress.isEmpty ? "Scanning…" : store.progress)
            : store.headline, action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        let detail = NSMenuItem(title: store.isScanning ? "" : store.subhead,
                                action: nil, keyEquivalent: "")
        detail.isEnabled = false
        if !detail.title.isEmpty { menu.addItem(detail) }

        if let error = store.lastError {
            let item = NSMenuItem(title: error, action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }

        menu.addItem(.separator())
        let top = store.projects.filter { $0.band <= .p1 }.prefix(6)
        if !top.isEmpty {
            let header = NSMenuItem(title: "Needs action", action: nil, keyEquivalent: "")
            header.isEnabled = false
            menu.addItem(header)
            for project in top {
                let entry = item("   \(project.name) — \(project.items.count)",
                                 #selector(openProject(_:)))
                entry.representedObject = project.path
                entry.image = dot(for: project.band)
                menu.addItem(entry)
            }
            menu.addItem(.separator())
        }

        menu.addItem(item(store.isScanning ? "Stop scan" : "Scan now",
                          store.isScanning ? #selector(stopScan) : #selector(runScan), key: "r"))
        menu.addItem(item("Open window", #selector(showWindow), key: "o"))
        menu.addItem(item("Open report", #selector(openReport)))
        menu.addItem(item("Open graph", #selector(openGraph)))
        menu.addItem(.separator())
        menu.addItem(item("Quit", #selector(quit), key: "q"))
    }

    private func dot(for band: Band) -> NSImage? {
        let color: NSColor = band == .p0 ? .systemRed : band == .p1 ? .systemOrange
            : band == .p2 ? .systemYellow : .secondaryLabelColor
        let size = NSSize(width: 9, height: 9)
        let image = NSImage(size: size)
        image.lockFocus()
        color.setFill()
        NSBezierPath(ovalIn: NSRect(origin: .zero, size: size)).fill()
        image.unlockFocus()
        return image
    }

    func menuWillOpen(_ menu: NSMenu) {
        store.loadFromDisk()
        rebuildMenu()
    }

    @objc private func runScan() {
        store.scan()
        refresh()
    }

    @objc private func stopScan() {
        store.cancelScan()
        refresh()
    }

    @objc private func openReport() { store.open(store.reportURL) }
    @objc private func openGraph() { store.open(store.graphURL) }

    @objc private func openProject(_ sender: NSMenuItem) {
        showWindow()
        if let path = sender.representedObject as? String {
            NotificationCenter.default.post(name: .selectProject, object: path)
        }
    }

    @objc func showWindow() {
        store.loadFromDisk()
        if window == nil {
            let hosting = NSHostingController(rootView: ContentView().environmentObject(store))
            let win = NSWindow(contentViewController: hosting)
            win.title = "Vulnerability Radar"
            win.setContentSize(NSSize(width: 1020, height: 660))
            win.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            win.isReleasedWhenClosed = false
            win.center()
            window = win
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc private func quit() { NSApp.terminate(nil) }
}

extension Notification.Name {
    static let selectProject = Notification.Name("vulnradar.selectProject")
}
