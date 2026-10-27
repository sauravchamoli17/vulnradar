import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var store: Store!
    private var menu: AppMenu!

    func applicationDidFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated {
            store = Store()
            store.loadFromDisk()
            store.scheduleAutoScan()
            menu = AppMenu(store: store)
            Notifier.prepare()
            // Nothing scanned yet: open the window so the app is not a mystery icon.
            if store.findings == nil { menu.showWindow() }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication,
                                       hasVisibleWindows flag: Bool) -> Bool {
        MainActor.assumeIsolated { menu.showWindow() }
        return true
    }

    /// Closing the window drops back to a menu bar–only app rather than quitting.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        NSApp.setActivationPolicy(.accessory)
        return false
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
