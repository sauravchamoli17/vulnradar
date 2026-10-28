import SwiftUI
import WebKit

/// The project-wise graph, rendered in-app instead of bouncing the user to a browser.
///
/// The page is handed to WebKit as a local file with read access to its folder, and told
/// it is embedded so it drops its own title bar, project list and legend — the app
/// already provides all three.
struct GraphWebView: NSViewRepresentable {
    let url: URL
    let reloadToken: Date?
    let focus: String?
    @Binding var status: String?

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        config.userContentController.addUserScript(WKUserScript(
            source: "document.documentElement.setAttribute('data-embed','1');",
            injectionTime: .atDocumentStart, forMainFrameOnly: true))

        let view = WKWebView(frame: .init(x: 0, y: 0, width: 800, height: 600),
                             configuration: config)
        view.navigationDelegate = context.coordinator
        view.underPageBackgroundColor = NSColor(Theme.contentPanel)
        // The app is dark whatever the system is set to; without this the page's
        // prefers-color-scheme resolves light and renders on white.
        view.appearance = NSAppearance(named: .darkAqua)
        context.coordinator.report = { status = $0 }
        context.coordinator.load(view, url: url, token: reloadToken)
        context.coordinator.applyFocus(view, focus)
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        context.coordinator.report = { status = $0 }
        context.coordinator.load(view, url: url, token: reloadToken)
        context.coordinator.applyFocus(view, focus)
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, WKNavigationDelegate {
        private var loadedToken: Date??
        private var isLoaded = false
        private var wantedFocus: String?
        private var appliedFocus: String??
        var report: ((String?) -> Void)?

        /// Never write SwiftUI state inside make/updateNSView — that re-enters the
        /// view update and the representable never settles.
        private func say(_ message: String?) {
            DispatchQueue.main.async { [report] in report?(message) }
        }

        func load(_ view: WKWebView, url: URL, token: Date?) {
            if let loadedToken, loadedToken == token { return }
            loadedToken = token
            isLoaded = false
            appliedFocus = nil
            guard FileManager.default.isReadableFile(atPath: url.path) else {
                say("Could not read \(url.lastPathComponent)")
                return
            }
            say(nil)
            // loadHTMLString with a file:// baseURL is refused by WebKit; this is the
            // API that grants read access to the containing directory.
            view.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }

        /// Focus the cluster for whatever project is selected in the sidebar.
        func applyFocus(_ view: WKWebView, _ path: String?) {
            wantedFocus = path
            guard isLoaded else { return }
            if let appliedFocus, appliedFocus == path { return }
            appliedFocus = path
            let target: String
            if let path, !path.isEmpty {
                let escaped = path
                    .replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "'", with: "\\'")
                target = "'proj:\(escaped)'"
            } else {
                target = "null"
            }
            view.evaluateJavaScript(
                "if (typeof select === 'function') { select(\(target)); }")
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            if action.navigationType == .linkActivated, let target = action.request.url {
                NSWorkspace.shared.open(target)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            isLoaded = true
            appliedFocus = nil
            applyFocus(webView, wantedFocus)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!,
                     withError error: Error) {
            say(error.localizedDescription)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            say(error.localizedDescription)
        }

        func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
            say("The graph view ran out of memory. Narrow the scan scope in Settings.")
        }
    }
}

struct GraphPane: View {
    @EnvironmentObject var store: Store
    let focus: String?
    @State private var status: String?

    private var hasGraph: Bool {
        FileManager.default.fileExists(atPath: store.graphURL.path)
    }

    var body: some View {
        ZStack {
            Theme.contentPanel
            if hasGraph {
                // A ZStack sizes children to their own ideal size, and a WKWebView has
                // none worth having — without this it lays out at the frame it was
                // created with, or at nothing at all, and the pane looks empty.
                GraphWebView(url: store.graphURL, reloadToken: store.lastScan,
                             focus: focus, status: $status)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                if let status {
                    VStack(spacing: Space.m) {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.system(size: 26)).foregroundStyle(Band.p1.tint)
                        Text(status).font(TypeScale.body).foregroundStyle(Theme.secondary)
                        PrimaryButton(title: "Open in browser",
                                      symbol: "arrow.up.forward.app") {
                            store.open(store.graphURL)
                        }
                    }
                    .padding(Space.xl)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Theme.contentPanel))
                }
            } else {
                VStack(spacing: Space.m) {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .font(.system(size: 36, weight: .light))
                        .foregroundStyle(Theme.tertiary)
                    Text("No graph yet").font(TypeScale.title)
                        .foregroundStyle(Theme.text)
                    Text("Run a scan to build the project-wise dependency graph.")
                        .font(TypeScale.body).foregroundStyle(Theme.secondary)
                    PrimaryButton(title: "Scan now", symbol: "play.fill") { store.scan() }
                }
            }
        }
    }
}
