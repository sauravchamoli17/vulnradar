import SwiftUI
import WebKit

/// The project-wise graph, rendered in-app instead of bouncing the user to a browser.
///
/// The page is self-contained, so it is handed to WebKit as a string rather than a file URL:
/// no local read-access scope to get wrong, and failures surface instead of showing blank.
struct GraphWebView: NSViewRepresentable {
    let url: URL
    let reloadToken: Date?
    @Binding var status: String?

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        let view = WKWebView(frame: .init(x: 0, y: 0, width: 800, height: 600),
                             configuration: config)
        view.navigationDelegate = context.coordinator
        view.underPageBackgroundColor = NSColor(Theme.bg)
        context.coordinator.report = { status = $0 }
        context.coordinator.load(view, url: url, token: reloadToken)
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        context.coordinator.report = { status = $0 }
        context.coordinator.load(view, url: url, token: reloadToken)
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, WKNavigationDelegate {
        private var loadedToken: Date??
        var report: ((String?) -> Void)?

        /// Never write SwiftUI state inside make/updateNSView — that re-enters the
        /// view update and the representable never settles.
        private func say(_ message: String?) {
            DispatchQueue.main.async { [report] in report?(message) }
        }

        func load(_ view: WKWebView, url: URL, token: Date?) {
            if let loadedToken, loadedToken == token { return }
            loadedToken = token
            guard FileManager.default.isReadableFile(atPath: url.path) else {
                say("Could not read \(url.lastPathComponent)")
                return
            }
            say(nil)
            // loadHTMLString with a file:// baseURL is refused by WebKit; this is the
            // API that grants read access to the containing directory.
            view.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }

        /// The graph is local; anything it links out to belongs in the real browser.
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
    @State private var status: String?

    private var hasGraph: Bool {
        FileManager.default.fileExists(atPath: store.graphURL.path)
    }

    var body: some View {
        ZStack {
            Theme.bg
            if hasGraph {
                GraphWebView(url: store.graphURL, reloadToken: store.lastScan,
                             status: $status)
                if let status {
                    VStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.system(size: 26)).foregroundStyle(Band.p1.tint)
                        Text(status).font(TypeScale.small).foregroundStyle(Theme.secondary)
                        PrimaryButton(title: "Open in browser",
                                      symbol: "arrow.up.forward.app") {
                            store.open(store.graphURL)
                        }
                    }
                    .padding(20)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Theme.surface))
                }
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .font(.system(size: 36, weight: .light))
                        .foregroundStyle(Theme.tertiary)
                    Text("No graph yet").font(TypeScale.title)
                        .foregroundStyle(Theme.text)
                    Text("Run a scan to build the project-wise dependency graph.")
                        .font(TypeScale.small).foregroundStyle(Theme.secondary)
                    PrimaryButton(title: "Scan now", symbol: "play.fill") { store.scan() }
                }
            }
        }
    }
}
