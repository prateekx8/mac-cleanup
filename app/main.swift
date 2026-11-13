// Mac Cleanup.app - native window around the local macguard UI.
// Starts `macguard.py ui` on a free localhost port, shows it in a WKWebView,
// and stops the server when the app quits.
import Cocoa
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate, WKUIDelegate, WKNavigationDelegate {
    var window: NSWindow!
    var web: WKWebView!

    func applicationDidFinishLaunching(_ note: Notification) {
        buildMenu()
        makeWindow()
        startServer()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ note: Notification) {
        launchctl(["bootout", "gui/\(getuid())/\(label)"])
    }

    // MARK: window

    func makeWindow() {
        let config = WKWebViewConfiguration()
        // lets the page adjust for the native window (e.g. no duplicate top padding)
        let js = "document.documentElement.classList.add('in-app')"
        config.userContentController.addUserScript(WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        web = WKWebView(frame: .zero, configuration: config)
        web.uiDelegate = self
        web.navigationDelegate = self
        web.setValue(false, forKey: "drawsBackground")

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 820),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Mac Cleanup"
        window.titlebarAppearsTransparent = true
        window.backgroundColor = NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(srgbRed: 0.043, green: 0.051, blue: 0.102, alpha: 1)
                : NSColor(srgbRed: 0.933, green: 0.941, blue: 0.984, alpha: 1)
        }
        window.minSize = NSSize(width: 760, height: 560)
        window.contentView = web
        window.center()
        window.setFrameAutosaveName("MacCleanupMain")
        window.makeKeyAndOrderFront(nil)
        web.loadHTMLString(loadingPage("Starting…"), baseURL: nil)
    }

    func loadingPage(_ msg: String) -> String {
        """
        <html><body style="margin:0;height:100vh;display:grid;place-items:center;background:transparent;
        font:15px -apple-system;color:#8b8fa8">\(msg)</body></html>
        """
    }

    // MARK: server

    let label = "ai.macguard.ui"
    var port = 0

    // The engine runs as a short-lived launchd job (not a child of this app): macOS only
    // shows other processes' sockets to processes it trusts, and an ad-hoc signed app's
    // children inherit its restrictions. No KeepAlive, not installed at login, removed on quit,
    // and the engine exits by itself if this app disappears (--parent-pid watchdog).
    func startServer() {
        guard let res = Bundle.main.resourcePath else { return fail("Missing app resources.") }
        let python = "/usr/bin/python3"
        // /usr/bin/python3 always exists, but without the Command Line Tools it is only a stub
        // that pops up Apple's installer, so check for the tools themselves.
        guard FileManager.default.isExecutableFile(atPath: python), launch("/usr/bin/xcode-select", ["-p"]) == 0 else {
            launch("/usr/bin/xcode-select", ["--install"])
            return fail("Mac Cleanup needs Apple's Command Line Tools (they include Python).\n\n"
                        + "1. Click Install in the window that just opened (5–10 minutes).\n"
                        + "2. Open Mac Cleanup again.\n\nNo window? In Terminal run: xcode-select --install")
        }
        port = freePort()
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".macguard")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let log = dir.appendingPathComponent("app.log").path
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [python, "-u", res + "/macguard.py", "ui", "--port", String(port), "--no-open",
                                 "--parent-pid", String(ProcessInfo.processInfo.processIdentifier)],
            "RunAtLoad": true, "KeepAlive": false, "ProcessType": "Interactive",
            "StandardOutPath": log, "StandardErrorPath": log,
        ]
        let path = dir.appendingPathComponent("ui-session.plist")
        guard let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
              (try? data.write(to: path)) != nil else { return fail("Could not write ~/.macguard/ui-session.plist") }
        launchctl(["bootout", "gui/\(getuid())/\(label)"])
        if launchctl(["bootstrap", "gui/\(getuid())", path.path]) != 0 {
            return fail("Could not start the cleanup engine.", showLog: true)
        }
        waitForServer(tries: 80)
    }

    func waitForServer(tries: Int) {
        let url = URL(string: "http://127.0.0.1:\(port)/")!
        URLSession.shared.dataTask(with: url) { [weak self] _, resp, _ in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if (resp as? HTTPURLResponse)?.statusCode == 200 { self.web.load(URLRequest(url: url)) }
                else if tries > 0 { DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { self.waitForServer(tries: tries - 1) } }
                else { self.fail("The cleanup engine did not start.", showLog: true) }
            }
        }.resume()
    }

    @discardableResult
    func launchctl(_ args: [String]) -> Int32 { launch("/bin/launchctl", args) }

    @discardableResult
    func launch(_ tool: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, len) } }
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: addr.sin_port))
    }

    func fail(_ msg: String, showLog: Bool = false) {
        func esc(_ t: String) -> String {
            t.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
        }
        var html = "<div style='max-width:560px;text-align:left;line-height:1.55'><b style='font-size:17px'>"
            + esc(msg).replacingOccurrences(of: "\n", with: "<br>") + "</b>"
        if showLog {
            let log = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".macguard/app.log")
            let tail = ((try? String(contentsOf: log, encoding: .utf8)) ?? "")
                .split(separator: "\n", omittingEmptySubsequences: false).suffix(12).joined(separator: "\n")
            html += "<p>Try these in order:</p><ol>"
                + "<li>Quit Mac Cleanup and open it again.</li>"
                + "<li>In Terminal, in the mac-cleanup folder: <code>./setup.sh</code> then <code>macguard doctor</code>. "
                + "Every ✘ line says how to fix it.</li>"
                + "<li>Rebuild the app: <code>./build_app.sh --install</code>.</li>"
                + "<li>Still stuck? <code>macguard doctor --bundle</code> and attach the file to a bug report.</li></ol>"
                + "<p>Guide: <code>docs/INSTALL.md</code>, section Troubleshooting.</p>"
            if !tail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                html += "<p>Last lines of ~/.macguard/app.log:</p><pre style='white-space:pre-wrap;font:11px Menlo;"
                    + "background:rgba(127,127,127,.12);padding:10px;border-radius:8px'>" + esc(tail) + "</pre>"
            }
        }
        web?.loadHTMLString(loadingPage(html + "</div>"), baseURL: nil)
    }

    // MARK: JS dialogs (confirm before deleting)

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert()
        a.alertStyle = .warning
        let lines = message.components(separatedBy: "\n")
        a.messageText = lines.first ?? "Confirm"
        a.informativeText = lines.dropFirst().joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        // the button says what happens: "Stop 2 item(s)?" -> Stop, "Pause …" -> Pause, "Quit Docker…" -> Quit, cleanup -> Delete
        let verb = String(lines.first?.split(separator: " ").first ?? "")
        a.addButton(withTitle: ["Start", "Prepare", "Stop", "Pause", "Quit", "Uninstall", "Reset"].contains(verb) ? verb
                    : (message.hasPrefix("Permanently delete") ? "Delete" : "Continue"))
        a.addButton(withTitle: "Cancel")
        a.buttons.first?.hasDestructiveAction = true
        a.beginSheetModal(for: window) { completionHandler($0 == .alertFirstButtonReturn) }
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert()
        a.messageText = message
        a.beginSheetModal(for: window) { _ in completionHandler() }
    }

    // keep the window on the local UI; open anything else in the default browser
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, let host = url.host, host != "127.0.0.1", host != "localhost" {
            NSWorkspace.shared.open(url)
            return decisionHandler(.cancel)
        }
        decisionHandler(.allow)
    }

    // MARK: menu

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem(); main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About Mac Cleanup", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Ready for Shutdown…", action: #selector(readyForShutdown), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Mac Cleanup", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit Mac Cleanup", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem(); main.addItem(editItem)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit

        let viewItem = NSMenuItem(); main.addItem(viewItem)
        let view = NSMenu(title: "View")
        view.addItem(withTitle: "Reload", action: #selector(reload), keyEquivalent: "r")
        viewItem.submenu = view

        let winItem = NSMenuItem(); main.addItem(winItem)
        let win = NSMenu(title: "Window")
        win.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        win.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        winItem.submenu = win
        NSApp.mainMenu = main
    }

    @objc func reload() { web.reload() }
    @objc func readyForShutdown() { web.evaluateJavaScript("window.readyForShutdown && readyForShutdown()") }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
