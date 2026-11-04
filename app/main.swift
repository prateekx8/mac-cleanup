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
        guard FileManager.default.isExecutableFile(atPath: python) else {
            return fail("Python is missing. Install Apple's Command Line Tools:\n\nxcode-select --install")
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
            return fail("Could not start the cleanup engine.\nSee ~/.macguard/app.log")
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
                else { self.fail("The cleanup engine did not start.\nSee ~/.macguard/app.log") }
            }
        }.resume()
    }

    @discardableResult
    func launchctl(_ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
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

    func fail(_ msg: String) {
        web?.loadHTMLString(loadingPage(msg.replacingOccurrences(of: "\n", with: "<br>")), baseURL: nil)
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
        a.addButton(withTitle: ["Stop", "Pause", "Quit", "Uninstall", "Reset"].contains(verb) ? verb
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
        appMenu.addItem(withTitle: "Hide Mac Cleanup", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit Mac Cleanup", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem(); main.addItem(editItem)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
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
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
