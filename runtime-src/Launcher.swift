import AppKit

enum Mode: String, CaseIterable { case automatic = "Automatic", window = "Windowed", terminal = "Terminal" }

struct LaunchError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

let paths = Bundle.main.infoDictionary ?? [:]
let runtime = Bundle.main.bundleURL.resolvingSymlinksInPath()
    .deletingLastPathComponent().deletingLastPathComponent()
let runner = runtime.deletingLastPathComponent().appendingPathComponent("reconstruct/oah").path
let roots = (paths["AttesorSysroots"] as? [String] ?? []).map {
    runtime.appendingPathComponent($0).path
}

func spawn(_ tool: String, _ args: [String], environment: [String: String]? = nil) throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: tool)
    process.arguments = args
    process.environment = environment
    try process.run()
    return process
}

func classify(_ file: URL) throws -> Mode {
    let handle = try FileHandle(forReadingFrom: file)
    defer { try? handle.close() }
    let header = [UInt8](try handle.read(upToCount: 64) ?? Data())
    guard header.count == 64, Array(header.prefix(7)) == [127, 69, 76, 70, 2, 1, 1],
          [0, 3].contains(header[7]), [2, 3].contains(header[16]), header[17] == 0,
          header[18] == 62, header[19] == 0, header[24..<32].contains(where: { $0 != 0 }) else {
        throw LaunchError(message: "Choose an x86-64 Linux ELF executable.")
    }
    let inspection = Process()
    let pipe = Pipe()
    inspection.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    inspection.arguments = ["llvm-objdump", "-p", file.standardizedFileURL.path]
    inspection.standardOutput = pipe
    inspection.standardError = FileHandle.nullDevice
    try inspection.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    inspection.waitUntilExit()
    guard inspection.terminationStatus == 0 else { return .terminal }
    let graphics = ["libX11", "libXaw", "libXt.", "libxcb", "libgtk", "libgdk",
                    "libQt", "libSDL", "libglfw", "libGL.", "libEGL", "libvulkan", "libwayland-client"]
    return String(decoding: data, as: UTF8.self).split(separator: "\n")
        .contains { line in line.contains("NEEDED") && graphics.contains { line.contains($0) } }
        ? .window : .terminal
}

func quote(_ word: String) -> String { "'" + word.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }

func launch(_ file: URL, requested: Mode) throws {
    let detected = try classify(file)
    let mode = requested == .automatic ? detected : requested
    let executable = file.resolvingSymlinksInPath()
    guard let root = roots.first(where: { executable.path.hasPrefix($0 + "/") }) ?? roots.first,
          FileManager.default.isExecutableFile(atPath: runner) else {
        throw LaunchError(message: "Attesor or its Debian sysroot was moved. Keep the Apps and sysroots folders together under Attesor.")
    }
    recordLaunch(executable)
    let args = ["--max-insns", "1500000000", "--sysroot", root, executable.path]
    var env = ProcessInfo.processInfo.environment
    env["LC_ALL"] = "C"
    env["HOME"] = "/root"
    env["XAUTHORITY"] = NSHomeDirectory() + "/.Xauthority"
    if mode == .window {
        env["DISPLAY"] = ":0"
        env["XFILESEARCHPATH"] = root + "/etc/X11/app-defaults/%N"
        guard FileManager.default.isExecutableFile(atPath: "/opt/X11/bin/xdpyinfo") else {
            throw LaunchError(message: "Install XQuartz to open X11 applications.")
        }
        func displayReady() throws -> Bool {
            let test = Process()
            test.executableURL = URL(fileURLWithPath: "/opt/X11/bin/xdpyinfo")
            test.arguments = ["-display", ":0"]
            test.environment = env
            test.standardOutput = FileHandle.nullDevice
            test.standardError = FileHandle.nullDevice
            try test.run()
            test.waitUntilExit()
            return test.terminationStatus == 0
        }
        if try !displayReady() {
            let xv = try spawn("/usr/bin/open", ["-a", "XQuartz"])
            xv.waitUntilExit()
            var ready = false
            for _ in 0..<30 {
                if try displayReady() { ready = true; break }
                Thread.sleep(forTimeInterval: 0.25)
            }
            if !ready { throw LaunchError(message: "XQuartz did not start its local display.") }
        }
        let command = Process()
        command.executableURL = URL(fileURLWithPath: runner)
        command.arguments = args
        command.environment = env
        command.currentDirectoryURL = executable.deletingLastPathComponent()
        command.terminationHandler = { process in
            if process.terminationReason == .exit && process.terminationStatus != 0 {
                DispatchQueue.main.async {
                    showError(LaunchError(message: "\(file.lastPathComponent) exited with status \(process.terminationStatus)."))
                }
            }
        }
        try command.run()
    } else {
        let commandFile = FileManager.default.temporaryDirectory.appendingPathComponent("Attesor-\(UUID().uuidString).command")
        let cmd = ([runner] + args).map(quote).joined(separator: " ")
        let script = """
        #!/bin/sh
        /bin/rm -f -- "$0"
        cd \(quote(executable.deletingLastPathComponent().path)) || exit 1
        LC_ALL=C \(cmd)
        status=$?
        printf '\\nAttesor exited with status %s.\\n' "$status"
        exit "$status"
        """
        try script.write(to: commandFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: commandFile.path)
        _ = try spawn("/usr/bin/open", ["-a", "Terminal", commandFile.path])
    }
}

func showError(_ error: Error) {
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert(error: error)
    alert.runModal()
}

// MARK: - Translation cache

let cacheDirectory: URL = {
    let env = ProcessInfo.processInfo.environment["OAH_CACHE_DIR"]
    if let env, !env.isEmpty { return URL(fileURLWithPath: env) }
    return FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Caches/Attesor/jit")
}()

func directorySize(_ url: URL) -> Int64 {
    guard let files = FileManager.default.enumerator(
        at: url, includingPropertiesForKeys: [.fileSizeKey],
        options: [.skipsHiddenFiles]) else { return 0 }
    var total: Int64 = 0
    for case let file as URL in files {
        total += Int64((try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
    }
    return total
}

func cacheSizeString() -> String {
    let bytes = directorySize(cacheDirectory)
    if bytes <= 0 { return "Translation cache: empty" }
    return "Translation cache: "
        + ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
}

// MARK: - Launch history

struct HistoryEntry {
    var path: String
    var lastRun: Int
    var count: Int
}

var historyFile: URL {
    runtime.appendingPathComponent("var/launcher-history.tsv")
}

func loadHistory() -> [HistoryEntry] {
    guard let text = try? String(contentsOf: historyFile, encoding: .utf8)
    else { return [] }
    var merged: [String: HistoryEntry] = [:]
    for line in text.split(separator: "\n") {
        let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
        guard let first = fields.first, !first.isEmpty else { continue }
        let path = String(first)
        let epoch = fields.count > 1 ? Int(fields[1]) ?? 0 : 0
        let count = fields.count > 2 ? Int(fields[2]) ?? 1 : 1
        var entry = merged[path] ?? HistoryEntry(path: path, lastRun: 0, count: 0)
        entry.lastRun = max(entry.lastRun, epoch)
        entry.count += count
        merged[path] = entry
    }
    return merged.values.sorted { $0.lastRun > $1.lastRun }
}

func recordLaunch(_ file: URL) {
    var entries = loadHistory()
    let path = file.resolvingSymlinksInPath().path
    let now = Int(Date().timeIntervalSince1970)
    if let i = entries.firstIndex(where: { $0.path == path }) {
        entries[i].lastRun = now
        entries[i].count += 1
    } else {
        entries.append(HistoryEntry(path: path, lastRun: now, count: 1))
    }
    entries.sort { $0.lastRun > $1.lastRun }
    let text = entries
        .map { "\($0.path)\t\($0.lastRun)\t\($0.count)" }
        .joined(separator: "\n") + "\n"
    try? FileManager.default.createDirectory(
        at: historyFile.deletingLastPathComponent(),
        withIntermediateDirectories: true)
    try? text.write(to: historyFile, atomically: true, encoding: .utf8)
}

final class ClearCacheButton: NSButton {
    weak var label: NSTextField?
    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        title = "Clear"
        bezelStyle = .rounded
        target = self
        action = #selector(clear)
    }
    required init?(coder: NSCoder) { fatalError() }
    @objc private func clear() {
        try? FileManager.default.removeItem(at: cacheDirectory)
        label?.stringValue = cacheSizeString()
    }
}

final class Launcher: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var receivedFiles = false
    private weak var appsMenu: NSMenu?

    func installMenus() {
        let mainMenu = NSMenu()
        let appItem = mainMenu.addItem(withTitle: "", action: nil, keyEquivalent: "")
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Attesor Linux Launcher",
                        action: #selector(NSApplication.terminate(_:)),
                        keyEquivalent: "q")
        appItem.submenu = appMenu

        let appsItem = mainMenu.addItem(withTitle: "Apps", action: nil, keyEquivalent: "")
        let apps = NSMenu(title: "Apps")
        apps.delegate = self
        appsItem.submenu = apps
        appsMenu = apps
        rebuildAppsMenu()

        NSApp.mainMenu = mainMenu
    }

    func menuWillOpen(_ menu: NSMenu) {
        if menu === appsMenu { rebuildAppsMenu() }
    }

    private func rebuildAppsMenu() {
        guard let menu = appsMenu else { return }
        menu.removeAllItems()
        let entries = loadHistory().prefix(15)
        if entries.isEmpty {
            let none = menu.addItem(withTitle: "No Recent Apps", action: nil, keyEquivalent: "")
            none.isEnabled = false
        } else {
            for entry in entries {
                let url = URL(fileURLWithPath: entry.path)
                let title = entry.path.hasSuffix(".app")
                    ? url.deletingPathExtension().lastPathComponent
                    : url.lastPathComponent
                let item = menu.addItem(withTitle: title,
                                        action: #selector(openRecent(_:)),
                                        keyEquivalent: "")
                item.target = self
                item.representedObject = entry.path
                item.toolTip = entry.path
                item.isEnabled = FileManager.default.fileExists(atPath: entry.path)
            }
        }
        menu.addItem(.separator())
        let open = menu.addItem(withTitle: "Open Linux Executable…",
                                action: #selector(openPanel(_:)),
                                keyEquivalent: "o")
        open.target = self
        let clear = menu.addItem(withTitle: "Clear Recent Items",
                                 action: #selector(clearHistory(_:)),
                                 keyEquivalent: "")
        clear.target = self
        menu.addItem(.separator())
        let sync = menu.addItem(withTitle: "Refresh Program Shortcuts",
                                action: #selector(syncShortcuts(_:)),
                                keyEquivalent: "")
        sync.target = self
    }

    @objc private func openRecent(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        if path.hasSuffix(".app") {
            // Bundled apps carry their own environment — reopen the bundle.
            _ = try? spawn("/usr/bin/open", [path])
            return
        }
        do { try launch(URL(fileURLWithPath: path), requested: .automatic) }
        catch { showError(error) }
    }

    @objc private func openPanel(_ sender: NSMenuItem) {
        choose()
    }

    @objc private func clearHistory(_ sender: NSMenuItem) {
        try? FileManager.default.removeItem(at: historyFile)
        rebuildAppsMenu()
    }

    @objc private func syncShortcuts(_ sender: NSMenuItem) {
        let script = runtime.appendingPathComponent("sync-programs.sh")
        guard FileManager.default.isExecutableFile(atPath: script.path) else {
            showError(LaunchError(message: "sync-programs.sh is missing — run runtime-src/assemble.sh."))
            return
        }
        do {
            let process = try spawn("/bin/sh", [script.path])
            process.waitUntilExit()
            if process.terminationStatus != 0 {
                showError(LaunchError(message: "Shortcut refresh exited with status \(process.terminationStatus)."))
            }
        } catch { showError(error) }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async {
            if !self.receivedFiles { self.choose() }
        }
    }

    func application(_ sender: NSApplication, openFiles files: [String]) {
        receivedFiles = true
        for path in files {
            do { try launch(URL(fileURLWithPath: path), requested: .automatic) }
            catch { showError(error) }
        }
        sender.reply(toOpenOrPrint: .success)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        choose()
        return true
    }

    private func choose() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.title = "Open a Linux program"
        panel.prompt = "Run"
        if let root = roots.first {
            panel.directoryURL = URL(fileURLWithPath: root).appendingPathComponent("usr/bin")
        }
        panel.allowsMultipleSelection = true
        let mode = NSPopUpButton()
        mode.addItems(withTitles: Mode.allCases.map(\.rawValue))
        let cacheLabel = NSTextField(labelWithString: cacheSizeString())
        cacheLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        let clearButton = ClearCacheButton()
        clearButton.label = cacheLabel
        let accessory = NSStackView(views: [mode, cacheLabel, clearButton])
        accessory.orientation = .horizontal
        accessory.spacing = 12
        accessory.edgeInsets = NSEdgeInsets(top: 0, left: 8, bottom: 0, right: 8)
        panel.accessoryView = accessory
        if panel.runModal() == .OK {
            for file in panel.urls {
                do { try launch(file, requested: Mode(rawValue: mode.titleOfSelectedItem ?? "") ?? .automatic) }
                catch { showError(error) }
            }
        }
    }
}

if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--classify" {
    do { print(try classify(URL(fileURLWithPath: CommandLine.arguments[2])).rawValue); exit(0) }
    catch { fputs(error.localizedDescription + "\n", stderr); exit(1) }
}

let app = NSApplication.shared
let delegate = Launcher()
app.setActivationPolicy(.regular)
app.delegate = delegate
delegate.installMenus()
app.run()
