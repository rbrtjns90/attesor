// Attesor Package Manager — browse Debian packages, install them into the
// sysroot through the native pipeline, and launch installed programs.
// GUI applications and terminal programs are shown in separate, labelled
// sections. Built by runtime-src/assemble.sh into runtime/Apps/.

import SwiftUI
import AppKit

// MARK: - Paths

struct Repo {
    // runtime/Apps/X.app/Contents/MacOS -> repo root (5 levels up from
    // the binary); falls back to the development path.
    static var root: URL = {
        let bundle = Bundle.main.bundleURL
        let candidate = bundle
            .deletingLastPathComponent()   // Contents
            .deletingLastPathComponent()   // X.app
            .deletingLastPathComponent()   // Apps
            .deletingLastPathComponent()   // runtime
        if FileManager.default.fileExists(
            atPath: candidate.appendingPathComponent("reconstruct/oah").path) {
            return candidate
        }
        return URL(fileURLWithPath: "/Users/rob/Documents/GitHub/attesor")
    }()
    static var sysroot: URL { root.appendingPathComponent("runtime/sysroots/debian-expanded") }
    static var oah: URL { root.appendingPathComponent("reconstruct/oah") }
    static var installer: URL { root.appendingPathComponent("runtime-src/apt-install.sh") }
    static var updater: URL { root.appendingPathComponent("runtime-src/apt-update.sh") }
    static var syncer: URL { root.appendingPathComponent("runtime-src/sync-programs.sh") }
    static var dpkgInfo: URL { sysroot.appendingPathComponent("var/lib/dpkg/info") }
    static var dpkgStatus: URL { sysroot.appendingPathComponent("var/lib/dpkg/status") }
    static var aptLists: URL { sysroot.appendingPathComponent("var/lib/apt/lists") }
    static var applications: URL { sysroot.appendingPathComponent("usr/share/applications") }
}

// MARK: - Models

struct InstalledProgram: Identifiable, Hashable {
    var id: String { binary }
    let name: String      // display name (from .desktop, else basename)
    let binary: String    // guest path, e.g. /usr/games/cowsay
    let package: String
    let isGUI: Bool
}

struct PackageEntry: Identifiable, Hashable {
    var id: String { "\(repo)|\(name)" }
    let name: String
    let version: String
    let section: String
    let desc: String
    let repo: String      // suite label, e.g. bookworm
    var installed: Bool
}

struct LaunchError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

// MARK: - App state

@MainActor
final class AppState: ObservableObject {
    @Published var guiPrograms: [InstalledProgram] = []
    @Published var termPrograms: [InstalledProgram] = []
    @Published var packages: [PackageEntry] = []
    @Published var log: String = ""
    @Published var busy = false
    @Published var busyTitle = ""
    @Published var alert: String?

    // --- process plumbing -------------------------------------------------

    /// Run a tool, streaming combined output into `log`. Returns exit status.
    @discardableResult
    func run(_ tool: String, _ args: [String], env extra: [String: String] = [:],
             title: String) async -> Int32 {
        busy = true
        busyTitle = title
        log = ""
        defer { busy = false; busyTitle = "" }
        append("$ \(tool) \(args.joined(separator: " "))\n")
        return await withCheckedContinuation { cont in
            let p = Process()
            let pipe = Pipe()
            p.executableURL = URL(fileURLWithPath: tool)
            p.arguments = args
            var env = ProcessInfo.processInfo.environment
            env["LC_ALL"] = "C"
            env.merge(extra) { _, new in new }
            p.environment = env
            p.standardOutput = pipe
            p.standardError = pipe
            pipe.fileHandleForReading.readabilityHandler = { fh in
                let data = fh.availableData
                guard !data.isEmpty else { return }
                Task { @MainActor in self.append(String(decoding: data, as: UTF8.self)) }
            }
            p.terminationHandler = { proc in
                pipe.fileHandleForReading.readabilityHandler = nil
                let tail = pipe.fileHandleForReading.readDataToEndOfFile()
                Task { @MainActor in
                    if !tail.isEmpty {
                        self.append(String(decoding: tail, as: UTF8.self))
                    }
                    cont.resume(returning: proc.terminationStatus)
                }
            }
            do { try p.run() }
            catch {
                Task { @MainActor in
                    self.append("failed to start: \(error.localizedDescription)\n")
                    cont.resume(returning: -1)
                }
            }
        }
    }

    func append(_ text: String) {
        log += text
        if log.count > 200_000 { log = String(log.suffix(150_000)) }
    }

    // --- loading -----------------------------------------------------------

    func reload() {
        let (gui, term) = Self.loadInstalled()
        guiPrograms = gui
        termPrograms = term
        packages = Self.loadPackages(installedNames: Self.loadInstalledNames())
    }

    static func loadInstalledNames() -> Set<String> {
        guard let text = try? String(contentsOf: Repo.dpkgStatus, encoding: .utf8) else { return [] }
        var names = Set<String>()
        var pkg = "", installed = false
        for line in text.split(separator: "\n") {
            if line.hasPrefix("Package: ") { pkg = String(line.dropFirst(9)) }
            if line.hasPrefix("Status: ") { installed = line.contains("installed") && !line.contains("half") }
            if line.isEmpty || line.hasPrefix("Package:") == false && line.hasPrefix(" ") == false {
                if installed && !pkg.isEmpty { names.insert(pkg) }
            }
        }
        return names
    }

    /// GUI = executable named by a .desktop file (no Terminal=true, not
    /// hidden); everything else in a bin dir is a terminal program.
    /// Mirrors runtime-src/sync-programs.sh.
    static func loadInstalled() -> ([InstalledProgram], [InstalledProgram]) {
        let fm = FileManager.default
        var guiBins: [String: String] = [:]   // binary -> display name
        if let desks = try? fm.contentsOfDirectory(atPath: Repo.applications.path) {
            for file in desks where file.hasSuffix(".desktop") {
                let url = Repo.applications.appendingPathComponent(file)
                guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
                var name = "", exec = "", hidden = false, term = false, nodisplay = false
                for line in text.split(separator: "\n") {
                    if line.hasPrefix("Name=") && name.isEmpty { name = String(line.dropFirst(5)) }
                    if line.hasPrefix("Exec=") && exec.isEmpty { exec = String(line.dropFirst(5)) }
                    if line.hasPrefix("Hidden=") { hidden = line.contains("true") }
                    if line.hasPrefix("Terminal=") { term = line.contains("true") }
                    if line.hasPrefix("NoDisplay=") { nodisplay = line.contains("true") }
                }
                guard !hidden && !term && !nodisplay && !exec.isEmpty else { continue }
                // First exec token, %-codes stripped, env wrappers skipped.
                var tokens = exec.replacingOccurrences(of: "%[a-zA-Z]", with: "",
                                     options: .regularExpression)
                    .split(separator: " ").map(String.init)
                while let first = tokens.first,
                      (first == "env" || first.contains("=") || first.hasPrefix("-")) {
                    tokens.removeFirst()
                }
                guard var bin = tokens.first else { continue }
                if !bin.hasPrefix("/") {
                    // Bare command name: resolve against the bin dirs.
                    let found = ["/usr/bin", "/usr/games", "/usr/local/bin",
                                 "/usr/sbin", "/bin", "/sbin"]
                        .first { fm.isExecutableFile(atPath: Repo.sysroot.path + $0 + "/" + bin) }
                    guard let found else { continue }
                    bin = found + "/" + bin
                }
                guard fm.isExecutableFile(atPath: Repo.sysroot.path + bin) else { continue }
                guiBins[bin] = name.isEmpty ? URL(fileURLWithPath: bin).lastPathComponent : name
            }
        }
        let bindirs = ["/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/games/", "/bin/", "/sbin/"]
        var gui: [InstalledProgram] = []
        var term: [InstalledProgram] = []
        guard let lists = try? fm.contentsOfDirectory(atPath: Repo.dpkgInfo.path) else { return ([], []) }
        for file in lists where file.hasSuffix(".list") {
            let pkg = String(file.dropLast(5))
                .components(separatedBy: ":").first ?? String(file.dropLast(5))
            guard let text = try? String(contentsOf: Repo.dpkgInfo.appendingPathComponent(file),
                                         encoding: .utf8) else { continue }
            for line in text.split(separator: "\n") {
                let path = String(line)
                guard bindirs.contains(where: { path.hasPrefix($0) }),
                      !path.hasSuffix("/"),
                      path.components(separatedBy: "/").count <= 4 else { continue }
                let full = Repo.sysroot.path + path
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue,
                      fm.isExecutableFile(atPath: full) else { continue }
                if let display = guiBins[path] {
                    gui.append(InstalledProgram(name: display, binary: path,
                                                package: pkg, isGUI: true))
                } else {
                    term.append(InstalledProgram(name: URL(fileURLWithPath: path).lastPathComponent,
                                                 binary: path, package: pkg, isGUI: false))
                }
            }
        }
        return (gui.sorted { $0.name < $1.name }, term.sorted { $0.name < $1.name })
    }

    /// Decompress an index file. .xz via xz/python3, .gz via gunzip,
    /// .lz4 via lz4 if present, uncompressed read directly.
    static func decodeIndex(_ url: URL) -> Data? {
        let path = url.path
        if path.hasSuffix(".lz4") {
            for tool in ["/opt/homebrew/bin/lz4", "/usr/local/bin/lz4"]
            where FileManager.default.isExecutableFile(atPath: tool) {
                return pipeOut(tool, ["-dc", path])
            }
            return nil
        }
        if path.hasSuffix(".xz") {
            for tool in ["/usr/bin/xz", "/opt/homebrew/bin/xz", "/usr/local/bin/xz"]
            where FileManager.default.isExecutableFile(atPath: tool) {
                return pipeOut(tool, ["-dc", path])
            }
            for py in ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
            where FileManager.default.isExecutableFile(atPath: py) {
                return pipeOut(py, ["-c",
                    "import lzma,sys;sys.stdout.buffer.write(lzma.decompress(sys.stdin.buffer.read()))"],
                               stdin: try? Data(contentsOf: url))
            }
            return nil
        }
        if path.hasSuffix(".gz") { return pipeOut("/usr/bin/gunzip", ["-c", path]) }
        return try? Data(contentsOf: url)
    }

    static func pipeOut(_ tool: String, _ args: [String], stdin: Data? = nil) -> Data? {
        let p = Process(), out = Pipe(), err = Pipe()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.standardOutput = out
        p.standardError = err
        if let stdin { p.standardInput = Pipe(); (p.standardInput as? Pipe)?.fileHandleForWriting.write(stdin); (p.standardInput as? Pipe)?.fileHandleForWriting.closeFile() }
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return p.terminationStatus == 0 ? data : nil
    }

    static func loadPackages(installedNames: Set<String>) -> [PackageEntry] {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: Repo.aptLists.path)
        else { return [] }
        var result: [PackageEntry] = []
        var seen = Set<String>()
        for file in files where file.contains("_Packages") {
            let url = Repo.aptLists.appendingPathComponent(file)
            guard let data = decodeIndex(url),
                  let text = String(data: data, encoding: .utf8) else { continue }
            // Suite label from the mangled filename: ..._dists_<suite>_...
            let suite = file.components(separatedBy: "_dists_").last?
                .components(separatedBy: "_").first ?? file
            var name = "", version = "", section = "", desc = ""
            func flush() {
                defer { name = ""; version = ""; section = ""; desc = "" }
                guard !name.isEmpty, seen.insert("\(suite)|\(name)").inserted else { return }
                result.append(PackageEntry(name: name, version: version, section: section,
                                           desc: desc, repo: suite,
                                           installed: installedNames.contains(name)))
            }
            for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
                let line = String(raw)
                if line.isEmpty { flush(); continue }
                if line.hasPrefix("Package: ") { name = String(line.dropFirst(9)) }
                else if line.hasPrefix("Version: ") { version = String(line.dropFirst(9)) }
                else if line.hasPrefix("Section: ") { section = String(line.dropFirst(9)) }
                else if line.hasPrefix("Description: ") && desc.isEmpty {
                    desc = String(line.dropFirst(13))
                } else if line.hasPrefix("Description-en: ") {
                    desc = String(line.dropFirst(15))
                }
            }
            flush()
        }
        return result.sorted { $0.name < $1.name }
    }

    // --- operations ---------------------------------------------------------

    func refreshIndex() async {
        let rc = await run("/bin/bash", [Repo.updater.path], title: "Refreshing package index")
        if rc != 0 { alert = "Index refresh failed — see log." }
        reload()
    }

    func install(_ pkg: PackageEntry) async {
        let rc = await run("/bin/bash", [Repo.installer.path, pkg.name],
                           title: "Installing \(pkg.name)")
        if rc != 0 { alert = "Install of \(pkg.name) failed — see log."; return }
        _ = await run("/bin/sh", [Repo.syncer.path], title: "Refreshing launchers")
        reload()
    }

    func uninstall(_ prog: InstalledProgram) async {
        let dpkg = Repo.sysroot.path + "/usr/bin/dpkg"
        let rc = await run(Repo.oah.path,
                           ["--sysroot", Repo.sysroot.path, dpkg, "-r", prog.package],
                           env: ["DEBIAN_FRONTEND": "noninteractive",
                                 "OAH_CACHE_DIR": Repo.root.path + "/runtime/var/cache/jit"],
                           title: "Removing \(prog.package)")
        if rc != 0 { alert = "Removal of \(prog.package) failed — see log."; return }
        _ = await run("/bin/sh", [Repo.syncer.path], title: "Refreshing launchers")
        reload()
    }

    func launch(_ prog: InstalledProgram) {
        do {
            if prog.isGUI { try launchGUI(prog) } else { try launchTerminal(prog) }
        } catch {
            alert = error.localizedDescription
        }
    }

    private func launchGUI(_ prog: InstalledProgram) throws {
        var env = ProcessInfo.processInfo.environment
        env["LC_ALL"] = "C"
        env["DISPLAY"] = ":0"
        env["OAH_CACHE_DIR"] = Repo.root.path + "/runtime/var/cache/jit"
        env["XFILESEARCHPATH"] = Repo.sysroot.path + "/etc/X11/app-defaults/%N"
        guard FileManager.default.isExecutableFile(atPath: "/opt/X11/bin/xdpyinfo") else {
            throw LaunchError(message: "Install XQuartz to run graphical Linux applications.")
        }
        if !displayReady(env) {
            let open = Process()
            open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            open.arguments = ["-a", "XQuartz"]
            try open.run()
            open.waitUntilExit()
            var ready = false
            for _ in 0..<30 {
                if displayReady(env) { ready = true; break }
                Thread.sleep(forTimeInterval: 0.25)
            }
            if !ready { throw LaunchError(message: "XQuartz did not start its local display.") }
        }
        let p = Process()
        p.executableURL = Repo.oah
        p.arguments = ["--sysroot", Repo.sysroot.path,
                       Repo.sysroot.path + prog.binary]
        p.environment = env
        try p.run()
    }

    private func displayReady(_ env: [String: String]) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/opt/X11/bin/xdpyinfo")
        p.arguments = ["-display", ":0"]
        p.environment = env
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run(); p.waitUntilExit() } catch { return false }
        return p.terminationStatus == 0
    }

    private func launchTerminal(_ prog: InstalledProgram) throws {
        let script = """
            #!/bin/sh
            # Attesor Package Manager launch
            export OAH_CACHE_DIR="\(Repo.root.path)/runtime/var/cache/jit" LC_ALL=C
            exec "\(Repo.oah.path)" --sysroot "\(Repo.sysroot.path)" \
                "\(Repo.sysroot.path)\(prog.binary)"
            """
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("Attesor-\(prog.name).command")
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        NSWorkspace.shared.open(url)
    }
}

// MARK: - Views

struct ProgramRow: View {
    let prog: InstalledProgram
    let onLaunch: () -> Void
    let onRemove: () -> Void
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: prog.isGUI ? "desktopcomputer" : "terminal")
                .font(.title3)
                .foregroundStyle(prog.isGUI ? Color.accentColor : Color.secondary)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(prog.name).font(.body)
                Text("\(prog.binary)  ·  \(prog.package)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Launch", action: onLaunch).buttonStyle(.borderedProminent)
                .controlSize(.small)
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Launch", action: onLaunch)
            Divider()
            Button("Remove \(prog.package)…", role: .destructive, action: onRemove)
        }
    }
}

struct PackageRow: View {
    let pkg: PackageEntry
    let busy: Bool
    let onInstall: () -> Void
    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(pkg.name).font(.body).bold()
                    Text(pkg.version).font(.caption).foregroundStyle(.secondary)
                    if pkg.installed {
                        Label("installed", systemImage: "checkmark.circle.fill")
                            .font(.caption).foregroundStyle(.green)
                    }
                }
                Text(pkg.desc).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Text(pkg.repo).font(.caption2).foregroundStyle(.tertiary)
            if !pkg.installed {
                Button("Install", action: onInstall).buttonStyle(.bordered)
                    .controlSize(.small).disabled(busy)
            }
        }
        .padding(.vertical, 2)
    }
}

struct InstalledView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        List {
            Section {
                if state.guiPrograms.isEmpty {
                    Text("No graphical applications installed yet.")
                        .foregroundStyle(.secondary)
                }
                ForEach(state.guiPrograms) { prog in
                    ProgramRow(prog: prog,
                               onLaunch: { state.launch(prog) },
                               onRemove: { Task { await state.uninstall(prog) } })
                }
            } header: {
                Label("GUI Applications", systemImage: "desktopcomputer")
            } footer: {
                Text("Graphical apps open in XQuartz.")
            }
            Section {
                if state.termPrograms.isEmpty {
                    Text("No terminal programs installed yet.").foregroundStyle(.secondary)
                }
                ForEach(state.termPrograms) { prog in
                    ProgramRow(prog: prog,
                               onLaunch: { state.launch(prog) },
                               onRemove: { Task { await state.uninstall(prog) } })
                }
            } header: {
                Label("Terminal Programs", systemImage: "terminal")
            } footer: {
                Text("Terminal programs open in Terminal.app.")
            }
        }
        .navigationTitle("Installed Applications")
    }
}

struct BrowseView: View {
    @EnvironmentObject var state: AppState
    @State private var query = ""
    @State private var installedOnly = false
    var filtered: [PackageEntry] {
        state.packages.filter { pkg in
            (!installedOnly || pkg.installed) &&
            (query.isEmpty || pkg.name.localizedCaseInsensitiveContains(query)
             || pkg.desc.localizedCaseInsensitiveContains(query))
        }
    }
    var body: some View {
        VStack(spacing: 0) {
            List(filtered) { pkg in
                PackageRow(pkg: pkg, busy: state.busy,
                           onInstall: { Task { await state.install(pkg) } })
            }
            .navigationTitle("Browse Packages")
            if state.packages.isEmpty {
                Text("No package index yet — press “Refresh Index” to download it.")
                    .foregroundStyle(.secondary).padding()
            }
        }
        .searchable(text: $query, placement: .toolbar, prompt: "Search packages")
        .toolbar {
            Toggle(isOn: $installedOnly) { Text("Installed only") }
                .toggleStyle(.checkbox)
        }
    }
}

struct LogView: View {
    @EnvironmentObject var state: AppState
    @State private var expanded = true
    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            ScrollViewReader { proxy in
                ScrollView {
                    Text(state.log.isEmpty ? "Command output appears here." : state.log)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .id("log-bottom")
                }
                .frame(height: 140)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor))
                .onChange(of: state.log) { proxy.scrollTo("log-bottom") }
            }
        } label: {
            HStack {
                Label("Output", systemImage: "text.alignleft")
                if state.busy {
                    ProgressView().controlSize(.small)
                    Text(state.busyTitle).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal)
        .padding(.bottom, 6)
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState
    @State private var selection: String? = "apps"
    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Applications", systemImage: "square.grid.2x2").tag("apps")
                Label("Browse Packages", systemImage: "shippingbox").tag("browse")
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            VStack(spacing: 0) {
                Group {
                    if selection == "browse" { BrowseView() } else { InstalledView() }
                }
                Divider()
                LogView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await state.refreshIndex() }
                } label: {
                    Label("Refresh Index", systemImage: "arrow.clockwise")
                }
                .disabled(state.busy)
            }
        }
        .alert("Attesor", isPresented: .constant(state.alert != nil)) {
            Button("OK") { state.alert = nil }
        } message: {
            Text(state.alert ?? "")
        }
    }
}

@main
struct AttesorPackageManager: App {
    @StateObject private var state = AppState()
    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(state)
                .frame(minWidth: 640, minHeight: 480)
                .onAppear { state.reload() }
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 780, height: 560)
    }
}
