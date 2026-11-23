// Attesor Package Manager — browse Debian packages, install them into the
// sysroot through the native pipeline, and launch installed programs.
// GUI applications and terminal programs are shown in separate, labelled
// sections. Built by runtime-src/assemble.sh into runtime/Apps/.

import SwiftUI
import AppKit

// MARK: - Paths

struct Repo {
    /// Where the runtime payload lives once downloaded on first launch —
    /// the "installed" location for a shipped Attesor.app.
    static var appSupport: URL {
        URL(fileURLWithPath: NSHomeDirectory()
            + "/Library/Application Support/Attesor")
    }

    /// The runtime root: payload installed under Application Support
    /// first, then a development checkout (bundle inside runtime/Apps or
    // the hardcoded path). Falls through to appSupport so the first-run
    /// bootstrap has a target to create.
    static var root: URL {
        let fm = FileManager.default
        let candidates = [
            appSupport,
            Bundle.main.bundleURL
                .deletingLastPathComponent()   // Contents
                .deletingLastPathComponent()   // X.app
                .deletingLastPathComponent()   // Apps
                .deletingLastPathComponent(),  // runtime
            URL(fileURLWithPath: "/Users/rob/Documents/GitHub/attesor"),
        ]
        for c in candidates where fm.fileExists(
            atPath: c.appendingPathComponent("reconstruct/oah").path) {
            return c
        }
        return appSupport
    }

    /// True when a usable payload (translator + at least one sysroot) is
    /// present — false on a fresh install before first-run setup.
    static var payloadPresent: Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: oah.path) else { return false }
        let sysroots = root.appendingPathComponent("runtime/sysroots")
        return !((try? fm.contentsOfDirectory(atPath: sysroots.path)) ?? [])
            .filter { !$0.hasPrefix(".") }.isEmpty
    }
    static var sysroot: URL { root.appendingPathComponent("runtime/sysroots/debian-expanded") }
    static var sysroots: [URL] {
        let dir = root.appendingPathComponent("runtime/sysroots")
        return ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [])
            .filter { !$0.hasPrefix(".") }
            .map { dir.appendingPathComponent($0) }
    }
    static func sysroot(named name: String) -> URL {
        root.appendingPathComponent("runtime/sysroots/\(name)")
    }
    static var oah: URL { root.appendingPathComponent("reconstruct/oah") }
    static var installer: URL { root.appendingPathComponent("runtime-src/apt-install.sh") }
    static var updater: URL { root.appendingPathComponent("runtime-src/apt-update.sh") }
    static var syncer: URL { root.appendingPathComponent("runtime-src/sync-programs.sh") }
    static var stateSync: URL { root.appendingPathComponent("runtime-src/state-sync.sh") }
    static var stateDb: URL { root.appendingPathComponent("runtime/var/state.sqlite") }
    static var dpkgInfo: URL { sysroot.appendingPathComponent("var/lib/dpkg/info") }
    static var dpkgStatus: URL { sysroot.appendingPathComponent("var/lib/dpkg/status") }
    static var aptLists: URL { sysroot.appendingPathComponent("var/lib/apt/lists") }
    static var applications: URL { sysroot.appendingPathComponent("usr/share/applications") }
}

// MARK: - Models

struct InstalledProgram: Identifiable, Hashable {
    var id: String { "\(sysroot)|\(binary)" }
    let name: String      // display name (from .desktop, else basename)
    let binary: String    // guest path, e.g. /usr/games/cowsay
    let package: String   // dpkg package, empty for hand-built sysroots
    let sysroot: String   // sysroot dir name, e.g. "debian-expanded"
    let isGUI: Bool
    var iconPath: String? // host path to a loadable icon image, if any
}

/// A curated, friendly entry on the Featured page. `package` is the apt
/// name used for install; `matchBin` lets the card light up when an
/// equivalent program is already installed (e.g. hand-built sysroots).
struct FeaturedApp: Identifiable {
    var id: String { package }
    let title: String
    let blurb: String
    let category: String   // "Games", "Utilities"…
    let package: String    // apt package name
    let matchBin: String   // substring matched against installed binaries
    let iconName: String?  // freedesktop icon name to resolve
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

// MARK: - Icons

/// Resolves freedesktop Icon= specs inside a sysroot and composites a
/// penguin badge onto loaded images so Linux apps are visually marked.
enum LinuxIcon {
    /// The generated Tux icon the app bundles already ship.
    static let penguin: NSImage? = {
        for path in [
            Repo.root.path + "/runtime/icons/Penguin.icns",
            Bundle.main.path(forResource: "Penguin", ofType: "icns"),
        ].compactMap({ $0 }) {
            if let img = NSImage(contentsOfFile: path) { return img }
        }
        return nil
    }()

    /// Extensions NSImage can actually decode (XPM is not supported).
    private static let loadable: Set<String> = ["png", "icns", "tiff", "jpg", "jpeg", "gif", "bmp"]

    /// Icon= is either an absolute guest path or a theme icon name.
    /// Theme names resolve through hicolor (largest size wins) with a
    /// pixmaps fallback, matching the freedesktop lookup order loosely.
    static func resolve(sysroot: String, spec: String) -> String? {
        let root = Repo.sysroot(named: sysroot).path
        if spec.hasPrefix("/") {
            let p = root + spec
            return loadable.contains((spec as NSString).pathExtension.lowercased())
                && FileManager.default.fileExists(atPath: p) ? p : nil
        }
        let name = (spec as NSString).deletingPathExtension
        var candidates: [(String, Int)] = []
        let themes = ["hicolor"]
        for theme in themes {
            let themeRoot = root + "/usr/share/icons/\(theme)"
            guard let sizes = try? FileManager.default.contentsOfDirectory(atPath: themeRoot)
            else { continue }
            for size in sizes {
                let dir = themeRoot + "/\(size)/apps"
                for ext in ["png", "svg", "xpm"] {
                    let p = dir + "/\(name).\(ext)"
                    guard loadable.contains(ext),
                          FileManager.default.fileExists(atPath: p) else { continue }
                    let px = Int(size.components(separatedBy: "x").first ?? "0") ?? 0
                    candidates.append((p, px))
                }
            }
        }
        if let best = candidates.sorted(by: { $0.1 > $1.1 }).first { return best.0 }
        for ext in ["png", "jpg", "jpeg", "gif", "bmp", "icns", "tiff"] {
            let p = root + "/usr/share/pixmaps/\(name).\(ext)"
            if FileManager.default.fileExists(atPath: p) { return p }
        }
        return nil
    }

    /// Guest binary path -> host icon path, from every .desktop file in
    /// the sysroot. Mirrors the Exec parsing in loadInstalled().
    static func iconMap(sysroot root: URL) -> [String: String] {
        let fm = FileManager.default
        let sname = root.lastPathComponent
        var map: [String: String] = [:]
        let binDirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin",
                       "/usr/games", "/bin", "/sbin"]
        let appsDir = root.appendingPathComponent("usr/share/applications")
        guard let desks = try? fm.contentsOfDirectory(atPath: appsDir.path) else { return map }
        for file in desks where file.hasSuffix(".desktop") {
            guard let text = try? String(
                contentsOf: appsDir.appendingPathComponent(file), encoding: .utf8)
            else { continue }
            var exec = "", icon = "", hidden = false, nodisplay = false, term = false
            for line in text.split(separator: "\n") {
                if line.hasPrefix("Exec=") && exec.isEmpty { exec = String(line.dropFirst(5)) }
                else if line.hasPrefix("Icon=") && icon.isEmpty { icon = String(line.dropFirst(5)) }
                else if line.hasPrefix("Hidden=") { hidden = line.contains("true") }
                else if line.hasPrefix("Terminal=") { term = line.contains("true") }
                else if line.hasPrefix("NoDisplay=") { nodisplay = line.contains("true") }
            }
            guard !hidden && !term && !nodisplay, !exec.isEmpty, !icon.isEmpty,
                  let resolved = resolve(sysroot: sname, spec: icon) else { continue }
            var tokens = exec.replacingOccurrences(of: "%[a-zA-Z]", with: "",
                             options: .regularExpression)
                .split(separator: " ").map(String.init)
            while let first = tokens.first,
                  (first == "env" || first.contains("=") || first.hasPrefix("-")) {
                tokens.removeFirst()
            }
            guard var bin = tokens.first else { continue }
            if !bin.hasPrefix("/") {
                guard let found = binDirs.first(where: {
                    fm.isExecutableFile(atPath: root.path + $0 + "/" + bin)
                }) else { continue }
                bin = found + "/" + bin
            }
            map[bin] = resolved
        }
        return map
    }

    private static var cache: [String: NSImage] = [:]

    /// App icon with the penguin badge composited bottom-right. Falls
    /// back to the penguin alone when the program ships no icon.
    static func image(for prog: InstalledProgram, size: CGFloat = 28) -> NSImage {
        let key = "\(prog.iconPath ?? "tux")@\(Int(size))"
        if let hit = cache[key] { return hit }
        let appIcon = prog.iconPath.flatMap { NSImage(contentsOfFile: $0) }
        let out = NSImage(size: NSSize(width: size, height: size))
        out.lockFocus()
        defer { out.unlockFocus() }
        let rect = NSRect(x: 0, y: 0, width: size, height: size)
        (appIcon ?? penguin)?.draw(in: rect)
        if appIcon != nil, let tux = penguin {
            let badge = size * 0.42
            let br = NSRect(x: size - badge, y: 0, width: badge, height: badge)
            // White backing disc keeps the penguin legible on dark icons.
            NSColor.white.setFill()
            NSBezierPath(ovalIn: br.insetBy(dx: -1, dy: -1)).fill()
            tux.draw(in: br)
        }
        cache[key] = out
        return out
    }
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
    /// Friendly name of the guest app currently spinning up — drives the
    /// "Starting…" overlay so slow emulated launches give feedback.
    @Published var launching: String?
    /// GUI programs launched from this window, keyed by program id.
    var procs: [String: Process] = [:]
    /// Program ids with a live guest process (for Running/Quit UI).
    @Published var running: Set<String> = []
    /// XQuartz is required for every graphical launch; checked at reload.
    @Published var xquartzMissing = false

    // --- first-run setup ----------------------------------------------------

    enum SetupPhase: Equatable {
        case needed           // no payload — show welcome
        case downloading(Double) // fraction 0…1 (negative = indeterminate)
        case extracting
        case failed(String)
    }
    @Published var setup: SetupPhase = .needed

    /// Release asset the bootstrap downloads; overridable for testing.
    static var runtimeURL: String {
        ProcessInfo.processInfo.environment["ATTESOR_RUNTIME_URL"]
            ?? "https://github.com/rbrtjns90/attesor/releases/latest/download/attesor-runtime.tar.xz"
    }

    /// Download + unpack the Linux runtime into Application Support.
    /// The tarball holds a repo-shaped tree: reconstruct/oah,
    /// runtime/sysroots/*, runtime-src/*.sh, runtime/Apps/*.
    func beginSetup() {
        setup = .downloading(-1)
        let url = Self.runtimeURL
        Task.detached {
            let fm = FileManager.default
            let dest = Repo.appSupport
            let tmp = dest.appendingPathComponent("runtime-download.tar.xz")
            do {
                try fm.createDirectory(at: dest, withIntermediateDirectories: true)
                try? fm.removeItem(at: tmp)
                // HEAD first so the progress bar has a denominator.
                var expected: Int64 = -1
                if let head = Self.pipeOut("/usr/bin/curl", ["-fsSI", url]),
                   let text = String(data: head, encoding: .utf8) {
                    for line in text.split(separator: "\r\n") + text.split(separator: "\n")
                    where line.lowercased().hasPrefix("content-length:") {
                        expected = Int64(line.split(separator: ":").last?
                            .trimmingCharacters(in: .whitespaces) ?? "") ?? -1
                    }
                }
                let curl = Process()
                curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                curl.arguments = ["-fSL", "--retry", "3", "-o", tmp.path, url]
                try curl.run()
                while curl.isRunning {
                    if expected > 0, let size = try? tmp.resourceValues(
                        forKeys: [.fileSizeKey]).fileSize {
                        let frac = min(0.99, Double(size) / Double(expected))
                        await MainActor.run { self.setup = .downloading(frac) }
                    }
                    try await Task.sleep(nanoseconds: 500_000_000)
                }
                guard curl.terminationStatus == 0 else {
                    throw LaunchError(message: "Download failed (curl exit \(curl.terminationStatus)). Check your connection.")
                }
                await MainActor.run { self.setup = .extracting }
                try fm.createDirectory(at: dest, withIntermediateDirectories: true)
                let tar = Process()
                tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
                tar.arguments = ["-xJf", tmp.path, "-C", dest.path]
                try tar.run(); tar.waitUntilExit()
                guard tar.terminationStatus == 0 else {
                    throw LaunchError(message: "Couldn't unpack the runtime (bad archive?).")
                }
                try? fm.removeItem(at: tmp)
                // Writable-data dirs the tarball may not carry.
                for d in ["runtime/var/cache/jit", "runtime/var/log",
                          "runtime/var/freeciv/home"] {
                    try? fm.createDirectory(
                        at: dest.appendingPathComponent(d),
                        withIntermediateDirectories: true)
                }
                await MainActor.run { self.setup = .needed; self.reload() }
            } catch {
                try? fm.removeItem(at: tmp)
                await MainActor.run {
                    self.setup = .failed(error.localizedDescription)
                }
            }
        }
    }

    /// Featured cards shown on the front page. `matchBin` marks the card
    /// installed when any installed binary contains it — hand-built
    /// sysroots (freeciv) light up without an apt record.
    static let featured: [FeaturedApp] = [
        FeaturedApp(title: "Freeciv", blurb: "Turn-based empire strategy game",
                    category: "Games", package: "freeciv",
                    matchBin: "freeciv-sdl2", iconName: "freeciv-client", isGUI: true),
        FeaturedApp(title: "DOSBox", blurb: "Run classic DOS games and software",
                    category: "Games", package: "dosbox",
                    matchBin: "dosbox", iconName: "dosbox", isGUI: true),
        FeaturedApp(title: "XDemineur", blurb: "Classic mine-sweeping puzzle",
                    category: "Games", package: "xdemineur",
                    matchBin: "xdemineur", iconName: "xdemineur-icon", isGUI: true),
        FeaturedApp(title: "XEyes", blurb: "Eyes that follow your mouse",
                    category: "Utilities", package: "x11-apps",
                    matchBin: "xeyes", iconName: nil, isGUI: true),
        FeaturedApp(title: "XLogo", blurb: "X Window System logo demo",
                    category: "Utilities", package: "x11-apps",
                    matchBin: "xlogo", iconName: nil, isGUI: true),
        FeaturedApp(title: "Cowsay", blurb: "A talking cow in your terminal",
                    category: "Fun", package: "cowsay",
                    matchBin: "cowsay", iconName: nil, isGUI: false),
    ]

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
        xquartzMissing = !FileManager.default.isExecutableFile(
            atPath: "/opt/X11/bin/xdpyinfo")
        // sysroot scanning + state-sync spawn processes — keep off main.
        DispatchQueue.global(qos: .userInitiated).async {
            Self.syncState()
            var (gui, term) = Self.loadInstalled()
            // Stamp desktop icons (DB rows don't carry them).
            for root in Repo.sysroots {
                let icons = LinuxIcon.iconMap(sysroot: root)
                guard !icons.isEmpty else { continue }
                gui = gui.map {
                    var p = $0
                    if p.sysroot == root.lastPathComponent { p.iconPath = icons[p.binary] }
                    return p
                }
            }
            let names = Self.loadInstalledNames()
            let pkgs = Self.loadPackages(installedNames: names)
            DispatchQueue.main.async {
                self.guiPrograms = gui
                self.termPrograms = term
                self.packages = pkgs
            }
        }
    }

    /// Rebuild the install index (state.sqlite). Guest-side apt/dpkg
    /// changes arrive via the state-dirty marker the post-invoke hook
    /// drops; the script no-ops when nothing changed.
    nonisolated static func syncState() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = [Repo.stateSync.path]
        try? p.run()
        p.waitUntilExit()
    }

    nonisolated static func loadInstalledNames() -> Set<String> {
        if let data = pipeOut("/usr/bin/sqlite3", [Repo.stateDb.path,
                "SELECT name FROM packages WHERE sysroot='debian-expanded';"]),
           let text = String(data: data, encoding: .utf8), !text.isEmpty {
            return Set(text.split(separator: "\n").map(String.init))
        }
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
    /// hidden) or, in hand-built sysroots, a binary linked against
    /// graphics libraries; everything else in a bin dir is terminal.
    /// Scans every sysroot under runtime/sysroots — debian-expanded is
    /// dpkg-managed, the others (freeciv, debian-x11, debian-python) are
    /// scanned by bin-dir contents instead.
    nonisolated static func loadInstalled() -> ([InstalledProgram], [InstalledProgram]) {
        if let fromDb = loadInstalledDB() { return fromDb }
        let fm = FileManager.default
        let binDirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin",
                       "/usr/games", "/bin", "/sbin"]
        var gui: [InstalledProgram] = []
        var term: [InstalledProgram] = []

        for root in Repo.sysroots {
            let sname = root.lastPathComponent
            // .desktop files -> GUI set (binary -> display name)
            var guiBins: [String: String] = [:]
            let appsDir = root.appendingPathComponent("usr/share/applications")
            if let desks = try? fm.contentsOfDirectory(atPath: appsDir.path) {
                for file in desks where file.hasSuffix(".desktop") {
                    let url = appsDir.appendingPathComponent(file)
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
                    var tokens = exec.replacingOccurrences(of: "%[a-zA-Z]", with: "",
                                         options: .regularExpression)
                        .split(separator: " ").map(String.init)
                    while let first = tokens.first,
                          (first == "env" || first.contains("=") || first.hasPrefix("-")) {
                        tokens.removeFirst()
                    }
                    guard var bin = tokens.first else { continue }
                    if !bin.hasPrefix("/") {
                        let found = binDirs.first {
                            fm.isExecutableFile(atPath: root.path + $0 + "/" + bin)
                        }
                        guard let found else { continue }
                        bin = found + "/" + bin
                    }
                    guard fm.isExecutableFile(atPath: root.path + bin) else { continue }
                    guiBins[bin] = name.isEmpty
                        ? URL(fileURLWithPath: bin).lastPathComponent : name
                }
            }

            let info = root.appendingPathComponent("var/lib/dpkg/info")
            if let lists = try? fm.contentsOfDirectory(atPath: info.path) {
                // dpkg-managed sysroot: every packaged executable in a bin dir.
                for file in lists where file.hasSuffix(".list") {
                    let base = String(file.dropLast(5))
                    let pkg = base.components(separatedBy: ":").first ?? base
                    guard let text = try? String(
                        contentsOf: info.appendingPathComponent(file), encoding: .utf8)
                    else { continue }
                    for line in text.split(separator: "\n") {
                        let path = String(line)
                        guard binDirs.contains(where: { path.hasPrefix($0 + "/") }),
                              !path.hasSuffix("/"),
                              path.components(separatedBy: "/").count <= 4 else { continue }
                        let full = root.path + path
                        var isDir: ObjCBool = false
                        guard fm.fileExists(atPath: full, isDirectory: &isDir),
                              !isDir.boolValue, fm.isExecutableFile(atPath: full) else { continue }
                        if let display = guiBins[path] {
                            gui.append(InstalledProgram(name: display, binary: path,
                                                        package: pkg, sysroot: sname, isGUI: true))
                        } else {
                            term.append(InstalledProgram(
                                name: URL(fileURLWithPath: path).lastPathComponent,
                                binary: path, package: pkg, sysroot: sname, isGUI: false))
                        }
                    }
                }
            } else {
                // Hand-built sysroot: scan bin dirs directly; GUI if a
                // .desktop names it or it links graphics libraries.
                for dir in binDirs {
                    guard let items = try? fm.contentsOfDirectory(atPath: root.path + dir)
                    else { continue }
                    for item in items {
                        let path = dir + "/" + item
                        let full = root.path + path
                        var isDir: ObjCBool = false
                        guard fm.fileExists(atPath: full, isDirectory: &isDir),
                              !isDir.boolValue, fm.isExecutableFile(atPath: full) else { continue }
                        let display = guiBins[path]
                        let graphical = display != nil || looksGraphical(full)
                        let entry = InstalledProgram(
                            name: display ?? item, binary: path,
                            package: "", sysroot: sname, isGUI: graphical)
                        if graphical { gui.append(entry) } else { term.append(entry) }
                    }
                }
            }
        }
        return (gui.sorted { $0.name < $1.name }, term.sorted { $0.name < $1.name })
    }

    /// Read the program index built by state-sync.sh. nil when the DB is
    /// absent or empty so callers can fall back to scanning.
    nonisolated static func loadInstalledDB() -> ([InstalledProgram], [InstalledProgram])? {
        guard FileManager.default.fileExists(atPath: Repo.stateDb.path),
              let data = pipeOut("/usr/bin/sqlite3", [Repo.stateDb.path,
                  "SELECT sysroot,binary,name,kind,package FROM programs ORDER BY kind,name;"]),
              let text = String(data: data, encoding: .utf8),
              !text.isEmpty else { return nil }
        var gui: [InstalledProgram] = []
        var term: [InstalledProgram] = []
        for line in text.split(separator: "\n") {
            let f = line.split(separator: "|", omittingEmptySubsequences: false)
                .map(String.init)
            guard f.count >= 5 else { continue }
            let p = InstalledProgram(
                name: f[2].isEmpty ? URL(fileURLWithPath: f[1]).lastPathComponent : f[2],
                binary: f[1], package: f[4], sysroot: f[0], isGUI: f[3] == "gui")
            if p.isGUI { gui.append(p) } else { term.append(p) }
        }
        return (gui.isEmpty && term.isEmpty) ? nil : (gui, term)
    }

    /// True when an ELF links a graphics library (same list Launcher.swift
    /// uses). Uses llvm-objdump via xcrun when available.
    nonisolated static func looksGraphical(_ path: String) -> Bool {
        guard let data = pipeOut("/usr/bin/xcrun", ["llvm-objdump", "-p", path]),
              let text = String(data: data, encoding: .utf8) else { return false }
        let graphics = ["libX11", "libXaw", "libXt.", "libxcb", "libgtk", "libgdk",
                        "libQt", "libSDL", "libglfw", "libGL.", "libEGL", "libvulkan",
                        "libwayland-client"]
        return text.split(separator: "\n").contains { line in
            line.contains("NEEDED") && graphics.contains { line.contains($0) }
        }
    }

    /// Decompress an index file. .xz via xz/python3, .gz via gunzip,
    /// .lz4 via lz4 if present, uncompressed read directly.
    nonisolated static func decodeIndex(_ url: URL) -> Data? {
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

    nonisolated static func pipeOut(_ tool: String, _ args: [String], stdin: Data? = nil) -> Data? {
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

    nonisolated static func loadPackages(installedNames: Set<String>) -> [PackageEntry] {
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
        let root = Repo.sysroot(named: prog.sysroot).path
        let dpkg = root + "/usr/bin/dpkg"
        let rc = await run(Repo.oah.path,
                           ["--sysroot", root, dpkg, "-r", prog.package],
                           env: ["DEBIAN_FRONTEND": "noninteractive",
                                 "OAH_CACHE_DIR": Repo.root.path + "/runtime/var/cache/jit"],
                           title: "Removing \(prog.package)")
        if rc != 0 { alert = "Removal of \(prog.package) failed — see log."; return }
        _ = await run("/bin/sh", [Repo.syncer.path], title: "Refreshing launchers")
        reload()
    }

    func launch(_ prog: InstalledProgram) {
        // Launch feedback: emulated guests can take tens of seconds before
        // their first frame — show the overlay right away, then give it a
        // generous window before auto-dismissing.
        launching = prog.name
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 12_000_000_000)
            self?.launching = nil
        }
        do {
            if prog.isGUI { try launchGUI(prog) } else { try launchTerminal(prog) }
        } catch {
            launching = nil
            alert = error.localizedDescription
        }
    }

    /// Stop a guest process launched from this window.
    func quit(_ prog: InstalledProgram) {
        procs[prog.id]?.terminate()
    }

    /// Generate a double-clickable ~/Applications/<Name>.app that launches
    /// this program — the same pattern runtime-src/apps uses by hand.
    func createShortcut(_ prog: InstalledProgram) {
        do {
            let appsDir = URL(fileURLWithPath:
                NSHomeDirectory() + "/Applications", isDirectory: true)
            try FileManager.default.createDirectory(
                at: appsDir, withIntermediateDirectories: true)
            let bundle = appsDir.appendingPathComponent("\(prog.name).app")
            let contents = bundle.appendingPathComponent("Contents")
            try FileManager.default.createDirectory(
                at: contents.appendingPathComponent("MacOS"),
                withIntermediateDirectories: true)
            try FileManager.default.createDirectory(
                at: contents.appendingPathComponent("Resources"),
                withIntermediateDirectories: true)

            let plist: [String: Any] = [
                "CFBundleExecutable": "launch",
                "CFBundleIdentifier": "ai.attesor.shortcut.\(prog.id.hashValue)",
                "CFBundleName": prog.name,
                "CFBundlePackageType": "APPL",
                "CFBundleIconFile": "app",
                "LSMinimumSystemVersion": "12.0",
            ]
            try (plist as NSDictionary).write(
                to: contents.appendingPathComponent("Info.plist"))

            // Same environment as launchGUI, baked to absolute paths so
            // the bundle works from anywhere.
            let root = Repo.sysroot(named: prog.sysroot).path
            var exports = """
                  export XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
                  HOME="\(root)/root" LC_ALL=C DISPLAY=:0
                  export OAH_CACHE_DIR="\(Repo.root.path)/runtime/var/cache/jit"
                  export OAH_WORKER_JIT=1
                  export XFILESEARCHPATH="\(root)/etc/X11/app-defaults/%N"
                """
            if prog.sysroot == "freeciv" {
                exports += "\n  export OAH_DISABLE_AUDIO=1 FREECIV_DATA_PATH=\"\(root)/usr/share/games/freeciv-attesor\""
                exports += "\n  export SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software SDL_AUDIODRIVER=alsa"
            }
            let script = """
                #!/bin/sh
                set -eu
                \(exports)
                mkdir -p "\(root)/root" "$OAH_CACHE_DIR" \
                    "\(Repo.root.path)/runtime/var/log"
                exec >>"\(Repo.root.path)/runtime/var/log/\(prog.name).log" 2>&1
                if ! /opt/X11/bin/xdpyinfo -display :0 >/dev/null 2>&1; then
                    /usr/bin/open -a XQuartz || true
                    attempts=0
                    until /opt/X11/bin/xdpyinfo -display :0 >/dev/null 2>&1; do
                        attempts=$((attempts + 1))
                        [ "$attempts" -lt 30 ] || exit 1
                        /bin/sleep 1
                    done
                fi
                exec "\(Repo.oah.path)" --max-insns 18446744073709551615 \
                    --sysroot "\(root)" "\(root)\(prog.binary)"
                """
            let launch = contents.appendingPathComponent("MacOS/launch")
            try script.write(to: launch, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o755], ofItemAtPath: launch.path)

            // App icon: the program's own icon as .icns when we have a
            // PNG, else the Tux default.
            let icns = contents.appendingPathComponent("Resources/app.icns")
            var made = false
            if let iconPath = prog.iconPath, iconPath.hasSuffix(".png") {
                let set = (NSTemporaryDirectory() as NSString)
                    .appendingPathComponent("attesor.iconset")
                try? FileManager.default.removeItem(atPath: set)
                try? FileManager.default.createDirectory(
                    atPath: set, withIntermediateDirectories: true)
                let link = set + "/icon_128x128.png"
                try? FileManager.default.copyItem(atPath: iconPath, toPath: link)
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
                p.arguments = ["-c", "icns", set, "-o", icns.path]
                try? p.run(); p.waitUntilExit()
                made = p.terminationStatus == 0 &&
                    FileManager.default.fileExists(atPath: icns.path)
            }
            if !made, let penguin = Bundle.main.path(forResource: "Penguin", ofType: "icns")
                       ?? Optional(Repo.root.path + "/runtime/icons/Penguin.icns") {
                try? FileManager.default.copyItem(atPath: penguin, toPath: icns.path)
            }
            NSWorkspace.shared.activateFileViewerSelecting([bundle])
            alert = "Created \(prog.name).app in ~/Applications — pin it to the Dock if you like."
        } catch {
            alert = "Couldn't create shortcut: \(error.localizedDescription)"
        }
    }

    /// Launch an arbitrary downloaded x86-64 ELF via an open panel —
    /// the same job the standalone Launcher app does.
    func openFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose an x86-64 Linux executable"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // Reuse the standalone Launcher's richer detection by delegating —
        // it owns ELF classification, mode choice and history.
        let launcher = Repo.root.path +
            "/runtime/Apps/Attesor Linux Launcher.app"
        guard FileManager.default.fileExists(atPath: launcher) else {
            alert = "The Attesor Linux Launcher app is missing — rebuild the app bundles."
            return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-a", launcher, url.path]
        try? p.run()
    }

    private func launchGUI(_ prog: InstalledProgram) throws {
        var env = ProcessInfo.processInfo.environment
        env["LC_ALL"] = "C"
        env["HOME"] = "/root"
        env["XAUTHORITY"] = NSHomeDirectory() + "/.Xauthority"
        env["DISPLAY"] = ":0"
        env["OAH_CACHE_DIR"] = Repo.root.path + "/runtime/var/cache/jit"
        // Guest worker threads (SDL audio/hotplug) run on the cached JIT
        // instead of the interpreter — much shorter guest_lock holds.
        env["OAH_WORKER_JIT"] = "1"
        if prog.sysroot == "freeciv" {
            // SDL's audio pump is CPU-bound guest code that contends
            // guest_lock with the UI thread; drop the emulated sound
            // device so freeciv runs silent and fast.
            env["OAH_DISABLE_AUDIO"] = "1"
        }
        env["XFILESEARCHPATH"] = Repo.sysroot(named: prog.sysroot).path + "/etc/X11/app-defaults/%N"
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
        let root = Repo.sysroot(named: prog.sysroot).path
        // HOME=/root points into the sysroot; ensure it exists so guests
        // doing level-by-level mkdir (freeciv's saves dir) succeed.
        try? FileManager.default.createDirectory(atPath: root + "/root",
                                                 withIntermediateDirectories: true)
        p.arguments = ["--sysroot", root, root + prog.binary]
        p.environment = env
        // Keep guest stdout/stderr: diagnosing launch/server failures is
        // impossible when output goes to /dev/null.
        let logDir = Repo.root.path + "/runtime/var/log"
        try? FileManager.default.createDirectory(atPath: logDir,
                                                 withIntermediateDirectories: true)
        let logPath = logDir + "/\(prog.name).log"
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil)
        }
        if let handle = try? FileHandle(forWritingTo: URL(fileURLWithPath: logPath)) {
            handle.truncateFile(atOffset: 0)
            p.standardOutput = handle
            p.standardError = handle
        }
        let id = prog.id
        p.terminationHandler = { _ in
            Task { @MainActor in
                self.procs.removeValue(forKey: id)
                self.running.remove(id)
            }
        }
        try p.run()
        procs[id] = p
        running.insert(id)
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
            export OAH_CACHE_DIR="\(Repo.root.path)/runtime/var/cache/jit" LC_ALL=C \
                XAUTHORITY="$HOME/.Xauthority" HOME=/root OAH_WORKER_JIT=1
            mkdir -p "\(Repo.sysroot(named: prog.sysroot).path)/root" \
                "\(Repo.root.path)/runtime/var/log"
            exec "\(Repo.oah.path)" --sysroot "\(Repo.sysroot(named: prog.sysroot).path)" \
                "\(Repo.sysroot(named: prog.sysroot).path)\(prog.binary)"
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
    let isRunning: Bool
    let onLaunch: () -> Void
    let onQuit: () -> Void
    let onRemove: () -> Void
    let onShortcut: () -> Void
    var body: some View {
        HStack(spacing: 10) {
            Image(nsImage: LinuxIcon.image(for: prog))
                .resizable()
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(prog.name).font(.body)
                Text(prog.package.isEmpty ? "Linux app" : "From \(prog.package)")
                    .font(.caption).foregroundStyle(.secondary)
                    .help(prog.binary)
            }
            if isRunning {
                Label("Running", systemImage: "circle.fill")
                    .font(.caption).foregroundStyle(.green)
            }
            Spacer()
            if isRunning {
                Button("Quit", action: onQuit).buttonStyle(.bordered)
                    .controlSize(.small)
            }
            Button("Launch", action: onLaunch).buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(isRunning)
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Launch", action: onLaunch)
            Button("Add to Applications Folder…", action: onShortcut)
            if !prog.package.isEmpty {
                Divider()
                Button("Remove \(prog.package)…", role: .destructive, action: onRemove)
            }
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

struct XQuartzBanner: View {
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            VStack(alignment: .leading, spacing: 2) {
                Text("XQuartz needed for graphical apps")
                    .font(.callout).bold()
                Text("One-time install — graphical Linux apps open through it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Get XQuartz") {
                NSWorkspace.shared.open(URL(string: "https://www.xquartz.org")!)
            }
            .buttonStyle(.borderedProminent).controlSize(.small)
        }
        .padding(10)
        .background(Color.yellow.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct InstalledView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        List {
            if state.xquartzMissing {
                Section { XQuartzBanner() }
                    .listRowSeparator(.hidden)
            }
            Section {
                if state.guiPrograms.isEmpty {
                    Text("No graphical applications installed yet.")
                        .foregroundStyle(.secondary)
                }
                ForEach(state.guiPrograms) { prog in
                    ProgramRow(prog: prog,
                               isRunning: state.running.contains(prog.id),
                               onLaunch: { state.launch(prog) },
                               onQuit: { state.quit(prog) },
                               onRemove: { Task { await state.uninstall(prog) } },
                               onShortcut: { state.createShortcut(prog) })
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
                               isRunning: false,
                               onLaunch: { state.launch(prog) },
                               onQuit: {},
                               onRemove: { Task { await state.uninstall(prog) } },
                               onShortcut: { state.createShortcut(prog) })
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

/// A curated card on the Featured page: icon, blurb, Install or Launch.
struct FeaturedCard: View {
    @EnvironmentObject var state: AppState
    let app: FeaturedApp
    var installedProg: InstalledProgram?
    var pkg: PackageEntry?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                if let installedProg {
                    Image(nsImage: LinuxIcon.image(for: installedProg, size: 40))
                        .resizable().frame(width: 40, height: 40)
                } else {
                    Image(systemName: app.isGUI ? "desktopcomputer" : "terminal")
                        .font(.system(size: 28))
                        .foregroundStyle(.secondary)
                        .frame(width: 40, height: 40)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.title).font(.headline)
                    Text(app.category).font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15))
                        .clipShape(Capsule())
                }
                Spacer()
            }
            Text(app.blurb).font(.caption).foregroundStyle(.secondary)
                .lineLimit(2)
            Spacer(minLength: 0)
            HStack {
                if let installedProg {
                    Label("Installed", systemImage: "checkmark.circle.fill")
                        .font(.caption).foregroundStyle(.green)
                    Spacer()
                    Button("Launch") { state.launch(installedProg) }
                        .buttonStyle(.borderedProminent).controlSize(.small)
                } else if let pkg, !pkg.installed {
                    Button("Install") { Task { await state.install(pkg) } }
                        .buttonStyle(.borderedProminent).controlSize(.small)
                        .disabled(state.busy)
                } else if pkg != nil {
                    Label("Installed", systemImage: "checkmark.circle.fill")
                        .font(.caption).foregroundStyle(.green)
                } else {
                    Text("Refresh the package index to install")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct FeaturedView: View {
    @EnvironmentObject var state: AppState
    /// Match a featured entry to a live installed program by binary name.
    func match(_ app: FeaturedApp) -> InstalledProgram? {
        (state.guiPrograms + state.termPrograms).first {
            $0.binary.contains(app.matchBin)
        }
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if state.xquartzMissing { XQuartzBanner() }
                Text("Featured").font(.title2).bold()
                Text("Hand-picked apps known to run well. One click installs; "
                     + "the Launch button appears once they're on your Mac.")
                    .font(.callout).foregroundStyle(.secondary)
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())],
                          spacing: 12) {
                    ForEach(AppState.featured) { app in
                        FeaturedCard(app: app,
                                     installedProg: match(app),
                                     pkg: state.packages.first { $0.name == app.package })
                    }
                }
                Divider()
                Text("Looking for something else? The full Debian catalog is "
                     + "under “All Packages” in the sidebar.")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            .padding(20)
        }
        .navigationTitle("Attesor")
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

/// Floating "Starting <app>…" card — emulated guests can take tens of
/// seconds to first paint, so silent launches read as "broken".
struct LaunchOverlay: View {
    let name: String
    var body: some View {
        VStack(spacing: 10) {
            ProgressView().controlSize(.large)
            Text("Starting \(name)…").font(.headline)
            Text("First launches translate code — this can take a minute.")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(minWidth: 260)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .shadow(radius: 20)
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState
    @State private var selection: String? = "featured"
    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Featured", systemImage: "star").tag("featured")
                Label("Applications", systemImage: "square.grid.2x2").tag("apps")
                Label("All Packages", systemImage: "shippingbox").tag("browse")
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            VStack(spacing: 0) {
                Group {
                    if selection == "browse" { BrowseView() }
                    else if selection == "apps" { InstalledView() }
                    else { FeaturedView() }
                }
                Divider()
                LogView()
            }
        }
        .toolbar {
            ToolbarItem {
                Button { state.openFile() } label: {
                    Label("Open File…", systemImage: "doc.badge.plus")
                }
                .help("Run a downloaded x86-64 Linux executable")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await state.refreshIndex() }
                } label: {
                    Label("Refresh Index", systemImage: "arrow.clockwise")
                }
                .disabled(state.busy)
            }
        }
        .overlay {
            if let name = state.launching {
                LaunchOverlay(name: name)
            }
        }
        .alert("Attesor", isPresented: .constant(state.alert != nil)) {
            Button("OK") { state.alert = nil }
        } message: {
            Text(state.alert ?? "")
        }
    }
}

/// First-run screen: downloads the Linux runtime into Application
/// Support so the app itself stays a thin bundle.
struct SetupView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        VStack(spacing: 18) {
            if let tux = LinuxIcon.penguin {
                Image(nsImage: tux).resizable().frame(width: 96, height: 96)
            }
            Text("Welcome to Attesor").font(.largeTitle).bold()
            Text("Attesor runs x86-64 Linux programs on your Mac.\n"
                 + "First launch downloads the Linux runtime (~350 MB) — "
                 + "this happens once.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            switch state.setup {
            case .needed:
                Button("Download & Set Up") { state.beginSetup() }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                if state.xquartzMissing {
                    Text("Tip: graphical apps need XQuartz — install it with "
                         + "“brew install --cask xquartz” anytime.")
                        .font(.caption).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            case .downloading(let frac):
                if frac >= 0 {
                    ProgressView(value: frac) {
                        Text("Downloading runtime… \(Int(frac * 100))%")
                    }
                } else {
                    ProgressView { Text("Downloading runtime…") }
                }
            case .extracting:
                ProgressView { Text("Unpacking…") }
            case .failed(let msg):
                Label(msg, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red).font(.callout)
                    .multilineTextAlignment(.center)
                Button("Try Again") { state.beginSetup() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

@main
struct AttesorPackageManager: App {
    @StateObject private var state = AppState()
    var body: some Scene {
        WindowGroup {
            Group {
                if Repo.payloadPresent {
                    RootView()
                } else {
                    SetupView()
                }
            }
            .environmentObject(state)
            .frame(minWidth: 640, minHeight: 480)
            .onAppear { state.reload() }
            // Picks up guest-side apt/dpkg installs made in the shell.
            .onReceive(NotificationCenter.default.publisher(
                for: NSApplication.didBecomeActiveNotification)) { _ in
                state.reload()
            }
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 780, height: 560)
    }
}
