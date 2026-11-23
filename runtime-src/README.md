# runtime-src

Tracked sources for the macOS runtime tree. `runtime/` itself is
git-ignored (downloaded sysroots, caches, logs); everything needed to
rebuild the app bundles lives here.

- `Launcher.swift` — the "Attesor Linux Launcher" Finder app (compiled
  with `swiftc` into `Attesor Linux Launcher.app`).
- `icons/draw.swift` — generates `Penguin.icns`.
- `apps/<Name>/` — `Info.plist` + `launch` script for each script-driven
  bundle (Debian Calculator/Clock/Eyes/X Logo, Freeciv via Attesor).
- `assemble.sh` — builds `oah`, compiles the launcher, generates the
  icon, writes `runtime/Apps/*.app`, copies `sync-programs.sh` into
  `runtime/`, then verifies expected guest payloads exist.
- `sync-programs.sh` — regenerates `~/Desktop/linux_progs/{terminal,gui}`
  `.command` launchers from the sysroot's dpkg database. A packaged
  executable is GUI when a `.desktop` file launches it (and
  `Terminal=true` is not set); everything else is terminal. Only
  launchers carrying the `# Attesor generated:` marker are refreshed —
  hand-made ones are untouched. The Launcher app's Apps menu exposes it
  as "Refresh Program Shortcuts".

Payloads NOT tracked (download locally): `runtime/sysroots/*`
(debian-expanded, debian-python, debian-x11, freeciv incl. the
freeciv-attesor data dir), `runtime/var/*` (jit cache, freeciv home,
launcher history).

Run: `./runtime-src/assemble.sh` from a fresh checkout after fetching
the sysroots.

## Installing programs (apt)

`debian-expanded` is the unified writable sysroot: guest FHS paths
(`/usr`, `/etc`, `/var`, ...) resolve inside it for reads (host fallback)
and all writes land in it. Inside the Debian Shell:

    apt update            # refresh indexes (bookworm + updates + security)
    apt install man-db    # resolves deps, unpacks, runs maintainer scripts

Then refresh the Desktop shortcuts so new executables appear:

    runtime/sync-programs.sh          # or: Launcher menu → Refresh Program Shortcuts

## Installing Attesor (end users)

Homebrew (pulls in XQuartz automatically):

    brew install --cask rbrtjns90/tap/attesor

Or the one-liner — installs XQuartz via Homebrew, then the app from
GitHub Releases:

    curl -fsSL https://raw.githubusercontent.com/rbrtjns90/attesor/main/runtime-src/install.sh | bash

Or manually:

    brew install --cask xquartz        # needed for graphical Linux apps
    # download Attesor-<ver>.dmg from
    # https://github.com/rbrtjns90/attesor/releases/latest
    # drag Attesor.app to Applications

On first launch `Attesor.app` downloads the Linux runtime
(`attesor-runtime.tar.xz`, ~350 MB) into
`~/Library/Application Support/Attesor/` — the app itself stays thin.
The downloaded tree is repo-shaped (`reconstruct/`, `runtime/`,
`runtime-src/`) so every script and bundle resolves paths the same way
as a dev checkout; `Repo.root` prefers the Application Support copy.

Homebrew cask: `Casks/attesor.rb` — the canonical copy lives in the tap
repo `rbrtjns90/homebrew-tap`; this one is the template. It declares
the xquartz dependency and `zap`s the runtime data on uninstall.

## Cutting a release

    runtime-src/release.sh v0.1.0

Builds in `dist/v0.1.0/`:

- `Attesor-v0.1.0.dmg` — drag-to-Applications thin app
- `attesor-runtime-v0.1.0.tar.xz` + `attesor-runtime.tar.xz` — payload;
  the un-versioned copy is what the app fetches via
  `releases/latest/download/attesor-runtime.tar.xz`
- `SHA256SUMS`

Upload all to a GitHub Release tagged `v0.1.0`. Override the download
URL for testing with `ATTESOR_RUNTIME_URL` (file:// works too).

## Future work

- GUI package manager app: browse/search the Debian archive (official
  sources via `debian.sources`, optionally Ubuntu repos), manage an
  install list, and drive `apt install` into the unified sysroot.
- apt `DPkg::Post-Invoke` cleanup hook reports a subprocess-status error
  although the `rm -f` it runs succeeds; worth a proper fix.
