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

## Future work

- GUI package manager app: browse/search the Debian archive (official
  sources via `debian.sources`, optionally Ubuntu repos), manage an
  install list, and drive `apt install` into the unified sysroot.
- apt `DPkg::Post-Invoke` cleanup hook reports a subprocess-status error
  although the `rm -f` it runs succeeds; worth a proper fix.
