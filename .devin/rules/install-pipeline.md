# Attesor — agent notes

## Install pipeline: native macOS tools only

User preference (persistent): when installing Debian packages into the
sysroot, use the **native macOS install pipeline** — never the guest
`apt-get` under the translator for dependency resolution.

- `runtime-src/apt-install.sh <pkgs>` is the entry point (what
  PackageManager.app shells out to). It resolves dependencies **host-side**
  via `runtime-src/native-resolve.py` (parses `var/lib/apt/lists/*Packages*`
  + `var/lib/dpkg/status` + `etc/apt` sources), downloads `.deb`s with curl,
  unpacks with `native-deb-install.sh` (`ar`/`tar`), then runs
  `dpkg --configure -a` under the translator only for maintainer scripts.
- `OAH_GUEST_RESOLVE=1` opts back into translated `apt-get --print-uris`
  for debugging only — it takes minutes vs. instant native resolution.
- `runtime-src/apt-update.sh` refreshes the index natively (fetch +
  guest `gpgv` verify only).
- After installs: `state-sync.sh` + `sync-programs.sh` regenerate
  `~/Desktop/linux_progs/{terminal,gui}` launchers. Per-app GUI args live in
  a table in `sync-programs.sh` (e.g. `xgalaga → -window`).

## Testing GUI apps

XQuartz on `:0`; run guests as:

    reconstruct/oah --sysroot runtime/sysroots/debian-expanded \
        runtime/sysroots/debian-expanded/usr/games/<app>

with `DISPLAY=:0`, `HOME=/root`, `LC_ALL=C`, `OAH_SYSROOT_STRICT=1`.
Smoke test = short `timeout` run; watch for `jit stop`/`guest stopped`.
Fullscreen apps that need XF86VidMode (e.g. xgalaga) fail on XQuartz —
prefer windowed flags rather than treating it as an emulator bug.

## Verification

`make -C reconstruct test-macos` — 96 checks including the differential
JIT/interp suite (`diff_guest`). Run it after any translator change.
