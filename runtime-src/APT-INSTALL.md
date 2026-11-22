# Installing Debian packages into the Attesor sysroot

The easiest entry point for non-technical users is the **Attesor Package
Manager** app (`runtime/Apps/Attesor Package Manager.app`, built by
`assemble.sh` from `PackageManager.swift`). It shows installed programs in
clearly labelled *GUI Applications* / *Terminal Programs* sections with
one-click Launch buttons, plus a searchable *Browse Packages* view with
Install buttons — all backed by the native pipeline below.

Debian `apt` is the default package manager. There are two ways to use it;
the second is much faster because it moves the two slow translated phases
(apt's HTTP event loop and dpkg-deb/xz decompression) into native macOS
code.

All packages land in the unified sysroot:

    runtime/sysroots/debian-expanded/

## Quick path: `apt-install.sh`

From a macOS terminal (not the Debian shell):

```sh
runtime-src/apt-install.sh <package> [<package>...]
```

Example:

```sh
runtime-src/apt-install.sh hello
```

Options:

| Flag | Meaning |
|---|---|
| `-u`, `--update` | refresh the package index first via `apt-update.sh` — needed when the index is stale or empty |
| `-f`, `--force` | reinstall packages already marked installed (repair mode) |

### Refreshing the index: `apt-update.sh`

```sh
runtime-src/apt-update.sh
```

This is a native replacement for translated `apt-get update`. For every
entry in `/etc/apt/sources.list` and `sources.list.d/` (both legacy
`deb ...` lines and deb822 `*.sources` files), it:

1. fetches `dists/<suite>/InRelease` (or `Release` + `Release.gpg`)
2. verifies the signature with the **guest** `gpgv` under the translator
   and the repo's `Signed-By` keyring — a tiny file, so fast even
   translated; falls back to checksum-only with a warning if gpgv or the
   keyring is missing
3. reads the Release's SHA256 table and downloads each component's
   `Packages` index (preferring `.lz4`, falling back to `.xz`/`.gz`) plus
   `Translation-en`, verifying size and sha256
4. installs files into `var/lib/apt/lists/` under the same mangled names
   apt itself uses, retiring stale compressions of the same index
5. drops `pkgcache.bin`/`srcpkgcache.bin` so apt regenerates them

### What the install script does

1. Runs `apt-get install --print-uris -y <pkgs>` under the translator —
   apt's solver resolves the full dependency set and prints the exact
   `.deb` URLs, but downloads nothing.
2. Fetches those URLs with native `curl` (full link speed; 85 base
   packages ≈31 MB took seconds).
3. Runs `runtime-src/native-deb-install.sh`, which unpacks each `.deb`
   into the sysroot with native `ar`/`tar`, writes the dpkg metadata
   (`info/<pkg>.list`, `.md5sums`, `.conffiles`, maintainer scripts), and
   finishes with `dpkg --configure -a` under the translator so maintainer
   scripts execute as Linux code with `DEBIAN_FRONTEND=noninteractive`.

## Slow path: plain `apt` inside the Debian shell

Double-click `~/Desktop/linux_progs/terminal/Debian Shell.command`, then:

```sh
apt update
apt install <package>
```

This is real Debian `apt` running under the translator. It works
end-to-end, but translated HTTP runs ~600 KB/s and unpack is also
translated, so large packages take minutes and occasionally hit the
intermittent decompressor crash. The native path (`apt-update.sh` +
`apt-install.sh`) is preferred for everything.

## After installing

- Binaries land under the sysroot (`usr/bin`, `usr/games`, ...). GUI and
  terminal launchers are synced into `~/Desktop/linux_progs/` by
  `runtime-src/sync-programs.sh`.
- To run a program directly:

  ```sh
  A=/Users/rob/Documents/GitHub/attesor
  S="$A/runtime/sysroots/debian-expanded"
  OAH_CACHE_DIR="$A/runtime/var/cache/jit" \
      "$A/reconstruct/oah" --sysroot "$S" "$S/usr/bin/<program>"
  ```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `apt` says package not found | run `apt-install.sh -u <pkg>` or `apt-update.sh` to refresh the index |
| package marked installed but files missing | `apt-install.sh -f <pkg>` |
| `dpkg` errors at configure time | run `dpkg --configure -a` in the Debian shell, then retry |
| `--print-uris` prints nothing for a needed package | the archive may already sit in `var/cache/apt/archives/`; remove it or pass `-f` |
| `E: Can not write log (Is /dev/pts mounted?)` | harmless warning; install still proceeds |

## Known gaps

- Some maintainer scripts assume a running system (init, udev, D-Bus).
  Most degrade gracefully under `DEBIAN_FRONTEND=noninteractive`; ones
  that don't usually leave the package half-configured — fix the
  underlying cause and re-run `dpkg --configure -a`.
