# Installing Debian packages into the Attesor sysroot

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
| `-u`, `--update` | run `apt-get update` in the guest first — needed when the package index is stale or empty |
| `-f`, `--force` | reinstall packages already marked installed (repair mode) |

### What the script does

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
intermittent decompressor crash. Use it when the native path misbehaves;
it is also the only way `apt update` currently works (there is no native
index fetcher yet).

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
| `apt` says package not found | run `apt-install.sh -u <pkg>` (or `apt update` in the Debian shell) to refresh the index |
| package marked installed but files missing | `apt-install.sh -f <pkg>` |
| `dpkg` errors at configure time | run `dpkg --configure -a` in the Debian shell, then retry |
| `--print-uris` prints nothing for a needed package | the archive may already sit in `var/cache/apt/archives/`; remove it or pass `-f` |
| `E: Can not write log (Is /dev/pts mounted?)` | harmless warning; install still proceeds |

## Known gaps

- `apt-get update` is still translated — the index files are small enough
  to tolerate it, but a native index fetcher is future work (it would
  belong in the planned GUI package manager).
- Some maintainer scripts assume a running system (init, udev, D-Bus).
  Most degrade gracefully under `DEBIAN_FRONTEND=noninteractive`; ones
  that don't usually leave the package half-configured — fix the
  underlying cause and re-run `dpkg --configure -a`.
