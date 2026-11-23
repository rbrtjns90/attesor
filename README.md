# Attesor

Attesor translates x86-64 Linux userspace programs for ARM64 Linux and Apple Silicon macOS. The maintained reconstruction runs the tested static ELF, musl-linked, and Debian glibc-linked programs. The macOS build runs directly from Terminal.

This project is a maintained continuation of [Inokinoki/attesor](https://github.com/Inokinoki/attesor), the original x86-64 → ARM64 translator research by [@Inokinoki](https://github.com/Inokinoki). This fork adds a persistent JIT fragment cache, guest threading and scheduler fairness, Debian `apt`/`dpkg` support with a writable sysroot, SDL2/X11 graphics via XQuartz, and a native macOS app for installing and launching Linux programs.

## Install on your Mac

Requires an Apple Silicon Mac. Graphical Linux apps need XQuartz.

**Homebrew (recommended)** — pulls in XQuartz automatically:

```sh
brew install --cask rbrtjns90/tap/attesor
```

**One-liner** — installs XQuartz via Homebrew, then the app from GitHub Releases:

```sh
curl -fsSL https://raw.githubusercontent.com/rbrtjns90/attesor/main/runtime-src/install.sh | bash
```

**Manual** — `brew install --cask xquartz`, then download `Attesor-<ver>.dmg` from [the latest release](https://github.com/rbrtjns90/attesor/releases/latest) and drag Attesor to Applications.

On first launch the app downloads the Linux runtime (~370 MB) into `~/Library/Application Support/Attesor/` — everything works offline after that. The package manager ships a Debian userland (guest `apt` works), Freeciv, DOSBox, and one-click installs for more programs. If Gatekeeper blocks the unsigned app, right-click → Open once.

![Attesor Package Manager](docs/screenshots/package-manager.png)

![Freeciv, DOSBox, xcalc, xdemineur, xeyes running through Attesor](docs/screenshots/apps-running.png)

## Build and test

On Linux or macOS with a C compiler, Make, and Python 3:

```sh
make
make test
```

The default build produces `reconstruct/oah`. Dynamic executables use an x86-64 library sysroot supplied with `--sysroot`. The [build and compatibility guide](reconstruct/README.md) documents the Alpine and Debian tests, required fixtures, and current limitations.

## Repository layout

| Path | Contents |
| --- | --- |
| [`reconstruct/`](reconstruct/README.md) | Maintained loader, translator, Linux syscall bridge, tests, and inventory tools |
| [`research/decompilation/`](research/decompilation/) | Archived RosettaLinux and daemon Ghidra exports |
| [`research/ghidra/`](research/ghidra/) | Historical scripts used to export decompiler output |
| [`legacy/translator/`](legacy/translator/) | Earlier translator rewrite, build files, test programs, and prebuilt artifacts |
| [`legacy/docs/`](legacy/docs/README.md) | Original project overview, guides, and [iteration reports](legacy/docs/iterations/) |

To reproduce the research inventory from the archived export, run `make inventory`. Historical translator commands use `legacy/translator/` as their working directory.
