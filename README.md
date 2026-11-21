# Attesor

Attesor translates x86-64 Linux userspace programs for ARM64 Linux and Apple Silicon macOS. The maintained reconstruction runs the tested static ELF, musl-linked, and Debian glibc-linked programs. The macOS build runs directly from Terminal.

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
