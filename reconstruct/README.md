# Reconstruction from RosettaLinux decompilation

This tree is a **from-scratch, evidence-based reconstruction** of Apple's
`RosettaLinux/rosetta` translator. It does **not** continue the earlier
`rosetta_*.c` rewrite (that tree mixed guessed names with empty tests).

Sources of truth, in order:

1. The original ELF (optional, gitignored): drop it at `bin/rosetta`
2. `../rosetta_decomp.c` (Ghidra dump of that ELF)

Do **not** commit the binary. `make inventory-binary` regenerates
`inventory/from_binary/` from it.

## Method

1. Extract original C++ file/function names from assertion strings.
2. Reconstruct only what the dump **or the ELF** actually supports
   (encodings, asserts, string literals, rodata tables, `movz x8,#NR`).
3. Mark every function with:
   - `decomp:` Ghidra `FUN_*` address
   - `orig:` `file:line:name` when an assert names it
   - confidence: `high` (bits/strings copied) / `derived` (inferred)
4. Tests must fail if the reconstructed behavior is wrong. Printing an
   expected encoding and calling `PASS` is not a test.
5. Tests must pass **without** the ELF in CI. `tests/test_binary` memcmps
   tables against `bin/rosetta` when that file is present, and skips
   otherwise.

## Layout

```
reconstruct/
  bin/           optional original ELF (gitignored)
  oah            new host executable (make oah)
  oah-aarch64    same program, cross-built for qemu-user (make oah-aarch64)
  inventory/     Layer 0 — maps from the dump and, when present, the ELF
  include/oah/   Public headers
  src/           Readable C, layered
  tests/         Behavioral tests
  tools/         Extraction scripts
```

## Layers (this PR)

| Layer | What | Why this first |
|-------|------|----------------|
| 0 | Source-file / function inventory | Names come from the binary, not guesses |
| 1 | Types, Register, syscall `Result`, AssemblerBuffer | Small, fully constrained |
| 2 | ARM64 emitters named by `AssemblerBase.hpp` | Opcode bits are in the dump |
| 3 | Linux ABI: `/proc` paths, open flags, fake cpuinfo | Format strings + path compares |
| 4 | Flags (x86 RFLAGS ↔ NZCV), condition codes, x86 decoder `read_int` | Bit copies + 15-byte insn limit |
| 5 | ELF rodata/text: CC table, `register_to_string`, host syscall NRs | Ghidra collapsed `svc` immediates |
| 6 | New ELF `oah`: map x86_64 guest, **x86→ARM translate**, runtime syscall shuffle | First runnable equivalent |
| 7 | Native RX jump + **qemu-user** (`oah-aarch64`) | Prove the emitted ARM is real, not only a C interpreter |

`oah` loads an x86-64 Linux ELF and executes it on Linux. Fixed-address guests retain their linked addresses. Static PIE guests are slid as one image and handle their own relocations. Startup supplies an aligned stack with arguments, environment, and auxiliary vector entries.

### Execution paths

On ARM64 Linux the runner executes translated AArch64 fragments in an RX mapping. `--interpret` runs those fragments in the ARM interpreter instead. Both paths execute instructions that need guest memory, flags, TLS, or SIMD state through the same checked x86 interpreter, and both route guest syscalls through the same Linux ABI bridge. Guest calls and returns use the guest stack. Unknown syscalls return `ENOSYS`. Set `OAH_TRACE_UNSUPPORTED=1` to print their numbers and guest addresses.

The runner supports the tested single-process static, musl-linked, and Debian glibc-linked Linux tools. Dynamically linked programs require a guest x86-64 sysroot. Attesor maps the ELF interpreter and transfers control to it with the executable’s auxiliary vector. The guest loader performs relocation and opens its own shared objects. Guest memory syscalls cover the tested anonymous and private file-backed mappings, including loader replacements within guest-owned file reservations. File-backed mappings are copied into anonymous storage. Threads, asynchronous host signal delivery, broader glibc workloads, and complete x86 floating-point and SIMD coverage remain future work. This runner is intended for trusted test executables.

## Build and verify

Needs: `gcc`, `make`, `python3`. Optional original ELF is **not** required.

### 1. Interpreter path (any x86_64 or aarch64 Linux host)

From the repository root:

```sh
make -C reconstruct test
./reconstruct/oah reconstruct/tests/hello.x86_64
echo "exit=$?"
```

Expect every `tests/test_*` line to print `<suite>: N checks passed` (non-zero `N`), then:

```
== oah tests/hello.x86_64
```

and the second command prints `hello` and `exit=0`. `tests/test_arm_native` on x86_64 only checks that native exec is stubbed (`OAH_INTERP_DECODE`); it does not jump ARM.

On failure, `make test` exits 1 and prints `FAIL …` from `tests/test_common.h`.

### 2. Native ARM via qemu-user (x86_64 host)

Debian / Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y qemu-user-static gcc-aarch64-linux-gnu libc6-dev-arm64-cross
```

Confirm the tools:

```sh
qemu-aarch64-static --version | head -1
aarch64-linux-gnu-gcc --version | head -1
```

Then:

```sh
make -C reconstruct test-qemu
```

That target:

1. Cross-compiles `reconstruct/oah-aarch64` and `reconstruct/tests/test_arm_native-aarch64` (static, load address `0x2000000000`).
2. Runs the trampoline test under qemu (`movz x8,#42; ret` must come back with `x8==42`).
3. Runs `qemu-aarch64-static ./oah-aarch64 tests/hello.x86_64` and requires stdout to be exactly `hello\n`.

Expected:

```
== qemu qemu-aarch64-static tests/test_arm_native-aarch64
arm_native: 5 checks passed
== qemu qemu-aarch64-static oah-aarch64 tests/hello.x86_64
```

The second recipe writes `reconstruct/tests/hello.qemu.got`. Check it yourself:

```sh
od -c reconstruct/tests/hello.qemu.got
# 0000000   h   e   l   l   o  \n
```

### 3. Prove the qemu binary is ARM, not the host interpreter

```sh
file reconstruct/oah-aarch64
readelf -l reconstruct/oah-aarch64 | head -16
```

Expect `ELF 64-bit LSB executable, ARM aarch64`, statically linked, and a `LOAD` `VirtAddr` of `0x0000002000000000`.

Manual equivalent of `test-qemu` (after `make -C reconstruct oah-aarch64 tests/hello.x86_64`):

```sh
qemu-aarch64-static ./reconstruct/oah-aarch64 ./reconstruct/tests/hello.x86_64
# hello
```

Override tools if they are not on `PATH` under the default names:

```sh
make -C reconstruct test-qemu \
    CC_AARCH64=aarch64-linux-gnu-gcc \
    QEMU_AARCH64=qemu-aarch64-static
```

### 4. Native aarch64 host (no qemu)

On Linux aarch64, host `cc` already targets ARM64, so `make -C reconstruct test` runs `tests/test_arm_native` for real (5 checks: `x8` becomes 42, `x0` is preserved). `./reconstruct/oah reconstruct/tests/hello.x86_64` uses `oah_jit_run_native` with `blr` for translated fragments and the shared guest syscall bridge. The host build links as PIE to keep the guest address range available.

### Compiler-built branch smoke test

With `x86_64-linux-gnu-gcc` installed, run:

```bash
make -C reconstruct test-branch-guest
```

The target builds fixed-address and static PIE x86-64 ELFs from freestanding C. It checks stdout and exit status after a taken and an untaken branch, calls and returns, and Linux write and exit syscalls. On an x86-64 Linux host with GCC, set `CC_X86_64=gcc`.

### Stock Alpine BusyBox compatibility

Use Alpine v3.22 main’s x86-64 package [busybox-static 1.37.0-r20](https://pkgs.alpinelinux.org/package/v3.22/main/x86_64/busybox-static). Extract `bin/busybox.static` from the package and make it executable. The expected ELF SHA-256 is `a477b4c1b332bb9b5d926dbfc75e0efc9b53193708d8be83295bfbb376fa9839`.

```bash
make -C reconstruct test-linux-static BUSYBOX_STATIC=/absolute/path/to/busybox.static
```

The test uses `qemu-x86_64` as its reference (`QEMU_X86_64` overrides the executable). It compares stdout, stderr, and exit status for `true`, `false`, `echo`, `cat`, and `wc -c`, including stdin, files, and a missing file. It runs both attesor backends. The normal `make test` target remains offline.

### Dynamically linked Alpine tools

Use `bin/busybox` and `lib/ld-musl-x86_64.so.1` from the official Alpine 3.22.7 x86-64 image. The differential test pins both files by SHA-256. It repeats the BusyBox cases and builds an additional guest whose imported function comes from a separate x86-64 shared object.

```bash
make -C reconstruct test-linux-dynamic ALPINE_SYSROOT=/absolute/path/to/alpine-root
./reconstruct/oah --sysroot /absolute/path/to/alpine-root \
    /absolute/path/to/alpine-root/bin/busybox echo hello
```

The test needs `qemu-x86_64` and `x86_64-linux-gnu-gcc`. `QEMU_X86_64` and `CC_X86_64` override them. With `--sysroot`, absolute guest loader and standard library/config paths are resolved within the supplied root by Linux `openat2`. Ordinary program file arguments are handled in the host working directory. The sysroot provides guest runtime files and does not isolate the process.

### Debian glibc compatibility

Use an extracted x86-64 Debian Bookworm slim root from image digest `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc`. Keep the root’s library symlinks intact. The test verifies the hashes of the Debian executables, loader, and libc before running them.

```bash
make -C reconstruct test-linux-glibc DEBIAN_SYSROOT=/absolute/path/to/debian-root
./reconstruct/oah --sysroot /absolute/path/to/debian-root \
    /absolute/path/to/debian-root/usr/bin/printf 'hello %s\n' glibc
```

The test needs QEMU user-mode and an x86-64 GNU compiler with glibc development headers and startup objects. It compares stock Debian `true`, `false`, `echo`, `cat`, `wc`, and `printf` with QEMU, including integer and floating-point formatting. It then builds a libc guest that exercises allocation, stdio, and a library loaded at runtime with `dlopen` and `dlsym`.

CPUID exposes the x86-64 baseline startup profile so glibc can select its baseline routines. Individual instructions still require decoder support. The glibc suite also exercises ordinary signals sent within the guest process. The runner maintains guest dispositions, masks, and pending signals, and builds Linux x86-64 signal frames on the normal or alternate stack. Handler return restores guest registers and the saved mask. Sending signals to other processes, realtime queues, and job control are outside this slice. Thread creation, rseq, robust futex registration, and comprehensive x87 arithmetic and exception handling remain open.

## What we will not do

- Name a `FUN_*` from its address order (`v128_add` at `0x26cdc` is a syscall
  errno wrapper, not a vector add).
- Claim production-ready status.
- Treat the sibling `rosetta_trans_*.c` tree as ground truth.
- Check in Apple's `rosetta` ELF.
- Copy Apple `runtime_*` machine code; only the recovered ABI is reimplemented.
