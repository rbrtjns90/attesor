"""Run pinned Linux ELF fixtures in attesor's native macOS modes.

Default coverage: every case runs under the JIT (with and without
fragment chaining) and under the interpreter. A small matrix also
checks that cache-disabled, cold-cache, and warm-cache runs produce
identical results. Debian sysroot fixtures are exercised when the
matching --*-sysroot arguments point at a populated tree; pass
--require-fixtures to fail rather than skip them (release gate).
"""

import argparse
import hashlib
import re
from pathlib import Path
import struct
import subprocess
import tempfile

from test_linux_glibc import HASHES
from test_linux_static import check_fixture, run

SAMPLE = b"line one\nline two\n"
TIMEOUT_HASHES = {
    "usr/bin/timeout": "5ef0eaaaa4220593add7716aad74da927ca3bb10605e964330de64fecc3ef15e",
    "usr/bin/sleep": "4add4bb89d8ca0e3b1bd861130ddd7ae0fd9617a8055de0a38c8d2ca1ac95723",
}


MODES = (("jit", [], {}),
         ("jit-nochain", [], {"OAH_JIT_NOCHAIN": "1"}),
         ("interpret", ["--interpret"], {}))

# Differential matrix: the optimized path (flag liveness on), the
# eager-flags JIT, and the interpreter — each in its own process and
# memory image, so a run cannot contaminate another's reference state.
DIFF_MODES = (("jit", [], {}),
              ("jit-eager", [], {"OAH_JIT_NOFLAGS": "1"}),
              ("interpret", ["--interpret"], {}))


def verify(runner, directory, title, command, expected, stdin=b"", *, extra_env=None):
    for mode, options, mode_env in MODES:
        env = dict(extra_env or {})
        env.update(mode_env)
        actual = run([runner, *options, *command], directory, stdin,
                     extra_env=env or None)
        if actual != expected:
            raise ValueError(f"{mode} {title}: expected {expected!r}, got {actual!r}")
        print(f"PASS {mode}: {title}")


def cache_matrix(runner, directory, title, command, expected, stdin=b""):
    """cache-disabled, cold, and warm runs must produce identical output."""
    cache_dir = Path(directory) / "jit-cache"
    for mode, env in (("nocache", {"OAH_JIT_NOCACHE": "1"}),
                      ("cold-cache", {"OAH_CACHE_DIR": str(cache_dir)}),
                      ("warm-cache", {"OAH_CACHE_DIR": str(cache_dir)})):
        actual = run([runner, *command], directory, stdin, extra_env=env)
        if actual != expected:
            raise ValueError(f"{mode} {title}: expected {expected!r}, got {actual!r}")
        print(f"PASS {mode}: {title}")


def tool_cases():
    return [
        ("true", [], b"", (0, b"", b"")),
        ("false", [], b"", (1, b"", b"")),
        ("echo", ["native macOS"], b"", (0, b"native macOS\n", b"")),
        ("cat", [], SAMPLE, (0, SAMPLE, b"")),
        ("cat", ["input.txt"], b"", (0, SAMPLE, b"")),
        ("wc", ["-c"], SAMPLE, (0, b"18\n", b"")),
        ("wc", ["-c", "input.txt"], b"", (0, b"18 input.txt\n", b"")),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--hello", type=Path, required=True)
    parser.add_argument("--sse", type=Path)
    parser.add_argument("--thread", type=Path,
                        help="two-worker TLS/XMM isolation fixture")
    parser.add_argument("--fault-store", type=Path,
                        help="mid-fragment fault store-replay fixture")
    parser.add_argument("--fault-state", type=Path,
                        help="mid-fragment fault register/memory/RIP "
                             "recovery fixture")
    parser.add_argument("--diff", type=Path,
                        help="optimized/eager/interp differential suite")
    parser.add_argument("--exec-guard", type=Path,
                        help="executable-range invalidation fixture")
    parser.add_argument("--flag-live", type=Path,
                        help="zero-count shift flag-liveness fixture")
    parser.add_argument("--smc-chain", type=Path,
                        help="self-modifying code under fragment chaining")
    parser.add_argument("--vec-align", type=Path,
                        help="vector memory fault-semantics fixture")
    parser.add_argument("--busybox", type=Path)
    parser.add_argument("--alpine-sysroot", type=Path)
    parser.add_argument("--debian-sysroot", type=Path)
    parser.add_argument("--debian-python-sysroot", type=Path)
    parser.add_argument("--require-fixtures", action="store_true",
                        help="fail instead of skipping when the pinned Debian "
                             "sysroots are absent (release gate)")
    args = parser.parse_args()
    runner = str(args.runner.resolve())
    if args.require_fixtures:
        missing = [name for name, path in
                   (("debian-sysroot", args.debian_sysroot),
                    ("debian-python-sysroot", args.debian_python_sysroot))
                   if not path or not path.is_dir()]
        if missing:
            parser.exit(1, f"required fixtures missing: {', '.join(missing)}\n")
    try:
        with tempfile.TemporaryDirectory(prefix="attesor-macos-") as directory:
            (Path(directory) / "input.txt").write_bytes(SAMPLE)
            verify(runner, directory, "static Linux hello", [str(args.hello.resolve())],
                   (0, b"hello\n", b""))
            cache_matrix(runner, directory, "static Linux hello",
                         [str(args.hello.resolve())], (0, b"hello\n", b""))
            if args.sse:
                sse_expected = (0, args.sse.with_suffix(
                    args.sse.suffix + ".expected").read_bytes(), b"")
                verify(runner, directory, "SSE guest vector ops",
                       [str(args.sse.resolve())], sse_expected)
                cache_matrix(runner, directory, "SSE guest vector ops",
                             [str(args.sse.resolve())], sse_expected)
            if args.thread:
                thread_expected = (0, b"workerjit ok\n", b"")
                verify(runner, directory, "worker TLS/XMM isolation",
                       [str(args.thread.resolve())], thread_expected)
                actual = run([runner, str(args.thread.resolve())], directory,
                             b"", extra_env={"OAH_WORKER_JIT": "1"})
                if actual != thread_expected:
                    raise ValueError(f"workerjit thread isolation: "
                                     f"expected {thread_expected!r}, got {actual!r}")
                print("PASS workerjit: worker TLS/XMM isolation")
            if args.fault_store:
                # The fixture bumps a MAP_SHARED counter, then faults on a
                # bad load mid-fragment. Every committed re-execution of
                # the store lands in the file — recovery must leave it at 1.
                for mode, options, mode_env in MODES:
                    counter = Path(directory) / "counter.bin"
                    counter.unlink(missing_ok=True)
                    env = dict(mode_env)
                    rc, out, err = run(
                        [runner, *options, str(args.fault_store.resolve())],
                        directory, b"", extra_env=env or None)
                    value = struct.unpack("<Q", counter.read_bytes()[:8])[0] \
                        if counter.exists() else -1
                    if value != 1:
                        raise ValueError(
                            f"{mode} mid-fragment fault store replay: "
                            f"counter={value} (rc={rc}, stderr={err!r})")
                    print(f"PASS {mode}: mid-fragment fault store replay")
            if args.fault_state:
                # Replay-safety across a fragment boundary: the guest
                # loads OLD into rbx, commits a NEW store to the same
                # shared qword, then faults on a separate load. Recovery
                # must keep rbx=OLD (a replayed load must not re-read
                # committed bytes), leave the file at NEW (store applied
                # once), and stop at the exact faulting RIP (lea'd into
                # r12 beforehand).
                for mode, options, mode_env in MODES:
                    state = Path(directory) / "state.bin"
                    state.unlink(missing_ok=True)
                    env = dict(mode_env)
                    env["OAH_STOP_TRACE"] = "1"
                    rc, out, err = run(
                        [runner, *options, str(args.fault_state.resolve())],
                        directory, b"", extra_env=env)
                    value = struct.unpack("<Q", state.read_bytes()[:8])[0] \
                        if state.exists() else -1
                    regs = {m.group(1): int(m.group(2), 16)
                            for m in re.finditer(
                                rb"\b(r\d+|r[a-z]{2})=([0-9a-f]+)", err)}
                    rip_m = re.search(rb"\brip=([0-9a-f]+)", err)
                    if value != 0x1001 or regs.get(b"rbx") != 0x1000 or \
                            not rip_m or \
                            regs.get(b"r12") != int(rip_m.group(1), 16):
                        raise ValueError(
                            f"{mode} fault-state recovery: file={value:#x} "
                            f"regs={regs} (rc={rc}, stderr={err!r})")
                    print(f"PASS {mode}: mid-fragment fault-state recovery")
            if args.diff:
                # One-fragment differential suite: identical bytes and
                # initial state through the optimized JIT, the
                # eager-flags JIT, and the interpreter — separate
                # processes, hence separate memory images. Per-case
                # dumps (all GPRs, masked rflags, all XMM lanes,
                # scratch memory), the fault RIP and the shared file's
                # committed bytes must be byte-identical across modes.
                runs = []
                for mode, options, mode_env in DIFF_MODES:
                    shared = Path(directory) / "diff.bin"
                    shared.unlink(missing_ok=True)
                    rc, out, err = run(
                        [runner, *options, str(args.diff.resolve())],
                        directory, b"", extra_env=mode_env or None)
                    rip = re.search(rb"image\+([0-9a-f]+)", err)
                    runs.append((mode, rc, out,
                                 rip.group(1) if rip else b"",
                                 shared.read_bytes()
                                 if shared.exists() else b""))
                base = runs[0]
                for mode, rc, out, rip, shared in runs[1:]:
                    if (rc, out, rip, shared) != base[1:]:
                        raise ValueError(
                            f"{mode} differential suite diverged from "
                            f"{base[0]}: rc={rc} vs {base[1]}, "
                            f"rip={rip} vs {base[3]}, "
                            f"stdout/shared differ")
                    print(f"PASS {mode}: differential suite")
            if args.exec_guard:
                # Two-sided invalidation check covering mprotect, munmap
                # and mremap. The fixture translates and runs mmap'd RWX
                # stubs, churns unrelated data mappings (must NOT flush),
                # re-enters stubA to prove its translation survived, then:
                #   - data mremap (grow+move): must not flush, data must
                #     land intact at the new gva;
                #   - exec mremap: moves a live translated stub — must
                #     flush; the new gva must execute, and a forked child
                #     proves the OLD gva cannot run its stale fragment
                #     (child must fault -> exit 126; if it ran stale code
                #     it would exit 43);
                #   - crossing [data][exec] munmap + stubB re-warm +
                #     de-exec: the revoke flush must evict live code and
                #     the final call must fault.
                # stdout: 24B report [base,stubA,stubB] + "OK\n" +
                #         16B report [stubC_old,stubC_new] + "KC\n".
                for mode, options, mode_env in MODES:
                    env = dict(mode_env)
                    env["OAH_JIT_FLUSH_DEBUG"] = "1"
                    rc, out, err = run(
                        [runner, *options, str(args.exec_guard.resolve())],
                        directory, b"", extra_env=env)
                    flushes = [line for line in err.splitlines()
                               if line.startswith(b"jit flush")]
                    if rc == 0:
                        raise ValueError(
                            f"{mode} exec-guard: de-exec'd stub ran "
                            f"without faulting (out={out!r}, err={err!r})")
                    if len(out) != 46 or out[24:27] != b"OK\n" \
                            or out[43:] != b"KC\n":
                        raise ValueError(
                            f"{mode} exec-guard: expected 40-byte address "
                            f"report + OK/KC markers, got out={out!r} "
                            f"(err={err!r})")
                    (base, stub_a, stub_b,
                     stub_c_old, stub_c_new) = struct.unpack(
                        "<QQQQQ", out[:24] + out[27:43])
                    # Exactly the three exec-range flushes: the mremap
                    # move, then the crossing munmap, then the de-exec.
                    if len(flushes) != 3 or b"mremap" not in flushes[0] \
                            or any(b"mprotect/munmap" not in line
                                   for line in flushes[1:]):
                        raise ValueError(
                            f"{mode} exec-guard: expected one mremap + two "
                            f"mprotect/munmap flushes, got {flushes!r} "
                            f"(stderr={err!r})")
                    stopped = [line for line in err.splitlines()
                               if b"guest stopped" in line]
                    # Two OAH_INTERP_FAULT (=3) stops: the child dies at the
                    # old (mremap'd-away) stubC gva, the parent at stubB.
                    fault_rips = set()
                    for line in stopped:
                        if b"(3)" not in line:
                            continue
                        m = re.search(rb"rip=([0-9a-f]+)", line)
                        if m:
                            fault_rips.add(int(m.group(1), 16))
                    if fault_rips != {stub_c_old, stub_b}:
                        raise ValueError(
                            f"{mode} exec-guard: expected faults at "
                            f"{stub_c_old:#x} (moved stub) and {stub_b:#x} "
                            f"(revoked stub), got rips "
                            f"{[hex(r) for r in fault_rips]} "
                            f"(stderr={err!r})")
                    # Every flush must evict live code — each dead-code
                    # site was re-warmed so a real fragment exists to
                    # invalidate. (Interpreter mode has no fragment table.)
                    if mode != "interpret":
                        for line in flushes:
                            live = re.search(rb"(\d+) live frags", line)
                            if not live or int(live.group(1)) < 1:
                                raise ValueError(
                                    f"{mode} exec-guard: flush evicted no "
                                    f"live fragments: {line!r}")
                    print(f"PASS {mode}: exec-range invalidation guard")
            if args.flag_live:
                # x86 shifts/rotates with an effective count of zero
                # preserve every status flag. The JIT flag-liveness pass
                # must model them as conditional writers — if it marks
                # the earlier producer's flags dead, a setcc/jcc/cmovcc
                # after a cl=0 (or masked-to-zero) shift reads stale
                # flags. The fixture runs 11 checks (cmp/CF producers,
                # shl/shr/sar/rol/ror at cl=0, cl=32 dword, cl=64 qword,
                # and imm=0) observed by setcc/jcc/cmovcc; any wrong
                # result exits with the test number. Runs under the
                # optimized JIT — OAH_JIT_VERIFY disables liveness, so
                # it cannot cover this path.
                for mode, options, mode_env in MODES:
                    env = dict(mode_env)
                    rc, out, err = run(
                        [runner, *options, str(args.flag_live.resolve())],
                        directory, b"", extra_env=env)
                    if rc != 0 or out != b"OK\n":
                        raise ValueError(
                            f"{mode} flag-liveness zero-count: expected "
                            f"OK + exit 0, got rc={rc} out={out!r} "
                            f"err={err!r}")
                    print(f"PASS {mode}: zero-count shift flag liveness")
            if args.smc_chain:
                # Writable-backed fragments carry a source hash that
                # dispatch re-checks, but a chain link patched into such
                # a fragment would skip the check entirely: the guest
                # could rewrite the target and keep running stale arena
                # code through the link. The fixture writes caller and
                # callee stubs into an RWX page, warms the caller->callee
                # chain, then rewrites the callee twice — each call must
                # see the new bytes (a stale link returns the old
                # constant -> exit 66). JIT modes must also report an
                # "smc" flush per rewrite under OAH_JIT_FLUSH_DEBUG.
                for mode, options, mode_env in MODES:
                    env = dict(mode_env)
                    env["OAH_JIT_FLUSH_DEBUG"] = "1"
                    rc, out, err = run(
                        [runner, *options, str(args.smc_chain.resolve())],
                        directory, b"", extra_env=env)
                    if rc != 0 or out != b"OK\n":
                        raise ValueError(
                            f"{mode} smc-chain: expected OK + exit 0, "
                            f"got rc={rc} out={out!r} err={err!r}")
                    if mode != "interpret":
                        smc = [line for line in err.splitlines()
                               if line.startswith(b"jit flush (smc)")]
                        if len(smc) != 2:
                            raise ValueError(
                                f"{mode} smc-chain: expected two smc "
                                f"flushes, got {smc!r} (stderr={err!r})")
                    print(f"PASS {mode}: self-modifying code under chaining")
            if args.vec_align:
                # aarch64 NEON never faults on unaligned addresses, so
                # the JIT must guard aligned vector memory forms itself:
                # misaligned movdqa/movaps exit through an interpreter
                # bail that raises the x86 #GP, while movdqu stays a bare
                # native access. Host page protections mirror guest
                # permissions, so a vector store to a read-only guest
                # page faults like the interpreter path. The fixture
                # runs aligned/misaligned/cross-page success cases, then
                # forks children for the three fault cases (misaligned
                # movdqa load, misaligned movaps store, movdqu store to a
                # page the guest mprotect'd read-only); each child must
                # die with the guest fault exit 126.
                for mode, options, mode_env in MODES:
                    env = dict(mode_env)
                    rc, out, err = run(
                        [runner, *options, str(args.vec_align.resolve())],
                        directory, b"", extra_env=env)
                    if rc != 0 or out != b"OK\n":
                        raise ValueError(
                            f"{mode} vector memory faults: expected "
                            f"OK + exit 0, got rc={rc} out={out!r} "
                            f"err={err!r}")
                    print(f"PASS {mode}: vector memory fault checks")
            for kind, binary, sysroot in (
                ("static", args.busybox, None),
                ("musl", args.alpine_sysroot / "bin/busybox" if args.alpine_sysroot else None,
                 args.alpine_sysroot),
            ):
                if not binary:
                    continue
                check_fixture(binary, sysroot)
                prefix = ["--sysroot", str(sysroot.resolve())] if sysroot else []
                missing = (1, b"", b"cat: can't open 'missing.txt': No such file or directory\n")
                for name, argv, stdin, expected in tool_cases() + [
                    ("cat", ["missing.txt"], b"", missing),
                ]:
                    verify(runner, directory, f"{kind} BusyBox {name} {argv}",
                           [*prefix, str(binary.resolve()), name, *argv], expected, stdin)
            if args.debian_sysroot:
                root = args.debian_sysroot.resolve()
                for path, expected in HASHES.items():
                    if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
                        raise ValueError(f"fixture does not match the pinned Debian image: {path}")
                missing = (1, b"",
                           b"/usr/bin/cat: missing.txt: No such file or directory\n")
                for name, argv, stdin, expected in tool_cases() + [
                    ("cat", ["missing.txt"], b"", missing),
                    ("printf", ["%.2f\n", "1.25"], b"", (0, b"1.25\n", b"")),
                ]:
                    verify(runner, directory, f"glibc {name} {argv}",
                           ["--sysroot", str(root), str(root / "usr/bin" / name), *argv],
                           expected, stdin)
                cache_matrix(runner, directory, "glibc cat input.txt",
                             ["--sysroot", str(root), str(root / "usr/bin/cat"),
                              "input.txt"], (0, SAMPLE, b""))
                if all((root / path).is_file() for path in TIMEOUT_HASHES):
                    for path, expected in TIMEOUT_HASHES.items():
                        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
                            raise ValueError(f"fixture does not match the pinned Debian image: {path}")
                    timeout = ["--sysroot", str(root), str(root / "usr/bin/timeout")]
                    verify(runner, directory, "glibc timeout child exits normally",
                           [*timeout, "2", "/usr/bin/true"], (0, b"", b""))
                    verify(runner, directory, "glibc timeout terminates its child",
                           [*timeout, "0.05", "/usr/bin/sleep", "2"], (124, b"", b""))
                strict = {"OAH_SYSROOT_STRICT": "1"}
                cat = b"/usr/bin/cat"
                verify(runner, directory, "strict mode hides host paths",
                       ["--sysroot", str(root), str(root / "usr/bin/cat"),
                        "/System/Library/CoreServices/SystemVersion.plist"],
                       (1, b"", cat + b": /System/Library/CoreServices/SystemVersion.plist: No such file or directory\n"),
                       extra_env=strict)
                verify(runner, directory, "strict mode serves sysroot paths",
                       ["--sysroot", str(root), str(root / "usr/bin/cat"),
                        "/etc/debian_version"],
                       (0, (root / "etc/debian_version").read_bytes(), b""),
                       extra_env=strict)
                verify(runner, directory, "strict mode rejects missing sysroot file",
                       ["--sysroot", str(root), str(root / "usr/bin/cat"),
                        "/definitely/missing"],
                       (1, b"", cat + b": /definitely/missing: No such file or directory\n"),
                       extra_env=strict)
                if not (root / "etc/hostname").exists():
                    verify(runner, directory, "strict mode relative path confined",
                           ["--sysroot", str(root), str(root / "bin/sh"), "-c",
                            "cd /etc && cat hostname"],
                           (1, b"", b"cat: hostname: No such file or directory\n"),
                           extra_env=strict)
                shell = root / "bin/sh"
                if shell.is_file():
                    if hashlib.sha256(shell.read_bytes()).hexdigest() != "f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6":
                        raise ValueError("fixture does not match the pinned Debian shell")
                    script = Path(directory) / "check-script"
                    script.write_text("#!/bin/sh -e\nprintf '%s\\n' \"$1\"\n")
                    script.chmod(0o755)
                    setup = ["--sysroot", str(root)]
                    verify(runner, directory, "direct shebang launch",
                           [*setup, str(script), "direct"], (0, b"direct\n", b""))
                    verify(runner, directory, "guest exec of a shebang script",
                           [*setup, str(shell), "-c", "exec ./check-script child"],
                           (0, b"child\n", b""))
            if args.debian_python_sysroot:
                root = args.debian_python_sysroot.resolve()
                python = root / "usr/bin/python3"
                fixtures = Path(__file__).resolve().parents[1] / "tests"
                for fixture, expected in (
                    ("python_threads.py", b"six workers joined\n"),
                    ("python_readiness.py", b"epoll and eventfd readiness checks passed\n"),
                    ("python_mmsg.py", b"mmsg semantics checks passed\n"),
                    ("python_scm_rights.py", b"scm rights descriptor passing works\n"),
                ):
                    verify(runner, directory, f"Debian {fixture}",
                           ["--max-insns", "500000000", "--sysroot", str(root),
                            str(python), "-S", str(fixtures / fixture)], (0, expected, b""),
                           extra_env={"PYTHONHOME": str(root / "usr"), "PYTHONDONTWRITEBYTECODE": "1"})
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
