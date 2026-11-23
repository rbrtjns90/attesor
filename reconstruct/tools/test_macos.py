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
                cat = str(root / "usr/bin/cat").encode()
                missing = (1, b"", cat + b": missing.txt: No such file or directory\n")
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
                cat = str(root / "usr/bin/cat").encode()
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
                ):
                    verify(runner, directory, f"Debian {fixture}",
                           ["--max-insns", "500000000", "--sysroot", str(root),
                            str(python), "-S", str(fixtures / fixture)], (0, expected, b""),
                           extra_env={"PYTHONHOME": str(root / "usr"), "PYTHONDONTWRITEBYTECODE": "1"})
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
