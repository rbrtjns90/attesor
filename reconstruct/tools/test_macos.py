"""Run pinned Linux ELF fixtures in attesor's two native macOS modes."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

from test_linux_glibc import HASHES
from test_linux_static import check_fixture, run

SAMPLE = b"line one\nline two\n"
TIMEOUT_HASHES = {
    "usr/bin/timeout": "5ef0eaaaa4220593add7716aad74da927ca3bb10605e964330de64fecc3ef15e",
    "usr/bin/sleep": "4add4bb89d8ca0e3b1bd861130ddd7ae0fd9617a8055de0a38c8d2ca1ac95723",
}


def verify(runner, directory, title, command, expected, stdin=b"", *, extra_env=None):
    for mode, options in (("jit", []), ("interpret", ["--interpret"])):
        actual = run([runner, *options, *command], directory, stdin, extra_env=extra_env)
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
    parser.add_argument("--busybox", type=Path)
    parser.add_argument("--alpine-sysroot", type=Path)
    parser.add_argument("--debian-sysroot", type=Path)
    parser.add_argument("--debian-python-sysroot", type=Path)
    args = parser.parse_args()
    runner = str(args.runner.resolve())
    try:
        with tempfile.TemporaryDirectory(prefix="attesor-macos-") as directory:
            (Path(directory) / "input.txt").write_bytes(SAMPLE)
            verify(runner, directory, "static Linux hello", [str(args.hello.resolve())],
                   (0, b"hello\n", b""))
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
