"""Run pinned Linux ELF fixtures in attesor's two native macOS modes."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

from test_linux_glibc import HASHES
from test_linux_static import check_fixture, run

SAMPLE = b"line one\nline two\n"


def verify(runner, directory, title, command, expected, stdin=b""):
    for mode, options in (("jit", []), ("interpret", ["--interpret"])):
        actual = run([runner, *options, *command], directory, stdin)
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
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
