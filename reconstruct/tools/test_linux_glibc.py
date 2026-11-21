"""Compare the Debian Bookworm x86-64 glibc fixtures with QEMU."""

import argparse
import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from test_linux_static import run

LIBDIR = Path("lib/x86_64-linux-gnu")
LOADER = "ld-linux-x86-64.so.2"
HASHES = {
    "usr/bin/true": "c79bf44242829108e323378531f4ac839513ca1fba45efd6583643526e1e9fd2",
    "usr/bin/false": "7faadececbd287e494595d6a8203bc521e4463c682a496569187a77e761156bc",
    "usr/bin/echo": "a049fb47554c6cde2ee452e5d87f6386abb63af7cdcae9cd0dc99fc80e0bcf35",
    "usr/bin/cat": "008f819498fe591f3cc920d543709347d8d14a139bb3482bc2cd8635c1b3162e",
    "usr/bin/wc": "7480f7cb7110af0f45b6e04b50f8d1fb2c6392cf911cb3a28c516ef1b725823e",
    "usr/bin/printf": "bf7cc8faa85842bb662243c5f945b03e284a823742d123ed7421a7f5c9c773e2",
    f"lib64/{LOADER}": "02bcda52c1a5dfc236f94d9e5255b4a0e26347d8a372a5223b650e31f291ce3c",
    str(LIBDIR / "libc.so.6"): "6b4a45352fd0c540a9c7c718f35ce8c8e46a4e482f9d3885a910c32d1a0e1421",
}


def compare(runner, qemu, sysroot, guest, directory, argv, stdin, status, expected_stdout=None):
    label = " ".join([guest.name, *(repr(arg) for arg in argv)])
    expected = run([qemu, "-L", str(sysroot), str(guest), *argv], directory, stdin)
    if expected[0] != status or (expected_stdout is not None and expected[1] != expected_stdout):
        raise ValueError(f"unexpected QEMU result for {label}: {expected!r}")
    failures = 0
    for mode, flags in (("native", []), ("interpret", ["--interpret"])):
        command = [runner, *flags, "--sysroot", str(sysroot), str(guest), *argv]
        try:
            actual = run(command, directory, stdin)
        except subprocess.TimeoutExpired:
            print(f"FAIL {mode}: {label}: timed out")
            failures += 1
            continue
        if actual != expected:
            print(f"FAIL {mode}: {label}\n  expected {expected!r}\n  actual   {actual!r}")
            failures += 1
        else:
            print(f"PASS {mode}: {label}")
    return failures


def build_libc_guest(directory, sysroot, compiler):
    sources = Path(__file__).resolve().parents[1] / "tests"
    root = directory / "root"
    libs = root / LIBDIR
    libs.mkdir(parents=True)
    (root / "lib64").mkdir()
    shutil.copyfile(sysroot / "lib64" / LOADER, root / "lib64" / LOADER)
    shutil.copyfile(sysroot / LIBDIR / "libc.so.6", libs / "libc.so.6")
    subprocess.run([*compiler, "-O2", "-nostdlib", "-fPIC", "-shared",
                    "-Wl,-soname,libattesor_glibc_fixture.so",
                    str(sources / "dynamic_library.c"),
                    "-o", str(libs / "libattesor_glibc_fixture.so")], check=True, timeout=30)
    guest = directory / "glibc_guest"
    subprocess.run([*compiler, "-O2", "-fno-builtin", "-fPIE", "-pie",
                    str(sources / "glibc_guest.c"), "-ldl", "-o", str(guest)],
                   check=True, timeout=30)
    return root, guest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--sysroot", type=Path, required=True)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--cc", default="x86_64-linux-gnu-gcc")
    args = parser.parse_args()
    root = args.sysroot.resolve()
    runner = str(args.runner.resolve())
    sample = b"one\ntwo\n"
    cases = [
        ("true", [], b"", 0),
        ("false", [], b"", 1),
        ("echo", ["attesor glibc"], b"", 0),
        ("cat", [], sample, 0),
        ("cat", ["input.txt"], b"", 0),
        ("cat", ["missing.txt"], b"", 1),
        ("wc", ["-c"], sample, 0),
        ("wc", ["-c", "input.txt"], b"", 0),
        ("printf", ["%s %04d\n", "glibc", "37"], b"", 0),
        ("printf", ["%.2f\n", "1.25"], b"", 0),
        ("printf", ["%+.3f\n", "-0.125"], b"", 0),
    ]
    try:
        for path, expected in HASHES.items():
            if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
                raise ValueError(f"fixture does not match the pinned Debian image: {path}")
        with tempfile.TemporaryDirectory(prefix="attesor-glibc-") as temp:
            directory = Path(temp)
            (directory / "input.txt").write_bytes(sample)
            failures = sum(compare(runner, args.qemu, root, root / "usr/bin" / name, directory,
                                   argv, stdin, status) for name, argv, stdin, status in cases)
            built_root, guest = build_libc_guest(directory, root, shlex.split(args.cc))
            failures += compare(runner, args.qemu, built_root, guest, directory, [], b"", 0,
                                b"attesor:10\n")
            signals = directory / "glibc_signals"
            source = Path(__file__).resolve().parents[1] / "tests" / "glibc_signals.c"
            subprocess.run([*shlex.split(args.cc), "-O2", "-fPIE", "-pie",
                            str(source), "-o", str(signals)], check=True, timeout=30)
            failures += compare(runner, args.qemu, built_root, signals, directory, [], b"", 0,
                                b"signals: ok\n")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
