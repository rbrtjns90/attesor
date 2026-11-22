"""Compare the pinned static or dynamic Alpine x86-64 BusyBox with QEMU."""

import argparse
import hashlib
import os
import shlex
import shutil
from pathlib import Path
import struct
import subprocess
import tempfile

BUSYBOX_SHA256 = "a477b4c1b332bb9b5d926dbfc75e0efc9b53193708d8be83295bfbb376fa9839"


DYNAMIC_BUSYBOX_SHA256 = "6dcd5f0190e8f4b055c2823b3d97660704b97d70c60cd3d3cf9805922fde1302"
MUSL_SHA256 = "6600020aec4ea506e4310a4f48ce8a998e85885d90863bade0e7344dcb067552"


def check_fixture(path, sysroot):
    data = path.read_bytes()
    expected = DYNAMIC_BUSYBOX_SHA256 if sysroot else BUSYBOX_SHA256
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("BusyBox does not match the pinned Alpine x86-64 fixture")
    if sysroot:
        loader = sysroot / "lib/ld-musl-x86_64.so.1"
        if hashlib.sha256(loader.read_bytes()).hexdigest() != MUSL_SHA256:
            raise ValueError("musl loader does not match the pinned Alpine x86-64 fixture")
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("expected a little-endian x86-64 ELF")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    has_interp = any(struct.unpack_from("<I", data, offset + i * size)[0] == 3 for i in range(count))
    if has_interp != bool(sysroot):
        raise ValueError("fixture ELF type does not match the requested test mode")


def run(command, directory, stdin, *, trace=False, extra_env=None):
    env = {"PATH": os.defpath, "LC_ALL": "C"}
    if extra_env:
        env.update(extra_env)
    if trace:
        env["OAH_TRACE_UNSUPPORTED"] = "1"
    result = subprocess.run(command, input=stdin, capture_output=True, cwd=directory,
                            env=env, timeout=20)
    return result.returncode, result.stdout, result.stderr


def shared_library_case(runner, qemu, sysroot, compiler):
    sources = Path(__file__).resolve().parents[1] / "tests"
    with tempfile.TemporaryDirectory(prefix="attesor-dso-") as temp:
        directory = Path(temp)
        root = directory / "root"
        lib = root / "lib"
        lib.mkdir(parents=True)
        loader = "ld-musl-x86_64.so.1"
        shutil.copyfile(sysroot / "lib" / loader, lib / loader)
        guest = directory / "guest"
        subprocess.run([*compiler, "-O2", "-nostdlib", "-fPIC", "-shared",
                        "-Wl,-soname,libattesor_fixture.so", str(sources / "dynamic_library.c"),
                        "-o", str(lib / "libattesor_fixture.so")], check=True, timeout=30)
        subprocess.run([*compiler, "-O2", "-nostdlib", "-fPIE", "-pie",
                        f"-Wl,-dynamic-linker,/lib/{loader}", f"-L{lib}",
                        str(sources / "dynamic_guest.c"), "-lattesor_fixture", "-o", str(guest)],
                       check=True, timeout=30)
        options = ["--sysroot", str(root), str(guest)]
        expected = run([qemu, "-L", str(root), str(guest)], directory, b"")
        if expected != (7, b"", b""):
            raise ValueError(f"shared-library reference failed: {expected!r}")
        failures = 0
        for backend, flags in (("native", []), ("interpret", ["--interpret"])):
            actual = run([runner, *flags, *options], directory, b"")
            if actual != expected:
                print(f"FAIL {backend}: separate shared library: {actual!r}")
                failures += 1
            else:
                print(f"PASS {backend}: separate shared library")
        missing = run([runner, str(guest)], directory, b"")
        if missing[0] != 127 or b"requires --sysroot" not in missing[2]:
            print(f"FAIL missing sysroot: {missing!r}")
            failures += 1
        else:
            print("PASS dynamic executable requires an explicit sysroot")
        return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--busybox", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--sysroot", type=Path)
    parser.add_argument("--cc", default="x86_64-linux-gnu-gcc")
    args = parser.parse_args()
    try:
        check_fixture(args.busybox, args.sysroot)
    except (ValueError, OSError, struct.error) as error:
        parser.error(str(error))

    cases = [
        (["true"], b""), (["false"], b""), (["echo", "attesor linux"], b""),
        (["cat"], b"line one\nline two\n"), (["cat", "input.txt"], b""),
        (["wc", "-c"], b"line one\nline two\n"), (["wc", "-c", "input.txt"], b""),
        (["cat", "missing.txt"], b""),
    ]
    failures = 0
    runner = str(args.runner.resolve())
    guest = str(args.busybox.resolve())
    guest_options = ["--sysroot", str(args.sysroot.resolve())] if args.sysroot else []
    reference_options = ["-L", str(args.sysroot.resolve())] if args.sysroot else []
    with tempfile.TemporaryDirectory(prefix="attesor-linux-") as directory:
        (Path(directory) / "input.txt").write_bytes(b"line one\nline two\n")
        for command, stdin in cases:
            label = " ".join(command)
            try:
                expected = run([args.qemu, *reference_options, guest, *command], directory, stdin)
            except (OSError, subprocess.TimeoutExpired) as error:
                parser.error(f"QEMU reference failed for {label}: {error}")
            status = int(command[0] == "false" or command[-1] == "missing.txt")
            if expected[0] != status:
                parser.error(f"QEMU reference for {label} returned {expected[0]}, expected {status}")
            for backend in ("native", "interpret"):
                options = ["--interpret"] if backend == "interpret" else []
                try:
                    actual = run([runner, *options, *guest_options, guest, *command], directory, stdin)
                except subprocess.TimeoutExpired:
                    print(f"FAIL {backend}: {label}: timed out")
                    failures += 1
                    continue
                if actual != expected:
                    print(f"FAIL {backend}: {label}\n  expected {expected!r}\n  actual   {actual!r}")
                    try:
                        _, _, trace = run([runner, *options, *guest_options, guest, *command], directory, stdin, trace=True)
                    except subprocess.TimeoutExpired:
                        trace = b""
                    syscall = next((line for line in trace.splitlines()
                                    if line.startswith(b"oah: unsupported syscall ")), None)
                    if syscall:
                        print(f"  {syscall.decode()}")
                    failures += 1
                else:
                    print(f"PASS {backend}: {label}")
    if args.sysroot:
        try:
            failures += shared_library_case(runner, args.qemu, args.sysroot.resolve(),
                                            shlex.split(args.cc))
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            parser.error(str(error))
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
