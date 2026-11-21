"""Compare the pinned Alpine x86-64 BusyBox fixture with QEMU."""

import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile

BUSYBOX_SHA256 = "a477b4c1b332bb9b5d926dbfc75e0efc9b53193708d8be83295bfbb376fa9839"


def check_fixture(path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != BUSYBOX_SHA256:
        raise ValueError("expected Alpine v3.22 x86-64 busybox-static 1.37.0-r20")
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("expected a little-endian x86-64 ELF")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if any(struct.unpack_from("<I", data, offset + i * size)[0] == 3 for i in range(count)):
        raise ValueError("expected a static ELF without PT_INTERP")


def run(command, directory, stdin, *, trace=False):
    env = {"PATH": os.defpath, "LC_ALL": "C"}
    if trace:
        env["OAH_TRACE_UNSUPPORTED"] = "1"
    result = subprocess.run(command, input=stdin, capture_output=True, cwd=directory,
                            env=env, timeout=20)
    return result.returncode, result.stdout, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--busybox", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--qemu", required=True)
    args = parser.parse_args()
    try:
        check_fixture(args.busybox)
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
    with tempfile.TemporaryDirectory(prefix="attesor-linux-") as directory:
        (Path(directory) / "input.txt").write_bytes(b"line one\nline two\n")
        for command, stdin in cases:
            label = " ".join(command)
            try:
                expected = run([args.qemu, guest, *command], directory, stdin)
            except (OSError, subprocess.TimeoutExpired) as error:
                parser.error(f"QEMU reference failed for {label}: {error}")
            status = int(command[0] == "false" or command[-1] == "missing.txt")
            if expected[0] != status:
                parser.error(f"QEMU reference for {label} returned {expected[0]}, expected {status}")
            for backend in ("native", "interpret"):
                options = ["--interpret"] if backend == "interpret" else []
                try:
                    actual = run([runner, *options, guest, *command], directory, stdin)
                except subprocess.TimeoutExpired:
                    print(f"FAIL {backend}: {label}: timed out")
                    failures += 1
                    continue
                if actual != expected:
                    print(f"FAIL {backend}: {label}\n  expected {expected!r}\n  actual   {actual!r}")
                    try:
                        _, _, trace = run([runner, *options, guest, *command], directory, stdin, trace=True)
                    except subprocess.TimeoutExpired:
                        trace = b""
                    syscall = next((line for line in trace.splitlines()
                                    if line.startswith(b"oah: unsupported syscall ")), None)
                    if syscall:
                        print(f"  {syscall.decode()}")
                    failures += 1
                else:
                    print(f"PASS {backend}: {label}")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
