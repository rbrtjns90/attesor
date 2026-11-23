#!/usr/bin/env python3
"""Emit an ET_DYN x86-64 guest that counts committed-store re-execution
across a mid-fragment fault — the check the host can observe.

The guest openat()s "counter.bin", ftruncates it to 8 bytes, and mmaps
it MAP_SHARED. Attesor hands MAP_SHARED guests a real shared host
mapping, so a guest store there commits straight to the file:

    xor ebx,ebx ; inc ebx        (rbx = 1, a bad address)
    mov r10d,imm ; mov r10d,imm  (padding so `inc` sits mid-fragment)
    inc qword [r13]              non-idempotent RMW into the shared page
    mov rax,[rbx]                faults (GVA 1 unmapped) — guest dies

Without precise recovery each intermediate replay re-JITs a fragment
that re-commits `inc`: the file ends holding f-i (>= 2). With
fault->guest-RIP recovery plus store-suppressed replay it must stay 1.

The host test reads counter.bin after the run; the guest exits nonzero
either way (the bad load is a real guest fault).
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFF = EHDR_SIZE + PHDR_SIZE

SYS_MMAP = 9
SYS_FTRUNCATE = 77
SYS_OPENAT = 257
SYS_EXIT = 60
AT_FDCWD = -100
O_RDWR_CREAT_TRUNC = 0x02 | 0x40 | 0x200   # O_RDWR|O_CREAT|O_TRUNC
PROT_RW = 3
MAP_SHARED = 0x01

# Data-block offsets.
FNAME = 0
END = 16


def emit() -> bytes:
    code = bytearray()
    fixups: list[tuple[int, str, int]] = []
    labels: dict[str, int] = {}

    def here(name: str) -> None:
        labels[name] = len(code)

    def rel32(name: str) -> None:
        fixups.append((len(code), name, len(code) + 4))
        code.extend(b"\x00" * 4)

    def lea_rip(reg: int, name: str) -> None:
        code.append(0x48 | (0x04 if reg >= 8 else 0))
        code.append(0x8D)
        code.append((reg & 7) << 3 | 5)
        fixups.append((len(code), name, len(code) + 4))
        code.extend(b"\x00" * 4)

    def syscall(nr: int) -> None:
        code.extend(b"\xb8" + struct.pack("<I", nr))
        code.extend(b"\x0f\x05")

    # openat(AT_FDCWD, "counter.bin", O_RDWR|O_CREAT|O_TRUNC, 0644)
    code.extend(b"\xbf" + struct.pack("<i", AT_FDCWD))    # mov edi,-100
    lea_rip(6, "fname")                                 # lea rsi,[rip+fname]
    code.extend(b"\xba" + struct.pack("<I", O_RDWR_CREAT_TRUNC))
    code.extend(b"\x41\xba" + struct.pack("<I", 0o644)) # mov r10d,0644
    syscall(SYS_OPENAT)
    code.extend(b"\x48\x85\xc0")                        # test rax,rax
    code.extend(b"\x0f\x88"); rel32("cerr")             # js cerr
    code.extend(b"\x49\x89\xc6")                        # mov r14,rax (fd)

    # ftruncate(fd, 8)
    code.extend(b"\x4c\x89\xf7")                        # mov rdi,r14
    code.extend(b"\xbe\x08\x00\x00\x00")                # mov esi,8
    syscall(SYS_FTRUNCATE)
    code.extend(b"\x48\x85\xc0")                        # test rax,rax
    code.extend(b"\x0f\x88"); rel32("cerr")             # js cerr

    # mmap(0, 8, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
    code.extend(b"\x31\xff")                            # xor edi,edi
    code.extend(b"\xbe\x08\x00\x00\x00")                # mov esi,8
    code.extend(b"\xba" + struct.pack("<I", PROT_RW))
    code.extend(b"\x41\xba" + struct.pack("<I", MAP_SHARED))
    code.extend(b"\x4d\x89\xf0")                        # mov r8,r14 (fd)
    code.extend(b"\x4d\x31\xc9")                        # xor r9d,r9d
    syscall(SYS_MMAP)
    code.extend(b"\x49\x89\xc5")                        # mov r13,rax
    code.extend(b"\x48\x85\xc0")                        # test rax,rax
    code.extend(b"\x0f\x88"); rel32("cerr")             # js cerr

    # --- the faulting fragment: rbx=1, pad, inc [r13], load [rbx] -----
    code.extend(b"\x48\x31\xdb")                        # xor rbx,rbx
    code.extend(b"\x48\xff\xc3")                        # inc rbx
    code.extend(b"\x41\xba\x11\x11\x11\x11")            # mov r10d,0x11111111
    code.extend(b"\x41\xba\x22\x22\x22\x22")            # mov r10d,0x22222222
    code.extend(b"\x49\xff\x45\x00")                    # inc qword [r13]
    code.extend(b"\x48\x8b\x03")                        # mov rax,[rbx]  FAULT
    code.extend(b"\xbf\x63\x00\x00\x00")                # mov edi,99
    syscall(SYS_EXIT)                                   # unreachable

    here("cerr")
    code.extend(b"\xbf\x05\x00\x00\x00")                # mov edi,5
    syscall(SYS_EXIT)

    return bytes(code), labels, fixups


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    args = ap.parse_args()

    code, labels, fixups = emit()

    data = b"counter.bin\x00" + b"\x00" * (END - len(b"counter.bin\x00"))
    data_off = CODE_OFF + len(code)
    label_off = {"fname": data_off + FNAME}

    code = bytearray(code)
    for pos, name, end in fixups:
        target = label_off.get(name, CODE_OFF + labels.get(name, 0))
        disp = target - (CODE_OFF + end)
        code[pos:end] = struct.pack("<i", disp)

    file_size = data_off + len(data)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        3, 62, 1,
        CODE_OFF, 64, 0, 0, EHDR_SIZE, PHDR_SIZE, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, 0, 0, file_size, file_size, 0x1000)
    args.out.write_bytes(ehdr + phdr + bytes(code) + data)


if __name__ == "__main__":
    main()
