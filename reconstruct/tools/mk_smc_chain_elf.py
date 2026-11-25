#!/usr/bin/env python3
"""Emit an ET_DYN x86-64 guest exercising SMC under fragment chaining.

Writable-backed fragments carry a source hash that dispatch re-checks,
but a chain link patched into such a fragment would skip the check
entirely: guest code could rewrite the target and keep running stale
arena code through the link. Chaining therefore refuses to link INTO
writable-backed fragments, so every entry rehashes at dispatch.

    mmap RWX page
    write callee  at page+0x00:  mov eax,42; ret
    write caller  at page+0x40:  call callee; ret   (direct exit -> callee)
    call caller x2               warms frags; buggy code chains caller->callee
    rewrite callee -> mov eax,43
    call caller                  must return 43 (a stale link returns 42)
    rewrite callee -> mov eax,44
    call caller                  must return 44 (repeated rehash)
    write "OK\n"; exit 0         fail path exits 66
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFF = EHDR_SIZE + PHDR_SIZE

SYS_MMAP = 9
SYS_MPROTECT = 10
SYS_WRITE = 1
SYS_EXIT = 60
PROT_RW = 3
PROT_RWX = 7
MAP_PRIVATE_ANON = 0x22

CALLEE = 0x00
CALLER = 0x40


def emit() -> bytes:
    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str, int]] = []

    def here(name: str) -> None:
        labels[name] = len(code)

    def rel8(name: str) -> None:
        fixups.append((len(code), name, len(code) + 1))
        code.append(0)

    def sys(nr: int) -> None:
        code.extend(b"\xb8" + struct.pack("<I", nr))
        code.extend(b"\x0f\x05")

    def call_stub(value: int) -> None:
        # lea rax,[r12+CALLER]; call rax; cmp eax,value; jne fail
        code.extend(b"\x49\x8d\x84\x24" + struct.pack("<i", CALLER))
        code.extend(b"\xff\xd0")
        code.extend(b"\x83\xf8" + bytes([value]))
        code.extend(b"\x75"); rel8("fail")

    # --- hot loop: warm the fragment table ----------------------------
    code.extend(b"\xb9" + struct.pack("<I", 1_000_000))  # mov ecx,1M
    loop = len(code)
    code.extend(b"\xff\xc9")                           # dec ecx
    code.extend(b"\x75" + bytes([-(len(code) + 2 - loop) & 0xff]))

    # --- mmap one page RW ----------------------------------------------
    code.extend(b"\x31\xff")                           # xor edi,edi
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000
    code.extend(b"\xba" + struct.pack("<I", PROT_RW))  # mov edx,3
    code.extend(b"\x41\xba" + struct.pack("<I", MAP_PRIVATE_ANON))
    code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")       # mov r8,-1
    code.extend(b"\x4d\x31\xc9")                       # xor r9d,r9d
    sys(SYS_MMAP)
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc4")                       # mov r12,rax

    # callee v1: mov eax,42; ret  (b8 2a 00 00 00 c3) via two dword stores
    code.extend(b"\x41\xc7\x84\x24" + struct.pack("<i", CALLEE) +
                struct.pack("<I", 0x00002AB8))         # mov dword [r12],b8 2a 00 00
    code.extend(b"\x41\xc7\x84\x24" + struct.pack("<i", CALLEE + 2) +
                struct.pack("<I", 0xC3000000))         # mov dword [r12+2],00 00 00 c3

    # caller: call CALLEE; ret  (e8 <rel32>; c3)
    # rel32 = CALLEE - (CALLER + 5)
    rel = CALLEE - (CALLER + 5)
    caller_bytes = b"\xe8" + struct.pack("<i", rel) + b"\xc3"
    for i in range(0, len(caller_bytes), 4):
        code.extend(b"\x41\xc7\x84\x24" +
                    struct.pack("<i", CALLER + i) +
                    caller_bytes[i:i + 4].ljust(4, b"\x90"))

    # mprotect the page RWX so the stubs execute
    code.extend(b"\x4c\x89\xe7")                       # mov rdi,r12
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000
    code.extend(b"\xba" + struct.pack("<I", PROT_RWX)) # mov edx,7
    sys(SYS_MPROTECT)
    code.extend(b"\x85\xc0")                           # test eax,eax
    code.extend(b"\x78"); rel8("fail")                 # js fail

    # warm: two calls install caller+callee frags and (without the guard)
    # a chain link caller->callee that bypasses the source rehash
    call_stub(42)
    call_stub(42)

    # rewrite callee to mov eax,43; ret — only the imm byte changes
    code.extend(b"\x41\xc7\x84\x24" + struct.pack("<i", CALLEE) +
                struct.pack("<I", 0x00002BB8))         # mov dword [r12],b8 2b 00 00
    call_stub(43)

    # second rewrite proves rehashing isn't a one-shot guard
    code.extend(b"\x41\xc7\x84\x24" + struct.pack("<i", CALLEE) +
                struct.pack("<I", 0x00002CB8))         # mov dword [r12],b8 2c 00 00
    call_stub(44)

    # write(1, "OK\n", 3); exit(0)
    code.extend(b"\x41\xc7\x84\x24\x00\x02\x00\x00" +
                b"\x4f\x4b\x0a\x00")                   # mov dword [r12+0x200],"OK\n"
    code.extend(b"\xbf\x01\x00\x00\x00")               # mov edi,1
    code.extend(b"\x49\x8d\xb4\x24\x00\x02\x00\x00")   # lea rsi,[r12+0x200]
    code.extend(b"\xba\x03\x00\x00\x00")               # mov edx,3
    sys(SYS_WRITE)
    code.extend(b"\x31\xff")                           # xor edi,edi
    sys(SYS_EXIT)

    here("fail")
    code.extend(b"\xbf\x42\x00\x00\x00")               # mov edi,66
    sys(SYS_EXIT)

    for off, name, rel_end in fixups:
        code[off] = (labels[name] - rel_end) & 0xFF
    return bytes(code)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    code = emit()

    img = bytearray(EHDR_SIZE + PHDR_SIZE)
    img[0:4] = b"\x7fELF"
    img[4] = 2      # ELFCLASS64
    img[5] = 1      # little-endian
    img[6] = 1      # EV_CURRENT
    struct.pack_into("<H", img, 16, 3)               # ET_DYN
    struct.pack_into("<H", img, 18, 62)              # EM_X86_64
    struct.pack_into("<I", img, 20, 1)
    struct.pack_into("<Q", img, 24, CODE_OFF)        # e_entry
    struct.pack_into("<Q", img, 32, EHDR_SIZE)       # e_phoff
    struct.pack_into("<H", img, 52, EHDR_SIZE)
    struct.pack_into("<H", img, 54, PHDR_SIZE)
    struct.pack_into("<H", img, 56, 1)
    struct.pack_into("<II", img, EHDR_SIZE + 0, 1, 5)         # PT_LOAD RX
    struct.pack_into("<QQQ", img, EHDR_SIZE + 8, 0, 0,
                     CODE_OFF + len(code))
    struct.pack_into("<QQ", img, EHDR_SIZE + 32,
                     CODE_OFF + len(code), 0x1000)
    args.output.write_bytes(bytes(img) + code)


if __name__ == "__main__":
    main()
