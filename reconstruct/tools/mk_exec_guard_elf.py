#!/usr/bin/env python3
"""Emit an ET_DYN x86-64 guest that exercises scoped JIT invalidation.

The syscall layer flushes the whole fragment table on any mapping change
that overlaps an executable segment. This fixture proves both sides:

  1. Translation survives unrelated mapping churn: the guest mprotects
     and unmaps a pure-data anonymous mapping — no flush may fire.
  2. Removal works: munmap a range CROSSING a data/exec mapping boundary
     and mprotect-remove-exec on a second stub page — both must flush,
     and the old translations must fault instead of running stale code.

To let the host resolve the reported fault RIP, the guest writes the
three addresses it uses (block base, stub A, stub B) to stdout.

    hot loop            populates the fragment table
    mmap 4 pages        [data][data][stubA][stubB]
    mprotect stubs RWX  add-exec — no flush needed (nothing stale)
    call stubA/stubB    each returns 42 — translations run
    write addrs         host learns the stub GVAs
    data mmap+mprotect+munmap   unrelated churn — must not flush
    call stubA again    re-enters the surviving translation, writes OK
    munmap [page1,page2]        crosses data|exec boundary — must flush
    call stubB again    installs a fresh live fragment to evict
    mprotect stubB -> R         remove exec — must flush live code
    call stubB          must fault (flushed and no PROT_EXEC)
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
SYS_MUNMAP = 11
SYS_MREMAP = 25
SYS_FORK = 57
SYS_WAIT4 = 61
SYS_WRITE = 1
SYS_EXIT = 60
PROT_RW = 3
PROT_R = 1
PROT_RWX = 7
MAP_PRIVATE_ANON = 0x22


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

    def mmap() -> None:
        code.extend(b"\x31\xff")                       # xor edi,edi
        code.extend(b"\x41\xba" + struct.pack("<I", MAP_PRIVATE_ANON))
        code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")   # mov r8,-1
        code.extend(b"\x4d\x31\xc9")                   # xor r9d,r9d
        sys(SYS_MMAP)

    def lea_r12(reg_op: bytes, disp: int) -> None:
        code.extend(reg_op + struct.pack("<i", disp))

    # --- hot loop: populate the fragment table ------------------------
    code.extend(b"\xb9" + struct.pack("<I", 3_000_000))  # mov ecx,3M
    loop = len(code)
    code.extend(b"\xff\xc9")                           # dec ecx
    code.extend(b"\x75" + bytes([-(len(code) + 2 - loop) & 0xff]))

    # --- mmap 4 pages RW: [data][data][stubA][stubB] ------------------
    code.extend(b"\xbe" + struct.pack("<I", 0x4000))   # mov esi,0x4000
    code.extend(b"\xba" + struct.pack("<I", PROT_RW))  # mov edx,3
    mmap()
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc4")                       # mov r12,rax

    # mprotect both stub pages RWX (adds exec: nothing stale, no flush)
    for disp in (0x2000, 0x3000):
        lea_r12(b"\x49\x8d\xbc\x24", disp)             # lea rdi,[r12+d]
        code.extend(b"\xbe\x00\x10\x00\x00")           # mov esi,0x1000
        code.extend(b"\xba" + struct.pack("<I", PROT_RWX))
        sys(SYS_MPROTECT)
        code.extend(b"\x85\xc0")                       # test eax,eax
        code.extend(b"\x78"); rel8("fail")             # js fail

    # stub bytes at each page: mov eax,42 (b8 2a 00 00 00); ret (c3).
    # Two overlapping dword stores with REX.B only — REX.W C7 writes a
    # sign-extended qword (clobbers trailing bytes) and C6 /0 confuses
    # the decoder.
    for disp in (0x2000, 0x3000):
        code.extend(b"\x41\xc7\x84\x24" + struct.pack("<i", disp) +
                    struct.pack("<I", 0x00002AB8))     # mov dword [r12+d],b8 2a 00 00
        code.extend(b"\x41\xc7\x84\x24" + struct.pack("<i", disp + 2) +
                    struct.pack("<I", 0xC3000000))     # mov dword [r12+d+2],00 00 00 c3

    # call each stub; both must return eax=42
    for disp in (0x2000, 0x3000):
        lea_r12(b"\x49\x8d\x84\x24", disp)             # lea rax,[r12+d]
        code.extend(b"\xff\xd0")                       # call rax
        code.extend(b"\x83\xf8\x2a")                   # cmp eax,42
        code.extend(b"\x75"); rel8("fail")             # jne fail

    # report base/stubA/stubB to the host: write(1, buf, 24)
    code.extend(b"\x4d\x89\x64\x24\x20")               # mov [r12+0x20],r12
    lea_r12(b"\x49\x8d\x84\x24", 0x2000)               # lea rax,[r12+0x2000]
    code.extend(b"\x49\x89\x84\x24\x28\x00\x00\x00")   # mov [r12+0x28],rax
    lea_r12(b"\x49\x8d\x84\x24", 0x3000)               # lea rax,[r12+0x3000]
    code.extend(b"\x49\x89\x84\x24\x30\x00\x00\x00")   # mov [r12+0x30],rax
    code.extend(b"\xbf\x01\x00\x00\x00")               # mov edi,1
    lea_r12(b"\x49\x8d\xb4\x24", 0x20)                 # lea rsi,[r12+0x20]
    code.extend(b"\xba\x18\x00\x00\x00")               # mov edx,24
    sys(SYS_WRITE)

    # --- unrelated data mapping churn: must NOT flush -----------------
    code.extend(b"\xbe\x00\x20\x00\x00")               # mov esi,0x2000
    code.extend(b"\xba" + struct.pack("<I", PROT_RW))  # mov edx,3
    mmap()
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc5")                       # mov r13,rax
    code.extend(b"\x49\xc7\x45\x00\x01\x00\x00\x00")   # mov qword [r13],1
    code.extend(b"\x4c\x89\xef")                       # mov rdi,r13
    code.extend(b"\xbe\x00\x20\x00\x00")               # mov esi,0x2000
    code.extend(b"\xba" + struct.pack("<I", PROT_R))   # mov edx,1
    sys(SYS_MPROTECT)                                  # data mprotect
    code.extend(b"\x4c\x89\xef")                       # mov rdi,r13
    code.extend(b"\xbe\x00\x20\x00\x00")               # mov esi,0x2000
    sys(SYS_MUNMAP)                                    # data unmap

    # --- survival proof: stubA's translation must still be installed ---
    lea_r12(b"\x49\x8d\x84\x24", 0x2000)               # lea rax,[r12+0x2000]
    code.extend(b"\xff\xd0")                           # call rax (stubA again)
    code.extend(b"\x83\xf8\x2a")                       # cmp eax,42
    code.extend(b"\x75"); rel8("fail")                 # jne fail
    # write(1, "OK\n", 3) so the host can assert we got here
    code.extend(b"\x41\xc7\x84\x24\x20\x00\x00\x00" +
                b"\x4f\x4b\x0a\x00")                   # mov dword [r12+0x20],"OK\n"
    code.extend(b"\xbf\x01\x00\x00\x00")               # mov edi,1
    lea_r12(b"\x49\x8d\xb4\x24", 0x20)                 # lea rsi,[r12+0x20]
    code.extend(b"\xba\x03\x00\x00\x00")               # mov edx,3
    sys(SYS_WRITE)

    # --- data mremap: grow+move a pure-data page -> must NOT flush ----
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000
    code.extend(b"\xba" + struct.pack("<I", PROT_RW))  # mov edx,3
    mmap()
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc6")                       # mov r14,rax
    code.extend(b"\x41\xc7\x06\xef\xbe\xad\xde")       # mov dword [r14],0xdeadbeef
    code.extend(b"\x4c\x89\xf7")                       # mov rdi,r14
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000 (prior)
    code.extend(b"\xba\x00\x20\x00\x00")               # mov edx,0x2000 (requested)
    code.extend(b"\x41\xba\x01\x00\x00\x00")           # mov r10d,1 (MREMAP_MAYMOVE)
    sys(SYS_MREMAP)
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc6")                       # mov r14,rax (new gva)
    code.extend(b"\x41\x81\x3e\xef\xbe\xad\xde")       # cmp dword [r14],0xdeadbeef
    code.extend(b"\x75"); rel8("fail")                 # jne fail

    # --- exec mremap: move a live translated stub -> must flush -------
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000
    code.extend(b"\xba" + struct.pack("<I", PROT_RW))  # mov edx,3
    mmap()
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc7")                       # mov r15,rax (stubC old gva)
    code.extend(b"\x4c\x89\xff")                       # mov rdi,r15
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000
    code.extend(b"\xba" + struct.pack("<I", PROT_RWX)) # mov edx,7
    sys(SYS_MPROTECT)
    code.extend(b"\x85\xc0")                           # test eax,eax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x41\xc7\x07\xb8\x2a\x00\x00")       # mov dword [r15],0x2ab8
    code.extend(b"\x41\xc7\x47\x02\x00\x00\x00\xc3")   # mov dword [r15+2],0xc3000000
    code.extend(b"\x4c\x89\xf8")                       # mov rax,r15
    code.extend(b"\xff\xd0")                           # call rax -> translate stubC
    code.extend(b"\x83\xf8\x2a")                       # cmp eax,42
    code.extend(b"\x75"); rel8("fail")                 # jne fail
    code.extend(b"\x4c\x89\xff")                       # mov rdi,r15
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000 (prior)
    code.extend(b"\xba\x00\x20\x00\x00")               # mov edx,0x2000 (requested)
    code.extend(b"\x41\xba\x01\x00\x00\x00")           # mov r10d,1 (MREMAP_MAYMOVE)
    sys(SYS_MREMAP)                                    # flushes; moves gva
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x78"); rel8("fail")                 # js fail
    code.extend(b"\x49\x89\xc5")                       # mov r13,rax (stubC new gva)
    # report stubC old/new addresses to the host
    code.extend(b"\x4d\x89\xbc\x24\x40\x00\x00\x00")   # mov [r12+0x40],r15
    code.extend(b"\x4d\x89\xac\x24\x48\x00\x00\x00")   # mov [r12+0x48],r13
    code.extend(b"\xbf\x01\x00\x00\x00")               # mov edi,1
    lea_r12(b"\x49\x8d\xb4\x24", 0x40)                 # lea rsi,[r12+0x40]
    code.extend(b"\xba\x10\x00\x00\x00")               # mov edx,16
    sys(SYS_WRITE)
    # the moved translation must work at the new gva
    code.extend(b"\x4c\x89\xe8")                       # mov rax,r13
    code.extend(b"\xff\xd0")                           # call rax (stubC new)
    code.extend(b"\x83\xf8\x2a")                       # cmp eax,42
    code.extend(b"\x75"); rel8("fail")                 # jne fail

    # --- sacrificial child: the OLD gva must not run stale code -------
    # The parent cannot call the old gva itself — the fault would end the
    # whole run before the stubB checks. fork() instead: the child calls
    # the dead address and must fault (exit 126); if the mremap flush had
    # not fired the stale fragment would run and the child would exit 43.
    code.extend(b"\xb8" + struct.pack("<I", SYS_FORK)) # mov eax,57
    code.extend(b"\x0f\x05")                           # syscall
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x74"); rel8("child")                # jz child
    # parent: wait4(child, &status, 0, NULL)
    code.extend(b"\x48\x89\xc7")                       # mov rdi,rax (pid)
    lea_r12(b"\x49\x8d\xb4\x24", 0x38)                 # lea rsi,[r12+0x38]
    code.extend(b"\x31\xd2")                           # xor edx,edx
    code.extend(b"\x45\x31\xd2")                       # xor r10d,r10d
    code.extend(b"\xb8" + struct.pack("<I", SYS_WAIT4))# mov eax,61
    code.extend(b"\x0f\x05")                           # syscall
    code.extend(b"\x48\x85\xc0")                       # test rax,rax
    code.extend(b"\x7e"); rel8("fail")                 # jle fail
    code.extend(b"\x41\x8b\x84\x24\x38\x00\x00\x00")   # mov eax,[r12+0x38]
    code.extend(b"\x3d\x00\x7e\x00\x00")               # cmp eax,0x7e00 (exit 126)
    code.extend(b"\x75"); rel8("fail")                 # jne fail
    # write(1, "KC\n", 3)
    code.extend(b"\x41\xc7\x84\x24\x38\x00\x00\x00" +
                b"\x4b\x43\x0a\x00")                   # mov dword [r12+0x38],"KC\n"
    code.extend(b"\xbf\x01\x00\x00\x00")               # mov edi,1
    lea_r12(b"\x49\x8d\xb4\x24", 0x38)                 # lea rsi,[r12+0x38]
    code.extend(b"\xba\x03\x00\x00\x00")               # mov edx,3
    sys(SYS_WRITE)
    code.extend(b"\xeb"); rel8("parent_cont")          # jmp over child code
    here("child")
    code.extend(b"\x4c\x89\xf8")                       # mov rax,r15 (old stubC)
    code.extend(b"\xff\xd0")                           # call rax -> must fault
    code.extend(b"\xbf\x2b\x00\x00\x00")               # mov edi,43 (stale ran!)
    sys(SYS_EXIT)
    here("parent_cont")

    # --- crossing munmap: [data page1][exec stubA] -> must flush ------
    lea_r12(b"\x49\x8d\xbc\x24", 0x1000)               # lea rdi,[r12+0x1000]
    code.extend(b"\xbe\x00\x20\x00\x00")               # mov esi,0x2000
    sys(SYS_MUNMAP)

    # --- re-warm stubB: its flush must evict a LIVE translation -------
    # Without this the de-exec flush below only proves a flush was
    # requested — stubB's fragment was already evicted by the crossing
    # munmap. Re-entering installs a fresh fragment so the revoke has
    # real stale code to kill.
    lea_r12(b"\x49\x8d\x84\x24", 0x3000)               # lea rax,[r12+0x3000]
    code.extend(b"\xff\xd0")                           # call rax (stubB)
    code.extend(b"\x83\xf8\x2a")                       # cmp eax,42
    code.extend(b"\x75"); rel8("fail")                 # jne fail

    # --- remove exec on stubB -> must flush ---------------------------
    lea_r12(b"\x49\x8d\xbc\x24", 0x3000)               # lea rdi,[r12+0x3000]
    code.extend(b"\xbe\x00\x10\x00\x00")               # mov esi,0x1000
    code.extend(b"\xba" + struct.pack("<I", PROT_R))   # mov edx,1
    sys(SYS_MPROTECT)

    # --- stubB must fault (flushed and no longer executable) ----------
    lea_r12(b"\x49\x8d\x84\x24", 0x3000)               # lea rax,[r12+0x3000]
    code.extend(b"\xff\xd0")                           # call rax -> fault
    code.extend(b"\xbf\x4d\x00\x00\x00")               # mov edi,77
    sys(SYS_EXIT)                                      # unreachable

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
