#!/usr/bin/env python3
"""Emit an ET_DYN x86-64 differential fixture: tagged mini-cases whose
full guest-visible state is dumped to stdout, then a rep movsb that
faults partway into a PROT_NONE page of a MAP_SHARED file.

The suite runs the same bytes and initial state through the optimized
JIT, the eager-flags JIT (OAH_JIT_NOFLAGS), and the interpreter — each
in a separate process, hence separate memory images — and asserts
byte-identical stdout, exit/fault outcome, fault RIP, and the shared
file's committed bytes. OAH_JIT_VERIFY cannot do this: its reference
runs on memory the JIT already mutated, and it disables flag liveness.

Per-case dump record (BUF=688 bytes, 16-aligned for movdqa):
    [0:128]   all 16 GPRs (RIP-relative stores, incl. rsp/r15)
    [128:136] rflags & 0xCD5 (CF PF AF ZF SF DF OF — the defined bits)
    [136:140] case tag
    [144:400] xmm0-15 lanes
    [400:656] DST scratch region (string/memory cases write here)
    [656:688] DST2 second scratch region

Flag bits outside the mask are architecturally undefined for some ops
(e.g. mul/imul) and may legitimately differ between engines.

Register encoding reminder: 0=rax 1=rcx 2=rdx 3=rbx 4=rsp 5=rbp
6=rsi 7=rdi 8-15=r8-r15.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFF = EHDR_SIZE + PHDR_SIZE

SYS_WRITE = 1
SYS_MMAP = 9
SYS_MPROTECT = 10
SYS_FTRUNCATE = 77
SYS_OPENAT = 257
SYS_EXIT = 60
AT_FDCWD = -100
O_RDWR_CREAT_TRUNC = 0x02 | 0x40 | 0x200
PROT_RW = 3
PROT_NONE = 0
MAP_SHARED = 0x01

BUF_LEN = 688
FLAG_MASK = 0xCD5  # CF|PF|AF|ZF|SF|DF|OF
GPRS = list(range(16))

fixups: list[tuple[int, str, int, int]] = []
labels: dict[str, int] = {}
code = bytearray()


def here(name: str) -> None:
    labels[name] = len(code)


def rel32(name: str, add: int = 0) -> None:
    fixups.append((len(code), name, len(code) + 4, add))
    code.extend(b"\x00" * 4)


def rex(r: int = 0, b: int = 0) -> int:
    return 0x48 | (0x04 if r >= 8 else 0) | (0x01 if b >= 8 else 0)


def mov_ri(r: int, imm: int, w: int = 8) -> None:
    if w == 8:
        code.append(0x48 | (1 if r >= 8 else 0))
        code.append(0xB8 + (r & 7))
        code.extend(struct.pack("<Q", imm & 0xFFFFFFFFFFFFFFFF))
    else:
        if r >= 8:
            code.append(0x41)
        code.append(0xB8 + (r & 7))
        code.extend(struct.pack("<I", imm & 0xFFFFFFFF))


def mov_rr(d: int, s: int) -> None:
    code.append(rex(s, d))
    code.extend((0x89, 0xC0 | (s & 7) << 3 | (d & 7)))


def st_rip(s: int, name: str, add: int = 0) -> None:
    code.append(rex(s))
    code.extend((0x89, (s & 7) << 3 | 5))
    rel32(name, add)


def ld_rip(d: int, name: str, add: int = 0) -> None:
    code.append(rex(d))
    code.extend((0x8B, (d & 7) << 3 | 5))
    rel32(name, add)


def lea_rip(d: int, name: str, add: int = 0) -> None:
    code.append(rex(d))
    code.extend((0x8D, (d & 7) << 3 | 5))
    rel32(name, add)


def sti_rip(imm: int, name: str, add: int = 0, w: int = 8) -> None:
    if w == 8:
        code.extend((0x48, 0xC7, 0x05))
    else:
        code.extend((0xC7, 0x05))
    rel32(name, add)
    code.extend(struct.pack("<i", imm))


def alu_rm(subop: int, rm: int, imm: int, w: int = 8) -> None:
    """grp1 reg,imm32: /0 add /1 or /2 adc /3 sbb /4 and /5 sub /6 xor /7 cmp"""
    if w == 8:
        code.append(rex(0, rm))
    elif rm >= 8:
        code.append(0x41)
    code.append(0x81)
    code.append(0xC0 | subop << 3 | (rm & 7))
    code.extend(struct.pack("<i", imm))


def shift_cl(subop: int, rm: int, w: int = 8) -> None:
    """d3 /x reg,cl: /0 rol /1 ror /4 shl /5 shr /7 sar"""
    if w == 8:
        code.append(rex(0, rm))
    elif rm >= 8:
        code.append(0x41)
    code.append(0xD3)
    code.append(0xC0 | subop << 3 | (rm & 7))


def syscall(nr: int) -> None:
    code.extend(b"\xb8" + struct.pack("<I", nr))
    code.extend(b"\x0f\x05")


def jcc(op: int, name: str) -> None:
    code.extend((0x0F, 0x80 + op))
    rel32(name)


def vec_st_rip(xmm: int, name: str, add: int = 0, dq: bool = True) -> None:
    code.append(0x66 if dq else 0xF3)
    if xmm >= 8:
        code.append(0x44)  # REX.R
    code.extend((0x0F, 0x7F, (xmm & 7) << 3 | 5))
    rel32(name, add)


def vec_ld_rip(xmm: int, name: str, add: int = 0, dq: bool = True) -> None:
    code.append(0x66 if dq else 0xF3)
    if xmm >= 8:
        code.append(0x44)
    code.extend((0x0F, 0x6F, (xmm & 7) << 3 | 5))
    rel32(name, add)


def vec_rr(op: int, d: int, s: int, pfx: int = 0x66) -> None:
    code.append(pfx)
    need = (0x04 if d >= 8 else 0) | (0x01 if s >= 8 else 0)
    if need:
        code.append(0x40 | need)
    code.extend((0x0F, op, 0xC0 | (d & 7) << 3 | (s & 7)))


def vec_imm_rip(op: int, d: int, imm: int, name: str, add: int = 0,
                pfx: int = 0x66) -> None:
    """op xmm_d, [rip+name+add], imm8 (pshufd 66 0f 70 / shufps 0f c6)"""
    if pfx:
        code.append(pfx)
    if d >= 8:
        code.append(0x44)
    code.extend((0x0F, op, (d & 7) << 3 | 5))
    rel32(name, add)
    code.append(imm & 0xFF)


# Slots that legitimately hold run-varying pointers: rsp (host-chosen
# stack), rsi (leftover buf gva from the previous write), rcx (syscall
# return RIP). Per-case pointer regs (rdi after rep ops) are added by
# the caller. Masked slots store 0 so runs compare byte-identically.
BASE_MASK = (1 << 4) | (1 << 6) | (1 << 1)  # rsp | rsi | rcx


def dump(tag: int, mask: int = BASE_MASK) -> None:
    for i, r in enumerate(GPRS):
        if (mask >> r) & 1:
            sti_rip(0, "buf", i * 8)
        else:
            st_rip(r, "buf", i * 8)
    code.extend(b"\x9c")                    # pushfq
    code.extend(b"\x58")                    # pop rax
    alu_rm(4, 0, FLAG_MASK)                 # and rax,0xCD5
    st_rip(0, "buf", 128)
    sti_rip(tag, "buf", 136, w=4)
    for x in range(16):
        vec_st_rip(x, "buf", 144 + x * 16)
    code.extend(b"\xbf\x01\x00\x00\x00")    # mov edi,1
    lea_rip(6, "buf")
    code.extend(b"\xba" + struct.pack("<I", BUF_LEN))
    syscall(SYS_WRITE)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    args = ap.parse_args()

    # S1: shl ebx,cl with cl=0 must preserve flags set by the add.
    mov_ri(0, 0x7FFFFFFF, w=4)
    alu_rm(0, 0, 1, w=4)                     # add eax,1 -> OF=SF=1
    mov_ri(3, 0x1234, w=4)
    code.extend(b"\xb1\x00")                 # mov cl,0
    shift_cl(4, 3, w=4)                      # shl ebx,cl (cl=0)
    dump(1)

    # S2: variable shr/sar/rol/ror counts incl. 32/64 wraps.
    mov_ri(3, 0xFEDCBA9876543210)
    code.extend(b"\xb1\x21")                 # mov cl,33
    shift_cl(5, 3)                           # shr rbx,cl (33)
    mov_ri(6, 0x80000000, w=4)
    code.extend(b"\xb1\x20")                 # mov cl,32
    shift_cl(7, 6, w=4)                      # sar esi,cl (32 -> sign fill)
    mov_ri(5, 0x0123456789ABCDEF)
    code.extend(b"\xb1\x08")                 # mov cl,8
    shift_cl(0, 5)                           # rol rbp,cl
    mov_ri(6, 0xA5A5A5A5A5A5A5A5)
    code.extend(b"\xb1\x48")                 # mov cl,72
    shift_cl(1, 6)                           # ror rsi,cl (72&63=8)
    dump(2)

    # S3: adc/sbb carry polarity — CF via add-borrow vs xor-clear.
    mov_ri(1, 0xFFFFFFFF, w=4)
    alu_rm(0, 1, 1, w=4)                     # add ecx,1 -> CF=1
    mov_ri(0, 5)
    alu_rm(2, 0, 7)                          # adc rax,7 -> 13
    mov_ri(3, 3)
    code.extend(b"\x48\x39\xd8")             # cmp rax,rbx -> CF=0
    alu_rm(3, 3, 10)                         # sbb rbx,10
    code.extend(b"\x31\xc9")                 # xor ecx,ecx -> CF=0
    mov_ri(1, 1, w=4)
    code.extend(b"\x48\x39\xd9")             # cmp rcx,rbx -> CF=1 (1<rbx)
    alu_rm(2, 3, 0)                          # adc rbx,0
    dump(3)

    # S4: inc/dec preserve CF.
    mov_ri(1, 0xFFFFFFFF, w=4)
    alu_rm(0, 1, 1, w=4)                     # CF=1
    mov_ri(0, 0xFFFFFFFF, w=4)
    code.extend(b"\xff\xc0")                 # inc eax -> 0, CF kept
    code.extend(b"\xff\xc8")                 # dec eax
    dump(4)

    # S5: neg/not flag paths.
    mov_ri(0, 1)
    code.extend(b"\x48\xf7\xd8")             # neg rax -> CF=1
    mov_ri(3, 0)
    code.extend(b"\x48\xf7\xdb")             # neg rbx -> CF=0
    code.extend(b"\x48\xf7\xd0")             # not rax (no flags)
    dump(5)

    # S6: setcc + cmov across conditions after a cmp.
    mov_ri(0, 5)
    mov_ri(3, 9)
    code.extend(b"\x48\x39\xd8")             # cmp rax,rbx
    code.extend(b"\x0f\x97\xc0")             # seta al
    code.extend(b"\x0f\x93\xc1")             # setae cl
    code.extend(b"\x0f\x92\xc2")             # setb dl
    code.extend(b"\x0f\x96\xc3")             # setbe bl
    code.extend(b"\x41\x0f\x94\xc0")         # sete r8b
    code.extend(b"\x41\x0f\x9c\xc1")         # setl r9b
    code.extend(b"\x48\x0f\x43\xc8")         # cmovae rcx,rax (no move)
    code.extend(b"\x48\x0f\x42\xcb")         # cmovb rcx,rbx (moves)
    dump(6)

    # S7: bt/bts/btc immediate + register forms + CF result.
    mov_ri(0, 0)
    code.extend(b"\x48\x0f\xba\xe8\x03")     # bts rax,3
    code.extend(b"\x0f\xba\xf8\x03")         # btc eax,3
    code.extend(b"\x48\x0f\xba\xf8\x01")     # btc rax,1
    mov_ri(3, 3)
    code.extend(b"\x48\x0f\xa3\xd8")         # bt rax,rbx -> CF
    dump(7)

    # S8: movsx/movzx/cqo.
    mov_ri(0, 0x80, w=4)
    code.extend(b"\x48\x0f\xbe\xd8")         # movsx rbx,al
    code.extend(b"\x0f\xb6\xc8")             # movzx ecx,al
    mov_ri(0, 0x8000000000000000)
    code.extend(b"\x48\x99")                 # cqo -> rdx=~0
    mov_ri(0, 0x8000, w=4)
    code.extend(b"\x0f\xbf\xd0")             # movsx edx,ax
    dump(8)

    # S9: xadd/cmpxchg/xchg on scratch.
    sti_rip(0x100, "dst")
    mov_ri(0, 5)
    code.extend(b"\x48\x0f\xc1\x05"); rel32("dst")   # xadd [dst],rax
    mov_ri(0, 0x105)
    mov_ri(3, 0x200)
    code.extend(b"\x48\x0f\xb1\x1d"); rel32("dst")   # cmpxchg [dst],rbx
    mov_ri(2, 0x777)
    code.extend(b"\x48\x87\x15"); rel32("dst")       # xchg [dst],rdx
    dump(9)

    # S10: scaled/rip addressing forms.
    mov_ri(3, 3)
    lea_rip(2, "table")
    code.extend(b"\x48\x8b\x44\xda\x08")     # mov rax,[rdx+rbx*8+8]
    mov_ri(1, 1)
    code.extend(b"\x48\x8d\x0c\xcd\x11\x22\x33\x44")
                                             # lea rcx,[rcx*8+0x44332211]
    dump(10, BASE_MASK | (1 << 2))           # rdx = table ptr

    # S11: mul / imul (undefined flag fields masked out of the dump).
    mov_ri(0, 0xFFFFFFFFFFFFFFFF)
    mov_ri(3, 0x10)
    code.extend(b"\x48\xf7\xe3")             # mul rbx -> rdx:rax
    mov_ri(1, 0xFFFFFFFD, w=4)
    code.extend(b"\x48\x0f\xaf\xcb")         # imul rcx,rbx
    dump(11)

    # S12: pushfq/popfq flag round-trip through memory.
    mov_ri(1, 0xFFFFFFFF, w=4)
    alu_rm(0, 1, 1, w=4)                     # CF=1
    code.extend(b"\x9c")                     # pushfq
    code.extend(b"\x58")                     # pop rax -> flags
    code.extend(b"\x48\x83\xc8\x01")         # or rax,1 (set CF bit)
    code.extend(b"\x50")                     # push rax
    code.extend(b"\x9d")                     # popfq
    mov_ri(0, 0x40)
    code.extend(b"\x48\xff\xc0")             # inc rax (defined flags)
    dump(12)

    # V1: movdqa + paddb/psubd/pcmpeqd/pshufd.
    vec_ld_rip(0, "vec0")
    vec_ld_rip(1, "vec1")
    vec_rr(0xFC, 0, 1)                       # paddb xmm0,xmm1
    vec_ld_rip(2, "vec2")
    vec_rr(0xFA, 2, 1)                       # psubd xmm2,xmm1
    vec_rr(0x76, 0, 1)                       # pcmpeqd xmm0,xmm1
    vec_imm_rip(0x70, 3, 0x1B, "vec1")       # pshufd xmm3,[vec1],0x1b
    dump(20)

    # V2: logic + shifts + movq/movd + movdqu unaligned.
    vec_ld_rip(4, "vec0")
    vec_ld_rip(5, "vec1")
    vec_rr(0xEF, 4, 4)                       # pxor xmm4,xmm4 -> 0
    vec_rr(0xEB, 4, 5)                       # por xmm4,xmm5
    vec_rr(0xDB, 4, 5)                       # pand xmm4,xmm5
    code.extend(b"\x66\x0f\x73\xfc\x04")     # pslldq xmm4,4
    code.extend(b"\x66\x0f\x73\xdc\x02")     # psrldq xmm4,2
    vec_ld_rip(6, "vec0", add=3, dq=False)   # movdqu unaligned load
    vec_st_rip(6, "dst", add=8, dq=False)    # movdqu unaligned store
    mov_ri(0, 0x1122334455667788)
    code.extend(b"\x66\x48\x0f\x6e\xf8")     # movq xmm7,rax
    vec_rr(0xD6, 0, 7)                       # movq xmm0,xmm7
    dump(21)

    # V3: shufps on high xmms + movaps round trip through scratch.
    vec_ld_rip(8, "vec0")
    vec_ld_rip(9, "vec1")
    code.extend(b"\x45\x0f\xc6\xc1\x4e")     # shufps xmm8,xmm9,0x4e
    vec_st_rip(8, "dst2")
    vec_ld_rip(10, "dst2")
    dump(22)

    # T1: rep stosb + rep stosq into dst2.
    lea_rip(7, "dst2")
    mov_ri(0, 0x41, w=4)
    mov_ri(1, 9)
    code.extend(b"\xfc")                     # cld
    code.extend(b"\xf3\xaa")                 # rep stosb
    mov_ri(0, 0xDEADBEEFCAFEF00D)
    mov_ri(1, 2)
    code.extend(b"\xf3\x48\xab")             # rep stosq
    dump(30, BASE_MASK | (1 << 7))           # rdi = dst end ptr

    # T2: rep movsb + rep movsq src->dst.
    lea_rip(6, "src")
    lea_rip(7, "dst")
    mov_ri(1, 24)
    code.extend(b"\xf3\xa4")                 # rep movsb
    lea_rip(6, "src")
    lea_rip(7, "dst", add=32)
    mov_ri(1, 2)
    code.extend(b"\xf3\x48\xa5")             # rep movsq
    dump(31, BASE_MASK | (1 << 7))

    # The faulting rep movsb: shared 2-page file, page 2 PROT_NONE.
    code.extend(b"\xbf" + struct.pack("<i", AT_FDCWD))
    lea_rip(6, "fname")
    code.extend(b"\xba" + struct.pack("<I", O_RDWR_CREAT_TRUNC))
    code.extend(b"\x41\xba" + struct.pack("<I", 0o644))
    syscall(SYS_OPENAT)
    code.extend(b"\x48\x85\xc0")
    jcc(0x8, "cerr")
    mov_rr(14, 0)                            # r14 = fd

    mov_rr(7, 14)
    mov_ri(6, 0x2000, w=4)
    syscall(SYS_FTRUNCATE)
    code.extend(b"\x48\x85\xc0")
    jcc(0x8, "cerr")

    code.extend(b"\x31\xff")                 # xor edi,edi
    mov_ri(6, 0x2000, w=4)
    mov_ri(2, PROT_RW, w=4)
    code.extend(b"\x41\xba" + struct.pack("<I", MAP_SHARED))
    mov_rr(8, 14)
    code.extend(b"\x4d\x31\xc9")             # xor r9d,r9d
    syscall(SYS_MMAP)
    code.extend(b"\x48\x85\xc0")
    jcc(0x8, "cerr")
    mov_rr(15, 0)                            # r15 = shared base

    mov_rr(7, 15)
    alu_rm(0, 7, 0x1000)
    mov_ri(6, 0x1000, w=4)
    code.extend(b"\x31\xd2")                 # xor edx,edx (PROT_NONE)
    syscall(SYS_MPROTECT)
    code.extend(b"\x48\x85\xc0")
    jcc(0x8, "cerr")

    mov_rr(7, 15)                            # rdi = base
    lea_rip(6, "srcpat")
    mov_ri(1, 0x1800)
    code.extend(b"\xfc")
    code.extend(b"\xf3\xa4")                 # rep movsb -> FAULT page 2
    mov_ri(7, 99, w=4)
    syscall(SYS_EXIT)

    here("cerr")
    mov_ri(7, 5, w=4)
    syscall(SYS_EXIT)

    # =============== data blob ===============
    fname = b"diff.bin\x00"
    srcpat = bytes((i * 7 + 3) & 0xFF for i in range(0x2000))
    vec0 = bytes(range(16))
    vec1 = bytes((0xF0 | i) for i in range(16))
    vec2 = bytes((i * 2) & 0xFF for i in range(16))
    table = b"".join(struct.pack("<Q", 0x9000 + i) for i in range(8))
    src = b"HELLO-ATTESOR-ZZZ!"
    src2 = b"HELLO-ATTESOR-ZZQ!"

    data_off = CODE_OFF + len(code)
    # Structured tail (srcpat..vec2) must sit on a 16 boundary for
    # movdqa — choose pad0 so the tail start is 16-aligned.
    pad0 = (16 - (data_off + len(fname)) % 16) % 16
    names: dict[str, int] = {}
    off = 0
    names["fname"] = off; off += len(fname) + pad0
    names["srcpat"] = off; off += len(srcpat)
    names["vec0"] = off; off += 16
    names["vec1"] = off; off += 16
    names["vec2"] = off; off += 16
    names["table"] = off; off += len(table)
    names["src"] = off; off += len(src)
    names["src2"] = off; off += len(src2)
    # buf must sit at a 16-aligned file offset (== gva offset).
    padbuf = (16 - (data_off + off) % 16) % 16
    off += padbuf
    names["buf"] = off; off += BUF_LEN

    data = fname + b"\x00" * pad0 + srcpat + vec0 + vec1 + vec2 + table \
        + src + src2 + b"\x00" * padbuf \
        + b"\x00" * BUF_LEN
    assert len(data) == off

    label_off = {k: data_off + v for k, v in names.items()}
    # dst/dst2 live INSIDE the dumped buf so string/memory results
    # reach stdout: dst = buf+400, dst2 = buf+656.
    label_off["dst"] = label_off["buf"] + 400
    label_off["dst2"] = label_off["buf"] + 656
    for pos, name, end, add in fixups:
        target = label_off.get(name, CODE_OFF + labels.get(name, 0)) + add
        code[pos:end] = struct.pack("<i", target - (CODE_OFF + end))

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
