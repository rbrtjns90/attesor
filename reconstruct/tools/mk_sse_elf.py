#!/usr/bin/env python3
"""Emit an ET_DYN x86-64 guest exercising the JIT's SSE translation subset.

The guest runs each op against fixed input vectors, stores every result
into an output arena, then write(1, out, len). A sibling <out>.expected
file carries the byte-exact stdout so test_macos.py can compare across
jit/jit-nochain/interpret and the cold/warm persistent-cache matrix.

ET_DYN with p_vaddr=0 is required: identity mapping routes execution
through the cached-fragment JIT where frag_translate_vector lives.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFF = EHDR_SIZE + PHDR_SIZE

INA = bytes(range(0, 256, 17))          # 00 11 22 ... ff (16 bytes)
INB = bytes(reversed(range(0, 256, 17)))  # ff ee dd ... 00


def modrm(mod: int, reg: int, rm: int) -> bytes:
    return bytes([(mod << 6) | (reg << 3) | rm])


def ld_xmm_regreg(pref: bytes, op: int, dst: int, src: int) -> bytes:
    return pref + b"\x0f" + bytes([op]) + modrm(3, dst, src)


def ld_xmm_mem(pref: bytes, op: int, dst: int, disp: int) -> bytes:
    """xmm <- [rbx + disp32]"""
    return pref + b"\x0f" + bytes([op]) + modrm(2, dst, 3) + struct.pack("<i", disp)


def st_xmm_mem(pref: bytes, op: int, src: int, disp: int) -> bytes:
    """[rbp + disp32] <- xmm"""
    return pref + b"\x0f" + bytes([op]) + modrm(2, src, 5) + struct.pack("<i", disp)


def movabs(gpr: int, imm: int) -> bytes:
    return bytes([0x48 | (1 if gpr >= 8 else 0), 0xB8 + (gpr & 7)]) + struct.pack("<Q", imm)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    args = ap.parse_args()

    code = bytearray()
    model_out = bytearray()

    # Input arena layout (offsets from r14).
    A, B = 0, 16
    data = INA + INB

    # Output slot allocator: 16-byte slots from r15.
    slot = 0

    def out_slot() -> int:
        nonlocal slot
        d = slot * 16
        slot += 1
        return d

    # Helpers emitting the common "load ina->xmm0, inb->xmm1" prologue.
    def load2() -> None:
        code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))   # movdqu xmm0,[ina]
        code.extend(ld_xmm_mem(b"\xf3", 0x6F, 1, B))   # movdqu xmm1,[inb]

    def store_xmm(xmm: int, model: bytes) -> None:
        d = out_slot()
        code.extend(st_xmm_mem(b"\xf3", 0x7F, xmm, d))  # movdqu [slot],xmm
        model_out.extend(model)

    def store_gpr64(gpr: int, model8: bytes) -> None:
        d = out_slot()
        # mov [rbp+d], gpr  (REX.W 89 /r, reg field = gpr)
        rex = 0x48 | (0x04 if gpr >= 8 else 0)
        code.extend(bytes([rex, 0x89]) + modrm(2, gpr & 7, 5) + struct.pack("<i", d))
        model_out.extend(model8 + b"\x00" * 8)

    def store_gpr32(gpr: int, model4: bytes) -> None:
        d = out_slot()
        code.extend(bytes([0x89]) + modrm(2, gpr & 7, 5) + struct.pack("<i", d))
        model_out.extend(model4 + b"\x00" * 12)

    def zip_lanes(a: bytes, b: bytes, esize: int, high: bool) -> bytes:
        n = 16 // esize
        lo = 0 if not high else n // 2
        out = bytearray()
        for i in range(n // 2):
            out += a[(lo + i) * esize:(lo + i + 1) * esize]
            out += b[(lo + i) * esize:(lo + i + 1) * esize]
        return bytes(out)

    def lanes(v: bytes, esize: int) -> list[int]:
        return [int.from_bytes(v[i * esize:(i + 1) * esize], "little")
                for i in range(16 // esize)]

    def unlanes(vals: list[int], esize: int) -> bytes:
        m = (1 << (8 * esize)) - 1
        return b"".join((v & m).to_bytes(esize, "little") for v in vals)

    def emit_alu(name: str, op: int, fn) -> None:
        load2()
        code.extend(ld_xmm_regreg(b"\x66", op, 0, 1))
        store_xmm(0, fn())

    def sbytes(v: bytes, esize: int) -> list[int]:
        mask = 1 << (8 * esize - 1)
        return [x - (mask << 1) if x & mask else x for x in lanes(v, esize)]

    # --- pure-vector ops ---------------------------------------------------
    emit_alu("pxor", 0xEF,
             lambda: unlanes([x ^ y for x, y in zip(lanes(INA, 8), lanes(INB, 8))], 8))
    emit_alu("por", 0xEB,
             lambda: unlanes([x | y for x, y in zip(lanes(INA, 8), lanes(INB, 8))], 8))
    emit_alu("pand", 0xDB,
             lambda: unlanes([x & y for x, y in zip(lanes(INA, 8), lanes(INB, 8))], 8))
    emit_alu("psubb", 0xF8,
             lambda: unlanes([x - y for x, y in zip(lanes(INA, 1), lanes(INB, 1))], 1))
    emit_alu("psubd", 0xFA,
             lambda: unlanes([x - y for x, y in zip(lanes(INA, 4), lanes(INB, 4))], 4))
    emit_alu("paddq", 0xD4,
             lambda: unlanes([x + y for x, y in zip(lanes(INA, 8), lanes(INB, 8))], 8))
    for name, op, es in (("pcmpeqb", 0x74, 1), ("pcmpeqd", 0x76, 4)):
        emit_alu(name, op,
                 lambda es=es: unlanes(
                     [(1 << (8 * es)) - 1 if x == y else 0
                      for x, y in zip(lanes(INA, es), lanes(INB, es))], es))
    for name, op, es, hi in (("punpcklbw", 0x60, 1, False),
                             ("punpckhwd", 0x69, 2, True),
                             ("punpcklqdq", 0x6C, 8, False),
                             ("punpckhqdq", 0x6D, 8, True)):
        emit_alu(name, op, lambda es=es, hi=hi: zip_lanes(INA, INB, es, hi))
    emit_alu("pminub", 0xDA,
             lambda: unlanes([min(x, y) for x, y in zip(lanes(INA, 1), lanes(INB, 1))], 1))
    emit_alu("pmaxub", 0xDE,
             lambda: unlanes([max(x, y) for x, y in zip(lanes(INA, 1), lanes(INB, 1))], 1))
    aw, bw = sbytes(INA, 2), sbytes(INB, 2)
    emit_alu("pmaddwd", 0xF5,
             lambda: unlanes([aw[2 * i] * bw[2 * i] +
                              aw[2 * i + 1] * bw[2 * i + 1]
                              for i in range(4)], 4))
    load2()
    code.extend(ld_xmm_regreg(b"", 0x12, 0, 1))               # movhlps (unprefixed)
    store_xmm(0, INB[8:16] + INA[8:16])        # dst.d0=src.d1, dst.d1 kept
    load2()
    code.extend(ld_xmm_regreg(b"", 0x16, 0, 1))               # movlhps (unprefixed)
    store_xmm(0, INA[0:8] + INB[0:8])          # dst.d1=src.d0, dst.d0 kept

    # --- shift group (imm forms) --------------------------------------------
    def emit_shift(ext: int, count: int, model: bytes) -> None:
        load2()
        code.extend(b"\x66\x0f\x73" + modrm(3, ext, 0) + bytes([count]))
        store_xmm(0, model)

    emit_shift(7, 5, b"\x00" * 5 + INA[:11])            # pslldq 5
    emit_shift(3, 9, INA[9:] + b"\x00" * 9)             # psrldq 9
    emit_shift(2, 7, unlanes([x >> 7 for x in lanes(INA, 8)], 8))   # psrlq 7
    emit_shift(6, 12, unlanes([x << 12 for x in lanes(INA, 8)], 8))  # psllq 12

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    code.extend(b"\x66\x0f\x72" + modrm(3, 4, 0) + b"\x04")         # psrad 4
    store_xmm(0, unlanes([x >> 4 for x in sbytes(INA, 4)], 4))

    # --- shuffle --------------------------------------------------------------
    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, B))
    code.extend(b"\x66\x0f\x70" + modrm(3, 0, 0) + b"\x1b")         # pshufd 0x1b
    iv = lanes(INB, 4)
    store_xmm(0, unlanes([iv[3], iv[2], iv[1], iv[0]], 4))

    load2()
    code.extend(b"\x66\x0f\xc6" + modrm(3, 0, 1) + b"\x01")         # shufpd 1
    ad, bd = lanes(INA, 8), lanes(INB, 8)
    store_xmm(0, unlanes([ad[1], bd[0]], 8))

    # --- gpr <-> xmm moves -----------------------------------------------------
    code.extend(b"\xb8\x44\x33\x22\x11")                            # mov eax,0x11223344
    code.extend(ld_xmm_regreg(b"\x66", 0x6E, 0, 0))                 # movd xmm0,eax
    store_xmm(0, struct.pack("<I", 0x11223344) + b"\x00" * 12)

    code.extend(movabs(0, 0x1122334455667788))                      # movabs rax,..
    code.extend(ld_xmm_regreg(b"\x66\x48", 0x6E, 1, 0))             # movq xmm1,rax
    store_xmm(1, struct.pack("<Q", 0x1122334455667788) + b"\x00" * 8)

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    code.extend(ld_xmm_regreg(b"\x66", 0x7E, 0, 0))                 # movd eax,xmm0
    store_gpr32(0, struct.pack("<I", int.from_bytes(INA[:4], "little")))

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    code.extend(ld_xmm_regreg(b"\x66\x48", 0x7E, 0, 2))             # movq rdx,xmm0
    store_gpr64(2, INA[:8])

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    code.extend(ld_xmm_regreg(b"\x66", 0xD7, 1, 0))                 # pmovmskb ecx,xmm0
    mask = sum(((INA[i] >> 7) & 1) << i for i in range(16))
    store_gpr32(1, struct.pack("<I", mask))

    # --- xmm<->xmm and 64-bit halves -------------------------------------------
    load2()
    code.extend(ld_xmm_regreg(b"\xf3", 0x7E, 0, 1))                 # movq xmm0,xmm1
    store_xmm(0, INB[:8] + b"\x00" * 8)

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    d = out_slot()
    code.extend(ld_xmm_mem(b"\x66", 0x16, 0, B))                    # movhpd xmm0,[inb]
    code.extend(st_xmm_mem(b"\xf3", 0x7F, 0, d))
    model_out.extend(INA[:8] + INB[:8])

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    d = out_slot()
    code.extend(ld_xmm_mem(b"\x66", 0x12, 0, B + 8))                # movlpd xmm0,[inb+8]
    code.extend(st_xmm_mem(b"\xf3", 0x7F, 0, d))
    model_out.extend(INB[8:16] + INA[8:16])

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    d = out_slot()
    code.extend(st_xmm_mem(b"\x66", 0x13, 0, d))                    # movlpd [d],xmm0
    model_out.extend(INA[:8] + b"\x00" * 8)

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    d = out_slot()
    code.extend(st_xmm_mem(b"\x66", 0x17, 0, d))                    # movhpd [d],xmm0
    model_out.extend(INA[8:16] + b"\x00" * 8)

    code.extend(ld_xmm_mem(b"\xf3", 0x6F, 0, A))
    d = out_slot()
    code.extend(st_xmm_mem(b"\x66", 0xD6, 0, d))                    # movq [d],xmm0
    model_out.extend(INA[:8] + b"\x00" * 8)

    d = out_slot()
    code.extend(ld_xmm_mem(b"\xf3", 0x7E, 0, B))                    # movq xmm0,[inb]
    code.extend(st_xmm_mem(b"\xf3", 0x7F, 0, d))
    model_out.extend(INB[:8] + b"\x00" * 8)

    # --- write(1, out, len); exit(0) -------------------------------------------
    code.extend(b"\xb8\x01\x00\x00\x00")            # mov eax,1
    code.extend(b"\xbf\x01\x00\x00\x00")            # mov edi,1
    code.extend(b"\x48\x89\xee")                    # mov rsi,rbp
    code.extend(b"\xba" + struct.pack("<I", len(model_out)))  # mov edx,len
    code.extend(b"\x0f\x05")                        # syscall
    code.extend(b"\xb8\x3c\x00\x00\x00")            # mov eax,60
    code.extend(b"\x31\xff")                        # xor edi,edi
    code.extend(b"\x0f\x05")

    # Layout: headers | code | data | out-arena (zeroed). The guest maps
    # at an arbitrary load bias, so only rip-relative addressing works:
    #   lea rbx,[rip+d] (48 8d 1d) = data base
    #   lea rbp,[rip+d] (48 8d 2d) = out base
    prologue = b"\x48\x8d\x1d" + b"\x00" * 4 + b"\x48\x8d\x2d" + b"\x00" * 4
    code = bytearray(prologue) + code
    data_off = CODE_OFF + len(code)
    out_off = data_off + len(data)
    file_size = out_off + len(model_out)
    code[3:7] = struct.pack("<i", data_off - (CODE_OFF + 7))
    code[10:14] = struct.pack("<i", out_off - (CODE_OFF + 14))

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        3, 62, 1,                # ET_DYN, EM_X86_64
        CODE_OFF, 64, 0, 0, EHDR_SIZE, PHDR_SIZE, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, 0, 0, file_size, file_size, 0x1000)

    args.out.write_bytes(ehdr + phdr + bytes(code) + data + b"\x00" * len(model_out))
    args.out.with_suffix(args.out.suffix + ".expected").write_bytes(bytes(model_out))


if __name__ == "__main__":
    main()
