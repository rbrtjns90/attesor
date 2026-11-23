#!/usr/bin/env python3
"""Build flag_live_guest.x86_64 — regression fixture for shift flag liveness.

x86 shifts/rotates whose effective count is zero preserve all flags, so a
conditional-writer must not make an earlier producer's flags "dead" in the
liveness pass. Each check below sets flags with a producer, inserts a
zero-count (or masked-to-zero) shift/rotate, then observes with
setcc/jcc/cmovcc. A failing check exits with its test number; all pass ->
writes "OK\n" and exits 0.
"""
import struct, sys

B = bytearray()
def emit(*bs): B.extend(bs)
def imm32(v): B.extend(struct.pack('<i', v))

# ---- helpers --------------------------------------------------------------
# exit with status = test id in edi
def fail(tid):
    emit(0xbf); imm32(tid)            # mov edi, tid
    emit(0xb8); imm32(60)             # mov eax, 60 (exit)
    emit(0x0f, 0x05)                  # syscall

# check edi (actual) == esi (expected); on mismatch exit with tid
def check(tid):
    emit(0x39, 0xf7)                  # cmp edi, esi
    emit(0x74, 0x0a)                  # jz +10
    fail(tid)

# set ZF=1 (and CF=0) via cmp eax,eax
PROD_ZF1 = bytes([0x39, 0xc0])
# produce CF=1: xor eax,eax; sub eax,1 -> borrow
PROD_CF1 = bytes([0x31, 0xc0, 0x83, 0xe8, 0x01])

# ---------------------------------------------------------------------------
# T1: cmp (ZF=1); shl ebx,cl (cl=0); setz dl -> 1
emit(0xb9); imm32(0)                  # mov ecx,0
B += PROD_ZF1
emit(0xd3, 0xe3)                      # shl ebx, cl
emit(0x0f, 0x94, 0xc2)                # setz dl
emit(0x0f, 0xb6, 0xfa)                # movzx edi, dl
emit(0xbe); imm32(1)                  # mov esi, 1
check(1)

# T2: cmp (ZF=1); shr ebx,cl (cl=0); jz taken -> edi=1
emit(0xb9); imm32(0)
B += PROD_ZF1
emit(0xd3, 0xeb)                      # shr ebx, cl
emit(0xbf); imm32(0)                  # mov edi,0
emit(0x74, 0x02)                      # jz +2 -> "mov edi,1"
emit(0xeb, 0x05)                      # jmp +5 -> over "mov edi,1"
emit(0xbf); imm32(1)                  # mov edi,1
emit(0xbe); imm32(1)
check(2)

# T3: cmp (ZF=1); sar edx,cl (cl=0); cmovz edi,esi -> edi=7
emit(0xb9); imm32(0)
emit(0xbf); imm32(0)                  # mov edi,0
emit(0xbe); imm32(7)                  # mov esi,7
B += PROD_ZF1
emit(0xd3, 0xfa)                      # sar edx, cl
emit(0x0f, 0x44, 0xfe)                # cmovz edi, esi
emit(0xbe); imm32(7)
check(3)

# T4: cmp (ZF=1); shl edx, 0 (imm); setz dl -> 1
B += PROD_ZF1
emit(0xc1, 0xe2, 0x00)                # shl edx, 0
emit(0x0f, 0x94, 0xc2)
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(1)
check(4)

# T5: cmp (ZF=1); rol ebx,cl (cl=0); jz -> 1
emit(0xb9); imm32(0)
B += PROD_ZF1
emit(0xd3, 0xc3)                      # rol ebx, cl
emit(0xbf); imm32(0)
emit(0x74, 0x02)                      # jz +2 -> "mov edi,1"
emit(0xeb, 0x05)                      # jmp +5 -> over "mov edi,1"
emit(0xbf); imm32(1)
emit(0xbe); imm32(1)
check(5)

# T6: cmp (ZF=1); ror ebx,cl (cl=0); setz -> 1
emit(0xb9); imm32(0)
B += PROD_ZF1
emit(0xd3, 0xcb)                      # ror ebx, cl
emit(0x0f, 0x94, 0xc2)
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(1)
check(6)

# T7: dword shift masked to zero: cmp; mov ecx,32; shl edx,cl; setz -> 1
emit(0xb9); imm32(32)                 # mov ecx,32 (masked to 0 for dword)
B += PROD_ZF1
emit(0xd3, 0xe2)                      # shl edx, cl
emit(0x0f, 0x94, 0xc2)
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(1)
check(7)

# T8: nonzero count writes shift flags: mov edx,2; cmp(ZF=1); shl edx,cl(1)
#     -> edx=4, ZF=0 -> setz -> 0 (proves the shift's flags won over cmp's)
emit(0xb9); imm32(1)
emit(0xba); imm32(2)                  # mov edx,2
B += PROD_ZF1
emit(0xd3, 0xe2)                      # shl edx, cl
emit(0x0f, 0x94, 0xc2)
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(0)
check(8)

# T9: CF preservation: sub eax,eax; dec eax (CF=1); shl edx,cl(0); setc -> 1
emit(0xb9); imm32(0)
B += PROD_CF1
emit(0xd3, 0xe2)                      # shl edx, cl
emit(0x0f, 0x92, 0xc2)                # setc dl
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(1)
check(9)

# T10: 64-bit shift masked to zero: mov ecx,64; shl rdx,cl; setz -> 1
emit(0xb9); imm32(64)                 # mov ecx,64 (masked to 0 for qword)
emit(0x48, 0x39, 0xc0)                # cmp rax, rax (ZF=1)
emit(0x48, 0xd3, 0xe2)                # shl rdx, cl
emit(0x0f, 0x94, 0xc2)
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(1)
check(10)

# T11: nonzero imm count writes shift flags: mov edx,1; cmp(ZF=1);
#      shl edx,16 -> 0x10000, ZF=0 -> setz -> 0 (shift's flags, not cmp's)
emit(0xba); imm32(1)                  # mov edx,1
B += PROD_ZF1
emit(0xc1, 0xe2, 0x10)                # shl edx, 16
emit(0x0f, 0x94, 0xc2)
emit(0x0f, 0xb6, 0xfa)
emit(0xbe); imm32(0)
check(11)

# success: write(1, msg, 3); exit(0)
emit(0xb8); imm32(1)                  # mov eax,1
emit(0xbf); imm32(1)                  # mov edi,1
emit(0x48, 0x8d, 0x35)                # lea rsi, [rip+disp32]
msg_fixup = len(B); B += b'\x00' * 4
msg_disp_end = len(B)
emit(0xba); imm32(3)                  # mov edx,3
emit(0x0f, 0x05)
emit(0xbf); imm32(0)
emit(0xb8); imm32(60)
emit(0x0f, 0x05)
msg_off = len(B)
B += b'OK\n'
struct.pack_into('<i', B, msg_fixup, msg_off - msg_disp_end)

# ---- ELF ------------------------------------------------------------------
# ET_DYN so the cached fragment JIT (not arm_native) executes it.
ehsize, phsize = 64, 56
off = ehsize + phsize
data = bytes(B)
elf = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8
elf += struct.pack('<HHIQQQIHHHHHH', 3, 0x3e, 1, off, ehsize, 0, 0,
                   ehsize, phsize, 1, 0, 0, 0)
elf += struct.pack('<IIQQQQQQ', 1, 5, 0, 0, 0, off + len(data),
                   off + len(data), 0x1000)
elf = elf.ljust(off, b'\x00') + data
open(sys.argv[1] if len(sys.argv) > 1 else
     'tests/flag_live_guest.x86_64', 'wb').write(elf)
print('wrote', len(elf), 'bytes')
