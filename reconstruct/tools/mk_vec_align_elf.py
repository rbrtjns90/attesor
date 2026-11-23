#!/usr/bin/env python3
"""Build vec_align_guest.x86_64 — vector memory fault-semantics fixture.

aarch64 NEON ldr/str never faults on unaligned addresses, but aligned x86
vector forms (movdqa/movaps) must #GP on EA & 15, and stores to read-only
guest pages must fault. The guest:

  1. aligned movdqa load+store             -> must succeed
  2. misaligned movdqu load+store          -> must succeed
  3. aligned movaps load+store             -> must succeed
  4. movdqu load crossing a page boundary  -> must succeed
  5. fork: child movdqa load  [r15+1]      -> must fault (else exit 41)
  6. fork: child movaps store [r15+1]      -> must fault (else exit 42)
  7. mprotect page R; fork: child movdqu store -> must fault (else 43)

The parent wait4s each child and requires exit code 126 (guest fault).
All pass -> writes "OK\n", exit 0. Fail exits use codes 11..13 / 41..43.
"""
import struct, sys

B = bytearray()
labels = {}
fixups = []

def emit(*bs): B.extend(bs)
def imm32(v): B.extend(struct.pack('<i', v))
def here(n): labels[n] = len(B)
def rel8(n): fixups.append((len(B), n, len(B) + 1)); B.append(0)

def syscall(nr):
    emit(0xb8); imm32(nr)              # mov eax, nr
    emit(0x0f, 0x05)

def mmap_rw(pages):
    emit(0x31, 0xff)                   # xor edi,edi
    emit(0xbe); imm32(pages * 0x1000)  # mov esi, len
    emit(0xba); imm32(3)               # mov edx, PROT_RW
    emit(0x41, 0xba); imm32(0x22)      # mov r10d, MAP_PRIVATE|ANON
    emit(0x49, 0xc7, 0xc0); imm32(-1)  # mov r8, -1
    emit(0x4d, 0x31, 0xc9)             # xor r9d, r9d
    syscall(9)

def fail(code):
    emit(0xbf); imm32(code)
    syscall(60)

def fault_child(exit_code, body):
    """fork; child runs `body` (must fault; exits exit_code if it
    survives); parent wait4s, requires status 0x7e00, else fail."""
    emit(0xb8); imm32(57)              # mov eax, 57 (fork)
    emit(0x0f, 0x05)
    emit(0x48, 0x85, 0xc0)             # test rax, rax
    emit(0x74); rel8('child' + str(exit_code))
    # parent: wait4(pid, &status=[r14], 0, NULL)
    emit(0x48, 0x89, 0xc7)             # mov rdi, rax
    emit(0x4c, 0x89, 0xf6)             # mov rsi, r14
    emit(0x31, 0xd2)                   # xor edx, edx
    emit(0x45, 0x31, 0xd2)             # xor r10d, r10d
    emit(0xb8); imm32(61)              # mov eax, 61 (wait4)
    emit(0x0f, 0x05)
    emit(0x48, 0x85, 0xc0)             # test rax, rax
    emit(0x7e); rel8('fail')           # jle fail
    emit(0x41, 0x8b, 0x06)             # mov eax, [r14]
    emit(0x3d); imm32(0x7e00)          # cmp eax, 0x7e00 (exit 126)
    emit(0x75); rel8('fail')
    emit(0xeb); rel8('cont' + str(exit_code))
    here('child' + str(exit_code))
    body()
    emit(0xbf); imm32(exit_code)       # survived -> exit(exit_code)
    syscall(60)
    here('cont' + str(exit_code))

# ---------------------------------------------------------------------------
# r15 = 2 test pages RW; r14 = status page RW
mmap_rw(2)
emit(0x49, 0x89, 0xc7)                 # mov r15, rax
mmap_rw(1)
emit(0x49, 0x89, 0xc6)                 # mov r14, rax

# T1: aligned movdqa load+store — must succeed
emit(0x66, 0x41, 0x0f, 0x6f, 0x07)     # movdqa xmm0, [r15]
emit(0x66, 0x41, 0x0f, 0x7f, 0x47, 0x10)  # movdqa [r15+0x10], xmm0
# T2: misaligned movdqu load+store — must succeed
emit(0xf3, 0x41, 0x0f, 0x7f, 0x47, 0x01)  # movdqu [r15+1], xmm0
emit(0xf3, 0x41, 0x0f, 0x6f, 0x47, 0x01)  # movdqu xmm0, [r15+1]
# T3: aligned movaps load+store — must succeed
emit(0x41, 0x0f, 0x28, 0x47, 0x20)     # movaps xmm0, [r15+0x20]
emit(0x41, 0x0f, 0x29, 0x47, 0x20)     # movaps [r15+0x20], xmm0
# T4: movdqu load crossing the page boundary [r15+0xff8] — must succeed
emit(0xf3, 0x41, 0x0f, 0x6f, 0x87); imm32(0xff8)  # movdqu xmm0,[r15+0xff8]

# F1: misaligned movdqa load must fault
fault_child(41, lambda: emit(0x66, 0x41, 0x0f, 0x6f, 0x47, 0x01))
# F2: misaligned movaps store must fault
fault_child(42, lambda: emit(0x41, 0x0f, 0x29, 0x47, 0x01))

# F3: mprotect(r15, 0x2000, R); movdqu store to read-only page must fault
emit(0x4c, 0x89, 0xf8)                 # mov rax, r15
emit(0x48, 0x89, 0xc7)                 # mov rdi, rax
emit(0xbe); imm32(0x2000)              # mov esi, 0x2000
emit(0xba); imm32(1)                   # mov edx, PROT_READ
syscall(10)
fault_child(43, lambda: emit(0xf3, 0x41, 0x0f, 0x7f, 0x07))  # movdqu [r15],xmm0

# success: write(1, msg, 3); exit(0)
emit(0xb8); imm32(1)                   # mov eax, 1
emit(0xbf); imm32(1)                   # mov edi, 1
emit(0x48, 0x8d, 0x35)                 # lea rsi, [rip+msg]
msg_fixup = len(B); B += b'\x00' * 4
msg_end = len(B)
emit(0xba); imm32(3)
emit(0x0f, 0x05)
emit(0x31, 0xff)                       # xor edi, edi
syscall(60)
msg_off = len(B)
B += b'OK\n'

here('fail')
fail(99)                               # generic fail path for wait4 checks

for off, name, base in fixups:
    B[off] = (labels[name] - base) & 0xff
struct.pack_into('<i', B, msg_fixup, msg_off - msg_end)

# ---- ELF: ET_DYN so the cached fragment JIT executes it -------------------
ehsize, phsize = 64, 56
off = ehsize + phsize
data = bytes(B)
elf = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8
elf += struct.pack('<HHIQQQIHHHHHH', 3, 0x3e, 1, off, ehsize, 0, 0,
                   ehsize, phsize, 1, 0, 0, 0)
elf += struct.pack('<IIQQQQQQ', 1, 5, 0, 0, 0, off + len(data),
                   off + len(data), 0x1000)
elf = elf.ljust(off, b'\x00') + data
out = sys.argv[1] if len(sys.argv) > 1 else 'tests/vec_align_guest.x86_64'
open(out, 'wb').write(elf)
print('wrote', len(elf), 'bytes')
