#!/usr/bin/env python3
"""Emit an ET_DYN x86-64 guest that stress-tests per-thread JIT state.

The guest clone()s one worker thread. Parent and child then run the SAME
code at the SAME rip — the exact case where a shared JIT fragment must
not leak state: each thread sets its own FS base via arch_prctl, writes a
distinct marker to fs:[0], loads a distinct constant into xmm0, then
spins verifying both survive. A fragment baked for one thread and run by
the other reads the wrong TLS base or xmm shadow and fails immediately.

Exits 0 and prints "workerjit ok\n" only if both threads keep their own
state for the full iteration count.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFF = EHDR_SIZE + PHDR_SIZE

# Linux x86-64
SYS_WRITE = 1
SYS_NANOSLEEP = 35
SYS_CLONE = 56
SYS_EXIT = 60
SYS_ARCH_PRCTL = 158
ARCH_SET_FS = 0x1002
# CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM
CLONE_FLAGS = 0x10F00 | 0x40000

# Per-thread verify-loop iterations: a leaked FS/XMM state fails within a
# few iterations, so this only needs to be large enough that both threads
# trade guest_lock slices many times. The parent waits on a nanosleep
# poll — a blocking syscall that releases guest_lock — so an interpreted
# worker gets real time; WAIT_BOUND is in ~1ms polls.
ITERS = 500_000
WAIT_BOUND = 20_000 # ~20s of 1ms polls waiting for the child

# Data-block offsets (r15-relative).
TLS_P = 0
TLS_C = 8
DONE = 16
MSG_OK = 24
MSG_FAIL = 40
MSG_TOUT = 56
MSG_CERR = 80
TS = 104
STACK = 120
STACK_LEN = 8192

OK = b"workerjit ok\n"
FAIL = b"workerjit FAIL\n"
TOUT = b"workerjit TIMEOUT\n"
CERR = b"workerjit clone FAILED\n"


def emit() -> bytes:
    code = bytearray()
    fixups: list[tuple[int, str, int]] = []  # (imm_pos, label, insn_end)
    labels: dict[str, int] = {}

    def here(name: str) -> None:
        labels[name] = len(code)

    def rel8(name: str) -> None:
        fixups.append((len(code), name, len(code) + 1))
        code.append(0)

    def rel32(name: str) -> None:
        fixups.append((len(code), name, len(code) + 4))
        code.extend(b"\x00" * 4)

    def lea_rip(reg: int, name: str) -> None:
        """lea reg,[rip+disp32] where disp targets data-block label."""
        code.append(0x48 | (0x04 if reg >= 8 else 0))
        code.append(0x8D)
        code.append((reg & 7) << 3 | 5)
        fixups.append((len(code), name, len(code) + 4))
        code.extend(b"\x00" * 4)

    def movabs(reg: int, imm: int) -> None:
        code.append(0x48 | (0x01 if reg >= 8 else 0))
        code.append(0xB8 + (reg & 7))
        code.extend(struct.pack("<Q", imm))

    # r15 = data base (patched below against file layout).
    code.extend(b"\x4c\x8d\x3d" + b"\x00" * 4)  # lea r15,[rip+d]

    # clone(flags, child_stack_top, 0, 0, 0)
    code.extend(b"\xb8" + struct.pack("<I", SYS_CLONE))
    code.extend(b"\xbf" + struct.pack("<I", CLONE_FLAGS))
    lea_rip(6, "stack_top")                 # lea rsi,[rip+stack_top]
    code.extend(b"\x31\xd2")                # xor edx,edx
    code.extend(b"\x4d\x31\xd2")            # xor r10d,r10d
    code.extend(b"\x4d\x31\xc0")            # xor r8d,r8d
    code.extend(b"\x0f\x05")                # syscall

    # Shared path: child sees rax=0, parent sees child tid.
    code.extend(b"\x49\x89\xc4")            # mov r12,rax (who am I)
    code.extend(b"\x48\x85\xc0")            # test rax,rax
    code.extend(b"\x0f\x88") ; rel32("cerr")  # js cerr (clone failed)
    lea_rip(3, "tls_p")                     # lea rbx,[rip+tls_p]
    lea_rip(1, "tls_c")                     # lea rcx,[rip+tls_c]
    code.extend(b"\x48\x85\xc0")            # test rax,rax
    code.extend(b"\x48\x0f\x44\xd9")        # cmovz rbx,rcx
    movabs(13, 0xAAAAAAAAAAAAAAA1)          # parent marker
    movabs(0, 0xBBBBBBBBBBBBBBB2)           # child marker
    code.extend(b"\x4c\x0f\x44\xe8")        # cmovz r13,rax

    # arch_prctl(ARCH_SET_FS, rbx) — each thread gets its own FS base.
    code.extend(b"\xb8" + struct.pack("<I", SYS_ARCH_PRCTL))
    code.extend(b"\xbf" + struct.pack("<I", ARCH_SET_FS))
    code.extend(b"\x48\x89\xde")            # mov rsi,rbx
    code.extend(b"\x0f\x05")                # syscall
    code.extend(b"\x48\x85\xc0")            # test rax,rax
    code.extend(b"\x0f\x85") ; rel32("fail")  # jnz fail

    # fs:[0] <- marker ; xmm0 <- marker
    code.extend(b"\x64\x4c\x89\x2c\x25\x00\x00\x00\x00")  # mov fs:[0],r13
    code.extend(b"\x66\x49\x0f\x6e\xc5")                 # movq xmm0,r13

    # Verify loop: our TLS slot and xmm0 must keep OUR values.
    code.extend(b"\xb9" + struct.pack("<I", ITERS))      # mov ecx,ITERS
    here("loop")
    code.extend(b"\x64\x48\x8b\x04\x25\x00\x00\x00\x00")  # mov rax,fs:[0]
    code.extend(b"\x4c\x39\xe8")                          # cmp rax,r13
    code.extend(b"\x0f\x85") ; rel32("fail")              # jne fail
    code.extend(b"\x66\x48\x0f\x7e\xc0")                  # movq rax,xmm0
    code.extend(b"\x4c\x39\xe8")                          # cmp rax,r13
    code.extend(b"\x0f\x85") ; rel32("fail")              # jne fail
    code.extend(b"\xff\xc9")                              # dec ecx
    code.extend(b"\x75") ; rel8("loop")                   # jnz loop

    code.extend(b"\x4d\x85\xe4")            # test r12,r12
    code.extend(b"\x74") ; rel8("child")    # jz child

    # Parent: poll the child's done flag with nanosleep(1ms) between
    # checks — a blocking syscall releases guest_lock so the worker gets
    # real time instead of contending with a JIT-speed spin.
    code.extend(b"\xba" + struct.pack("<I", WAIT_BOUND))  # mov edx,BOUND
    here("wait")
    code.extend(b"\x41\x80\x7f" + bytes([DONE]) + b"\x00")  # cmp byte [r15+DONE],0
    code.extend(b"\x75") ; rel8("ok")       # jnz ok
    code.extend(b"\xb8" + struct.pack("<I", SYS_NANOSLEEP))
    lea_rip(7, "ts")                        # lea rdi,[rip+ts]
    code.extend(b"\x31\xf6")                # xor esi,esi
    code.extend(b"\x0f\x05")                # syscall
    code.extend(b"\xff\xca")                # dec edx
    code.extend(b"\x74") ; rel8("tout")     # jz tout
    code.extend(b"\xeb") ; rel8("wait")     # jmp wait

    # Child: flag done and exit.
    here("child")
    code.extend(b"\x41\xc6\x47" + bytes([DONE - 0]) + b"\x01")  # mov byte [r15+DONE],1
    code.extend(b"\xb8" + struct.pack("<I", SYS_EXIT))
    code.extend(b"\x31\xff")                # xor edi,edi
    code.extend(b"\x0f\x05")                # syscall

    def write_and_exit(msg: str, status: int) -> None:
        code.extend(b"\xb8" + struct.pack("<I", SYS_WRITE))
        code.extend(b"\xbf\x01\x00\x00\x00")            # mov edi,1
        lea_rip(6, msg)                                 # lea rsi,[rip+msg]
        ln = {"msg_ok": OK, "msg_fail": FAIL, "msg_tout": TOUT,
              "msg_cerr": CERR}[msg]
        code.extend(b"\xba" + struct.pack("<I", len(ln)))
        code.extend(b"\x0f\x05")
        code.extend(b"\xb8" + struct.pack("<I", SYS_EXIT))
        code.extend(b"\xbf" + bytes([status]) + b"\x00\x00\x00")
        code.extend(b"\x0f\x05")

    here("ok")
    write_and_exit("msg_ok", 0)
    here("fail")
    write_and_exit("msg_fail", 1)
    here("tout")
    write_and_exit("msg_tout", 2)
    here("cerr")
    write_and_exit("msg_cerr", 3)

    return bytes(code), labels, fixups


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    args = ap.parse_args()

    code, labels, fixups = emit()

    data = bytearray()
    data += b"\x00" * 8          # tls_p
    data += b"\x00" * 8          # tls_c
    data += b"\x00" * 8          # done (pad)
    assert len(data) == MSG_OK
    data += OK + b"\x00" * (MSG_FAIL - MSG_OK - len(OK))
    data += FAIL + b"\x00" * (MSG_TOUT - MSG_FAIL - len(FAIL))
    data += TOUT + b"\x00" * (MSG_CERR - MSG_TOUT - len(TOUT))
    data += CERR + b"\x00" * (TS - MSG_CERR - len(CERR))
    data += struct.pack("<QQ", 0, 1000000)   # ts: 1ms nanosleep poll
    assert len(data) == STACK
    data += b"\x00" * STACK_LEN

    data_off = CODE_OFF + len(code)
    stack_top = data_off + STACK + STACK_LEN - 16
    label_off = {
        "tls_p": data_off + TLS_P,
        "tls_c": data_off + TLS_C,
        "stack_top": stack_top,
        "msg_ok": data_off + MSG_OK,
        "msg_fail": data_off + MSG_FAIL,
        "msg_tout": data_off + MSG_TOUT,
        "msg_cerr": data_off + MSG_CERR,
        "ts": data_off + TS,
    }

    code = bytearray(code)
    for pos, name, end in fixups:
        if name in label_off:
            target = label_off[name]
        else:
            target = CODE_OFF + labels[name]
        disp = target - (CODE_OFF + end)
        code[pos:end] = (struct.pack("<b", disp) if end - pos == 1
                         else struct.pack("<i", disp))
    # r15 lea (first instruction): imm at offset 3, insn end at 7.
    code[3:7] = struct.pack("<i", data_off - (CODE_OFF + 7))

    file_size = data_off + len(data)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        3, 62, 1,
        CODE_OFF, 64, 0, 0, EHDR_SIZE, PHDR_SIZE, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, 0, 0, file_size, file_size, 0x1000)
    args.out.write_bytes(ehdr + phdr + bytes(code) + bytes(data))


if __name__ == "__main__":
    main()
