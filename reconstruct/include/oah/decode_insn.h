#ifndef OAH_DECODE_INSN_H
#define OAH_DECODE_INSN_H

#include "oah/decoder.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OAH_OP_INVALID = 0,
    OAH_OP_NOP,
    OAH_OP_ENDBR64,
    OAH_OP_SYSCALL,
    OAH_OP_RET,
    OAH_OP_MOV_IMM,     /* rST = imm; opsize 4 zero-extends, 8 is imm64 */
    OAH_OP_XOR_RR,      /* rST ^= rSRC, opsize */
    OAH_OP_MOV_RR,      /* rST = rSRC */
    OAH_OP_LEA_RIP,     /* rST = rip_after + disp32 */
    OAH_OP_PUSH,
    OAH_OP_PUSH_IMM,
    OAH_OP_POP,
    OAH_OP_JMP_REL,
    OAH_OP_CALL_REL,
    OAH_OP_CMP_RR,
    OAH_OP_CMP_IMM,
    OAH_OP_TEST_RR,
    OAH_OP_JCC_REL,
    OAH_OP_SCALAR,
    OAH_OP_STRING,
    OAH_OP_VECTOR,
    OAH_OP_RDTSC,
    OAH_OP_CPUID,
    OAH_OP_LEAVE,
    OAH_OP_FXSTATE,
    OAH_OP_X87_MOVE,
    OAH_OP_X87_COMPARE
} oah_op;

typedef enum {
    OAH_SC_MOV, OAH_SC_LEA, OAH_SC_MOVSX, OAH_SC_MOVZX,
    OAH_SC_ADD, OAH_SC_OR, OAH_SC_ADC, OAH_SC_SBB, OAH_SC_AND,
    OAH_SC_SUB, OAH_SC_XOR, OAH_SC_CMP, OAH_SC_TEST,
    OAH_SC_JMP, OAH_SC_CALL, OAH_SC_CMOV, OAH_SC_SETCC,
    OAH_SC_SHL, OAH_SC_SHR, OAH_SC_SAR, OAH_SC_ROL, OAH_SC_ROR, OAH_SC_SHLD, OAH_SC_SHRD, OAH_SC_IMUL, OAH_SC_NEG, OAH_SC_NOT, OAH_SC_BSF, OAH_SC_BSR, OAH_SC_INC, OAH_SC_DEC, OAH_SC_XCHG, OAH_SC_DIV, OAH_SC_BT, OAH_SC_BTS, OAH_SC_BTR, OAH_SC_BTC, OAH_SC_MUL, OAH_SC_CMPXCHG, OAH_SC_CMPXCHG8B, OAH_SC_XADD, OAH_SC_PUSH
} oah_scalar_op;

typedef struct {
    u8 base;
    u8 index;
    u8 scale;
    u8 segment;
    bool rip_relative;
    bool address32;
    s32 disp;
} oah_address;

#define OAH_NO_GPR 16

typedef struct {
    oah_op op;
    u8  length;
    u8  opsize; /* 1, 2, 4, or 8 */
    u8  dst;    /* gpr 0..15 */
    u8  src;
    u8  cc;     /* x86 condition for Jcc */
    u64 imm;
    s32 disp;
    oah_scalar_op scalar;
    oah_address address;
    bool memory;
    bool rm_dest;
    bool immediate;
    bool rex_present;
    u8 src_width;
    bool repeat;
    bool string_move;
    u8 vector_opcode;
    u8 x87_modrm;
    bool aligned;
} oah_insn;

/*
 * Long-mode decoder for the nolibc vertical slice.
 * Prefix handling follows FUN_80000008d8c0 (REX 4x, seg 26/2e/36/3e).
 * Uses Decoder.cpp read_int for immediates (15-byte limit).
 */
bool oah_decode_insn(const u8 *pc, const u8 *end, oah_insn *out);

#ifdef __cplusplus
}
#endif

#endif /* OAH_DECODE_INSN_H */
