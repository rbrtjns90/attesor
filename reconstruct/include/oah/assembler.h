#ifndef OAH_ASSEMBLER_H
#define OAH_ASSEMBLER_H

#include "oah/assembler_buffer.h"
#include "oah/register.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ARM64 NOP. Used as padding (0xd503201f) in TranslatorBase.hpp fixup loops. */
#define OAH_INSN_NOP 0xd503201fu

/*
 * Emitters below copy the bit formulas from the dump. They return false when
 * the original would have aborted (SP/XZR used in the wrong context, or an
 * AssemblerBase.hpp assert).
 */

/* decomp: FUN_8000000280d0
 * BR (link=0) / BLR (link=1): 0xd61f0000 | (link<<21) | (Rn<<5) */
bool oah_emit_br(oah_asm_buf *buf, bool link, oah_gpr rn);

/* decomp: FUN_800000027914
 * ADC/SBC family: 0x1a000000 / 0x9a000000 | (S<<29) | (op<<30) | Rm<<16|Rn<<5|Rd
 * is_64 selects 0x9a vs 0x1a (sf). op=1 is SBC. set_flags is bit 29. */
bool oah_emit_adc_sbc(oah_asm_buf *buf, bool is_64, bool is_sbc, bool set_flags,
                      oah_gpr rd, oah_gpr rn, oah_gpr rm);

/* orig: AssemblerBase.hpp:0x4d7 ldp_post
 * decomp: FUN_800000028970
 * size is S32 or S64. Immediate is implicit +2 elements (pair writeback). */
bool oah_emit_ldp_post(oah_asm_buf *buf, oah_mem_size size,
                       oah_gpr rt, oah_gpr rt2, oah_gpr rn);

/* orig: AssemblerBase.hpp:0x7f5 stp_pre
 * decomp: FUN_80000002954c */
bool oah_emit_stp_pre(oah_asm_buf *buf, oah_mem_size size,
                      oah_gpr rt, oah_gpr rt2, oah_gpr rn, u32 imm7);

/* orig: AssemblerBase.hpp:0x506 ldr_post  "Rt != Rn"
 * decomp: FUN_800000028c50 (Rn was constant-folded to X4 at this call site;
 *          the API takes Rn, matching the assert). */
bool oah_emit_ldr_post(oah_asm_buf *buf, oah_mem_size size,
                       oah_gpr rt, oah_gpr rn, s32 imm9);

/* orig: AssemblerBase.hpp:0x82c str_pre  "Rt != Rn"
 * decomp: FUN_8000000296f8 */
bool oah_emit_str_pre(oah_asm_buf *buf, oah_mem_size size,
                      oah_gpr rt, oah_gpr rn, s32 imm9);

/* orig: AssemblerBase.hpp:0x894 smov_64
 * decomp: FUN_8000000297e4  index must fit in 2 bits. */
bool oah_emit_smov_64(oah_asm_buf *buf, oah_gpr rd, oah_gpr vn, u32 index);

/* orig: AssemblerBase.hpp:0x982 ushr_vec  "immh != 0"
 * decomp: FUN_800000029a00 */
bool oah_emit_ushr_vec(oah_asm_buf *buf, u32 elem_size_log2,
                       oah_gpr vd, oah_gpr vn, s32 shift);

/* decomp: FUN_800000028c04 — LDR (literal), imm19 = 0, 64-bit. */
bool oah_emit_ldr_literal_pc(oah_asm_buf *buf, oah_gpr rt);

/*
 * MOVZ/MOVK — same encoding as the libc wrappers (e.g. `d2800708` movz x8,#56).
 * hw is the 16-bit shift index 0..3. SP rejected.
 */
bool oah_emit_movz(oah_asm_buf *buf, bool is_64, oah_gpr rd, u32 hw, u32 imm16);
bool oah_emit_movk(oah_asm_buf *buf, bool is_64, oah_gpr rd, u32 hw, u32 imm16);

/* MOV Xd, Xm  = ORR Xd, XZR, Xm. 32-bit zero-extends. */
bool oah_emit_mov_reg(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rm);

/* EOR (shifted register, shift=0). */
bool oah_emit_eor(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn, oah_gpr rm);

/* ADD/SUB Xd, Xn, #imm12 (shift 0). Rn may be SP. */
bool oah_emit_add_sub_imm(oah_asm_buf *buf, bool is_64, bool is_sub,
                          oah_gpr rd, oah_gpr rn, u32 imm12);

/* 64-bit LDR/STR unsigned offset. imm is in bytes, must be 8-aligned. */
bool oah_emit_ldr_str_uoff(oah_asm_buf *buf, bool is_store,
                           oah_gpr rt, oah_gpr rn, u32 imm_bytes);

/* SVC #imm. Binary wrappers use `d4000001` (imm=0). */
bool oah_emit_svc(oah_asm_buf *buf, u16 imm);

/* RET (BR X30). */
bool oah_emit_ret(oah_asm_buf *buf);

/* Materialize a 64-bit constant with MOVZ/MOVK. */
bool oah_emit_mov_u64(oah_asm_buf *buf, oah_gpr rd, u64 val);

/*
 * Extended emitters for the cached-fragment JIT. These follow the same
 * decomp bit formulas; Rn/Rd/Rm are runtime host registers (0..31).
 */

/* Patch a 32-bit instruction already in the buffer (forward fixups). */
void oah_asm_patch32(oah_asm_buf *buf, u64 offset, u32 insn);

/* Add/subtract (shifted register): op bit30 (sub), S bit29 (flags).
 * shift: 0=LSL 1=LSR 2=ASR. */
bool oah_emit_add_sub_reg(oah_asm_buf *buf, bool is_64, bool is_sub,
                          bool set_flags, oah_gpr rd, oah_gpr rn, oah_gpr rm,
                          u32 shift, u32 amount);

/* Logical (shifted register): op selects AND/ORR/EOR/ANDS. */
typedef enum {
    OAH_LOGIC_AND = 0,
    OAH_LOGIC_ORR,
    OAH_LOGIC_EOR,
    OAH_LOGIC_ANDS
} oah_logic_op;
bool oah_emit_logic_reg(oah_asm_buf *buf, oah_logic_op op, bool is_64,
                        oah_gpr rd, oah_gpr rn, oah_gpr rm, u32 shift,
                        u32 amount);

/* ADD/SUB immediate with optional flag update (S bit). */
bool oah_emit_add_sub_imm_flags(oah_asm_buf *buf, bool is_64, bool is_sub,
                                bool set_flags, oah_gpr rd, oah_gpr rn,
                                u32 imm12, u32 sh);

/* Bitfield moves: UBFM (uxtb/uxth/ubfx/lsl/lsr), SBFM (sxt, asr), BFM (bfi). */
bool oah_emit_ubfm(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                   u32 immr, u32 imms);
bool oah_emit_sbfm(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                   u32 immr, u32 imms);
bool oah_emit_bfm(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                  u32 immr, u32 imms);

/* Variable shifts: 0=LSL 1=LSR 2=ASR 3=ROR. */
bool oah_emit_shift_var(oah_asm_buf *buf, bool is_64, u32 which,
                        oah_gpr rd, oah_gpr rn, oah_gpr rm);

/* MOVN (inverted move wide). */
bool oah_emit_movn(oah_asm_buf *buf, bool is_64, oah_gpr rd, u32 hw, u32 imm16);

/* NZCV system register access. */
bool oah_emit_mrs_nzcv(oah_asm_buf *buf, oah_gpr rt);
bool oah_emit_msr_nzcv(oah_asm_buf *buf, oah_gpr rn);

/* Conditional compare: ANDS XZR (TST) / SUBS XZR (CMP), shifted register. */
bool oah_emit_tst_reg(oah_asm_buf *buf, bool is_64, oah_gpr rn, oah_gpr rm,
                      u32 shift, u32 amount);
bool oah_emit_cmp_reg(oah_asm_buf *buf, bool is_64, oah_gpr rn, oah_gpr rm,
                      u32 shift, u32 amount);

/* B.cond / CBZ/CBNZ / TBZ/TBNZ. Offsets are signed byte offsets relative to
 * the instruction; emitters validate range. */
bool oah_emit_bcond(oah_asm_buf *buf, u32 cond, s32 imm19);
bool oah_emit_cbz_cbnz(oah_asm_buf *buf, bool is_64, bool nz, oah_gpr rt,
                       s32 imm19);
bool oah_emit_tbz_tbnz(oah_asm_buf *buf, bool nz, u32 bit, oah_gpr rt,
                       s32 imm14);

/* CSEL / CSINC (conditional select; cset via rn=rm=XZR + inverted cond). */
bool oah_emit_csel(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                   oah_gpr rm, u32 cond);
bool oah_emit_csinc(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                    oah_gpr rm, u32 cond);

/* Multiply: MUL (madd ra=31), SMULH, SMADDL (w->x). */
bool oah_emit_mul(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                  oah_gpr rm);
bool oah_emit_smulh(oah_asm_buf *buf, oah_gpr rd, oah_gpr rn, oah_gpr rm);
bool oah_emit_smull(oah_asm_buf *buf, oah_gpr rd, oah_gpr rn, oah_gpr rm);

/* REV (byte swap): 32 or 64 bit. */
bool oah_emit_rev(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn);

/* CLZ. */
bool oah_emit_clz(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn);

/*
 * Sized guest-memory LDR/STR at [Rn + imm_bytes], unsigned offset.
 * size_log2: 0=B 1=H 2=W 3=X. sign_extend selects LDRSB/LDRSH/LDRSW on loads;
 * dst64 only matters for sign-extended loads.
 */
bool oah_emit_mem(oah_asm_buf *buf, u32 size_log2, bool is_store,
                  bool sign_extend, bool dst64, oah_gpr rt, oah_gpr rn,
                  u32 imm_bytes);

/* ORN (bitwise OR NOT, shifted register) — used for MVN. */
bool oah_emit_orn(oah_asm_buf *buf, bool is_64, oah_gpr rd, oah_gpr rn,
                  oah_gpr rm, u32 shift, u32 amount);

#ifdef __cplusplus
}
#endif

#endif /* OAH_ASSEMBLER_H */
