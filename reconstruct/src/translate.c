#include "oah/translate.h"

#include "oah/assembler.h"
#include "oah/decode_insn.h"
#include "oah/register.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static oah_gpr xn(oah_x86_gpr g)
{
    return (oah_gpr)oah_host_xn_for_x86_gpr(g);
}

static bool emit_mov_imm(oah_asm_buf *buf, oah_x86_gpr g, u8 opsize, u64 imm)
{
    oah_gpr d = xn(g);
    if (opsize == 8) {
        return oah_emit_mov_u64(buf, d, imm);
    }
    /* 32-bit write zero-extends: MOVZ/MOVK Wd */
    if (!oah_emit_movz(buf, false, d, 0, (u32)(imm & 0xffffu))) {
        return false;
    }
    if ((imm >> 16) & 0xffffu) {
        return oah_emit_movk(buf, false, d, 1, (u32)((imm >> 16) & 0xffffu));
    }
    return true;
}

bool oah_translate_block(oah_asm_buf *buf, oah_image *img, u64 rip, u64 *next_rip)
{
    return oah_translate_block_flags(buf, img, rip, next_rip, 0);
}

bool oah_translate_block_flags(oah_asm_buf *buf, oah_image *img, u64 rip,
                               u64 *next_rip, u32 flags)
{
    unsigned n = 0;
    u64 cur = rip;
    int host_svc = (flags & OAH_XLAT_HOST_SVC) != 0;

    if (next_rip) {
        *next_rip = rip;
    }

    while (n < 64) {
        u64 available = OAH_X86_MAX_INSN;
        const u8 *pc = oah_guest_span(img, cur, &available);
        oah_insn in;
        u64 after;
        bool is_64;
        oah_gpr rsp;

        if (!pc || !oah_guest_access(img, cur, 1, PROT_EXEC)) {
            if (n == 0) {
                return false;
            }
            break;
        }
        if (!oah_decode_insn(pc, pc + available, &in)) {
            if (n == 0) {
                return false;
            }
            break;
        }
        after = cur + in.length;
        is_64 = in.opsize == 8;
        rsp = xn(OAH_X86_RSP);

        switch (in.op) {
        case OAH_OP_NOP:
        case OAH_OP_ENDBR64:
            break;
        case OAH_OP_MOV_IMM:
            if (!emit_mov_imm(buf, (oah_x86_gpr)in.dst, in.opsize, in.imm)) {
                return false;
            }
            break;
        case OAH_OP_XOR_RR:
            if (flags & OAH_XLAT_DISPATCH_STATE) {
                return n == 0 || oah_emit_ret(buf);
            }
            if (!oah_emit_eor(buf, is_64, xn((oah_x86_gpr)in.dst),
                              xn((oah_x86_gpr)in.dst), xn((oah_x86_gpr)in.src))) {
                return false;
            }
            break;
        case OAH_OP_MOV_RR:
            if (!oah_emit_mov_reg(buf, is_64, xn((oah_x86_gpr)in.dst),
                                  xn((oah_x86_gpr)in.src))) {
                return false;
            }
            break;
        case OAH_OP_LEA_RIP:
            if (!oah_emit_mov_u64(buf, xn((oah_x86_gpr)in.dst),
                                  after + (u64)(s64)in.disp)) {
                return false;
            }
            break;
        case OAH_OP_PUSH:
            if (flags & OAH_XLAT_DISPATCH_STATE) {
                return n == 0 || oah_emit_ret(buf);
            }
            if (!oah_emit_add_sub_imm(buf, true, true, rsp, rsp, 8) ||
                !oah_emit_ldr_str_uoff(buf, true, xn((oah_x86_gpr)in.dst), rsp, 0)) {
                return false;
            }
            break;
        case OAH_OP_POP:
            if (in.memory || (flags & OAH_XLAT_DISPATCH_STATE)) {
                if (in.memory && !(flags & OAH_XLAT_DISPATCH_STATE)) {
                    return false;
                }
                return n == 0 || oah_emit_ret(buf);
            }
            if (!oah_emit_ldr_str_uoff(buf, false, xn((oah_x86_gpr)in.dst), rsp, 0) ||
                !oah_emit_add_sub_imm(buf, true, false, rsp, rsp, 8)) {
                return false;
            }
            break;
        case OAH_OP_SYSCALL:
            if (flags & OAH_XLAT_DISPATCH_STATE) {
                return n == 0 || oah_emit_ret(buf);
            }
            if (host_svc) {
                if (!oah_emit_runtime_syscall_host(buf)) {
                    return false;
                }
            } else if (!oah_emit_runtime_syscall(buf)) {
                return false;
            }
            break;
        case OAH_OP_JMP_REL:
            cur = after + (u64)(s64)in.disp;
            if (next_rip) {
                *next_rip = cur;
            }
            return oah_emit_ret(buf);
        case OAH_OP_PUSH_IMM:
        case OAH_OP_CALL_REL:
        case OAH_OP_RET:
        case OAH_OP_CMP_RR:
        case OAH_OP_CMP_IMM:
        case OAH_OP_TEST_RR:
        case OAH_OP_JCC_REL:
        case OAH_OP_SCALAR:
        case OAH_OP_STRING:
        case OAH_OP_VECTOR:
        case OAH_OP_RDTSC:
        case OAH_OP_CPUID:
        case OAH_OP_LEAVE:
        case OAH_OP_FXSTATE:
        case OAH_OP_X87_MOVE:
        case OAH_OP_X87_COMPARE:
        case OAH_OP_EMPTY_MMX:
        case OAH_OP_FLAGS_STACK:
        case OAH_OP_SET_DIRECTION:
        case OAH_OP_STORE_FENCE:
        case OAH_OP_SIGN_HIGH:
            if (!(flags & OAH_XLAT_DISPATCH_STATE)) {
                return false;
            }
            return n == 0 || oah_emit_ret(buf);
        default:
            return false;
        }

        cur = after;
        n++;
        if (next_rip) {
            *next_rip = cur;
        }

        if (in.op == OAH_OP_SYSCALL) {
            /* Keep going; exit is detected when SVC runs. */
        }
    }
    return oah_emit_ret(buf);
}

/* ================= Cached-fragment translation =================
 *
 * Register contract inside fragments (oah_jit_native_enter):
 *   x0–x15  guest GPRs        x19  guest RFLAGS (eager, full SZAPCO)
 *   x20     next guest RIP    x16,x17,x21–x28  scratch
 * Every fragment sets x20 before RET.
 */

enum {
    F_RF = 19, F_NR = 20,
    T0 = 16, T1 = 17, T2 = 21, T3 = 22, T4 = 23, T5 = 24, T6 = 25, T7 = 26
};

static bool frag_lsl(oah_asm_buf *buf, bool is64, u8 rd, u8 rn, u32 sh)
{
    /* lsl = UBFM rd, rn, #(bits-sh), #(bits-1-sh) */
    u32 bits = is64 ? 64 : 32;
    if (!sh || sh >= bits) {
        return false;
    }
    return oah_emit_ubfm(buf, is64, rd, rn, bits - sh, bits - 1 - sh);
}

static bool frag_lsr(oah_asm_buf *buf, bool is64, u8 rd, u8 rn, u32 sh)
{
    return oah_emit_ubfm(buf, is64, rd, rn, sh, (is64 ? 63 : 31));
}

static bool frag_asr(oah_asm_buf *buf, bool is64, u8 rd, u8 rn, u32 sh)
{
    return oah_emit_sbfm(buf, is64, rd, rn, sh, (is64 ? 63 : 31));
}

static bool frag_ubfx(oah_asm_buf *buf, u8 rd, u8 rn, u32 lsb, u32 w)
{
    return oah_emit_ubfm(buf, false, rd, rn, lsb, lsb + w - 1);
}

static bool frag_bfi(oah_asm_buf *buf, u8 rd, u8 rn, u32 lsb, u32 w)
{
    return oah_emit_bfm(buf, true, rd, rn, (64 - lsb) & 63, w - 1);
}

static bool frag_movi(oah_asm_buf *buf, u8 rd, u64 val)
{
    return oah_emit_mov_u64(buf, rd, val);
}

static bool frag_mov(oah_asm_buf *buf, bool is64, u8 rd, u8 rm)
{
    if (rd == rm) {
        return true;
    }
    return oah_emit_mov_reg(buf, is64, rd, rm);
}

/* Set by oah_translate_frag while emitting; the helpers below are only
 * reachable under it, so the pointer cannot dangle elsewhere. */
static oah_frag_info *frag_relocs;

/* Fixed-length (4 insn) 64-bit materialization recorded for relocation.
 * Guest addresses and FS/GS bases must be rebindable when a persisted
 * fragment is reused at a different load address. */
static bool emit_reloc_imm(oah_asm_buf *buf, u8 rd, u64 val, u32 kind)
{
    if (frag_relocs) {
        if (frag_relocs->nrelocs == OAH_FRAG_MAX_RELOCS) {
            frag_relocs->reloc_overflow = 1;
        } else {
            oah_frag_reloc *r =
                &frag_relocs->relocs[frag_relocs->nrelocs++];
            r->off = (u32)buf->size;
            r->kind = kind;
            r->rd = rd;
            r->value = val;
        }
    }
    return oah_emit_movz(buf, true, rd, 0, (u32)(val & 0xffff)) &&
           oah_emit_movk(buf, true, rd, 1, (u32)((val >> 16) & 0xffff)) &&
           oah_emit_movk(buf, true, rd, 2, (u32)((val >> 32) & 0xffff)) &&
           oah_emit_movk(buf, true, rd, 3, (u32)((val >> 48) & 0xffff));
}

/* Read guest GPR (partial width, zero-extended) into host reg hr. */
static bool emit_read_gpr(oah_asm_buf *buf, u8 hr, u8 g, u8 width, bool rex)
{
    if (width == 1 && !rex && g >= 4 && g <= 7) {
        return oah_emit_ubfm(buf, false, hr, xn((oah_x86_gpr)(g - 4)), 8, 15);
    }
    if (width == 8) {
        return frag_mov(buf, true, hr, xn((oah_x86_gpr)g));
    }
    if (width == 4) {
        return frag_mov(buf, false, hr, xn((oah_x86_gpr)g));
    }
    return oah_emit_ubfm(buf, false, hr, xn((oah_x86_gpr)g), 0, width * 8 - 1);
}

/* Store host reg hv into guest GPR partial field. */
static bool emit_store_gpr(oah_asm_buf *buf, u8 g, u8 hv, u8 width, bool rex)
{
    if (width == 1 && !rex && g >= 4 && g <= 7) {
        return frag_bfi(buf, xn((oah_x86_gpr)(g - 4)), hv, 8, 8);
    }
    if (width == 8) {
        return frag_mov(buf, true, xn((oah_x86_gpr)g), hv);
    }
    if (width == 4) {
        return frag_mov(buf, false, xn((oah_x86_gpr)g), hv);
    }
    return frag_bfi(buf, xn((oah_x86_gpr)g), hv, 0, width * 8);
}

/* Effective address -> ea register. FS/GS bases are baked in. */
static bool emit_ea(oah_asm_buf *buf, const oah_guest *g, const oah_address *a,
                    u64 next, u8 ea)
{
    bool have = false;
    if (a->rip_relative) {
        if (!emit_reloc_imm(buf, ea, next, OAH_RELOC_GVA)) {
            return false;
        }
        have = true;
    } else if (a->base != OAH_NO_GPR) {
        if (!oah_emit_mov_reg(buf, true, ea, xn((oah_x86_gpr)a->base))) {
            return false;
        }
        have = true;
    }
    if (a->index != OAH_NO_GPR) {
        if (have) {
            if (!oah_emit_add_sub_reg(buf, true, false, false, ea, ea,
                                      xn((oah_x86_gpr)a->index), 0, a->scale)) {
                return false;
            }
        } else {
            if (!frag_lsl(buf, true, ea, xn((oah_x86_gpr)a->index), a->scale)) {
                return false;
            }
        }
        have = true;
    }
    if (a->disp) {
        s64 d = a->disp;
        if (!have) {
            if (!frag_movi(buf, ea, (u64)d)) {
                return false;
            }
            have = true;
        } else if (d > 0 && d <= 4095) {
            if (!oah_emit_add_sub_imm(buf, true, false, ea, ea, (u32)d)) {
                return false;
            }
        } else if (d < 0 && d >= -4095) {
            if (!oah_emit_add_sub_imm(buf, true, true, ea, ea, (u32)-d)) {
                return false;
            }
        } else {
            if (!frag_movi(buf, T7, (u64)d) ||
                !oah_emit_add_sub_reg(buf, true, false, false, ea, ea, T7, 0, 0)) {
                return false;
            }
        }
    }
    if (!have && !frag_movi(buf, ea, 0)) {
        return false;
    }
    if (a->address32 && !frag_mov(buf, false, ea, ea)) {
        return false;
    }
    if (a->segment == 0x64 || a->segment == 0x65) {
        u32 kind = a->segment == 0x64 ? OAH_RELOC_FS : OAH_RELOC_GS;
        u64 base = a->segment == 0x64 ? g->fs_base : g->gs_base;
        if (!emit_reloc_imm(buf, T7, base, kind) ||
            !oah_emit_add_sub_reg(buf, true, false, false, ea, ea, T7, 0, 0)) {
            return false;
        }
    }
    return true;
}

static u32 mem_size_log2(u8 width)
{
    return width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3;
}

/* Scratch regs reserved for the flag-merge helpers (never operand regs). */
enum { M1 = 27, M2 = 28 };

/* --- Guest flag liveness ----------------------------------------------------
 * The translator used to rematerialize every produced flag field into the
 * x19 shadow (F_RF) after each arithmetic/logic instruction — ~10-14 host
 * insns per guest op whether or not anything ever reads them. A per-fragment
 * liveness pre-pass now computes which produced fields reach a consumer (or
 * the fragment exit, which needs a complete shadow for interp handoff), and
 * producers merge only those. Producers still emit the flag-setting host
 * op, so NZCV stays live: flag consumers (jcc/setcc/cmov) test NZCV
 * directly whenever the fields they read were produced in it.
 *
 * Masks use the guest rflags bit positions for the six status flags. */
#define OAH_FL_CF   0x001u
#define OAH_FL_PF   0x004u
#define OAH_FL_AF   0x010u
#define OAH_FL_ZF   0x040u
#define OAH_FL_SF   0x080u
#define OAH_FL_OF   0x800u
#define OAH_FL_ALL  0x8d5u
#define OAH_FL_NZCV (OAH_FL_CF | OAH_FL_ZF | OAH_FL_SF | OAH_FL_OF)

/* Which guest flag fields currently live in host NZCV, and the C polarity
 * (1 = C holds !guestCF — the sub/cmp/restore convention). PF/AF are never
 * NZCV-resident. */
static __thread u16 nzcv_fields;
static __thread int nzcv_cfinv;

/* Per-insn merge masks from the liveness pre-pass, indexed by the emit
 * loop's insn counter; uncovered insns fall back to ALL (eager merge). */
#define OAH_FLAG_SCAN_MAX 256
static __thread oah_insn frag_pins[OAH_FLAG_SCAN_MAX];
static __thread u16 frag_frd[OAH_FLAG_SCAN_MAX];
static __thread u16 frag_fwr[OAH_FLAG_SCAN_MAX];
static __thread u16 frag_fmerge[OAH_FLAG_SCAN_MAX];
static __thread unsigned frag_fmerge_n;

/* x86 condition code -> guest flag fields it reads. */
static u16 cc_flag_mask(u8 cc)
{
    switch (cc & 0xf) {
    case 0: case 1:   return OAH_FL_OF;
    case 2: case 3:   return OAH_FL_CF;
    case 4: case 5:   return OAH_FL_ZF;
    case 6: case 7:   return OAH_FL_CF | OAH_FL_ZF;
    case 8: case 9:   return OAH_FL_SF;
    case 10: case 11: return OAH_FL_PF;
    default:          return OAH_FL_ZF | OAH_FL_SF | OAH_FL_OF;
    }
}

/* Flag read/write masks (status fields only) for the liveness pre-pass.
 * Anything that may take an interpreter boundary reads ALL: the exit then
 * forces preceding producers to leave F_RF complete. */
static void insn_flag_masks(const oah_insn *in, u16 *rd, u16 *wr)
{
    *rd = 0;
    *wr = 0;
    switch (in->op) {
    case OAH_OP_XOR_RR: case OAH_OP_CMP_RR: case OAH_OP_CMP_IMM:
    case OAH_OP_TEST_RR:
        *wr = OAH_FL_ALL;
        return;
    case OAH_OP_JCC_REL: case OAH_OP_RET:
    case OAH_OP_JMP_REL: case OAH_OP_CALL_REL:
        *rd = OAH_FL_ALL;            /* fragment exit */
        return;
    case OAH_OP_FLAGS_STACK:
        *rd = OAH_FL_ALL;            /* pushf reads the whole shadow */
        return;
    case OAH_OP_SCALAR:
        switch (in->scalar) {
        case OAH_SC_MOV: case OAH_SC_LEA: case OAH_SC_MOVSX:
        case OAH_SC_MOVZX: case OAH_SC_NOT: case OAH_SC_BSWAP:
        case OAH_SC_PUSH: case OAH_SC_XCHG:
            return;
        case OAH_SC_DIV:
            *rd = OAH_FL_ALL;        /* internal #DE bail exits to interp */
            return;
        case OAH_SC_ADD: case OAH_SC_SUB: case OAH_SC_CMP:
        case OAH_SC_OR: case OAH_SC_AND: case OAH_SC_XOR:
        case OAH_SC_TEST: case OAH_SC_NEG:
            *wr = OAH_FL_ALL;
            return;
        case OAH_SC_SHL: case OAH_SC_SHR: case OAH_SC_SAR: {
            if (!in->immediate) {
                /* CL count: a masked-to-zero count preserves every
                 * flag (the emit sits behind a cbz) — conditional
                 * writer: it may read all fields and may write all. */
                *rd = OAH_FL_ALL;
                *wr = OAH_FL_ALL;
                return;
            }
            u32 bits = in->opsize * 8;
            u32 raw = (u32)(in->imm & (in->opsize == 8 ? 63 : 31));
            if (!raw) {
                return;                 /* no-op: flags preserved */
            }
            *wr = OAH_FL_ALL & ~(OAH_FL_CF | OAH_FL_OF);
            if (raw <= bits) {
                *wr |= OAH_FL_CF;       /* defined when count <= width */
            }
            if (raw == 1) {
                *wr |= OAH_FL_OF;       /* defined only for count 1 */
            }
            return;
        }
        case OAH_SC_INC: case OAH_SC_DEC:
            *wr = OAH_FL_ALL & ~OAH_FL_CF;
            return;
        case OAH_SC_IMUL:
            *wr = OAH_FL_CF | OAH_FL_OF;
            return;
        case OAH_SC_ROL: case OAH_SC_ROR: {
            if (in->opsize < 4) {
                *rd = OAH_FL_ALL;    /* narrow widths -> interp boundary */
            }
            if (!in->immediate) {
                /* CL count: masked-to-zero preserves all flags. */
                *rd = OAH_FL_ALL;
                *wr = OAH_FL_CF | OAH_FL_OF;
                return;
            }
            u32 m = (u32)(in->imm & (in->opsize == 8 ? 63 : 31));
            if (!m) {
                return;                 /* no-op: flags preserved */
            }
            *wr = OAH_FL_CF;            /* CF written for any masked>0 */
            if (m == 1) {
                *wr |= OAH_FL_OF;
            }
            return;
        }
        case OAH_SC_BSF: case OAH_SC_BSR:
            *wr = OAH_FL_ZF;
            return;
        case OAH_SC_SETCC: case OAH_SC_CMOV:
            /* P/NP conds are always interp-boundary in the emit loop. */
            *rd = (in->cc & 0xfe) == 10 ? OAH_FL_ALL : cc_flag_mask(in->cc);
            return;
        case OAH_SC_JMP: case OAH_SC_CALL:
            *rd = OAH_FL_ALL;        /* fragment exit */
            return;
        default:
            *rd = OAH_FL_ALL;        /* unsupported scalar -> boundary */
            return;
        }
    case OAH_OP_MOV_IMM: case OAH_OP_MOV_RR: case OAH_OP_LEA_RIP:
    case OAH_OP_PUSH: case OAH_OP_PUSH_IMM: case OAH_OP_POP:
    case OAH_OP_NOP: case OAH_OP_ENDBR64: case OAH_OP_LEAVE:
    case OAH_OP_SIGN_HIGH: case OAH_OP_SET_DIRECTION:
    case OAH_OP_STORE_FENCE:
        return;
    default:
        /* vector/string/x87/syscall/etc.: no flags of its own, but a
         * possible interp boundary => complete shadow needed. */
        *rd = OAH_FL_ALL;
        return;
    }
}

/* PF = even parity of res low byte -> x19 bit 2. Scratch: M2. */
static bool emit_parity(oah_asm_buf *buf, u8 res)
{
    return oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, res, res, 1, 4) &&
           oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, M2, M2, 1, 2) &&
           oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, M2, M2, 1, 1) &&
           frag_ubfx(buf, M2, M2, 0, 1) &&
           oah_emit_orn(buf, true, M2, 31, M2, 0, 0) && /* mvn */
           frag_bfi(buf, F_RF, M2, 2, 1);
}

/*
 * Merge the live subset of host NZCV into guest RFLAGS (x19).
 * res = masked result reg (low byte feeds PF).
 * lhs/rhs = masked operand regs feeding AF (lhs^rhs^res bit 4).
 * invert_cf: host C is not-borrow for subs → flip.
 * set_af: write AF from operands when live (cleared by logic ops —
 *         the base mask clears AF either way).
 * mask: produced fields that are live — only those are written to F_RF.
 */
static bool emit_merge_arith(oah_asm_buf *buf, u8 res, u8 lhs, u8 rhs,
                             bool invert_cf, bool set_af, u16 mask)
{
    if (!mask) {
        return true;                        /* all produced flags dead */
    }
    u16 nz = mask & OAH_FL_NZCV;
    if (!oah_emit_movn(buf, true, M2, 0, mask) ||
        !oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, F_RF, F_RF, M2, 0, 0)) {
        return false;
    }
    if (nz && !oah_emit_mrs_nzcv(buf, M1)) {
        return false;
    }
    if (nz & (OAH_FL_SF | OAH_FL_ZF)) {
        if (!frag_ubfx(buf, M2, M1, 30, 2) ||          /* N,Z -> 6,7 */
            !frag_lsl(buf, false, M2, M2, 6) ||
            !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, F_RF, F_RF, M2, 0, 0)) {
            return false;
        }
    }
    if (nz & OAH_FL_CF) {
        if (!frag_ubfx(buf, M2, M1, 29, 1)) {
            return false;
        }
        if (invert_cf &&
            !oah_emit_orn(buf, true, M2, 31, M2, 0, 0)) {
            return false;
        }
        if (!frag_bfi(buf, F_RF, M2, 0, 1)) {
            return false;
        }
    }
    if (nz & OAH_FL_OF) {
        if (!frag_ubfx(buf, M2, M1, 28, 1) ||
            !frag_bfi(buf, F_RF, M2, 11, 1)) {
            return false;
        }
    }
    if ((mask & OAH_FL_PF) && !emit_parity(buf, res)) {
        return false;
    }
    if ((mask & OAH_FL_AF) && set_af) {
        if (!oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, lhs, rhs, 0, 0) ||
            !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, M2, res, 0, 0) ||
            !frag_ubfx(buf, M2, M2, 4, 1) ||
            !frag_bfi(buf, F_RF, M2, 4, 1)) {
            return false;
        }
    }
    return true;
}

/* SZP flags for a masked result; clears the live subset of CF|OF|AF
 * (logical op semantics) and merges live SF/ZF/PF. mask==0 skips all
 * flag work — and leaves NZCV alone since the ANDS is skipped too. */
static bool emit_merge_logic(oah_asm_buf *buf, u8 res, u8 width, u16 mask)
{
    if (!mask) {
        return true;
    }
    if (!oah_emit_movn(buf, true, M2, 0, mask) ||
        !oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, F_RF, F_RF, M2, 0, 0)) {
        return false;
    }
    if (mask & (OAH_FL_SF | OAH_FL_ZF)) {
        /* Position the result's sign bit for the flag producer. */
        u8 t = M1;
        if (width < 4) {
            if (!frag_lsl(buf, false, t, res, 32 - 8 * width)) {
                return false;
            }
        } else {
            t = res;
        }
        if (!oah_emit_logic_reg(buf, OAH_LOGIC_ANDS, width == 8, 31, t, t, 0, 0) ||
            !oah_emit_mrs_nzcv(buf, M1) ||
            !frag_ubfx(buf, M2, M1, 30, 2) ||
            !frag_lsl(buf, false, M2, M2, 6) ||
            !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, F_RF, F_RF, M2, 0, 0)) {
            return false;
        }
    }
    if ((mask & OAH_FL_PF) && !emit_parity(buf, res)) {
        return false;
    }
    return true;
}

/*
 * Emit the flag-producing compute for lhs op rhs at guest width.
 * res_r receives the masked result. For width<8 the host op runs in the
 * sign-extended W domain so NZCV lands at the right position.
 */
static bool emit_arith_compute(oah_asm_buf *buf, bool is_sub, u8 res_r,
                               u8 lhs_r, u8 rhs_r, u8 width)
{
    if (width < 4) {
        u32 sh = 32 - 8 * width;
        return frag_lsl(buf, false, T4, lhs_r, sh) &&
               frag_lsl(buf, false, T5, rhs_r, sh) &&
               oah_emit_add_sub_reg(buf, false, is_sub, true, T4, T4, T5, 0, 0) &&
               frag_lsr(buf, false, res_r, T4, sh);
    }
    return oah_emit_add_sub_reg(buf, width == 8, is_sub, true, res_r,
                                lhs_r, rhs_r, 0, 0);
}

/* ADD/SUB/CMP family with a live-masked flag merge; res_r = result. */
static bool emit_arith_flags(oah_asm_buf *buf, bool is_sub, u8 res_r,
                             u8 lhs_r, u8 rhs_r, u8 width, u16 mask)
{
    return emit_arith_compute(buf, is_sub, res_r, lhs_r, rhs_r, width) &&
           emit_merge_arith(buf, res_r, lhs_r, rhs_r, is_sub, true, mask);
}

/* Build host NZCV from guest RFLAGS into scratch t, then msr. */
static bool emit_rflags_to_nzcv(oah_asm_buf *buf, u8 t)
{
    /* NZCV: N=SF(7) Z=ZF(6) C=!CF(0) V=OF(11) */
    return frag_ubfx(buf, t, F_RF, 6, 2) &&          /* SF,ZF -> 0,1 */
           frag_lsl(buf, false, t, t, 30) &&         /* -> 30,31 */
           frag_ubfx(buf, T7, F_RF, 0, 1) &&         /* CF */
           oah_emit_orn(buf, false, T7, 31, T7, 0, 0) && /* !CF (all bits) */
           frag_ubfx(buf, T7, T7, 0, 1) &&           /* keep bit0 only */
           oah_emit_logic_reg(buf, OAH_LOGIC_ORR, false, t, t, T7, 0, 29) &&
           frag_ubfx(buf, T7, F_RF, 11, 1) &&        /* OF */
           oah_emit_logic_reg(buf, OAH_LOGIC_ORR, false, t, t, T7, 0, 28) &&
           oah_emit_msr_nzcv(buf, t);
}

/* Map an x86 condition code to the ARM cond used after NZCV restore. */
static u32 arm_cond_for_x86(u8 cc)
{
    static const u8 map[16] = {
        /* O NO B AE Z NZ BE A S NS P NP L GE LE G */
        0x6 /*VS*/, 0x7 /*VC*/, 0x3 /*CC*/, 0x2 /*CS*/,
        0x0 /*EQ*/, 0x1 /*NE*/, 0x9 /*LS*/, 0x8 /*HI*/,
        0x4 /*MI*/, 0x5 /*PL*/, 0x9 /*LS*/, 0x8 /*HI*/,
        0xb /*LT*/, 0xa /*GE*/, 0xd /*LE*/, 0xc /*GT*/
    };
    return cc < 16 ? map[cc] : 0xe;
}

/* Same mapping under the carry polarity of the live NZCV producer.
 * cfinv=0 means C == guest CF (add/logic producers): CF-only conds swap,
 * CF+ZF conds (BE/A) have no single ARM encoding -> 0xff (materialize). */
static u32 arm_cond_pol(u8 cc, int cfinv)
{
    static const u8 map0[16] = {
        0x6 /*VS*/, 0x7 /*VC*/, 0x2 /*CS*/, 0x3 /*CC*/,
        0x0 /*EQ*/, 0x1 /*NE*/, 0xff, 0xff,
        0x4 /*MI*/, 0x5 /*PL*/, 0xff, 0xff,
        0xb /*LT*/, 0xa /*GE*/, 0xd /*LE*/, 0xc /*GT*/
    };
    if (cfinv) {
        return arm_cond_for_x86(cc);
    }
    return cc < 16 ? map0[cc & 0xf] : 0xe;
}

/*
 * Prepare flags for a conditional consumer: when every field the cc reads
 * still lives in host NZCV, just return the matching ARM cond (free);
 * otherwise rebuild NZCV from the F_RF shadow (the materialized value
 * uses the !CF convention, so the standard map applies afterward).
 */
static bool emit_flags_for_cc(oah_asm_buf *buf, u8 cc, u32 *cond)
{
    u16 need = cc_flag_mask(cc);
    if ((need & ~nzcv_fields) == 0) {
        u32 c = arm_cond_pol(cc, nzcv_cfinv);
        if (c != 0xff) {
            *cond = c;
            return true;
        }
    }
    if (!emit_rflags_to_nzcv(buf, T4)) {
        return false;
    }
    nzcv_fields = OAH_FL_NZCV;
    nzcv_cfinv = 1;
    *cond = arm_cond_for_x86(cc);
    return true;
}

static __thread u16 xmm_resident, xmm_dirty;
static bool emit_xmm_spill(oah_asm_buf *buf, const oah_guest *g);

/* Terminate the fragment: x20 = next rip (or computed), then ret.
 * Constant exits are recorded so the dispatcher can repatch the ret
 * into a direct branch once the successor fragment exists (repatch-style
 * block chaining). */
static bool frag_exit_imm(oah_asm_buf *buf, u64 next)
{
    if (!emit_reloc_imm(buf, F_NR, next, OAH_RELOC_GVA) ||
        !oah_emit_ret(buf)) {
        return false;
    }
    if (frag_relocs->nexits < 2) {
        unsigned i = frag_relocs->nexits++;
        frag_relocs->exit_rip[i] = next;
        frag_relocs->exit_off[i] = (u32)buf->size - 4; /* the ret insn */
    }
    return true;
}

/* Same exit shape as frag_exit_imm but recorded as a bail: the
 * dispatcher runs one interpreter step at the returned RIP, and the
 * exit is never chain-patched (chaining to a frag at the bailing insn
 * would loop forever). */
static bool frag_bail_exit(oah_asm_buf *buf, u64 next)
{
    if (!emit_reloc_imm(buf, F_NR, next, OAH_RELOC_GVA) ||
        !oah_emit_ret(buf)) {
        return false;
    }
    if (!frag_relocs || frag_relocs->nbails >= 8) {
        return false;
    }
    frag_relocs->bail_rip[frag_relocs->nbails++] = next;
    return true;
}

/* frag_exit_imm with the resident-xmm spill first: chainable or not,
 * every exit must commit dirty NEON regs so the dispatcher, interpreter,
 * and successor fragments see exact g->xmm. */
static bool frag_exit(oah_asm_buf *buf, const oah_guest *g, u64 next)
{
    return emit_xmm_spill(buf, g) && frag_exit_imm(buf, next);
}

/* Push/Pop on the guest stack (identity memory, RSP = x12). */
static bool emit_push64(oah_asm_buf *buf, u8 val)
{
    u8 rsp = xn(OAH_X86_RSP);
    return oah_emit_add_sub_imm(buf, true, true, rsp, rsp, 8) &&
           oah_emit_mem(buf, 3, true, false, false, val, rsp, 0);
}

/* Fetch the r/m operand: memory -> read at ea(T0) into rm_r; reg -> read. */
static bool emit_rm_operand(oah_asm_buf *buf, const oah_guest *g,
                            const oah_insn *in, u64 next, u8 rm_r, u8 ea_r,
                            bool sign, bool sign64)
{
    if (!in->memory) {
        return emit_read_gpr(buf, rm_r, in->dst,
                             in->src_width ? in->src_width : in->opsize,
                             in->rex_present);
    }
    return emit_ea(buf, g, &in->address, next, ea_r) &&
           oah_emit_mem(buf, mem_size_log2(in->src_width ? in->src_width
                                                        : in->opsize),
                        false, sign, sign64, rm_r, ea_r, 0);
}

/* Store the op result (res in res_r) to dest reg or memory at ea_r. */
static bool emit_store_result(oah_asm_buf *buf, const oah_insn *in, u8 res_r,
                              u8 ea_r)
{
    if (in->memory && in->rm_dest) {
        return oah_emit_mem(buf, mem_size_log2(in->opsize), true, false,
                            false, res_r, ea_r, 0);
    }
    return emit_store_gpr(buf, in->rm_dest ? in->dst : in->src, res_r,
                          in->opsize, in->rex_present);
}

static bool frag_scalar_supported(const oah_insn *in)
{
    switch (in->scalar) {
    case OAH_SC_MOV: case OAH_SC_LEA: case OAH_SC_MOVSX: case OAH_SC_MOVZX:
    case OAH_SC_ADD: case OAH_SC_OR: case OAH_SC_AND: case OAH_SC_SUB:
    case OAH_SC_XOR: case OAH_SC_CMP: case OAH_SC_TEST:
    case OAH_SC_JMP: case OAH_SC_CALL: case OAH_SC_CMOV: case OAH_SC_SETCC:
    case OAH_SC_IMUL: case OAH_SC_NEG: case OAH_SC_NOT:
    case OAH_SC_INC: case OAH_SC_DEC: case OAH_SC_BSWAP: case OAH_SC_PUSH:
    case OAH_SC_BSF: case OAH_SC_BSR: case OAH_SC_XCHG:
        return true;
    case OAH_SC_SHL: case OAH_SC_SHR: case OAH_SC_SAR:
    case OAH_SC_ROL: case OAH_SC_ROR: case OAH_SC_DIV:
        return true;
    default:
        return false;
    }
}

static bool frag_translate_scalar(oah_asm_buf *buf, const oah_guest *g,
                                  const oah_insn *in, u64 next, u16 fmask)
{
    u8 width = in->opsize;

    if (!frag_scalar_supported(in)) {
        return false;
    }

    switch (in->scalar) {
    case OAH_SC_MOV:
        if (in->rm_dest) {
            /* mov r/m, src|imm — the r/m operand is the DESTINATION.
             * EA first: emit_ea uses T7 for far displacements and seg bases. */
            u8 v;
            if (in->memory &&
                !emit_ea(buf, g, &in->address, next, T0)) {
                return false;
            }
            if (in->immediate) {
                u64 mask = width == 8 ? ~0ull : (1ull << (width * 8)) - 1;
                if (!frag_movi(buf, T7, in->imm & mask)) {
                    return false;
                }
                v = T7;
            } else {
                if (!emit_read_gpr(buf, T2, in->src, width,
                                   in->rex_present)) {
                    return false;
                }
                v = T2;
            }
            return emit_store_result(buf, in, v, T0);
        }
        /* mov reg, rm */
        return emit_rm_operand(buf, g, in, next, T1, T0, false, false) &&
               emit_store_result(buf, in, T1, T0);
    case OAH_SC_MOVZX:
        /* result = rm -> dest */
        return emit_rm_operand(buf, g, in, next, T1, T0, false, false) &&
               emit_store_result(buf, in, T1, T0);
    case OAH_SC_MOVSX:
        /* result = sign-extended rm -> dest */
        if (in->memory) {
            return emit_rm_operand(buf, g, in, next, T1, T0, true, true) &&
                   emit_store_result(buf, in, T1, T0);
        }
        /* reg->reg sign extension */
        return emit_rm_operand(buf, g, in, next, T1, T0, false, false) &&
               oah_emit_sbfm(buf, width == 8, T1, T1, 0,
                             (u32)((in->src_width ? in->src_width : width) * 8 - 1)) &&
               emit_store_result(buf, in, T1, T0);
    case OAH_SC_LEA:
        return emit_ea(buf, g, &in->address, next, T1) &&
               emit_store_gpr(buf, in->src, T1, width, in->rex_present);
    default:
        break;
    }

    /* Fetch operands: rm -> T1 (rm_width), reg operand -> T2 (width). */
    if (!emit_rm_operand(buf, g, in, next, T1, T0, false, false) ||
        !emit_read_gpr(buf, T2, in->src, width, in->rex_present)) {
        return false;
    }
    u8 lhs = in->rm_dest ? T1 : T2;
    u8 rhs = in->rm_dest ? T2 : T1;
    u8 res = T6;

    switch (in->scalar) {
    case OAH_SC_ADD: case OAH_SC_SUB: case OAH_SC_CMP:
    case OAH_SC_OR: case OAH_SC_AND: case OAH_SC_XOR: case OAH_SC_TEST: {
        if (in->immediate) {
            u64 mask = width == 8 ? ~0ull : (1ull << (width * 8)) - 1;
            if (!frag_movi(buf, T7, in->imm & mask)) {
                return false;
            }
        }
        u8 r = in->immediate ? T7 : rhs;
        switch (in->scalar) {
        case OAH_SC_ADD:
            if (!emit_arith_flags(buf, false, res, lhs, r, width, fmask)) {
                return false;
            }
            nzcv_fields = OAH_FL_NZCV;
            nzcv_cfinv = 0;
            break;
        case OAH_SC_SUB: case OAH_SC_CMP:
            if (!emit_arith_flags(buf, true, res, lhs, r, width, fmask)) {
                return false;
            }
            nzcv_fields = OAH_FL_NZCV;
            nzcv_cfinv = 1;
            break;
        case OAH_SC_OR:
            if (!oah_emit_logic_reg(buf, OAH_LOGIC_ORR, width == 8, res, lhs, r, 0, 0) ||
                !emit_merge_logic(buf, res, width, fmask)) {
                return false;
            }
            nzcv_fields = (fmask & (OAH_FL_SF | OAH_FL_ZF)) ? OAH_FL_NZCV : 0;
            nzcv_cfinv = 0;
            break;
        case OAH_SC_AND: case OAH_SC_TEST:
            if (!oah_emit_logic_reg(buf, OAH_LOGIC_AND, width == 8, res, lhs, r, 0, 0) ||
                !emit_merge_logic(buf, res, width, fmask)) {
                return false;
            }
            nzcv_fields = (fmask & (OAH_FL_SF | OAH_FL_ZF)) ? OAH_FL_NZCV : 0;
            nzcv_cfinv = 0;
            break;
        case OAH_SC_XOR:
            if (!oah_emit_logic_reg(buf, OAH_LOGIC_EOR, width == 8, res, lhs, r, 0, 0) ||
                !emit_merge_logic(buf, res, width, fmask)) {
                return false;
            }
            nzcv_fields = (fmask & (OAH_FL_SF | OAH_FL_ZF)) ? OAH_FL_NZCV : 0;
            nzcv_cfinv = 0;
            break;
        default:
            return false;
        }
        if (in->scalar == OAH_SC_CMP || in->scalar == OAH_SC_TEST) {
            return true;
        }
        return emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_INC: case OAH_SC_DEC: {
        /* res = lhs +- 1; flags keep CF; AF from lhs^res. */
        bool dec = in->scalar == OAH_SC_DEC;
        if (width < 4) {
            u32 sh = 32 - 8 * width;
            if (!frag_lsl(buf, false, T4, lhs, sh) ||
                !oah_emit_movz(buf, false, T5, 0, 1) ||
                !frag_lsl(buf, false, T5, T5, sh) ||
                !oah_emit_add_sub_reg(buf, false, dec, true, T4, T4, T5, 0, 0) ||
                !frag_lsr(buf, false, res, T4, sh)) {
                return false;
            }
        } else if (!oah_emit_add_sub_imm_flags(buf, width == 8, dec, true,
                                               res, lhs, 1, 0)) {
            return false;
        }
        /* S-form compute leaves N,Z,V valid in NZCV; C is the inc/dec
         * carry, not guest CF — don't claim it. AF operands are
         * lhs ^ res: the +-1 immediate has no bit 4, so xzr stands in
         * for it. */
        nzcv_fields = OAH_FL_SF | OAH_FL_ZF | OAH_FL_OF;
        return emit_merge_arith(buf, res, lhs, 31, dec, true,
                                fmask & ~OAH_FL_CF) &&
               emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_NEG:
        /* res = 0 - lhs; flags = cmp(0,lhs); AF = lhs^res */
        if (!emit_arith_compute(buf, true, res, 31, lhs, width) ||
            !emit_merge_arith(buf, res, 31, lhs, true, true, fmask)) {
            return false;
        }
        nzcv_fields = OAH_FL_NZCV;
        nzcv_cfinv = 1;
        return emit_store_result(buf, in, res, T0);
    case OAH_SC_NOT:
        return oah_emit_orn(buf, width == 8, res, 31, lhs, 0, 0) &&
               emit_store_result(buf, in, res, T0);
    case OAH_SC_IMUL: {
        /* res = rm * (imm | reg). CF=OF = product overflow. */
        u8 a = in->immediate ? T1 : T2;
        u8 b = in->immediate ? T7 : rhs;
        if (in->immediate &&
            !frag_movi(buf, T7, (u64)(s64)in->imm)) {
            return false;
        }
        if (width == 8) {
            if (!oah_emit_mul(buf, true, res, a, b) ||
                !oah_emit_smulh(buf, T4, a, b) ||
                !frag_asr(buf, true, T5, res, 63) ||
                !oah_emit_cmp_reg(buf, true, T4, T5, 0, 0)) {
                return false;
            }
        } else {
            if (!oah_emit_smull(buf, T4, a, b) ||
                !frag_mov(buf, false, res, T4) ||
                !oah_emit_sbfm(buf, false, T5, res, 0,
                               (u32)(width * 8 - 1)) ||
                !oah_emit_cmp_reg(buf, true, T4, T5, 0, 0)) {
                return false;
            }
        }
        /* c = !Z (high != sign-extension of res) -> CF and OF */
        nzcv_fields = 0;                    /* cmp_reg clobbered NZCV */
        if ((fmask & (OAH_FL_CF | OAH_FL_OF)) &&
            !(oah_emit_csinc(buf, false, T4, 31, 31, 0 /*EQ*/) &&
              oah_emit_movn(buf, true, T5, 0, 0x801) &&
              oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, F_RF, F_RF, T5, 0, 0) &&
              frag_lsl(buf, false, T5, T4, 11) &&
              oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, T5, T5, T4, 0, 0) &&
              oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, F_RF, F_RF, T5, 0, 0))) {
            return false;
        }
        return emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_SHL: case OAH_SC_SHR: case OAH_SC_SAR: {
        u32 bits = width * 8;
        u8 kind = in->scalar == OAH_SC_SHL ? 0 : in->scalar == OAH_SC_SHR ? 1 : 2;
        if (!in->immediate) {
            /* Shift by CL: count masked to 6 bits (64-bit operand) or
             * 5 bits. A masked count of 0 changes no state at all, so
             * the whole sequence sits behind a patched forward cbz. */
            if (!frag_ubfx(buf, T4, xn(OAH_X86_RCX), 0,
                           width == 8 ? 6 : 5)) {
                return false;
            }
            u64 skip_all = buf->size;
            if (!oah_emit_cbz_cbnz(buf, false, false, T4, 0)) {
                return false;
            }
            u8 op = lhs;
            if (kind == 2 && width < 8) {
                if (!oah_emit_sbfm(buf, false, T5, lhs, 0, bits - 1)) {
                    return false;
                }
                op = T5;
            }
            if (!oah_emit_shift_var(buf, width == 8, kind, res, op, T4) ||
                !emit_merge_logic(buf, res, width, fmask)) {
                return false;
            }
            nzcv_fields = 0;
            /* CF = bit(bits-cnt) [SHL] or bit(cnt-1) [SHR/SAR] of lhs;
             * defined only when cnt <= bits (undefined otherwise). */
            u64 skip_cf = 0;
            if ((fmask & OAH_FL_CF) && bits < 32) {
                if (!oah_emit_add_sub_imm_flags(buf, false, true, true, 31,
                                                T4, bits, 0)) {
                    return false;
                }
                skip_cf = buf->size;
                if (!oah_emit_bcond(buf, OAH_ARM_HI, 0)) {
                    return false;
                }
            }
            /* SHL's OF reads F_RF.CF, so the CF bit is needed when
             * either field is live (over-storing a dead CF is harmless —
             * it is the produced value anyway). */
            if (fmask & (OAH_FL_CF | OAH_FL_OF)) {
                if (kind == 0) {
                    if (!frag_movi(buf, T5, bits) ||
                        !oah_emit_add_sub_reg(buf, false, true, false, T5, T5,
                                              T4, 0, 0)) {
                        return false;
                    }
                } else if (!oah_emit_add_sub_imm(buf, false, true, T5, T4, 1)) {
                    return false;
                }
                if (!oah_emit_shift_var(buf, width == 8, 1, T7, lhs, T5) ||
                    !frag_bfi(buf, F_RF, T7, 0, 1)) {
                    return false;
                }
            }
            if (skip_cf) {
                oah_asm_patch32(buf, skip_cf,
                                0x54000000u |
                                (((u32)(buf->size - skip_cf) >> 2) << 5) |
                                OAH_ARM_HI);
            }
            /* OF on cnt==1: SHR = sign(lhs); SHL = sign(res)^CF. */
            if ((fmask & OAH_FL_OF) && kind != 2) {
                if (!oah_emit_add_sub_imm_flags(buf, false, true, true, 31,
                                                T4, 1, 0)) {
                    return false;
                }
                u64 skip_of = buf->size;
                if (!oah_emit_bcond(buf, OAH_ARM_NE, 0)) {
                    return false;
                }
                if (kind == 1) {
                    if (!oah_emit_ubfm(buf, width == 8, T7, lhs,
                                       bits - 1, bits - 1) ||
                        !frag_bfi(buf, F_RF, T7, 11, 1)) {
                        return false;
                    }
                } else if (!oah_emit_ubfm(buf, width == 8, T7, res,
                                          bits - 1, bits - 1) ||
                           !frag_ubfx(buf, T5, F_RF, 0, 1) ||
                           !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, false,
                                               T7, T7, T5, 0, 0) ||
                           !frag_bfi(buf, F_RF, T7, 11, 1)) {
                    return false;
                }
                oah_asm_patch32(buf, skip_of,
                                0x54000000u |
                                (((u32)(buf->size - skip_of) >> 2) << 5) |
                                OAH_ARM_NE);
            }
            if (!emit_store_result(buf, in, res, T0)) {
                return false;
            }
            oah_asm_patch32(buf, skip_all,
                            0x34000000u |
                            (((u32)(buf->size - skip_all) >> 2) << 5) |
                            T4);
            return true;
        }
        u32 raw_count = (u32)(in->imm & (width == 8 ? 63 : 31));
        if (!raw_count) {
            return true; /* x86: no state change at all */
        }
        u32 count = raw_count;
        if (kind == 0) { /* SHL */
            if (width == 8) {
                if (count >= 64 || !frag_lsl(buf, true, res, lhs, count)) {
                    return false;
                }
            } else {
                if (!frag_lsl(buf, false, res, lhs, count < 32 ? count : 31) ||
                    !frag_ubfx(buf, res, res, 0, bits < 32 ? bits : 32)) {
                    return false;
                }
            }
        } else if (kind == 1) { /* SHR */
            if (count >= bits) {
                if (!oah_emit_movz(buf, false, res, 0, 0)) {
                    return false;
                }
            } else if (!frag_lsr(buf, width == 8, res, lhs, count)) {
                return false;
            }
        } else { /* SAR */
            u8 se = width < 8 ? T5 : lhs;
            if (width < 8 &&
                !oah_emit_sbfm(buf, false, T5, lhs, 0, bits - 1)) {
                return false;
            }
            if (count >= bits) {
                count = bits - 1;
            }
            if (!frag_asr(buf, width == 8, res, se, count)) {
                return false;
            }
        }
        if (!emit_merge_logic(buf, res, width, fmask)) {
            return false;
        }
        nzcv_fields = 0;
        /* CF = bit(bits-count) [SHL] or bit(count-1) [SHR/SAR] of lhs,
         * only when the masked count doesn't exceed the operand width.
         * Computed when CF or OF is live (SHL's OF reads F_RF.CF). */
        if ((fmask & (OAH_FL_CF | OAH_FL_OF)) && raw_count <= bits) {
            u32 bit = kind == 0 ? bits - raw_count : raw_count - 1;
            if (!oah_emit_ubfm(buf, width == 8, T4, lhs, bit, bit) ||
                !frag_bfi(buf, F_RF, T4, 0, 1)) {
                return false;
            }
        }
        /* OF on count==1: SHR = sign(lhs); SHL = sign(res)^CF; SAR unchanged. */
        if ((fmask & OAH_FL_OF) && raw_count == 1 && kind != 2) {
            if (kind == 1) {
                if (!oah_emit_ubfm(buf, width == 8, T4, lhs,
                                   bits - 1, bits - 1) ||
                    !frag_bfi(buf, F_RF, T4, 11, 1)) {
                    return false;
                }
            } else {
                if (!oah_emit_ubfm(buf, width == 8, T4, res,
                                   bits - 1, bits - 1) ||
                    !frag_ubfx(buf, T5, F_RF, 0, 1) ||
                    !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, false, T4, T4, T5, 0, 0) ||
                    !frag_bfi(buf, F_RF, T4, 11, 1)) {
                    return false;
                }
            }
        }
        return emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_DIV: {
        /* Unsigned only; IDIV stays on the interpreter. Divisor is the
         * rm operand (T1). Fast path: masked divisor nonzero, dividend
         * fits one register (rdx == 0 for 64-bit div), quotient fits.
         * Every #DE-shaped edge case branches to an out-of-line stub
         * that exits the fragment so the interpreter runs this insn. */
        u32 bits = width * 8;
        u8 tdiv = T3, tquot = T4, tdividend = T5, trem = T7;
        u64 bail_off[4];
        u32 bail_enc[4];
        unsigned nbail = 0;
        if (bits < 64) {
            if (!frag_ubfx(buf, tdiv, T1, 0, bits)) {
                return false;
            }
        } else if (!frag_mov(buf, true, tdiv, T1)) {
            return false;
        }
        bail_off[nbail] = buf->size;
        bail_enc[nbail++] = 0x34000000u | (u32)(bits == 64) << 31 | tdiv;
        if (!oah_emit_cbz_cbnz(buf, bits == 64, false, tdiv, 0)) {
            return false;
        }
        switch (width) {
        case 1:  /* dividend = AX */
            if (!frag_ubfx(buf, tdividend, xn(OAH_X86_RAX), 0, 16)) {
                return false;
            }
            break;
        case 2:  /* dividend = DX:AX */
            if (!frag_ubfx(buf, tdividend, xn(OAH_X86_RDX), 0, 16) ||
                !frag_ubfx(buf, T6, xn(OAH_X86_RAX), 0, 16) ||
                !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, tdividend,
                                    T6, tdividend, 0, 16)) {
                return false;
            }
            break;
        case 4:  /* dividend = EDX:EAX */
            if (!frag_ubfx(buf, tdividend, xn(OAH_X86_RDX), 0, 32) ||
                !frag_ubfx(buf, T6, xn(OAH_X86_RAX), 0, 32) ||
                !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, tdividend,
                                    T6, tdividend, 0, 32)) {
                return false;
            }
            break;
        default: /* dividend = RDX:RAX; bail on the wide case */
            bail_off[nbail] = buf->size;
            bail_enc[nbail++] = 0xb5000000u | xn(OAH_X86_RDX);
            if (!oah_emit_cbz_cbnz(buf, true, true, xn(OAH_X86_RDX), 0) ||
                !frag_mov(buf, true, tdividend, xn(OAH_X86_RAX))) {
                return false;
            }
            break;
        }
        if (!oah_emit_udiv(buf, width >= 4, tquot, tdividend, tdiv)) {
            return false;
        }
        if (bits < 64) {
            /* quotient must fit in `bits`; else #DE -> interpreter */
            bail_off[nbail] = buf->size + 4; /* after the ubfx */
            bail_enc[nbail++] =
                0x34000000u | (u32)(width >= 4) << 31 | 0x01000000u | T6;
            if (!oah_emit_ubfm(buf, width >= 4, T6, tquot, bits,
                               width >= 4 ? 63 : 31) ||
                !oah_emit_cbz_cbnz(buf, width >= 4, true, T6, 0)) {
                return false;
            }
        }
        if (!oah_emit_msub(buf, width >= 4, trem, tquot, tdiv, tdividend)) {
            return false;
        }
        /* quot -> RAX[bits], rem -> RDX[bits] */
        if (width == 1) {
            if (!frag_bfi(buf, xn(OAH_X86_RAX), tquot, 0, 8) ||
                !frag_bfi(buf, xn(OAH_X86_RAX), trem, 8, 8)) {
                return false;
            }
        } else {
            if (!emit_store_gpr(buf, OAH_X86_RAX, tquot, width,
                                false) ||
                !emit_store_gpr(buf, OAH_X86_RDX, trem, width, false)) {
                return false;
            }
        }
        /* Skip the out-of-line bail stub, then emit it. The stub's spill
         * runs only on the bail path, but emit_xmm_spill clears the
         * translate-time dirty set — restore it so regs still dirty in
         * NEON are flushed by the fragment's real exit (same pattern as
         * the vector alignment stub in emit_vec_ea). */
        u64 over = buf->size;
        u64 stub;
        oah_asm_emit32(buf, 0x14000000u); /* b <after stub> */
        stub = buf->size;
        u16 saved_dirty = xmm_dirty;
        if (!emit_xmm_spill(buf, g) ||
            !frag_bail_exit(buf, next - in->length)) {
            return false;
        }
        xmm_dirty = saved_dirty;
        while (nbail) {
            unsigned i = --nbail;
            oah_asm_patch32(buf, bail_off[i],
                            bail_enc[i] |
                            (u32)(((stub - bail_off[i]) >> 2) << 5));
        }
        oah_asm_patch32(buf, over,
                        0x14000000u |
                        (u32)(((buf->size - over) >> 2) & 0x3ffffff));
        return true;
    }
    case OAH_SC_ROL: case OAH_SC_ROR: {
        /* masked count: x86 wraps rol r8/r16 by the operand width for
         * the rotate but applies flags to the masked count. CF is the
         * bit rotated out; OF only updates when masked == 1. */
        u32 bits = width * 8;
        bool left = in->scalar == OAH_SC_ROL;
        if (width < 4) {
            return false; /* rare; let the interpreter handle it */
        }
        if (!in->immediate) {
            if (!frag_ubfx(buf, T4, xn(OAH_X86_RCX), 0,
                           width == 8 ? 6 : 5)) {
                return false;
            }
            u64 skip_all = buf->size;
            if (!oah_emit_cbz_cbnz(buf, false, false, T4, 0)) {
                return false;
            }
            u8 amount = T4;
            if (left) {
                /* rol r,k = ror r,(bits-k); (-k) & (bits-1) */
                if (!oah_emit_add_sub_reg(buf, false, true, false, T5, 31,
                                          T4, 0, 0) ||
                    !frag_ubfx(buf, T5, T5, 0, width == 8 ? 6 : 5)) {
                    return false;
                }
                amount = T5;
            }
            /* No emit_merge_logic: rotates only touch CF/OF, they do
             * not compute SZP like shifts do. */
            if (!oah_emit_shift_var(buf, width == 8, 3, res, lhs, amount)) {
                return false;
            }
            nzcv_fields = 0;
            /* CF = res&1 [ROL] or res>>(bits-1) [ROR]. */
            if ((fmask & OAH_FL_CF) &&
                (!oah_emit_ubfm(buf, width == 8, T7, res,
                                left ? 0 : bits - 1, left ? 0 : bits - 1) ||
                 !frag_bfi(buf, F_RF, T7, 0, 1))) {
                return false;
            }
            /* OF (masked==1): ROL = msb^CF; ROR = msb^(msb-1). */
            if (fmask & OAH_FL_OF) {
                if (!oah_emit_add_sub_imm_flags(buf, false, true, true, 31,
                                                T4, 1, 0)) {
                    return false;
                }
                u64 skip_of = buf->size;
                if (!oah_emit_bcond(buf, OAH_ARM_NE, 0)) {
                    return false;
                }
                if (left) {
                    if (!oah_emit_ubfm(buf, width == 8, T7, res,
                                       bits - 1, bits - 1) ||
                        !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, false, T7, T7,
                                            res, 0, 0) ||
                        !frag_bfi(buf, F_RF, T7, 11, 1)) {
                        return false;
                    }
                } else {
                    if (!frag_lsr(buf, width == 8, T7, res, 1) ||
                        !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, width == 8,
                                            T7, T7, res, 0, 0) ||
                        !oah_emit_ubfm(buf, width == 8, T7, T7,
                                       bits - 2, bits - 2) ||
                        !frag_bfi(buf, F_RF, T7, 11, 1)) {
                        return false;
                    }
                }
                oah_asm_patch32(buf, skip_of,
                                0x54000000u |
                                (((u32)(buf->size - skip_of) >> 2) << 5) |
                                OAH_ARM_NE);
            }
            if (!emit_store_result(buf, in, res, T0)) {
                return false;
            }
            oah_asm_patch32(buf, skip_all,
                            0x34000000u |
                            (((u32)(buf->size - skip_all) >> 2) << 5) |
                            T4);
            return true;
        }
        u32 masked = (u32)(in->imm & (width == 8 ? 63 : 31));
        if (!masked) {
            return true; /* x86: no state change at all */
        }
        u32 count = masked % bits;
        if (!count) {
            /* Full-width rotate: result = lhs, CF = edge bit of lhs. */
            if (!frag_mov(buf, width == 8, res, lhs)) {
                return false;
            }
        } else {
            u32 k = left ? bits - count : count;
            if (!frag_lsl(buf, width == 8, T5, lhs, bits - k) ||
                !frag_lsr(buf, width == 8, res, lhs, k) ||
                !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, width == 8, res,
                                    res, T5, 0, 0)) {
                return false;
            }
        }
        nzcv_fields = 0;
        if ((fmask & OAH_FL_CF) &&
            (!oah_emit_ubfm(buf, width == 8, T7, res,
                            left ? 0 : bits - 1, left ? 0 : bits - 1) ||
             !frag_bfi(buf, F_RF, T7, 0, 1))) {
            return false;
        }
        if ((fmask & OAH_FL_OF) && masked == 1) {
            if (left) {
                if (!oah_emit_ubfm(buf, width == 8, T7, res,
                                   bits - 1, bits - 1) ||
                    !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, false, T7, T7,
                                        res, 0, 0) ||
                    !frag_bfi(buf, F_RF, T7, 11, 1)) {
                    return false;
                }
            } else {
                if (!oah_emit_ubfm(buf, width == 8, T7, res,
                                   bits - 2, bits - 2) ||
                    !oah_emit_ubfm(buf, width == 8, T5, res,
                                   bits - 1, bits - 1) ||
                    !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, false, T7, T7,
                                        T5, 0, 0) ||
                    !frag_bfi(buf, F_RF, T7, 11, 1)) {
                    return false;
                }
            }
        }
        return emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_BSF: case OAH_SC_BSR: {
        /* Input is the rm operand (T1); dest is in->src. Zero input:
         * ZF=1 and dest unchanged; else ZF=0 and res = lowest/highest
         * set-bit index. Other flags are undefined on x86 — untouched. */
        bool is64 = width == 8;
        nzcv_fields = 0;
        if ((fmask & OAH_FL_ZF) &&
            (!oah_emit_add_sub_imm_flags(buf, is64, true, true, 31, T1, 0, 0) ||
             !oah_emit_csinc(buf, false, T4, 31, 31, OAH_ARM_NE) ||
             !frag_bfi(buf, F_RF, T4, 6, 1))) {
            return false;
        }
        u64 skip_store = buf->size;
        if (!oah_emit_cbz_cbnz(buf, is64, false, T1, 0)) {
            return false;
        }
        if (in->scalar == OAH_SC_BSF) {
            /* ctz = clz(rbit(x)) — operand is zero-extended so the
             * lowest set bit always sits inside the operand width. */
            if (!oah_emit_rbit(buf, is64, T5, T1) ||
                !oah_emit_clz(buf, is64, res, T5)) {
                return false;
            }
        } else {
            /* index = (bits-1) - clz(x); for width<8 the padded upper
             * zeros keep 31-clz32 inside the operand's range. */
            if (!oah_emit_clz(buf, is64, T5, T1) ||
                !frag_movi(buf, T4, is64 ? 63 : 31) ||
                !oah_emit_add_sub_reg(buf, is64, true, false, res, T4,
                                      T5, 0, 0)) {
                return false;
            }
        }
        if (!emit_store_result(buf, in, res, T0)) {
            return false;
        }
        oah_asm_patch32(buf, skip_store,
                        0x34000000u | ((u32)is64 << 31) |
                        (((u32)(buf->size - skip_store) >> 2) << 5) | T1);
        return true;
    }
    case OAH_SC_XCHG:
        /* rm <- reg, reg <- rm; no flags. */
        return emit_store_result(buf, in, T2, T0) &&
               emit_store_gpr(buf, in->src, T1, width, in->rex_present);
    case OAH_SC_BSWAP:
        return oah_emit_rev(buf, width == 8, res, lhs) &&
               emit_store_result(buf, in, res, T0);
    case OAH_SC_SETCC: {
        u32 cond;
        return emit_flags_for_cc(buf, in->cc, &cond) &&
               oah_emit_csinc(buf, false, res, 31, 31, cond ^ 1) &&
               emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_CMOV: {
        /* csel res = cond ? rm(T1) : dst(T2). */
        u32 cond;
        return emit_flags_for_cc(buf, in->cc, &cond) &&
               oah_emit_csel(buf, width == 8, res, T1, T2, cond) &&
               emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_PUSH:
        return emit_push64(buf, T1);
    case OAH_SC_JMP:
        return emit_xmm_spill(buf, g) && frag_mov(buf, true, F_NR, T1) &&
               oah_emit_ret(buf);
    case OAH_SC_CALL:
        return emit_xmm_spill(buf, g) &&
               emit_reloc_imm(buf, T4, next, OAH_RELOC_GVA) &&
               emit_push64(buf, T4) &&
               frag_mov(buf, true, F_NR, T1) && oah_emit_ret(buf);
    default:
        return false;
    }
}

/* --- SSE -> NEON -----------------------------------------------------------
 * Guest xmm state lives in g->xmm shadow memory at a fixed host address for
 * the guest's lifetime, so fragments materialize it as an immediate — this
 * works under every entry ABI (native trampoline, chain hops, C executor). */
static bool oah_frag_sse;
static u8 oah_sse_tab[256]; /* OAH_SSE_OPS comma-hex list, for bisection */

void oah_translate_enable_sse(bool on)
{
    const char *ops;
    oah_frag_sse = on;
    memset(oah_sse_tab, 1, sizeof(oah_sse_tab));
    if (on && (ops = getenv("OAH_SSE_OPS")) != NULL) {
        char *copy = strdup(ops), *tok = copy;
        memset(oah_sse_tab, 0, sizeof(oah_sse_tab));
        while (tok) {
            char *comma = strchr(tok, ',');
            u32 op;
            if (comma) {
                *comma = '\0';
            }
            if (sscanf(tok, "%x", &op) == 1 && op < 256) {
                oah_sse_tab[op] = 1;
            }
            tok = comma ? comma + 1 : NULL;
        }
        free(copy);
    }
}

/* Three-same vector encodings (Q=1). ADD/SUB/CMEQ element size goes in
 * bits 23..22: b=0, h=1, s=2, d=3. */
#define OAH_V_EOR  0x6e201c00u
#define OAH_V_ORR  0x4ea01c00u
#define OAH_V_AND  0x4e201c00u
#define OAH_V_ADD(sz)  (0x4e208400u | ((u32)(sz) << 22))
#define OAH_V_SUB(sz)  (0x6e208400u | ((u32)(sz) << 22))
#define OAH_V_CMEQ(sz) (0x6e208c00u | ((u32)(sz) << 22))
#define OAH_V_ZIP1(sz) (0x4e003800u | ((u32)(sz) << 22))
#define OAH_V_ZIP2(sz) (0x4e007800u | ((u32)(sz) << 22))
#define OAH_V_UMIN     0x6e206c00u
#define OAH_V_UMAX     0x6e206400u
/* Signed saturating narrow: SQXTN writes the low lanes, SQXTN2 the high —
 * together they match x86 packss* (dest narrows low, source high). */
#define OAH_V_SQXTN(sz)  (0x0e214800u | ((u32)(sz) << 22))
#define OAH_V_SQXTN2(sz) (0x4e214800u | ((u32)(sz) << 22))
/* pmaddwd idiom: SMULL widens the low word products to dwords, SMULL2 the
 * high ones, then ADDP pairs them — dst.s[i] = a.h[2i]*b.h[2i] +
 * a.h[2i+1]*b.h[2i+1]. */
#define OAH_V_SMULL_4H   0x0e60c000u
#define OAH_V_SMULL2_8H  0x4e60c000u
#define OAH_V_ADDP_4S    0x4ea0bc00u

/* --- XMM-in-NEON residency --------------------------------------------------
 * Within a fragment each guest xmm[i] lives in a host NEON register so
 * vector ops move data in registers instead of materializing the shadow
 * pointer per operand. The map keeps to caller-saved regs: v8-v15's low
 * halves are callee-saved and v18 is platform-reserved, while v16/v17/v18
 * stay the translator's scratch temps:
 *   xmm0-7 -> v0-7,  xmm8-15 -> v19-v26
 * Loads are lazy (first read pulls g->xmm into the resident reg), writes
 * mark the reg dirty, and every fragment exit spills dirty regs back to
 * g->xmm. Guest memory therefore matches interpreter state at every exit
 * and interp boundary, and a mid-fragment fault replays correctly because
 * recovery re-derives the vector state from the committed shadow. */
/* One slot beyond MAX so a bound_start index is always valid even when
 * the persisted bound table is already full (oversized OAH_JIT_FRAGLEN). */
static __thread u16 bound_res_snap[OAH_FRAG_MAX_BOUNDS + 1],
                    bound_dirty_snap[OAH_FRAG_MAX_BOUNDS + 1];
static const u8 xmm_vreg[16] = {
    0, 1, 2, 3, 4, 5, 6, 7, 19, 20, 21, 22, 23, 24, 25, 26
};

/* hr = &g->xmm[idx]. The shadow base is emitted as a fixed-length
 * immediate recorded with OAH_RELOC_XMMBASE so persisted fragments are
 * rebound to the live guest at materialize time. */
static bool emit_xmm_ptr(oah_asm_buf *buf, const oah_guest *g, u8 hr, u8 idx)
{
    if (idx > 15) {
        return false;
    }
    return emit_reloc_imm(buf, hr, (u64)&g->xmm[0][0],
                          OAH_RELOC_XMMBASE) &&
           (idx == 0 || oah_emit_add_sub_imm(buf, true, false, hr, hr,
                                             (u32)idx * 16));
}

static bool emit_ld_xmm_reg(oah_asm_buf *buf, const oah_guest *g, u8 v,
                                 u8 idx, u8 hr)
{
    if (idx > 15) {
        return false;
    }
    u8 vx = xmm_vreg[idx];
    if (!(xmm_resident & (u16)(1u << idx))) {
        if (!emit_xmm_ptr(buf, g, hr, idx) ||
            !oah_emit_ldr_str_vec(buf, false, true, vx, hr, 0)) {
            return false;
        }
        xmm_resident |= (u16)(1u << idx);
    }
    return v == vx || oah_emit_vec3(buf, OAH_V_ORR, v, vx, vx);
}

static bool emit_st_xmm_reg(oah_asm_buf *buf, const oah_guest *g, u8 v,
                                 u8 idx, u8 hr)
{
    (void)g;
    (void)hr;
    if (idx > 15) {
        return false;
    }
    xmm_resident |= (u16)(1u << idx);
    xmm_dirty |= (u16)(1u << idx);
    u8 vx = xmm_vreg[idx];
    return v == vx || oah_emit_vec3(buf, OAH_V_ORR, vx, v, v);
}

/* Spill every dirty resident xmm back to g->xmm. Emitted before each
 * fragment exit so shadow memory is exact whenever the dispatcher or
 * interpreter next inspects it. */
static bool emit_xmm_spill(oah_asm_buf *buf, const oah_guest *g)
{
    for (u8 idx = 0; idx < 16; idx++) {
        if (!(xmm_dirty & (u16)(1u << idx))) {
            continue;
        }
        if (!emit_xmm_ptr(buf, g, T4, idx) ||
            !oah_emit_ldr_str_vec(buf, true, true, xmm_vreg[idx], T4, 0)) {
            return false;
        }
    }
    xmm_dirty = 0;
    return true;
}

/* Vector memory EA with the alignment guard x86 requires: aarch64 NEON
 * ldr/str never faults on unaligned addresses, but aligned forms
 * (movdqa/movaps/movapd/movntdq, in->aligned) must #GP on EA & 15.
 * Emits EA into `ea`, then — for aligned insns — a ubfx+cbz skip over an
 * out-of-line bail stub. A misaligned address falls into the stub, which
 * spills resident XMM and bails at this insn's gva so the interpreter
 * re-executes it and raises the fault. Guest page permissions need no
 * explicit check: guest mappings are real host mmaps, so a store to a
 * PROT_READ page faults at the host level and the fault handler routes
 * it back through the interpreter. */
static bool emit_vec_ea(oah_asm_buf *buf, const oah_guest *g,
                        const oah_insn *in, u64 next, u8 ea)
{
    if (!emit_ea(buf, g, &in->address, next, ea)) {
        return false;
    }
    if (!in->aligned) {
        return true;
    }
    if (!oah_emit_ubfm(buf, true, T4, ea, 0, 3)) {
        return false;
    }
    u64 cbz_off = buf->size;
    oah_asm_emit32(buf, 0xb4000000u | T4); /* cbz xT4, patched to skip stub */
    /* The stub's spill is for the misaligned path only — emit_xmm_spill
     * clears the translate-time dirty set, but the fast path keeps the
     * regs dirty in NEON, so restore the tracking for the real exit. */
    u16 saved_dirty = xmm_dirty;
    if (!emit_xmm_spill(buf, g) ||
        !frag_bail_exit(buf, next - in->length)) {
        return false;
    }
    xmm_dirty = saved_dirty;
    oah_asm_patch32(buf, cbz_off,
                    0xb4000000u | T4 |
                    (u32)(((buf->size - cbz_off) >> 2) << 5));
    return true;
}

/* rm-side operand -> v (v16/v17 vector temps): memory EA or xmm[in->dst]. */
static bool emit_ld_rm128(oah_asm_buf *buf, const oah_guest *g,
                          const oah_insn *in, u64 next, u8 v)
{
    if (in->memory) {
        return emit_vec_ea(buf, g, in, next, T0) &&
               oah_emit_ldr_str_vec(buf, false, true, v, T0, 0);
    }
    return emit_ld_xmm_reg(buf, g, v, in->dst, T4);
}

static bool frag_translate_vector(oah_asm_buf *buf, const oah_guest *g,
                                  const oah_insn *in, u64 next)
{
    u32 enc = 0;
    switch (in->vector_opcode) {
    case 0x6f:  /* movdqa/movdqu xmm, r/m128 */
    case 0x10:  /* movups/movupd load */
    case 0x28:  /* movaps load */
        return emit_ld_rm128(buf, g, in, next, 16) &&
               emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0x7f:  /* movdqa/movdqu r/m128, xmm */
    case 0x11:  /* movups/movupd store */
    case 0x29:  /* movaps store */
        if (!emit_ld_xmm_reg(buf, g, 16, in->src, T4)) {
            return false;
        }
        if (in->memory) {
            return emit_vec_ea(buf, g, in, next, T0) &&
                   oah_emit_ldr_str_vec(buf, true, true, 16, T0, 0);
        }
        return emit_st_xmm_reg(buf, g, 16, in->dst, T5);
    case 0xef: enc = OAH_V_EOR;     goto alu;  /* pxor */
    case 0xeb: enc = OAH_V_ORR;     goto alu;  /* por */
    case 0xdb: enc = OAH_V_AND;     goto alu;  /* pand */
    case 0xf8: enc = OAH_V_SUB(0);  goto alu;  /* psubb */
    case 0xf9: enc = OAH_V_SUB(1);  goto alu;  /* psubw */
    case 0xfa: enc = OAH_V_SUB(2);  goto alu;  /* psubd */
    case 0xfb: enc = OAH_V_SUB(3);  goto alu;  /* psubq */
    case 0xd4: enc = OAH_V_ADD(3);  goto alu;  /* paddq */
    case 0x74: enc = OAH_V_CMEQ(0); goto alu;  /* pcmpeqb */
    case 0x75: enc = OAH_V_CMEQ(1); goto alu;  /* pcmpeqw */
    case 0x76: enc = OAH_V_CMEQ(2); goto alu;  /* pcmpeqd */
    alu:
        return emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               emit_ld_rm128(buf, g, in, next, 17) &&
               oah_emit_vec3(buf, enc, 16, 16, 17) &&
               emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0x60: enc = OAH_V_ZIP1(0); goto zip;  /* punpcklbw */
    case 0x61: enc = OAH_V_ZIP1(1); goto zip;  /* punpcklwd */
    case 0x62: enc = OAH_V_ZIP1(2); goto zip;  /* punpckldq */
    case 0x6c: enc = OAH_V_ZIP1(3); goto zip;  /* punpcklqdq */
    case 0x68: enc = OAH_V_ZIP2(0); goto zip;  /* punpckhbw */
    case 0x69: enc = OAH_V_ZIP2(1); goto zip;  /* punpckhwd */
    case 0x6a: enc = OAH_V_ZIP2(2); goto zip;  /* punpckhdq */
    case 0x6d: enc = OAH_V_ZIP2(3);            /* punpckhqdq */
    zip:
        return emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               emit_ld_rm128(buf, g, in, next, 17) &&
               oah_emit_vec3(buf, enc, 16, 16, 17) &&
               emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0x63:  /* packsswb: sat-narrow 8+8 words -> 16 bytes */
    case 0x6b:  /* packssdw: sat-narrow 4+4 dwords -> 8 words */
        {
            u32 l2 = in->vector_opcode == 0x63 ? 0 : 1;
            if (!emit_ld_xmm_reg(buf, g, 16, in->src, T4) ||
                !emit_ld_rm128(buf, g, in, next, 17)) {
                return false;
            }
            oah_asm_emit32(buf, OAH_V_SQXTN(l2) | (16u << 5) | 16);
            oah_asm_emit32(buf, OAH_V_SQXTN2(l2) | (17u << 5) | 16);
            return emit_st_xmm_reg(buf, g, 16, in->src, T4);
        }
    case 0xda: enc = OAH_V_UMIN; goto alu;     /* pminub */
    case 0xde: enc = OAH_V_UMAX; goto alu;     /* pmaxub */
    case 0xf5:  /* pmaddwd: sign-widen word products, pairwise add */
        if (!emit_ld_xmm_reg(buf, g, 16, in->src, T4) ||
            !emit_ld_rm128(buf, g, in, next, 17)) {
            return false;
        }
        /* v18 = lo products; v16 = hi products (input consumed, dead);
         * addp(v18,v16) pairs them into dword lanes. Only v16-18 are
         * scratch — v19+ hold resident guest xmm8-15. */
        oah_asm_emit32(buf, OAH_V_SMULL_4H | (17u << 16) | (16u << 5) | 18);
        oah_asm_emit32(buf, OAH_V_SMULL2_8H | (17u << 16) | (16u << 5) | 16);
        oah_asm_emit32(buf, OAH_V_ADDP_4S | (16u << 16) | (18u << 5) | 16);
        return emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0x71:  /* psrlw /2, psraw /4, psllw /6 */
    case 0x72:  /* psrld /2, psrad /4, pslld /6 */
    case 0x73:  /* psrlq /2, psrldq /3, psllq /6, pslldq /7 */
        {
            /* 0x71: h, 0x72: s, 0x73: d element shifts; /3 /7 are the
             * whole-register byte shifts (0x73 only). */
            u32 l2 = in->vector_opcode - 0x70;
            u32 esize = 8u << l2;
            u32 k = (u32)in->imm;
            if (k == 0) {
                return true; /* in-place op, count 0: nothing to emit */
            }
            if (in->cc == 3 || in->cc == 7) {
                /* psrldq /3, pslldq /7: byte-wise whole-reg shifts. */
                if (in->vector_opcode != 0x73) {
                    return false;
                }
                if (!emit_ld_xmm_reg(buf, g, 16, in->dst, T4)) {
                    return false;
                }
                if (k <= 15) {
                    if (!oah_emit_vec3(buf, OAH_V_EOR, 18, 18, 18) ||
                        !oah_emit_ext16(buf, 16,
                                        in->cc == 3 ? 16 : 18,
                                        in->cc == 3 ? 18 : 16,
                                        in->cc == 3 ? k : 16 - k)) {
                        return false;
                    }
                } else if (!oah_emit_vec3(buf, OAH_V_EOR, 16, 16, 16)) {
                    return false;
                }
                return emit_st_xmm_reg(buf, g, 16, in->dst, T4);
            }
            if (!emit_ld_xmm_reg(buf, g, 16, in->dst, T4)) {
                return false;
            }
            switch (in->cc) {
            case 2: /* psrl*: logical right; count >= width -> 0 */
                if (k >= esize) {
                    if (!oah_emit_vec3(buf, OAH_V_EOR, 16, 16, 16)) {
                        return false;
                    }
                } else if (!oah_emit_vushr_imm(buf, l2, 16, 16, k)) {
                    return false;
                }
                break;
            case 4: /* psra*: arithmetic right; count clamps to width-1 */
                if (in->vector_opcode == 0x73 ||
                    !oah_emit_vsshr_imm(buf, l2, 16, 16,
                                        k >= esize ? esize - 1 : k)) {
                    return false;
                }
                break;
            case 6: /* psll*: left; count >= width -> 0 */
                if (k >= esize) {
                    if (!oah_emit_vec3(buf, OAH_V_EOR, 16, 16, 16)) {
                        return false;
                    }
                } else if (!oah_emit_vshl_imm(buf, l2, 16, 16, k)) {
                    return false;
                }
                break;
            default:
                return false;
            }
            return emit_st_xmm_reg(buf, g, 16, in->dst, T4);
        }
    case 0x12:  /* movlpd xmm, m64 / movhlps xmm, xmm */
        if (!in->memory) {
            /* movhlps: dst.d[0] = src.d[1]; dst upper qword kept */
            return emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
                   emit_ld_xmm_reg(buf, g, 17, in->dst, T5) &&
                   oah_emit_ins_elem(buf, 3, 16, 0, 17, 1) &&
                   emit_st_xmm_reg(buf, g, 16, in->src, T4);
        }
        return emit_vec_ea(buf, g, in, next, T0) &&
               emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               oah_emit_mem(buf, 3, false, false, false, T6, T0, 0) &&
               oah_emit_ins_gpr(buf, 16, 0x08, T6) &&
               emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0x13:  /* movlpd/movlps m64, xmm */
        if (!in->memory) {
            return false;
        }
        return emit_vec_ea(buf, g, in, next, T0) &&
               emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               oah_emit_ldr_str_vec(buf, true, false, 16, T0, 0);
    case 0x16:  /* movhpd xmm, m64 */
        if (!in->memory) {
            return false;
        }
        return emit_vec_ea(buf, g, in, next, T0) &&
               emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               oah_emit_mem(buf, 3, false, false, false, T6, T0, 0) &&
               oah_emit_ins_gpr(buf, 16, 0x18, T6) &&
               emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0x17:  /* movhpd m64, xmm */
        if (!in->memory) {
            return false;
        }
        return emit_vec_ea(buf, g, in, next, T0) &&
               emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               oah_emit_umov_gpr(buf, true, T6, 16, 0x18) &&
               oah_emit_mem(buf, 3, true, false, false, T6, T0, 0);
    case 0x7a:  /* movq xmm, xmm64/m64 (f3 0f 7e): zero-extend low qword */
        if (!oah_emit_vec3(buf, OAH_V_EOR, 16, 16, 16)) {
            return false;
        }
        {
            bool ok;
            if (in->memory) {
                ok = emit_vec_ea(buf, g, in, next, T0) &&
                     oah_emit_mem(buf, 3, false, false, false, T6, T0, 0);
            } else {
                ok = emit_ld_xmm_reg(buf, g, 18, in->dst, T5) &&
                     oah_emit_umov_gpr(buf, true, T6, 18, 0x08);
            }
            return ok && oah_emit_ins_gpr(buf, 16, 0x08, T6) &&
                   emit_st_xmm_reg(buf, g, 16, in->src, T4);
        }
    case 0x6e:  /* movd xmm, r/m32 */
        if (!oah_emit_vec3(buf, OAH_V_EOR, 16, 16, 16)) {
            return false;
        }
        {
            bool w64 = in->opsize == 8;
            bool ok;
            if (in->memory) {
                ok = emit_vec_ea(buf, g, in, next, T0) &&
                     oah_emit_mem(buf, w64 ? 3 : 2, false, false, w64,
                                  T6, T0, 0);
            } else {
                ok = emit_read_gpr(buf, T6, in->dst, in->opsize,
                                   in->rex_present);
            }
            return ok &&
                   oah_emit_ins_gpr(buf, 16, w64 ? 0x08 : 0x04, T6) &&
                   emit_st_xmm_reg(buf, g, 16, in->src, T4);
        }
    case 0x7e:  /* movd r/m, xmm (66 0f 7e) */
        {
            bool w64 = in->opsize == 8;
            if (!emit_ld_xmm_reg(buf, g, 16, in->src, T4) ||
                !oah_emit_umov_gpr(buf, w64, T6, 16, w64 ? 0x08 : 0x04)) {
                return false;
            }
            if (in->memory) {
                return emit_vec_ea(buf, g, in, next, T0) &&
                       oah_emit_mem(buf, w64 ? 3 : 2, true, false, false,
                                    T6, T0, 0);
            }
            return emit_store_gpr(buf, in->dst, T6, in->opsize,
                                  in->rex_present);
        }
    case 0x70:  /* pshufd xmm, xmm/m128, imm8 */
        if (!emit_ld_rm128(buf, g, in, next, 17)) {
            return false;
        }
        for (u32 i = 0; i < 4; i++) {
            if (!oah_emit_ins_elem(buf, 2, 16, i, 17,
                                   ((u32)in->imm >> (2 * i)) & 3)) {
                return false;
            }
        }
        return emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0xc6:  /* shufpd xmm, xmm/m128, imm8 (66 0f c6) */
        /* dst.d[0] = dst.d[imm&1]; dst.d[1] = src.d[(imm>>1)&1] */
        return emit_ld_xmm_reg(buf, g, 16, in->src, T4) &&
               emit_ld_rm128(buf, g, in, next, 17) &&
               oah_emit_ins_elem(buf, 3, 16, 0, 16, (u32)in->imm & 1) &&
               oah_emit_ins_elem(buf, 3, 16, 1, 17,
                                 ((u32)in->imm >> 1) & 1) &&
               emit_st_xmm_reg(buf, g, 16, in->src, T4);
    case 0xd6:  /* movq xmm/m64, xmm (66 0f d6) */
        if (!emit_ld_xmm_reg(buf, g, 16, in->src, T4)) {
            return false;
        }
        if (in->memory) {
            return emit_vec_ea(buf, g, in, next, T0) &&
                   oah_emit_ldr_str_vec(buf, true, false, 16, T0, 0);
        }
        /* xmm low->low, upper zeroed */
        return oah_emit_vec3(buf, OAH_V_EOR, 18, 18, 18) &&
               oah_emit_ins_elem(buf, 3, 18, 0, 16, 0) &&
               emit_st_xmm_reg(buf, g, 18, in->dst, T5);
    case 0xd7:  /* pmovmskb r32, xmm */
        /* Bytes -> 0/1 via ushr#7, then bit-gather each 64-bit half
         * with (x * 0x0102040810204080) >> 56. */
        if (in->memory) {
            return false;
        }
        return emit_ld_xmm_reg(buf, g, 16, in->dst, T4) &&
               oah_emit_vushr_imm(buf, 0, 16, 16, 7) &&
               oah_emit_umov_gpr(buf, true, T6, 16, 0x08) &&
               oah_emit_umov_gpr(buf, true, T5, 16, 0x18) &&
               oah_emit_mov_u64(buf, T7, 0x0102040810204080ull) &&
               oah_emit_mul(buf, true, T6, T6, T7) &&
               oah_emit_mul(buf, true, T5, T5, T7) &&
               oah_emit_ubfm(buf, true, T6, T6, 56, 63) &&
               oah_emit_ubfm(buf, true, T5, T5, 56, 63) &&
               oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, T6, T6,
                                  T5, 0, 8) &&
               emit_store_gpr(buf, in->src, T6, 4, in->rex_present);
    default:
        return false;
    }
}

/* Memory direction for replay safety: a native fault restores the
 * entered fragment's entry state and replays the prefix under the
 * interpreter with committed stores suppressed, so a replayed load
 * must never precede a committed store — it would re-read new bytes.
 * Conservative: anything ambiguous counts as both directions. */
bool oah_insn_writes_mem(const oah_insn *in)
{
    switch (in->op) {
    case OAH_OP_PUSH:
    case OAH_OP_PUSH_IMM:
    case OAH_OP_CALL_REL:
    case OAH_OP_STRING: /* movs/stos write; lods/cmps/scas stay interp */
        return true;
    case OAH_OP_POP:
        return in->rm_dest; /* pop r/m writes the destination */
    case OAH_OP_FLAGS_STACK:
        return in->rm_dest; /* pushf; popf goes to interp */
    case OAH_OP_SCALAR:
        if (in->scalar == OAH_SC_PUSH || in->scalar == OAH_SC_CALL) {
            return true; /* stack write */
        }
        return in->memory && in->rm_dest;
    case OAH_OP_VECTOR:
        if (!in->memory) {
            return false;
        }
        switch (in->vector_opcode) {
        case 0x7f: case 0x11: case 0x29: /* mov stores */
        case 0x13: case 0x17:           /* movlps/movhps stores */
        case 0x7e: case 0xd6:           /* movd/movq stores */
        case 0xe7:                      /* movntdq */
            return true;
        }
        return false;
    default:
        return false;
    }
}

bool oah_insn_reads_mem(const oah_insn *in)
{
    switch (in->op) {
    case OAH_OP_POP:
    case OAH_OP_RET:
    case OAH_OP_LEAVE:
    case OAH_OP_STRING:
        return true;
    case OAH_OP_FLAGS_STACK:
        return !in->rm_dest; /* popf */
    case OAH_OP_SCALAR:
        if (in->scalar == OAH_SC_JMP) {
            return in->memory; /* indirect target */
        }
        if (in->scalar == OAH_SC_PUSH || in->scalar == OAH_SC_CALL) {
            return in->memory; /* operand read; stack side is a write */
        }
        /* rm load, or RMW — a plain mov store does not read */
        return in->memory && !(in->rm_dest && in->scalar == OAH_SC_MOV);
    case OAH_OP_VECTOR:
        return in->memory && !oah_insn_writes_mem(in);
    default:
        return false;
    }
}

bool oah_translate_frag(oah_asm_buf *buf, oah_image *img, const oah_guest *g,
                        u64 rip, oah_frag_info *info)
{
    u64 cur = rip;
    unsigned n = 0;
    u32 frag_mem = 0;

    memset(info, 0, sizeof(*info));
    frag_relocs = info;
    xmm_resident = 0;
    xmm_dirty = 0;

    static int max_insns = -1;
    if (max_insns < 0) {
        const char *e = getenv("OAH_JIT_FRAGLEN");
        max_insns = e ? atoi(e) : 96;
    }

    /* Flag liveness pre-pass: decode the fragment's insn stream the same
     * way the emit loop will, then propagate F_RF needs backward from the
     * exit (which requires a complete shadow). A producer merges only the
     * fields in frag_fmerge[i]; dead flag work drops to zero host insns.
     * Disabled under VERIFY (dead fields stay stale, the verifier compares
     * full rflags) and under the OAH_JIT_NO* bisection gates, which create
     * unpredictable interp boundaries. OAH_JIT_NOFLAGS also forces eager
     * merges for A/B debugging. */
    static int flag_live_on = -1;
    if (flag_live_on < 0) {
        flag_live_on = !getenv("OAH_JIT_VERIFY") &&
                       !getenv("OAH_JIT_NOFLAGS") &&
                       !getenv("OAH_JIT_NOSTORE") && !getenv("OAH_JIT_NOLOAD") &&
                       !getenv("OAH_JIT_NOCTRL") && !getenv("OAH_JIT_NOALU") &&
                       !getenv("OAH_JIT_NOALL") && !getenv("OAH_JIT_NORMW") &&
                       !getenv("OAH_JIT_NOJCC") && !getenv("OAH_JIT_NOCALL") &&
                       !getenv("OAH_JIT_RMWTRACE");
    }
    nzcv_fields = 0;
    nzcv_cfinv = 0;
    frag_fmerge_n = 0;
    if (flag_live_on && max_insns > 0) {
        u64 c = rip;
        unsigned k = 0;
        bool term = false;
        for (; k < (unsigned)max_insns && k < OAH_FLAG_SCAN_MAX && !term; k++) {
            u64 avail = OAH_X86_MAX_INSN;
            const u8 *p = oah_guest_span(img, c, &avail);
            oah_insn *pi = &frag_pins[k];
            if (!p || !oah_guest_access(img, c, 1, PROT_EXEC) ||
                !oah_decode_insn(p, p + avail, pi)) {
                break;
            }
            insn_flag_masks(pi, &frag_frd[k], &frag_fwr[k]);
            c += pi->length;
            term = pi->op == OAH_OP_RET || pi->op == OAH_OP_JMP_REL ||
                   pi->op == OAH_OP_CALL_REL || pi->op == OAH_OP_JCC_REL ||
                   (pi->op == OAH_OP_SCALAR &&
                    (pi->scalar == OAH_SC_JMP || pi->scalar == OAH_SC_CALL));
        }
        frag_fmerge_n = k;
        /* live = fields whose value must be correct in F_RF for later
         * readers; the fragment exit (seeded below) needs all six. */
        u16 live = OAH_FL_ALL;
        for (unsigned i = k; i-- > 0;) {
            frag_fmerge[i] = (u16)(frag_fwr[i] & live);
            live = (u16)((live & ~frag_fwr[i]) | frag_frd[i]);
        }
    }
    while (n < (unsigned)max_insns) {
        u64 available = OAH_X86_MAX_INSN;
        const u8 *pc = oah_guest_span(img, cur, &available);
        oah_insn in;
        u64 after;

        if (!pc || !oah_guest_access(img, cur, 1, PROT_EXEC) ||
            !oah_decode_insn(pc, pc + available, &in)) {
            if (n == 0) {
                return false;
            }
            break;
        }
        after = cur + in.length;
        u8 rsp = xn(OAH_X86_RSP);
        bool done = false;
        bool boundary_interp = false;
        u16 fmask = (n < frag_fmerge_n) ? frag_fmerge[n] : OAH_FL_ALL;
        u64 insn_start = buf->size;
        u32 reloc_start = info->nrelocs;
        u32 reloc_overflow_start = info->reloc_overflow;
        /* Record this insn's boundary so a mid-fragment fault can map the
         * native fault offset back to its owning guest instruction. */
        u32 bound_start = info->nbounds;
        bound_res_snap[bound_start] = xmm_resident;
        bound_dirty_snap[bound_start] = xmm_dirty;
        if (info->nbounds < OAH_FRAG_MAX_BOUNDS) {
            info->bound_off[info->nbounds] = (u32)insn_start;
            info->bound_rip[info->nbounds] = cur;
            info->nbounds++;
        }

        /* Bisect aid: OAH_JIT_NOSTORE sends every memory-writing insn to the
         * interpreter so store-emit bugs can be isolated. */
        static int nostore = -1, noload = -1, noctrl = -1, noalu = -1, noall = -1;
        if (nostore < 0) {
            nostore = getenv("OAH_JIT_NOSTORE") != NULL;
            noload = getenv("OAH_JIT_NOLOAD") != NULL;
            noctrl = getenv("OAH_JIT_NOCTRL") != NULL;
            noalu = getenv("OAH_JIT_NOALU") != NULL;
            noall = getenv("OAH_JIT_NOALL") != NULL;
        }
        static int normw = -1;
        if (normw < 0) {
            normw = getenv("OAH_JIT_NORMW") != NULL;
        }
        if (getenv("OAH_JIT_RMWTRACE") && in.memory && in.rm_dest &&
            in.op == OAH_OP_SCALAR) {
            fprintf(stderr, "rmw rip=%llx sc=%d w=%u imm=%u\n",
                    (unsigned long long)cur, in.scalar, in.opsize, in.immediate);
        }
        if (noall ||
            (normw && in.memory && in.rm_dest && in.op == OAH_OP_SCALAR) ||
            (nostore && ((in.memory && in.rm_dest) ||
                         in.op == OAH_OP_PUSH || in.op == OAH_OP_PUSH_IMM ||
                         in.op == OAH_OP_POP || in.op == OAH_OP_CALL_REL ||
                         (in.op == OAH_OP_FLAGS_STACK && in.rm_dest))) ||
            (noload && in.memory) ||
            ((in.op == OAH_OP_JCC_REL && (in.cc & 0xfe) == 10) ||
             (in.op == OAH_OP_SCALAR &&
              (in.scalar == OAH_SC_CMOV || in.scalar == OAH_SC_SETCC) &&
              (in.cc & 0xfe) == 10)) ||
            (noctrl && (in.op == OAH_OP_JCC_REL || in.op == OAH_OP_JMP_REL ||
                        in.op == OAH_OP_CALL_REL || in.op == OAH_OP_RET ||
                        (in.op == OAH_OP_SCALAR &&
                         (in.scalar == OAH_SC_JMP || in.scalar == OAH_SC_CALL)))) ||
            (getenv("OAH_JIT_NOJCC") && in.op == OAH_OP_JCC_REL) ||
            (getenv("OAH_JIT_NOCALL") &&
             (in.op == OAH_OP_CALL_REL || in.op == OAH_OP_RET ||
              (in.op == OAH_OP_SCALAR &&
               (in.scalar == OAH_SC_JMP || in.scalar == OAH_SC_CALL)))) ||
            (noalu && (in.op == OAH_OP_SCALAR || in.op == OAH_OP_XOR_RR ||
                       in.op == OAH_OP_CMP_RR || in.op == OAH_OP_CMP_IMM ||
                       in.op == OAH_OP_TEST_RR))) {
            boundary_interp = true;
        }

        /* Replay safety: once this fragment emitted a load, a following
         * store must start a new fragment — a fault replayed past it
         * would re-read bytes the committed store already changed. */
        if (!boundary_interp && (frag_mem & OAH_FRAG_HAS_LOAD) &&
            oah_insn_writes_mem(&in)) {
            if (!frag_exit(buf, g, cur)) {
                return false;
            }
            info->insns = n;
            info->src_len = (u32)(cur - rip);
            info->interp_next = 0;
            info->mem_flags = frag_mem;
            return true;
        }

        if (!boundary_interp)
        switch (in.op) {
        case OAH_OP_NOP:
        case OAH_OP_ENDBR64:
            break;
        case OAH_OP_MOV_IMM:
            if (in.opsize == 8) {
                if (!frag_movi(buf, xn((oah_x86_gpr)in.dst), in.imm)) {
                    return false;
                }
            } else {
                u8 t = T6;
                u64 v = in.imm;
                if (!oah_emit_movz(buf, false, t, 0, (u32)(v & 0xffff)) ||
                    (((v >> 16) & 0xffff) != 0 &&
                    !oah_emit_movk(buf, false, t, 1, (u32)((v >> 16) & 0xffff)))) {
                    return false;
                }
                if (!emit_store_gpr(buf, in.dst, t, in.opsize, in.rex_present)) {
                    return false;
                }
            }
            break;
        case OAH_OP_MOV_RR:
            if (!emit_read_gpr(buf, T6, in.src, in.opsize, in.rex_present) ||
                !emit_store_gpr(buf, in.dst, T6, in.opsize, in.rex_present)) {
                return false;
            }
            break;
        case OAH_OP_XOR_RR:
            /* dst ^= src at opsize */
            if (!emit_read_gpr(buf, T1, in.dst, in.opsize, in.rex_present) ||
                !emit_read_gpr(buf, T2, in.src, in.opsize, in.rex_present) ||
                !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, in.opsize == 8,
                                    T6, T1, T2, 0, 0) ||
                !emit_merge_logic(buf, T6, in.opsize, fmask) ||
                !emit_store_gpr(buf, in.dst, T6, in.opsize, in.rex_present)) {
                return false;
            }
            nzcv_fields = (fmask & (OAH_FL_SF | OAH_FL_ZF)) ? OAH_FL_NZCV : 0;
            nzcv_cfinv = 0;
            break;
        case OAH_OP_LEA_RIP:
            if (!emit_reloc_imm(buf, T6, after + (u64)(s64)in.disp,
                                OAH_RELOC_GVA) ||
                !emit_store_gpr(buf, in.dst, T6, in.opsize, in.rex_present)) {
                return false;
            }
            break;
        case OAH_OP_PUSH:
            if (!emit_push64(buf, xn((oah_x86_gpr)in.dst))) {
                return false;
            }
            break;
        case OAH_OP_PUSH_IMM:
            if (!frag_movi(buf, T6, in.imm) || !emit_push64(buf, T6)) {
                return false;
            }
            break;
        case OAH_OP_POP:
            if (in.memory) { /* pop r/m — interp handles the store */
                boundary_interp = true;
                break;
            }
            if (!oah_emit_mem(buf, 3, false, false, true,
                              xn((oah_x86_gpr)in.dst), rsp, 0) ||
                !oah_emit_add_sub_imm(buf, true, false, rsp, rsp, 8)) {
                return false;
            }
            break;
        case OAH_OP_RET:
            if (!emit_xmm_spill(buf, g) ||
                !oah_emit_mem(buf, 3, false, false, true, F_NR, rsp, 0) ||
                !oah_emit_add_sub_imm(buf, true, false, rsp, rsp, 8) ||
                !oah_emit_ret(buf)) {
                return false;
            }
            done = true;
            break;
        case OAH_OP_JMP_REL:
            if (!frag_exit(buf, g, after + (u64)(s64)in.disp)) {
                return false;
            }
            done = true;
            break;
        case OAH_OP_CALL_REL:
            if (!emit_reloc_imm(buf, T6, after, OAH_RELOC_GVA) ||
                !emit_push64(buf, T6) ||
                !frag_exit(buf, g, after + (u64)(s64)in.disp)) {
                return false;
            }
            done = true;
            break;
        case OAH_OP_JCC_REL:
            /* Two constant exits: b.cc skips itself plus the fall exit
             * (reloc_imm 4 + ret 1 = 5 insns) to reach the taken exit:
             * 4 + 20 = 24 bytes. Both rets are chainable, so hot loop
             * back-edges repatch to direct branches. The xmm spill must
             * precede the b.cond so both paths keep the fixed skip. */
            {
                u32 cc_cond;
                if (!emit_flags_for_cc(buf, in.cc, &cc_cond)) {
                    return false;
                }
                if (!emit_xmm_spill(buf, g) ||
                    !oah_emit_bcond(buf, cc_cond, 24) ||
                    !frag_exit_imm(buf, after) ||
                    !frag_exit_imm(buf, after + (u64)(s64)in.disp)) {
                    return false;
                }
            }
            done = true;
            break;
        case OAH_OP_CMP_RR:
        case OAH_OP_CMP_IMM: {
            /* cmp dst, rhs — flags only, no result store */
            if (!emit_read_gpr(buf, T1, in.dst, in.opsize, in.rex_present)) {
                return false;
            }
            if (in.op == OAH_OP_CMP_RR) {
                if (!emit_read_gpr(buf, T5, in.src, in.opsize, in.rex_present)) {
                    return false;
                }
            } else {
                u64 mask = in.opsize == 8 ? ~0ull
                                        : (1ull << (in.opsize * 8)) - 1;
                if (!frag_movi(buf, T5, in.imm & mask)) {
                    return false;
                }
            }
            if (!emit_arith_flags(buf, true, T6, T1, T5, in.opsize, fmask)) {
                return false;
            }
            nzcv_fields = OAH_FL_NZCV;
            nzcv_cfinv = 1;
            break;
        }
        case OAH_OP_TEST_RR:
            if (!emit_read_gpr(buf, T1, in.dst, in.opsize, in.rex_present) ||
                !emit_read_gpr(buf, T2, in.src, in.opsize, in.rex_present) ||
                !oah_emit_logic_reg(buf, OAH_LOGIC_AND, in.opsize == 8,
                                    T6, T1, T2, 0, 0) ||
                !emit_merge_logic(buf, T6, in.opsize, fmask)) {
                return false;
            }
            nzcv_fields = (fmask & (OAH_FL_SF | OAH_FL_ZF)) ? OAH_FL_NZCV : 0;
            nzcv_cfinv = 0;
            break;
        case OAH_OP_LEAVE: {
            u8 rbp = xn(OAH_X86_RBP);
            /* rsp = rbp; rbp = [rsp]; rsp += 8 */
            if (!oah_emit_mov_reg(buf, true, rsp, rbp) ||
                !oah_emit_mem(buf, 3, false, false, true, rbp, rsp, 0) ||
                !oah_emit_add_sub_imm(buf, true, false, rsp, rsp, 8)) {
                return false;
            }
            break;
        }
        case OAH_OP_SET_DIRECTION:
            /* insn.imm: 1 = std (set DF bit10), 0 = cld (clear it) */
            if (in.imm) {
                if (!oah_emit_movz(buf, true, T4, 0, 0x400) ||
                    !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true,
                                        F_RF, F_RF, T4, 0, 0)) {
                    return false;
                }
            } else {
                if (!oah_emit_movn(buf, true, T4, 0, 0x400) ||
                    !oah_emit_logic_reg(buf, OAH_LOGIC_AND, true,
                                        F_RF, F_RF, T4, 0, 0)) {
                    return false;
                }
            }
            break;
        case OAH_OP_SIGN_HIGH:
            /* rdx = rax >> (width-1) (sign fill) */
            if (in.opsize == 8) {
                if (!frag_asr(buf, true, xn(OAH_X86_RDX), xn(OAH_X86_RAX), 63)) {
                    return false;
                }
            } else {
                u8 t = T6;
                if (!oah_emit_sbfm(buf, false, t, xn(OAH_X86_RAX), 0,
                                   (u32)(in.opsize * 8 - 1)) ||
                    !frag_asr(buf, false, t, t, in.opsize * 8 - 1) ||
                    !emit_store_gpr(buf, OAH_X86_RDX, t, in.opsize,
                                    in.rex_present)) {
                    return false;
                }
            }
            break;
        case OAH_OP_FLAGS_STACK:
            /* pushf only (rm_dest writes flags to stack); popf -> interp */
            if (!in.rm_dest || in.opsize != 8) {
                boundary_interp = true;
                break;
            }
            {
                u8 rsp2 = xn(OAH_X86_RSP);
                if (!oah_emit_movn(buf, true, T4, 1, 3) || /* ~0x30000 */
                    !oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, T4, F_RF, T4, 0, 0) ||
                    !oah_emit_add_sub_imm(buf, true, true, rsp2, rsp2, 8) ||
                    !oah_emit_mem(buf, 3, true, false, false, T4, rsp2, 0)) {
                    return false;
                }
            }
            break;
        case OAH_OP_STORE_FENCE:
            oah_asm_emit32(buf, 0xd5033bbfu); /* dmb ish */
            break;
        case OAH_OP_SCALAR:
            if (!frag_translate_scalar(buf, g, &in, after, fmask)) {
                boundary_interp = true;
                break;
            }
            /* Indirect jumps/calls returned via F_NR terminate the block. */
            if (in.scalar == OAH_SC_JMP || in.scalar == OAH_SC_CALL) {
                done = true;
            }
            break;
        case OAH_OP_VECTOR:
            if (!oah_frag_sse || !oah_sse_tab[in.vector_opcode] ||
                !frag_translate_vector(buf, g, &in, after)) {
                boundary_interp = true;
            }
            break;
        default:
            boundary_interp = true;
            break;
        }

        if (boundary_interp) {
            /* End the fragment: x20 = cur (this insn runs under interp).
             * Drop whatever the aborted case body emitted, including any
             * relocs recorded before it failed. */
            buf->size = insn_start;
            info->nrelocs = reloc_start;
            info->reloc_overflow = reloc_overflow_start;
            info->nbounds = bound_start;
            /* Vector state rolls back with the code: a partially emitted
             * insn must not leak residency/dirty bits into the exit. */
            xmm_resident = bound_res_snap[bound_start];
            xmm_dirty = bound_dirty_snap[bound_start];
            if (getenv("OAH_JIT_TRACE")) {
                fprintf(stderr, "  boundary %llx op=%d sc=%d w=%d imm=%d b0=%02x b1=%02x b2=%02x b3=%02x mem=%d\n",
                        (unsigned long long)cur, in.op, in.scalar,
                        in.opsize, in.immediate, pc[0], pc[1], pc[2],
                        pc[3], in.memory);
            }
            if (!frag_exit(buf, g, cur)) {
                return false;
            }
            info->nexits = 0; /* interp step must run before the next frag */
            info->insns = n;
            info->src_len = (u32)(cur - rip);
            info->interp_next = 1;
            info->mem_flags = frag_mem;
            return true;
        }
        if (oah_insn_reads_mem(&in)) {
            frag_mem |= OAH_FRAG_HAS_LOAD;
        }
        if (oah_insn_writes_mem(&in)) {
            frag_mem |= OAH_FRAG_HAS_STORE;
        }
        if (done) {
            info->insns = n + 1;
            info->src_len = (u32)(after - rip);
            info->interp_next = 0;
            info->mem_flags = frag_mem;
            return true;
        }
        cur = after;
        n++;
    }
    if (!frag_exit(buf, g, cur)) {
        return false;
    }
    info->insns = n;
    info->src_len = (u32)(cur - rip);
    info->interp_next = 0;
    info->mem_flags = frag_mem;
    return true;
}
