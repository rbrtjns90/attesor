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
            if (flags & OAH_XLAT_DISPATCH_STATE) {
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
 * Merge host NZCV into guest RFLAGS (x19). Sets CF,PF,AF,ZF,SF,OF.
 * res = masked result reg (low byte feeds PF).
 * lhs/rhs = masked operand regs feeding AF (lhs^rhs^res bit 4).
 * invert_cf: host C is not-borrow for subs → flip.
 * keep_cf: inc/dec leave guest CF alone.
 * set_af: write AF from operands (cleared by logic ops).
 */
static bool emit_merge_arith(oah_asm_buf *buf, u8 res, u8 lhs, u8 rhs,
                             bool invert_cf, bool keep_cf, bool set_af)
{
    if (!oah_emit_mrs_nzcv(buf, M1) ||
        !oah_emit_movn(buf, true, M2, 0, 0x8d5 - (keep_cf ? 1 : 0)) ||
        !oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, F_RF, F_RF, M2, 0, 0) ||
        !frag_ubfx(buf, M2, M1, 30, 2) ||          /* N,Z -> 6,7 */
        !frag_lsl(buf, false, M2, M2, 6) ||
        !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, F_RF, F_RF, M2, 0, 0)) {
        return false;
    }
    if (!keep_cf) {
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
    if (!frag_ubfx(buf, M2, M1, 28, 1) ||
        !frag_bfi(buf, F_RF, M2, 11, 1) ||
        !emit_parity(buf, res)) {
        return false;
    }
    if (set_af) {
        if (!oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, lhs, rhs, 0, 0) ||
            !oah_emit_logic_reg(buf, OAH_LOGIC_EOR, true, M2, M2, res, 0, 0) ||
            !frag_ubfx(buf, M2, M2, 4, 1) ||
            !frag_bfi(buf, F_RF, M2, 4, 1)) {
            return false;
        }
    }
    return true;
}

/* SZP flags for a masked result; clears CF|OF|AF (logical op semantics). */
static bool emit_merge_logic(oah_asm_buf *buf, u8 res, u8 width)
{
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
        !oah_emit_movn(buf, true, M2, 0, 0x8d5) ||
        !oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, F_RF, F_RF, M2, 0, 0) ||
        !frag_ubfx(buf, M2, M1, 30, 2) ||
        !frag_lsl(buf, false, M2, M2, 6) ||
        !oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, F_RF, F_RF, M2, 0, 0) ||
        !emit_parity(buf, res)) {
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

/* ADD/SUB/CMP family with full flag merge; res_r = result. */
static bool emit_arith_flags(oah_asm_buf *buf, bool is_sub, u8 res_r,
                             u8 lhs_r, u8 rhs_r, u8 width, bool keep_cf)
{
    return emit_arith_compute(buf, is_sub, res_r, lhs_r, rhs_r, width) &&
           emit_merge_arith(buf, res_r, lhs_r, rhs_r, is_sub, keep_cf, true);
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
        return true;
    default:
        return false;
    }
}

static bool frag_translate_scalar(oah_asm_buf *buf, const oah_guest *g,
                                  const oah_insn *in, u64 next)
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
            if (!emit_arith_flags(buf, false, res, lhs, r, width, false)) {
                return false;
            }
            break;
        case OAH_SC_SUB: case OAH_SC_CMP:
            if (!emit_arith_flags(buf, true, res, lhs, r, width, false)) {
                return false;
            }
            break;
        case OAH_SC_OR:
            if (!oah_emit_logic_reg(buf, OAH_LOGIC_ORR, width == 8, res, lhs, r, 0, 0) ||
                !emit_merge_logic(buf, res, width)) {
                return false;
            }
            break;
        case OAH_SC_AND: case OAH_SC_TEST:
            if (!oah_emit_logic_reg(buf, OAH_LOGIC_AND, width == 8, res, lhs, r, 0, 0) ||
                !emit_merge_logic(buf, res, width)) {
                return false;
            }
            break;
        case OAH_SC_XOR:
            if (!oah_emit_logic_reg(buf, OAH_LOGIC_EOR, width == 8, res, lhs, r, 0, 0) ||
                !emit_merge_logic(buf, res, width)) {
                return false;
            }
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
        return emit_merge_arith(buf, res, lhs, res, dec, true, true) &&
               emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_NEG:
        /* res = 0 - lhs; flags = cmp(0,lhs); AF = lhs^res */
        return emit_arith_compute(buf, true, res, 31, lhs, width) &&
               emit_merge_arith(buf, res, 31, lhs, true, false, true) &&
               emit_store_result(buf, in, res, T0);
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
        return oah_emit_csinc(buf, false, T4, 31, 31, 0 /*EQ*/) &&
               oah_emit_movn(buf, true, T5, 0, 0x801) &&
               oah_emit_logic_reg(buf, OAH_LOGIC_AND, true, F_RF, F_RF, T5, 0, 0) &&
               frag_lsl(buf, false, T5, T4, 11) &&
               oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, T5, T5, T4, 0, 0) &&
               oah_emit_logic_reg(buf, OAH_LOGIC_ORR, true, F_RF, F_RF, T5, 0, 0) &&
               emit_store_result(buf, in, res, T0);
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
                !emit_merge_logic(buf, res, width)) {
                return false;
            }
            /* CF = bit(bits-cnt) [SHL] or bit(cnt-1) [SHR/SAR] of lhs;
             * defined only when cnt <= bits (undefined otherwise). */
            u64 skip_cf = 0;
            if (bits < 32) {
                if (!oah_emit_add_sub_imm_flags(buf, false, true, true, 31,
                                                T4, bits, 0)) {
                    return false;
                }
                skip_cf = buf->size;
                if (!oah_emit_bcond(buf, OAH_ARM_HI, 0)) {
                    return false;
                }
            }
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
            if (skip_cf) {
                oah_asm_patch32(buf, skip_cf,
                                0x54000000u |
                                (((u32)(buf->size - skip_cf) >> 2) << 5) |
                                OAH_ARM_HI);
            }
            /* OF on cnt==1: SHR = sign(lhs); SHL = sign(res)^CF. */
            if (kind != 2) {
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
        if (!emit_merge_logic(buf, res, width)) {
            return false;
        }
        /* CF = bit(bits-count) [SHL] or bit(count-1) [SHR/SAR] of lhs,
         * only when the masked count doesn't exceed the operand width. */
        if (raw_count <= bits) {
            u32 bit = kind == 0 ? bits - raw_count : raw_count - 1;
            if (!oah_emit_ubfm(buf, width == 8, T4, lhs, bit, bit) ||
                !frag_bfi(buf, F_RF, T4, 0, 1)) {
                return false;
            }
        }
        /* OF on count==1: SHR = sign(lhs); SHL = sign(res)^CF; SAR unchanged. */
        if (raw_count == 1 && kind != 2) {
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
    case OAH_SC_BSF: case OAH_SC_BSR: {
        /* Input is the rm operand (T1); dest is in->src. Zero input:
         * ZF=1 and dest unchanged; else ZF=0 and res = lowest/highest
         * set-bit index. Other flags are undefined on x86 — untouched. */
        bool is64 = width == 8;
        if (!oah_emit_add_sub_imm_flags(buf, is64, true, true, 31, T1, 0, 0) ||
            !oah_emit_csinc(buf, false, T4, 31, 31, OAH_ARM_NE) ||
            !frag_bfi(buf, F_RF, T4, 6, 1)) {
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
    case OAH_SC_SETCC:
        return emit_rflags_to_nzcv(buf, T4) &&
               oah_emit_csinc(buf, false, res, 31, 31,
                              arm_cond_for_x86(in->cc) ^ 1) &&
               emit_store_result(buf, in, res, T0);
    case OAH_SC_CMOV: {
        /* csel res = cond ? rm(T1) : dst(T2). */
        if (!emit_rflags_to_nzcv(buf, T4)) {
            return false;
        }
        u32 cond = arm_cond_for_x86(in->cc);
        return oah_emit_csel(buf, width == 8, res, T1, T2, cond) &&
               emit_store_result(buf, in, res, T0);
    }
    case OAH_SC_PUSH:
        return emit_push64(buf, T1);
    case OAH_SC_JMP:
        return frag_mov(buf, true, F_NR, T1) && oah_emit_ret(buf);
    case OAH_SC_CALL:
        return emit_reloc_imm(buf, T4, next, OAH_RELOC_GVA) &&
               emit_push64(buf, T4) &&
               frag_mov(buf, true, F_NR, T1) && oah_emit_ret(buf);
    default:
        return false;
    }
}

bool oah_translate_frag(oah_asm_buf *buf, oah_image *img, const oah_guest *g,
                        u64 rip, oah_frag_info *info)
{
    u64 cur = rip;
    unsigned n = 0;

    memset(info, 0, sizeof(*info));
    frag_relocs = info;

    static int max_insns = -1;
    if (max_insns < 0) {
        const char *e = getenv("OAH_JIT_FRAGLEN");
        max_insns = e ? atoi(e) : 96;
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
        u64 insn_start = buf->size;

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
                !emit_merge_logic(buf, T6, in.opsize) ||
                !emit_store_gpr(buf, in.dst, T6, in.opsize, in.rex_present)) {
                return false;
            }
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
            if (!oah_emit_mem(buf, 3, false, false, true,
                              xn((oah_x86_gpr)in.dst), rsp, 0) ||
                !oah_emit_add_sub_imm(buf, true, false, rsp, rsp, 8)) {
                return false;
            }
            break;
        case OAH_OP_RET:
            if (!oah_emit_mem(buf, 3, false, false, true, F_NR, rsp, 0) ||
                !oah_emit_add_sub_imm(buf, true, false, rsp, rsp, 8) ||
                !oah_emit_ret(buf)) {
                return false;
            }
            done = true;
            break;
        case OAH_OP_JMP_REL:
            if (!frag_exit_imm(buf, after + (u64)(s64)in.disp)) {
                return false;
            }
            done = true;
            break;
        case OAH_OP_CALL_REL:
            if (!emit_reloc_imm(buf, T6, after, OAH_RELOC_GVA) ||
                !emit_push64(buf, T6) ||
                !frag_exit_imm(buf, after + (u64)(s64)in.disp)) {
                return false;
            }
            done = true;
            break;
        case OAH_OP_JCC_REL:
            /* Two constant exits: b.cc skips itself plus the fall exit
             * (reloc_imm 4 + ret 1 = 5 insns) to reach the taken exit:
             * 4 + 20 = 24 bytes. Both rets are chainable, so hot loop
             * back-edges repatch to direct branches. */
            if (!emit_rflags_to_nzcv(buf, T4) ||
                !oah_emit_bcond(buf, arm_cond_for_x86(in.cc), 24) ||
                !frag_exit_imm(buf, after) ||
                !frag_exit_imm(buf, after + (u64)(s64)in.disp)) {
                return false;
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
            if (!emit_arith_flags(buf, true, T6, T1, T5, in.opsize, false)) {
                return false;
            }
            break;
        }
        case OAH_OP_TEST_RR:
            if (!emit_read_gpr(buf, T1, in.dst, in.opsize, in.rex_present) ||
                !emit_read_gpr(buf, T2, in.src, in.opsize, in.rex_present) ||
                !oah_emit_logic_reg(buf, OAH_LOGIC_AND, in.opsize == 8,
                                    T6, T1, T2, 0, 0) ||
                !emit_merge_logic(buf, T6, in.opsize)) {
                return false;
            }
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
            if (!frag_translate_scalar(buf, g, &in, after)) {
                boundary_interp = true;
                break;
            }
            /* Indirect jumps/calls returned via F_NR terminate the block. */
            if (in.scalar == OAH_SC_JMP || in.scalar == OAH_SC_CALL) {
                done = true;
            }
            break;
        default:
            boundary_interp = true;
            break;
        }

        if (boundary_interp) {
            /* End the fragment: x20 = cur (this insn runs under interp).
             * Drop whatever the aborted case body emitted. */
            buf->size = insn_start;
            if (getenv("OAH_JIT_TRACE")) {
                fprintf(stderr, "  boundary %llx op=%d sc=%d w=%d imm=%d b0=%02x b1=%02x b2=%02x mem=%d\n",
                        (unsigned long long)cur, in.op, in.scalar,
                        in.opsize, in.immediate, pc[0], pc[1], pc[2],
                        in.memory);
            }
            if (!frag_exit_imm(buf, cur)) {
                return false;
            }
            info->nexits = 0; /* interp step must run before the next frag */
            info->insns = n;
            info->interp_next = 1;
            return true;
        }
        if (done) {
            info->insns = n + 1;
            info->interp_next = 0;
            return true;
        }
        cur = after;
        n++;
    }
    if (!frag_exit_imm(buf, cur)) {
        return false;
    }
    info->insns = n;
    info->interp_next = 0;
    return true;
}
