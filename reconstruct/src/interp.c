#include "oah/interp.h"
#include "oah/decode_insn.h"
#include "oah/condition.h"
#include "oah/flags.h"

#include <string.h>
#include <sys/mman.h>
#include <time.h>

static u64 mask_for(u8 opsize)
{
    if (opsize == 1) {
        return 0xffull;
    }
    if (opsize == 2) {
        return 0xffffull;
    }
    if (opsize == 4) {
        return 0xffffffffull;
    }
    return ~0ull;
}

static void write_gpr(oah_guest *g, u8 r, u8 opsize, u64 val)
{
    if (opsize == 4) {
        g->gpr[r] = val & 0xffffffffull; /* 32-bit writes zero-extend */
    } else if (opsize == 8) {
        g->gpr[r] = val;
    } else {
        g->gpr[r] = (g->gpr[r] & ~mask_for(opsize)) | (val & mask_for(opsize));
    }
}

static bool push64(oah_guest *g, oah_image *img, u64 val)
{
    u64 rsp = g->gpr[OAH_X86_RSP] - 8;
    void *slot = oah_guest_access(img, rsp, 8, PROT_WRITE);
    if (!slot) {
        return false;
    }
    memcpy(slot, &val, sizeof(val));
    g->gpr[OAH_X86_RSP] = rsp;
    return true;
}

static bool pop64(oah_guest *g, oah_image *img, u8 dst)
{
    const void *slot = oah_guest_access(img, g->gpr[OAH_X86_RSP], 8, PROT_READ);
    u64 value;
    if (!slot) {
        return false;
    }
    memcpy(&value, slot, sizeof(value));
    g->gpr[OAH_X86_RSP] += 8;
    g->gpr[dst] = value;
    return true;
}

static u64 effective_address(const oah_guest *g, const oah_address *a, u64 next)
{
    u64 base = a->rip_relative ? next : 0;
    if (a->base != OAH_NO_GPR) {
        base = g->gpr[a->base];
    }
    if (a->index != OAH_NO_GPR) {
        base += g->gpr[a->index] << a->scale;
    }
    base += (u64)(s64)a->disp;
    return a->address32 ? (u32)base : base;
}

static u64 read_reg(const oah_guest *g, u8 reg, u8 width, bool rex)
{
    if (width == 1 && !rex && reg >= 4 && reg <= 7) {
        return (g->gpr[reg - 4] >> 8) & 0xff;
    }
    return g->gpr[reg] & mask_for(width);
}

static void store_reg(oah_guest *g, u8 reg, u8 width, bool rex, u64 value)
{
    if (width == 1 && !rex && reg >= 4 && reg <= 7) {
        u64 *r = &g->gpr[reg - 4];
        *r = (*r & ~0xff00ull) | ((value & 0xff) << 8);
    } else {
        write_gpr(g, reg, width, value);
    }
}

static bool run_vector(oah_guest *g, oah_image *img, const oah_insn *in, u64 next)
{
    u8 op = in->vector_opcode;
    unsigned width = (op == 0x6e || op == 0x7e) ? in->opsize
                   : ((op >= 0x12 && op <= 0x17) || op == 0x7a || op == 0xd6) ? 8 : 16;
    bool store = op == 0x11 || op == 0x29 || op == 0x7f || op == 0x7e || op == 0xd6 ||
                 op == 0x13 || op == 0x17;
    u8 *xmm = g->xmm[in->src];
    u8 *other = g->xmm[in->dst];
    if (in->memory) {
        u64 address = effective_address(g, &in->address, next);
        address += in->address.segment == 0x64 ? g->fs_base
                 : in->address.segment == 0x65 ? g->gs_base : 0;
        if ((in->aligned && (address & 15)) || op == 0xd7) {
            return false;
        }
        other = oah_guest_access(img, address, width, store ? PROT_WRITE : PROT_READ);
        if (!other) {
            return false;
        }
    }
    switch (op) {
    case 0x6e:
        memset(xmm, 0, 16);
        memcpy(xmm, in->memory ? other : (u8 *)&g->gpr[in->dst], width);
        break;
    case 0x7e:
        if (in->memory) {
            memcpy(other, xmm, width);
        } else {
            u64 value = 0;
            memcpy(&value, xmm, width);
            write_gpr(g, in->dst, width, value);
        }
        break;
    case 0xd6:
        if (other != xmm) {
            memcpy(other, xmm, 8);
        }
        if (!in->memory) {
            memset(other + 8, 0, 8);
        }
        break;
    case 0x7a:
        if (other != xmm) {
            memcpy(xmm, other, 8);
        }
        memset(xmm + 8, 0, 8);
        break;
    case 0x12:
        if (in->memory || other != xmm) {
            memcpy(xmm, other + (in->memory ? 0 : 8), 8);
        } else {
            memmove(xmm, xmm + 8, 8);
        }
        break;
    case 0x13:
    case 0x17:
        memcpy(other, xmm + (op == 0x17 ? 8 : 0), 8);
        break;
    case 0x16:
    case 0x6c:
        memcpy(xmm + 8, other, 8);
        break;
    case 0x60:
    case 0x61:
    case 0x62:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6d: {
        unsigned lane = op == 0x6d ? 8 : 1u << (op & 3);
        unsigned start = op >= 0x68 ? 8 : 0;
        u8 values[16];
        for (unsigned offset = 0; offset < 8; offset += lane) {
            memcpy(values + 2 * offset, xmm + start + offset, lane);
            memcpy(values + 2 * offset + lane, other + start + offset, lane);
        }
        memcpy(xmm, values, sizeof(values));
        break;
    }
    case 0xc6: {
        u8 values[16];
        memcpy(values, xmm + (in->imm & 1) * 8, 8);
        memcpy(values + 8, other + ((in->imm >> 1) & 1) * 8, 8);
        memcpy(xmm, values, sizeof(values));
        break;
    }
    case 0x70: {
        u8 values[16];
        for (unsigned lane = 0; lane < 4; lane++) {
            memcpy(values + lane * 4, other + ((in->imm >> (lane * 2)) & 3) * 4, 4);
        }
        memcpy(xmm, values, sizeof(values));
        break;
    }
    case 0x73: {
        unsigned count = in->imm < 16 ? (unsigned)in->imm : 16;
        u8 values[16] = {0};
        if (in->cc == 7) {
            memcpy(values + count, other, 16 - count);
        } else {
            memcpy(values, other + count, 16 - count);
        }
        memcpy(other, values, sizeof(values));
        break;
    }
    case 0x74:
    case 0x75:
    case 0x76: {
        unsigned lane = 1u << (op - 0x74);
        for (unsigned i = 0; i < 16; i += lane) {
            memset(xmm + i, memcmp(xmm + i, other + i, lane) ? 0 : 255, lane);
        }
        break;
    }
    case 0xf8:
    case 0xda:
        for (unsigned i = 0; i < 16; i++) {
            xmm[i] = op == 0xf8 ? (u8)(xmm[i] - other[i])
                   : xmm[i] < other[i] ? xmm[i] : other[i];
        }
        break;
    case 0x57:
    case 0xef:
    case 0xdb:
    case 0xeb:
        for (unsigned i = 0; i < 16; i++) {
            xmm[i] = op == 0xdb ? xmm[i] & other[i]
                   : op == 0xeb ? xmm[i] | other[i] : xmm[i] ^ other[i];
        }
        break;
    case 0xd7: {
        u32 mask = 0;
        for (unsigned i = 0; i < 16; i++) {
            mask |= (u32)(other[i] >> 7) << i;
        }
        write_gpr(g, in->src, 4, mask);
        break;
    }
    default:
        if (xmm != other) {
            memcpy(store ? other : xmm, store ? xmm : other, width);
        }
        break;
    }
    g->rip = next;
    return true;
}

static s64 signed_operand(u64 value, u8 width)
{
    unsigned shift = 64 - width * 8;
    return (s64)(value << shift) >> shift;
}

static bool run_string(oah_guest *g, oah_image *img, const oah_insn *in, u64 next)
{
    u64 *count = &g->gpr[OAH_X86_RCX];
    u64 *dst = &g->gpr[OAH_X86_RDI];
    u64 *src = &g->gpr[OAH_X86_RSI];
    u64 value = g->gpr[OAH_X86_RAX];
    u8 width = in->opsize;
    u64 step = (g->rflags & OAH_RFLAGS_DF) ? -(u64)width : width;
    if (in->repeat && !*count) {
        g->rip = next;
        return true;
    }
    void *out = oah_guest_access(img, *dst, width, PROT_WRITE);
    if (!out) {
        return false;
    }
    if (in->string_move) {
        const void *input = oah_guest_access(img, *src, width, PROT_READ);
        if (!input) {
            return false;
        }
        memcpy(&value, input, width);
        *src += step;
    }
    memcpy(out, &value, width);
    *dst += step;
    if (!in->repeat || --*count == 0) {
        g->rip = next;
    }
    return true;
}

static bool run_scalar(oah_guest *g, oah_image *img, const oah_insn *in, u64 next)
{
    u8 width = in->opsize;
    oah_scalar_op op = in->scalar;
    bool indirect = op == OAH_SC_CALL || op == OAH_SC_JMP;
    bool move = op == OAH_SC_MOV || op == OAH_SC_MOVSX || op == OAH_SC_MOVZX ||
                op == OAH_SC_CMOV || op == OAH_SC_SETCC;
    bool write = op != OAH_SC_CMP && op != OAH_SC_TEST && op != OAH_SC_DIV &&
                 op != OAH_SC_BT && op != OAH_SC_MUL && op != OAH_SC_PUSH && !indirect;
    u8 rm_width = in->src_width ? in->src_width : width;
    u64 rm = 0, address = 0, result;
    void *slot = NULL;

    if (in->memory) {
        address = effective_address(g, &in->address, next);
        if (op == OAH_SC_LEA) {
            write_gpr(g, in->src, width, address);
            g->rip = next;
            return true;
        }
        if (in->address.segment == 0x64) {
            address += g->fs_base;
        } else if (in->address.segment == 0x65) {
            address += g->gs_base;
        }
        u32 prot = in->rm_dest && write ? PROT_WRITE : PROT_READ;
        if (!move) {
            prot |= PROT_READ;
        }
        slot = oah_guest_access(img, address, rm_width, prot);
        if (!slot) {
            return false;
        }
        if (!in->rm_dest || !move) {
            memcpy(&rm, slot, rm_width);
        }
    } else {
        rm = read_reg(g, in->dst, rm_width, in->rex_present);
    }

    if (op == OAH_SC_PUSH) {
        if (!push64(g, img, rm)) {
            return false;
        }
        g->rip = next;
        return true;
    }

    if (indirect) {
        if (op == OAH_SC_CALL && !push64(g, img, next)) {
            return false;
        }
        g->rip = rm;
        return true;
    }

    u64 reg = read_reg(g, in->src, width, in->rex_present);
    u64 lhs = in->rm_dest ? rm : reg;
    u64 rhs = in->immediate ? in->imm : in->rm_dest ? reg : rm;
    u64 mask = mask_for(width);
    rhs &= mask;
    result = rhs;
    if (op == OAH_SC_MUL) {
        unsigned bits = width * 8;
        __uint128_t product = (__uint128_t)(g->gpr[OAH_X86_RAX] & mask) * rm;
        u64 upper = (u64)(product >> bits);
        if (width == 1) {
            write_gpr(g, OAH_X86_RAX, 2, (u64)product);
        } else {
            write_gpr(g, OAH_X86_RAX, width, (u64)product);
            write_gpr(g, OAH_X86_RDX, width, upper);
        }
        g->rflags &= ~(OAH_RFLAGS_CF | OAH_RFLAGS_OF);
        if (upper) {
            g->rflags |= OAH_RFLAGS_CF | OAH_RFLAGS_OF;
        }
    } else if (op == OAH_SC_DIV) {
        unsigned bits = width * 8;
        __uint128_t dividend = width == 1 ? g->gpr[OAH_X86_RAX] & 0xffff
                            : ((__uint128_t)(g->gpr[OAH_X86_RDX] & mask) << bits) |
                              (g->gpr[OAH_X86_RAX] & mask);
        if (!rm || dividend / rm > mask) {
            return false;
        }
        u64 quotient = (u64)(dividend / rm);
        u64 remainder = (u64)(dividend % rm);
        if (width == 1) {
            write_gpr(g, OAH_X86_RAX, 2, quotient | (remainder << 8));
        } else {
            write_gpr(g, OAH_X86_RAX, width, quotient);
            write_gpr(g, OAH_X86_RDX, width, remainder);
        }
    } else if (op == OAH_SC_BT || op == OAH_SC_BTS || op == OAH_SC_BTR || op == OAH_SC_BTC) {
        unsigned bit = (in->immediate ? in->imm : reg) & (width * 8 - 1);
        u64 bit_mask = 1ull << bit;
        g->rflags = (g->rflags & ~OAH_RFLAGS_CF) | ((rm >> bit) & 1);
        result = op == OAH_SC_BTS ? rm | bit_mask
               : op == OAH_SC_BTR ? rm & ~bit_mask : rm ^ bit_mask;
    } else if (op == OAH_SC_CMPXCHG8B) {
        u64 expected = ((u64)(u32)g->gpr[OAH_X86_RDX] << 32) | (u32)g->gpr[OAH_X86_RAX];
        if (expected == rm) {
            g->rflags |= OAH_RFLAGS_ZF;
            result = ((u64)(u32)g->gpr[OAH_X86_RCX] << 32) | (u32)g->gpr[OAH_X86_RBX];
        } else {
            g->rflags &= ~OAH_RFLAGS_ZF;
            write_gpr(g, OAH_X86_RAX, 4, rm);
            write_gpr(g, OAH_X86_RDX, 4, rm >> 32);
            write = false;
        }
    } else if (op == OAH_SC_CMPXCHG) {
        /* The runtime dispatches one guest thread, including LOCK forms. */
        u64 expected = read_reg(g, OAH_X86_RAX, width, true);
        g->rflags = oah_cmp_rflags(g->rflags, expected, rm, width);
        if (expected != rm) {
            write_gpr(g, OAH_X86_RAX, width, rm);
            write = false;
        }
    } else if (op == OAH_SC_XCHG) {
        store_reg(g, in->src, width, in->rex_present, rm);
    } else if (op == OAH_SC_MOVSX) {
        result = (u64)signed_operand(rm, rm_width);
    } else if (op == OAH_SC_SETCC) {
        result = oah_condition_holds(in->cc, g->rflags);
    } else if (op == OAH_SC_CMOV) {
        write = oah_condition_holds(in->cc, g->rflags);
        if (!write && width == 4) {
            /* CMOVcc r32,r/m32 clears the upper half even when false. */
            write_gpr(g, in->src, 4, reg);
        }
    } else if (op == OAH_SC_BSF || op == OAH_SC_BSR) {
        g->rflags &= ~OAH_RFLAGS_ZF;
        if (!rm) {
            g->rflags |= OAH_RFLAGS_ZF;
            write = false;
        } else {
            result = op == OAH_SC_BSF ? (u64)__builtin_ctzll(rm)
                                     : (u64)(63 - __builtin_clzll(rm));
        }
    } else if (op == OAH_SC_INC || op == OAH_SC_DEC) {
        u64 saved_carry = g->rflags & OAH_RFLAGS_CF;
        u64 sign = 1ull << (width * 8 - 1);
        result = (op == OAH_SC_INC ? lhs + 1 : lhs - 1) & mask;
        g->rflags = oah_logic_rflags(g->rflags, result, width) | saved_carry;
        if (lhs == (op == OAH_SC_INC ? sign - 1 : sign)) {
            g->rflags |= OAH_RFLAGS_OF;
        }
        if ((lhs ^ result) & 0x10) {
            g->rflags |= OAH_RFLAGS_AF;
        }
    } else if (op == OAH_SC_NEG) {
        result = -lhs & mask;
        g->rflags = oah_cmp_rflags(g->rflags, 0, lhs, width);
    } else if (op == OAH_SC_NOT) {
        result = ~lhs & mask;
    } else if (op == OAH_SC_IMUL) {
        __int128 product = (__int128)signed_operand(in->immediate ? rm : reg, width) *
                           signed_operand(rhs, width);
        result = (u64)product & mask;
        g->rflags &= ~(OAH_RFLAGS_CF | OAH_RFLAGS_OF);
        if (product != signed_operand(result, width)) {
            g->rflags |= OAH_RFLAGS_CF | OAH_RFLAGS_OF;
        }
    } else if (op == OAH_SC_SHLD || op == OAH_SC_SHRD) {
        unsigned bits = width * 8;
        unsigned count = (in->immediate ? in->imm : g->gpr[OAH_X86_RCX]) &
                         (width == 8 ? 63 : 31);
        if (!count || count > bits) {
            g->rip = next;
            return true;
        }
        bool left = op == OAH_SC_SHLD;
        result = count == bits ? reg : left ? (lhs << count) | (reg >> (bits - count))
                                            : (lhs >> count) | (reg << (bits - count));
        result &= mask;
        g->rflags = oah_logic_rflags(g->rflags, result, width);
        if ((lhs >> (left ? bits - count : count - 1)) & 1) {
            g->rflags |= OAH_RFLAGS_CF;
        }
        if (count == 1 && ((lhs ^ result) >> (bits - 1))) {
            g->rflags |= OAH_RFLAGS_OF;
        }
    } else if (op == OAH_SC_ROL || op == OAH_SC_ROR) {
        unsigned bits = width * 8;
        unsigned masked = rhs & (width == 8 ? 63 : 31);
        unsigned count = masked % bits;
        if (!masked) {
            g->rip = next;
            return true;
        }
        result = lhs;
        if (count) {
            result = op == OAH_SC_ROL ? (lhs << count) | (lhs >> (bits - count))
                                      : (lhs >> count) | (lhs << (bits - count));
            result &= mask;
        }
        u64 carry = op == OAH_SC_ROL ? result & 1 : result >> (bits - 1);
        g->rflags = (g->rflags & ~OAH_RFLAGS_CF) | carry;
        if (masked == 1) {
            u64 top = result >> (bits - 1);
            u64 other = op == OAH_SC_ROL ? carry : (result >> (bits - 2)) & 1;
            g->rflags = (g->rflags & ~OAH_RFLAGS_OF) | ((top ^ other) ? OAH_RFLAGS_OF : 0);
        }
    } else if (op == OAH_SC_SHL || op == OAH_SC_SHR || op == OAH_SC_SAR) {
        unsigned bits = width * 8;
        unsigned count = rhs & (width == 8 ? 63 : 31);
        if (count == 0) {
            g->rip = next;
            return true;
        }
        if (op == OAH_SC_SHL) {
            result = (lhs << count) & mask;
        } else if (op == OAH_SC_SHR) {
            result = lhs >> count;
        } else {
            result = (u64)(signed_operand(lhs, width) >> count) & mask;
        }
        g->rflags = oah_logic_rflags(g->rflags, result, width);
        if (count <= bits) {
            unsigned bit = op == OAH_SC_SHL ? bits - count : count - 1;
            if ((lhs >> bit) & 1) {
                g->rflags |= OAH_RFLAGS_CF;
            }
        }
        if (count == 1 && (op == OAH_SC_SHR ? (lhs >> (bits - 1)) != 0
                        : op == OAH_SC_SHL && ((result >> (bits - 1)) !=
                                               !!(g->rflags & OAH_RFLAGS_CF)))) {
            g->rflags |= OAH_RFLAGS_OF;
        }
    } else if (!move) {
        u64 sign = 1ull << (width * 8 - 1);
        u64 carry = (op == OAH_SC_ADC || op == OAH_SC_SBB) &&
                    (g->rflags & OAH_RFLAGS_CF);
        bool subtract = op == OAH_SC_SUB || op == OAH_SC_SBB || op == OAH_SC_CMP;
        bool arithmetic = subtract || op == OAH_SC_ADD || op == OAH_SC_ADC || op == OAH_SC_XADD;
        if (arithmetic) {
            __uint128_t full = subtract ? (__uint128_t)lhs - rhs - carry
                                        : (__uint128_t)lhs + rhs + carry;
            result = (u64)full & mask;
            if (op == OAH_SC_XADD) {
                store_reg(g, in->src, width, in->rex_present, lhs);
            }
            g->rflags = oah_logic_rflags(g->rflags, result, width);
            if (full > mask) {
                g->rflags |= OAH_RFLAGS_CF;
            }
            u64 operands = lhs ^ rhs;
            if ((subtract ? operands : ~operands) & (lhs ^ result) & sign) {
                g->rflags |= OAH_RFLAGS_OF;
            }
            if ((lhs ^ rhs ^ result) & 0x10) {
                g->rflags |= OAH_RFLAGS_AF;
            }
        } else {
            result = op == OAH_SC_OR ? lhs | rhs
                   : op == OAH_SC_XOR ? lhs ^ rhs : lhs & rhs;
            g->rflags = oah_logic_rflags(g->rflags, result, width);
        }
    }
    if (write) {
        if (in->memory && in->rm_dest) {
            memcpy(slot, &result, width);
        } else {
            store_reg(g, in->rm_dest ? in->dst : in->src, width, in->rex_present, result);
        }
    }
    g->rip = next;
    return true;
}

static u64 x87_compare_flags(const u8 *lhs, const u8 *rhs)
{
    u64 a, b;
    u16 ae, be;
    memcpy(&a, lhs, 8);
    memcpy(&b, rhs, 8);
    memcpy(&ae, lhs + 8, 2);
    memcpy(&be, rhs + 8, 2);
    bool a_negative = (ae & 0x8000) != 0;
    bool b_negative = (be & 0x8000) != 0;
    ae &= 0x7fff;
    be &= 0x7fff;
    const u64 integer_bit = 1ull << 63;
    if ((ae == 0x7fff && a != integer_bit) || (be == 0x7fff && b != integer_bit) ||
        (ae && !(a & integer_bit)) || (be && !(b & integer_bit))) {
        return OAH_RFLAGS_CF | OAH_RFLAGS_ZF | OAH_RFLAGS_PF;
    }
    if (ae == 0 && (a & integer_bit)) {
        ae = 1;
    }
    if (be == 0 && (b & integer_bit)) {
        be = 1;
    }
    if ((ae == 0 && be == 0 && a == 0 && b == 0) ||
        (a_negative == b_negative && ae == be && a == b)) {
        return OAH_RFLAGS_ZF;
    }
    bool less = a_negative != b_negative ? a_negative
              : a_negative ? ae > be || (ae == be && a > b)
              : ae < be || (ae == be && a < b);
    return less ? OAH_RFLAGS_CF : 0;
}

static bool run_x87_data(oah_guest *g, oah_image *img, const oah_insn *in, u64 next)
{
    /* FXSAVE holds logical ST slots, while its abridged tag bits use
     * physical register indices. Keep both in sync when TOP changes. */
    u8 *state = g->legacy_fx;
    u8 *st = state + 32;
    unsigned top = (state[3] >> 3) & 7;
    u8 value[16] = {0};
    bool push = false, pop = false;
    u8 code = in->x87_modrm;
    unsigned reg = code & 7;

    if (in->op == OAH_OP_X87_COMPARE) {
        unsigned tags = (1u << top) | (1u << ((top + reg) & 7));
        if ((state[4] & tags) != tags) {
            return false;
        }
        u64 comparison = x87_compare_flags(st, st + 16 * reg);
        g->rflags &= ~(OAH_RFLAGS_CF | OAH_RFLAGS_ZF | OAH_RFLAGS_PF |
                       OAH_RFLAGS_OF | OAH_RFLAGS_SF | OAH_RFLAGS_AF);
        g->rflags |= comparison;
        pop = in->rm_dest;
    } else if (in->memory) {
        u64 address = effective_address(g, &in->address, next);
        address += in->address.segment == 0x64 ? g->fs_base
                 : in->address.segment == 0x65 ? g->gs_base : 0;
        void *slot = oah_guest_access(img, address, 10, in->rm_dest ? PROT_WRITE : PROT_READ);
        if (!slot) {
            return false;
        }
        if (in->rm_dest) {
            if (!(state[4] & (1u << top))) {
                return false;
            }
            memcpy(slot, st, 10);
            pop = true;
        } else {
            memcpy(value, slot, 10);
            push = true;
        }
    } else if (code == 0xe8 || code == 0xee) {
        if (code == 0xe8) {
            value[7] = 0x80;
            value[8] = 0xff;
            value[9] = 0x3f;
        }
        push = true;
    } else if (code <= 0xc7) {
        if (!(state[4] & (1u << ((top + reg) & 7)))) {
            return false;
        }
        memcpy(value, st + 16 * reg, 16);
        push = true;
    } else {
        if (!(state[4] & (1u << top))) {
            return false;
        }
        if (code == 0xe0) {
            st[9] ^= 0x80;
        } else if (code == 0xe1) {
            st[9] &= 0x7f;
        } else if (code >= 0xd8) {
            if (reg) {
                memcpy(st + 16 * reg, st, 16);
            }
            state[4] |= 1u << ((top + reg) & 7);
            pop = true;
        } else if (reg) {
            if (!(state[4] & (1u << ((top + reg) & 7)))) {
                return false;
            }
            memcpy(value, st, 16);
            memcpy(st, st + 16 * reg, 16);
            memcpy(st + 16 * reg, value, 16);
        }
    }
    if (push) {
        top = (top + 7) & 7;
        if (state[4] & (1u << top)) {
            return false;
        }
        memmove(st + 16, st, 7 * 16);
        memcpy(st, value, 16);
        state[4] |= 1u << top;
    } else if (pop) {
        state[4] &= ~(1u << top);
        top = (top + 1) & 7;
        memmove(st, st + 16, 7 * 16);
        memset(st + 7 * 16, 0, 16);
    }
    state[3] = (u8)((state[3] & ~0x38) | (top << 3));
    g->rip = next;
    return true;
}

static void guest_cpuid(oah_guest *g)
{
    u32 leaf = (u32)g->gpr[OAH_X86_RAX];
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    switch (leaf) {
    case 0:
        eax = 1;
        ebx = 0x756e6547u; /* GenuineIntel byte order */
        edx = 0x49656e69u;
        ecx = 0x6c65746eu;
        break;
    case 1:
        eax = 0x000006f0u;
        /* Expose the glibc x86-64 baseline startup profile. The decoder
         * still reports individual instructions it cannot execute.
         * EDX: FPU, TSC, CX8, CMOV, MMX, FXSR, SSE and SSE2. */
        edx = (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15) |
              (1u << 23) | (1u << 24) | (1u << 25) | (1u << 26);
        break;
    case 0x80000000u:
        eax = 0x80000001u;
        break;
    case 0x80000001u:
        edx = (1u << 29) | (1u << 11); /* Long mode and SYSCALL. */
        break;
    }
    g->gpr[OAH_X86_RAX] = eax;
    g->gpr[OAH_X86_RBX] = ebx;
    g->gpr[OAH_X86_RCX] = ecx;
    g->gpr[OAH_X86_RDX] = edx;
}

oah_interp_result oah_interp_run(oah_guest *g, oah_image *img, u64 max_insns)
{
    oah_interp_result r;
    r.status = OAH_INTERP_OK;
    r.exit_code = 0;
    r.insns = 0;

    if (max_insns == 0) {
        max_insns = OAH_INTERP_MAX_INSNS;
    }

    while (r.insns < max_insns) {
        u64 available = OAH_X86_MAX_INSN;
        const u8 *pc = oah_guest_span(img, g->rip, &available);
        oah_insn insn;
        u64 next;
        oah_sys_status ss;

        if (!pc || !oah_guest_access(img, g->rip, 1, PROT_EXEC)) {
            r.status = OAH_INTERP_FAULT;
            return r;
        }
        if (!oah_decode_insn(pc, pc + available, &insn)) {
            r.status = OAH_INTERP_DECODE;
            return r;
        }

        next = g->rip + insn.length;
        r.insns++;

        switch (insn.op) {
        case OAH_OP_NOP:
        case OAH_OP_ENDBR64:
            g->rip = next;
            break;
        case OAH_OP_MOV_IMM:
            write_gpr(g, insn.dst, insn.opsize, insn.imm);
            g->rip = next;
            break;
        case OAH_OP_XOR_RR: {
            u64 v = g->gpr[insn.dst] ^ g->gpr[insn.src];
            write_gpr(g, insn.dst, insn.opsize, v);
            g->rflags = oah_logic_rflags(g->rflags, v, insn.opsize);
            g->rip = next;
            break;
        }
        case OAH_OP_CMP_RR:
        case OAH_OP_CMP_IMM: {
            u64 rhs = insn.op == OAH_OP_CMP_RR ? g->gpr[insn.src] : insn.imm;
            g->rflags = oah_cmp_rflags(g->rflags, g->gpr[insn.dst], rhs, insn.opsize);
            g->rip = next;
            break;
        }
        case OAH_OP_TEST_RR:
            g->rflags = oah_logic_rflags(g->rflags, g->gpr[insn.dst] & g->gpr[insn.src],
                                        insn.opsize);
            g->rip = next;
            break;
        case OAH_OP_JCC_REL:
            g->rip = oah_condition_holds(insn.cc, g->rflags)
                   ? next + (u64)(s64)insn.disp : next;
            break;
        case OAH_OP_MOV_RR:
            write_gpr(g, insn.dst, insn.opsize, g->gpr[insn.src]);
            g->rip = next;
            break;
        case OAH_OP_LEA_RIP:
            write_gpr(g, insn.dst, 8, next + (u64)(s64)insn.disp);
            g->rip = next;
            break;
        case OAH_OP_PUSH_IMM:
        case OAH_OP_PUSH:
            if (!push64(g, img, insn.op == OAH_OP_PUSH ? g->gpr[insn.dst] : insn.imm)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            g->rip = next;
            break;
        case OAH_OP_POP:
            if (!pop64(g, img, insn.dst)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            g->rip = next;
            break;
        case OAH_OP_JMP_REL:
            g->rip = next + (u64)(s64)insn.disp;
            break;
        case OAH_OP_CALL_REL:
            if (!push64(g, img, next)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            g->rip = next + (u64)(s64)insn.disp;
            break;
        case OAH_OP_LEAVE: {
            u64 frame = g->gpr[OAH_X86_RBP];
            const void *slot = oah_guest_access(img, frame, 8, PROT_READ);
            if (!slot) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            memcpy(&g->gpr[OAH_X86_RBP], slot, 8);
            g->gpr[OAH_X86_RSP] = frame + 8;
            g->rip = next;
            break;
        }
        case OAH_OP_RET: {
            const void *slot = oah_guest_access(img, g->gpr[OAH_X86_RSP], 8, PROT_READ);
            if (!slot) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            memcpy(&g->rip, slot, sizeof(g->rip));
            g->gpr[OAH_X86_RSP] += 8;
            break;
        }
        case OAH_OP_VECTOR:
            if (!run_vector(g, img, &insn, next)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            break;
        case OAH_OP_STRING:
            if (!run_string(g, img, &insn, next)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            break;
        case OAH_OP_SCALAR:
            if (!run_scalar(g, img, &insn, next)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            break;
        case OAH_OP_X87_MOVE:
        case OAH_OP_X87_COMPARE:
            if (!run_x87_data(g, img, &insn, next)) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            break;
        case OAH_OP_FXSTATE: {
            u64 address = effective_address(g, &insn.address, next);
            address += insn.address.segment == 0x64 ? g->fs_base
                     : insn.address.segment == 0x65 ? g->gs_base : 0;
            u64 width = insn.opsize ? insn.opsize : 512;
            u8 *area = (!insn.opsize && (address & 15)) ? NULL : oah_guest_access(
                img, address, width, insn.rm_dest ? PROT_WRITE : PROT_READ);
            if (!area) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            if (insn.opsize == 2) {
                if (insn.rm_dest) {
                    memcpy(area, g->legacy_fx, 2);
                } else {
                    memcpy(g->legacy_fx, area, 2);
                }
            } else if (insn.opsize) {
                u32 value;
                if (insn.rm_dest) {
                    memcpy(area, g->legacy_fx + 24, sizeof(value));
                } else {
                    memcpy(&value, area, sizeof(value));
                    if (value & ~0xffffu) {
                        r.status = OAH_INTERP_FAULT;
                        return r;
                    }
                    memcpy(g->legacy_fx + 24, &value, sizeof(value));
                }
            } else if (insn.rm_dest) {
                memcpy(area, g->legacy_fx, sizeof(g->legacy_fx));
                memcpy(area + 160, g->xmm, sizeof(g->xmm));
                memset(area + 416, 0, 48);
            } else {
                u32 mxcsr;
                memcpy(&mxcsr, area + 24, sizeof(mxcsr));
                if (mxcsr & ~0xffffu) {
                    r.status = OAH_INTERP_FAULT;
                    return r;
                }
                memcpy(g->legacy_fx, area, 28);
                memcpy(g->legacy_fx + 32, area + 32, sizeof(g->legacy_fx) - 32);
                memcpy(g->xmm, area + 160, sizeof(g->xmm));
            }
            g->rip = next;
            break;
        }
        case OAH_OP_RDTSC: {
            struct timespec time;
            if (clock_gettime(CLOCK_MONOTONIC_RAW, &time) != 0) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            u64 ticks = (u64)time.tv_sec * 1000000000ull + (u64)time.tv_nsec;
            g->gpr[OAH_X86_RAX] = (u32)ticks;
            g->gpr[OAH_X86_RDX] = ticks >> 32;
            g->rip = next;
            break;
        }
        case OAH_OP_CPUID:
            guest_cpuid(g);
            g->rip = next;
            break;
        case OAH_OP_SYSCALL:
            g->rip = next;
            ss = oah_guest_syscall(g, img);
            if (ss == OAH_SYS_EXIT) {
                r.status = OAH_INTERP_EXIT;
                r.exit_code = (int)(g->gpr[OAH_X86_RDI] & 0xff);
                return r;
            }
            if (ss == OAH_SYS_FATAL) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            break;
        default:
            r.status = OAH_INTERP_DECODE;
            return r;
        }
    }

    r.status = OAH_INTERP_LIMIT;
    return r;
}
