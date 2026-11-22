#include "oah/interp.h"
#include "oah/decode_insn.h"
#include "oah/condition.h"
#include "oah/flags.h"

#include <float.h>
#include <math.h>
#include <stdatomic.h>
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

static long double round_guest_integer(long double value, unsigned mode);

static void shift_packed_integer(u8 *vector, unsigned lane, u64 count, unsigned operation)
{
    unsigned bits = lane * 8;
    unsigned shift = count < bits ? (unsigned)count : bits - 1;
    for (unsigned offset = 0; offset < 16; offset += lane) {
        u64 value = 0;
        memcpy(&value, vector + offset, lane);
        if (operation == 4) {
            s64 signed_value = lane == 2 ? (int16_t)value : (s32)value;
            value = (u64)(signed_value >> shift);
        } else if (count >= bits) {
            value = 0;
        } else {
            value = operation == 2 ? value >> shift : value << shift;
        }
        memcpy(vector + offset, &value, lane);
    }
}

static bool run_vector(oah_guest *g, oah_image *img, const oah_insn *in, u64 next)
{
    u8 op = in->vector_opcode;
    bool fp_alu = op == 0x58 || op == 0x59 || op == 0x5c || op == 0x5d || op == 0x5e || op == 0x5f;
    bool fp_compare = op == 0x2e || op == 0x2f;
    unsigned width = (op == OAH_VECTOR_DUPLICATE_DOUBLE || op == OAH_VECTOR_CONVERT_SINGLES_TO_DOUBLES ||
                      (op == OAH_VECTOR_CONVERT_PACKED_DOUBLES && !in->cc)) ? 8 : op == 0xc4 ? 2
                   : op == 0x2a ? in->src_width
                   : (fp_alu || fp_compare || op == 0xc2 || op == 0x2c || op == 0x2d || op == 0x51 || op == 0x5a) ? in->opsize
                   : (op == 0x6e || op == 0x7e || op == OAH_VECTOR_SCALAR_LOAD || op == OAH_VECTOR_SCALAR_STORE) ? in->opsize
                   : ((op >= 0x12 && op <= 0x17) || op == 0x7a || op == 0xd6) ? 8 : 16;
    bool store = op == 0xe7 || op == OAH_VECTOR_SCALAR_STORE || op == 0x11 || op == 0x29 || op == 0x7f || op == 0x7e || op == 0xd6 ||
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
    case 0x67: {
        u8 packed[16];
        for (unsigned i = 0; i < 16; i++) {
            int16_t value;
            memcpy(&value, (i < 8 ? xmm : other) + (i % 8) * 2, 2);
            packed[i] = value < 0 ? 0 : value > 255 ? 255 : (u8)value;
        }
        memcpy(xmm, packed, sizeof(packed));
        break;
    }
    case 0x64: case 0x65: case 0x66: {
        unsigned lane = 1u << (op - 0x64);
        for (unsigned i = 0; i < 16; i += lane) {
            u32 a = 0, b = 0;
            memcpy(&a, xmm + i, lane);
            memcpy(&b, other + i, lane);
            u32 sign = 1u << (lane * 8 - 1);
            memset(xmm + i, (a ^ sign) > (b ^ sign) ? 255 : 0, lane);
        }
        break;
    }
    case OAH_VECTOR_CONVERT_PACKED_DOUBLES: {
        u8 result[16] = {0};
        if (!in->cc) {
            for (unsigned i = 0; i < 2; i++) {
                s32 source;
                memcpy(&source, other + i * 4, sizeof(source));
                double converted = source;
                memcpy(result + i * 8, &converted, sizeof(converted));
            }
        } else {
            u32 mxcsr;
            memcpy(&mxcsr, g->legacy_fx + 24, sizeof(mxcsr));
            unsigned rounding = in->cc == 1 ? 3 : (mxcsr >> 13) & 3;
            for (unsigned i = 0; i < 2; i++) {
                double source;
                memcpy(&source, other + i * 8, sizeof(source));
                long double rounded = round_guest_integer(source, rounding);
                s32 converted = rounded >= -0x1p31L && rounded < 0x1p31L ?
                                (s32)rounded : INT32_MIN;
                memcpy(result + i * 4, &converted, sizeof(converted));
            }
        }
        memcpy(xmm, result, sizeof(result));
        break;
    }
    case OAH_VECTOR_CONVERT_PACKED_DWORDS: {
        u32 mxcsr;
        memcpy(&mxcsr, g->legacy_fx + 24, sizeof(mxcsr));
        for (unsigned i = 0; i < 16; i += 4) {
            if (in->cc) {
                float source;
                memcpy(&source, other + i, sizeof(source));
                long double rounded = round_guest_integer(source, in->cc == 2 ? 3 : (mxcsr >> 13) & 3);
                s32 converted = rounded >= -0x1p31L && rounded < 0x1p31L ?
                                (s32)rounded : INT32_MIN;
                memcpy(xmm + i, &converted, sizeof(converted));
            } else {
                s32 source;
                memcpy(&source, other + i, sizeof(source));
                float converted = (float)source;
                memcpy(xmm + i, &converted, sizeof(converted));
            }
        }
        break;
    }
    case OAH_VECTOR_CONVERT_DOUBLES_TO_SINGLES: {
        u8 result[16] = {0};
        for (unsigned i = 0; i < 2; i++) {
            double source;
            memcpy(&source, other + i * 8, sizeof(source));
            float converted = (float)source;
            memcpy(result + i * 4, &converted, sizeof(converted));
        }
        memcpy(xmm, result, sizeof(result));
        break;
    }
    case OAH_VECTOR_CONVERT_SINGLES_TO_DOUBLES:
        for (unsigned i = 0; i < 2; i++) {
            float source;
            memcpy(&source, other + i * 4, sizeof(source));
            double converted = source;
            memcpy(xmm + i * 8, &converted, sizeof(converted));
        }
        break;
    case OAH_VECTOR_ARITH_PACKED_FLOAT:
        for (unsigned i = 0; i < 16; i += in->opsize) {
            if (in->opsize == 4) {
                float lhs, rhs;
                memcpy(&lhs, xmm + i, sizeof(lhs));
                memcpy(&rhs, other + i, sizeof(rhs));
                switch (in->cc) {
                case 0x51: lhs = sqrtf(lhs); break;
                case 0x59: lhs *= rhs; break;
                case 0x5c: lhs -= rhs; break;
                case 0x5d: lhs = lhs < rhs ? lhs : rhs; break;
                case 0x5e: lhs /= rhs; break;
                case 0x5f: lhs = lhs > rhs ? lhs : rhs; break;
                default: lhs += rhs; break;
                }
                memcpy(xmm + i, &lhs, sizeof(lhs));
            } else {
                double lhs, rhs;
                memcpy(&lhs, xmm + i, sizeof(lhs));
                memcpy(&rhs, other + i, sizeof(rhs));
                switch (in->cc) {
                case 0x51: lhs = sqrt(lhs); break;
                case 0x59: lhs *= rhs; break;
                case 0x5c: lhs -= rhs; break;
                case 0x5d: lhs = lhs < rhs ? lhs : rhs; break;
                case 0x5e: lhs /= rhs; break;
                case 0x5f: lhs = lhs > rhs ? lhs : rhs; break;
                default: lhs += rhs; break;
                }
                memcpy(xmm + i, &lhs, sizeof(lhs));
            }
        }
        break;
    case 0x51:
        if (width == 4) {
            float value;
            memcpy(&value, other, sizeof(value));
            value = sqrtf(value);
            memcpy(xmm, &value, sizeof(value));
        } else {
            double value;
            memcpy(&value, other, sizeof(value));
            value = sqrt(value);
            memcpy(xmm, &value, sizeof(value));
        }
        break;
    case 0x5a:
        if (width == 4) {
            float value;
            memcpy(&value, other, 4);
            double converted = value;
            memcpy(xmm, &converted, 8);
        } else {
            double value;
            memcpy(&value, other, 8);
            float converted = (float)value;
            memcpy(xmm, &converted, 4);
        }
        break;
    case 0x2c:
    case 0x2d: {
        double value;
        if (width == 4) {
            float single;
            memcpy(&single, other, 4);
            value = single;
        } else {
            memcpy(&value, other, 8);
        }
        if (op == 0x2d) {
            u32 mxcsr;
            memcpy(&mxcsr, g->legacy_fx + 24, sizeof(mxcsr));
            value = (double)round_guest_integer(value, (mxcsr >> 13) & 3);
        }
        double bound = in->src_width == 8 ? 0x1p63 : 0x1p31;
        u64 result = value >= -bound && value < bound ? (u64)(s64)value
                     : 1ull << (in->src_width * 8 - 1);
        write_gpr(g, in->src, in->src_width, result);
        break;
    }
    case 0x2a: {
        s64 value = in->memory ? 0 : (s64)g->gpr[in->dst];
        if (in->memory) {
            memcpy(&value, other, width);
        }
        if (width == 4) {
            value = (s32)value;
        }
        if (in->opsize == 4) {
            float result = (float)value;
            memcpy(xmm, &result, 4);
        } else {
            double result = (double)value;
            memcpy(xmm, &result, 8);
        }
        break;
    }
    case 0xc2:
    case 0x2e: case 0x2f:
    case 0x58: case 0x59: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
        double lhs, rhs;
        if (width == 4) {
            float a, b;
            memcpy(&a, xmm, 4);
            memcpy(&b, other, 4);
            lhs = a;
            rhs = b;
        } else {
            memcpy(&lhs, xmm, 8);
            memcpy(&rhs, other, 8);
        }
        if (op == 0xc2) {
            bool unordered = __builtin_isunordered(lhs, rhs);
            bool matches;
            switch (in->imm & 7) {
            case 0: matches = lhs == rhs; break;
            case 1: matches = lhs < rhs; break;
            case 2: matches = lhs <= rhs; break;
            case 3: matches = unordered; break;
            case 4: matches = lhs != rhs; break;
            case 5: matches = !(lhs < rhs); break;
            case 6: matches = !(lhs <= rhs); break;
            default: matches = !unordered; break;
            }
            memset(xmm, matches ? 255 : 0, width);
        } else if (op == 0x5d || op == 0x5f) {
            if (!(op == 0x5d ? lhs < rhs : lhs > rhs)) {
                memmove(xmm, other, width);
            }
        } else if (fp_compare) {
            g->rflags &= ~(OAH_RFLAGS_CF | OAH_RFLAGS_PF | OAH_RFLAGS_AF |
                           OAH_RFLAGS_ZF | OAH_RFLAGS_SF | OAH_RFLAGS_OF);
            if (__builtin_isunordered(lhs, rhs)) {
                g->rflags |= OAH_RFLAGS_CF | OAH_RFLAGS_PF | OAH_RFLAGS_ZF;
            } else if (lhs < rhs) {
                g->rflags |= OAH_RFLAGS_CF;
            } else if (lhs == rhs) {
                g->rflags |= OAH_RFLAGS_ZF;
            }
        } else if (width == 4) {
            float a = (float)lhs, b = (float)rhs;
            float result = op == 0x58 ? a + b : op == 0x59 ? a * b :
                           op == 0x5c ? a - b : a / b;
            memcpy(xmm, &result, 4);
        } else {
            double result = op == 0x58 ? lhs + rhs : op == 0x59 ? lhs * rhs :
                            op == 0x5c ? lhs - rhs : lhs / rhs;
            memcpy(xmm, &result, 8);
        }
        break;
    }
    case OAH_VECTOR_SCALAR_LOAD:
        memmove(xmm, other, width);
        if (in->memory) {
            memset(xmm + width, 0, 16 - width);
        }
        break;
    case OAH_VECTOR_SCALAR_STORE:
        memmove(other, xmm, width);
        break;
    case 0xd5:
        for (unsigned offset = 0; offset < 16; offset += 2) {
            uint16_t lhs, rhs;
            memcpy(&lhs, xmm + offset, sizeof(lhs));
            memcpy(&rhs, other + offset, sizeof(rhs));
            uint16_t product = (u32)lhs * rhs;
            memcpy(xmm + offset, &product, sizeof(product));
        }
        break;
    case 0xf4:
        for (unsigned offset = 0; offset < 16; offset += 8) {
            u32 lhs, rhs;
            memcpy(&lhs, xmm + offset, sizeof(lhs));
            memcpy(&rhs, other + offset, sizeof(rhs));
            u64 product = (u64)lhs * rhs;
            memcpy(xmm + offset, &product, sizeof(product));
        }
        break;
    case 0xd4:
    case 0xf9:
    case 0xfa:
    case 0xfb:
    case 0xfd:
    case 0xfe: {
        unsigned lane = op == 0xfd || op == 0xf9 ? 2 :
                        op == 0xfe || op == 0xfa ? 4 : 8;
        for (unsigned i = 0; i < 16; i += lane) {
            u64 lhs = 0, rhs = 0;
            memcpy(&lhs, xmm + i, lane);
            memcpy(&rhs, other + i, lane);
            lhs = op >= 0xf9 && op <= 0xfb ? lhs - rhs : lhs + rhs;
            memcpy(xmm + i, &lhs, lane);
        }
        break;
    }
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
    case OAH_VECTOR_DUPLICATE_DOUBLE: {
        u64 value;
        memcpy(&value, other, sizeof(value));
        memcpy(xmm, &value, sizeof(value));
        memcpy(xmm + 8, &value, sizeof(value));
        break;
    }
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
    case 0x14:
    case 0x15:
    case OAH_VECTOR_UNPACK_LOW_DOUBLE:
    case OAH_VECTOR_UNPACK_HIGH_DOUBLE:
    case 0x60:
    case 0x61:
    case 0x62:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6d: {
        unsigned lane = op == 0x6d || op == OAH_VECTOR_UNPACK_LOW_DOUBLE ||
                        op == OAH_VECTOR_UNPACK_HIGH_DOUBLE ? 8 :
                        op == 0x14 || op == 0x15 ? 4 : 1u << (op & 3);
        unsigned start = op == 0x15 || op == OAH_VECTOR_UNPACK_HIGH_DOUBLE ||
                         op >= 0x68 ? 8 : 0;
        u8 values[16];
        for (unsigned offset = 0; offset < 8; offset += lane) {
            memcpy(values + 2 * offset, xmm + start + offset, lane);
            memcpy(values + 2 * offset + lane, other + start + offset, lane);
        }
        memcpy(xmm, values, sizeof(values));
        break;
    }
    case 0xc5: {
        u16 value;
        memcpy(&value, other + (in->imm & 7) * 2, sizeof(value));
        write_gpr(g, in->src, 4, value);
        break;
    }
    case 0xc4: {
        u16 value = (u16)g->gpr[in->dst];
        if (in->memory) {
            memcpy(&value, other, sizeof(value));
        }
        memcpy(xmm + (in->imm & 7) * 2, &value, sizeof(value));
        break;
    }
    case OAH_VECTOR_SHUFFLE_PACKED_SINGLE: {
        u8 result[16];
        for (unsigned lane = 0; lane < 4; lane++) {
            unsigned selected = (in->imm >> (lane * 2)) & 3;
            memcpy(result + lane * 4, (lane < 2 ? xmm : other) + selected * 4, 4);
        }
        memcpy(xmm, result, sizeof(result));
        break;
    }
    case 0xc6: {
        u8 values[16];
        memcpy(values, xmm + (in->imm & 1) * 8, 8);
        memcpy(values + 8, other + ((in->imm >> 1) & 1) * 8, 8);
        memcpy(xmm, values, sizeof(values));
        break;
    }
    case OAH_VECTOR_SHUFFLE_LOW_WORDS:
    case OAH_VECTOR_SHUFFLE_HIGH_WORDS: {
        unsigned offset = op == OAH_VECTOR_SHUFFLE_HIGH_WORDS ? 8 : 0;
        u8 values[16];
        memcpy(values, other, sizeof(values));
        for (unsigned lane = 0; lane < 4; lane++) {
            memcpy(values + offset + lane * 2,
                   other + offset + ((in->imm >> (lane * 2)) & 3) * 2, 2);
        }
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
    case 0xd1: case 0xd2: case 0xd3:
    case 0xe1: case 0xe2:
    case 0xf1: case 0xf2: case 0xf3: {
        u64 count;
        memcpy(&count, other, sizeof(count));
        unsigned lane = 1u << (op & 0xf);
        unsigned operation = op < 0xe0 ? 2 : op < 0xf0 ? 4 : 6;
        shift_packed_integer(xmm, lane, count, operation);
        break;
    }
    case 0x71:
    case 0x72:
    case 0x73: {
        if (in->cc == 2 || in->cc == 4 || in->cc == 6) {
            shift_packed_integer(other, 2u << (op - 0x71), in->imm, in->cc);
            break;
        }
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
    case 0xfc:
    case 0xf8:
    case 0xda:
        for (unsigned i = 0; i < 16; i++) {
            unsigned sum = xmm[i] + other[i];
            xmm[i] = op == 0xfc ? (u8)sum
                   : op == 0xf8 ? (u8)(xmm[i] - other[i])
                   : xmm[i] < other[i] ? xmm[i] : other[i];
        }
        break;
    case 0xd8:              /* PSUBUSB */
    case 0xdc:              /* PADDUSB */
    case 0xde:              /* PMAXUB */
    case 0xe0:              /* PAVGB */
    case 0xe8:              /* PSUBSB */
    case 0xec:              /* PADDSB */
        for (unsigned i = 0; i < 16; i++) {
            u8 a = xmm[i], b = other[i];
            s32 r;
            switch (op) {
            case 0xd8: r = a > b ? a - b : 0; break;
            case 0xdc: r = a + b; if (r > 255) r = 255; break;
            case 0xde: r = a > b ? a : b; break;
            case 0xe0: r = (a + b + 1) >> 1; break;
            case 0xe8: r = (s8)a - (s8)b; r = r < -128 ? -128 : r > 127 ? 127 : r; break;
            default:   r = (s8)a + (s8)b; r = r < -128 ? -128 : r > 127 ? 127 : r; break;
            }
            xmm[i] = (u8)r;
        }
        break;
    case 0xd9:              /* PSUBUSW */
    case 0xdd:              /* PADDUSW */
    case 0xe3:              /* PAVGW */
    case 0xe4:              /* PMULHUW */
    case 0xe5:              /* PMULHW */
    case 0xe9:              /* PSUBSW */
    case 0xea:              /* PMINSW */
    case 0xed:              /* PADDSW */
    case 0xee:              /* PMAXSW */
        for (unsigned i = 0; i < 16; i += 2) {
            u16 a, b, w;
            memcpy(&a, xmm + i, sizeof(a));
            memcpy(&b, other + i, sizeof(b));
            s32 r;
            switch (op) {
            case 0xd9: r = a > b ? a - b : 0; break;
            case 0xdd: r = a + b; if (r > 65535) r = 65535; break;
            case 0xe3: r = (a + b + 1) >> 1; break;
            case 0xe4: r = ((u32)a * b) >> 16; break;
            case 0xe5: r = ((s32)(s16)a * (s32)(s16)b) >> 16; break;
            case 0xe9: r = (s16)a - (s16)b; r = r < -32768 ? -32768 : r > 32767 ? 32767 : r; break;
            case 0xea: r = (s16)a < (s16)b ? a : b; break;
            case 0xed: r = (s16)a + (s16)b; r = r < -32768 ? -32768 : r > 32767 ? 32767 : r; break;
            default:   r = (s16)a > (s16)b ? a : b; break;
            }
            w = (u16)r;
            memcpy(xmm + i, &w, sizeof(w));
        }
        break;
    case 0x57:
    case 0xef:
    case 0x55:
    case 0x56:
    case 0xdf:
    case 0x54:
    case 0xdb:
    case 0xeb:
        for (unsigned i = 0; i < 16; i++) {
            xmm[i] = (op == 0xdf || op == 0x55) ? ~xmm[i] & other[i]
                   : (op == 0xdb || op == 0x54) ? xmm[i] & other[i]
                   : (op == 0xeb || op == 0x56) ? xmm[i] | other[i] : xmm[i] ^ other[i];
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
                 op != OAH_SC_IDIV &&
                 op != OAH_SC_BT && op != OAH_SC_MUL && op != OAH_SC_IMUL_WIDE && op != OAH_SC_PUSH && !indirect;
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
        if (!in->immediate && (op == OAH_SC_BT || op == OAH_SC_BTS ||
            op == OAH_SC_BTR || op == OAH_SC_BTC)) {
            s64 bit = signed_operand(read_reg(g, in->src, width, in->rex_present), width);
            s64 offset = (bit >> (width == 8 ? 6 : width == 4 ? 5 : 4)) * width;
            address += (u64)offset;
            if (in->address.address32) {
                address = (u32)address;
            }
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
    if (op == OAH_SC_MUL || op == OAH_SC_IMUL_WIDE) {
        unsigned bits = width * 8;
        __uint128_t product = (__uint128_t)(g->gpr[OAH_X86_RAX] & mask) * rm;
        if (op == OAH_SC_IMUL_WIDE) {
            product = (__int128_t)signed_operand(g->gpr[OAH_X86_RAX] & mask, width) *
                      signed_operand(rm, width);
        }
        u64 upper = (u64)(product >> bits) & mask;
        if (width == 1) {
            write_gpr(g, OAH_X86_RAX, 2, (u64)product);
        } else {
            write_gpr(g, OAH_X86_RAX, width, (u64)product);
            write_gpr(g, OAH_X86_RDX, width, upper);
        }
        g->rflags &= ~(OAH_RFLAGS_CF | OAH_RFLAGS_OF);
        u64 sign_extension = (u64)(signed_operand((u64)product & mask, width) < 0 ? mask : 0);
        if (upper != (op == OAH_SC_IMUL_WIDE ? sign_extension : 0)) {
            g->rflags |= OAH_RFLAGS_CF | OAH_RFLAGS_OF;
        }
    } else if (op == OAH_SC_DIV || op == OAH_SC_IDIV) {
        unsigned bits = width * 8;
        __uint128_t dividend = width == 1 ? g->gpr[OAH_X86_RAX] & 0xffff
                            : ((__uint128_t)(g->gpr[OAH_X86_RDX] & mask) << bits) |
                              (g->gpr[OAH_X86_RAX] & mask);
        if (!rm) {
            return false;
        }
        bool dividend_negative = false, quotient_negative = false;
        u64 limit = mask;
        if (op == OAH_SC_IDIV) {
            dividend_negative = (dividend >> (bits * 2 - 1)) != 0;
            s64 divisor = signed_operand(rm, width);
            quotient_negative = dividend_negative != (divisor < 0);
            if (divisor < 0) {
                rm = 0 - (u64)divisor;
            }
            if (dividend_negative) {
                dividend = -dividend;
                if (bits < 64) {
                    dividend &= (((__uint128_t)1 << (bits * 2)) - 1);
                }
            }
            limit = (1ull << (bits - 1)) - !quotient_negative;
        }
        __uint128_t quotient_magnitude = dividend / rm;
        if (quotient_magnitude > limit) {
            return false;
        }
        u64 quotient = (u64)quotient_magnitude;
        u64 remainder = (u64)(dividend % rm);
        if (quotient_negative) {
            quotient = -quotient & mask;
        }
        if (dividend_negative) {
            remainder = -remainder & mask;
        }
        if (width == 1) {
            write_gpr(g, OAH_X86_RAX, 2, quotient | (remainder << 8));
        } else {
            write_gpr(g, OAH_X86_RAX, width, quotient);
            write_gpr(g, OAH_X86_RDX, width, remainder);
        }
    } else if (op == OAH_SC_BSWAP) {
        result = width == 8 ? __builtin_bswap64(rm) : __builtin_bswap32((u32)rm);
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
        /* Darwin serializes guest instruction dispatch, including LOCK forms. */
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

/* Keep the guest format in FXSAVE. Arithmetic is evaluated in the
 * widest scalar format supplied by the host C implementation. */
static long double x87_to_host(const u8 *source)
{
    u64 mantissa;
    u16 exponent;
    memcpy(&mantissa, source, sizeof(mantissa));
    memcpy(&exponent, source + 8, sizeof(exponent));
    unsigned magnitude = exponent & 0x7fff;
    long double value = magnitude == 0x7fff ?
        (mantissa == (1ull << 63) ? INFINITY : NAN) :
        ldexpl((long double)mantissa, (int)(magnitude ? magnitude : 1) - 16383 - 63);
    return exponent & 0x8000 ? -value : value;
}

static void x87_from_host(u8 *target, long double value)
{
    u64 mantissa = 0;
    u16 exponent = signbit(value) ? 0x8000 : 0;
    if (!isfinite(value)) {
        exponent |= 0x7fff;
        mantissa = isnan(value) ? 0xc000000000000000ull : 1ull << 63;
    } else if (value != 0) {
        int rank;
        long double fraction = frexpl(fabsl(value), &rank);
        if (rank <= -16382) {
            mantissa = (u64)ldexpl(fraction, rank + 16445);
        } else {
            exponent |= (u16)(rank + 16382);
            mantissa = (u64)ldexpl(fraction, 64);
        }
    }
    memcpy(target, &mantissa, sizeof(mantissa));
    memcpy(target + 8, &exponent, sizeof(exponent));
}

static long double x87_arithmetic(unsigned operation, long double a, long double b)
{
    switch (operation) {
    case 0: return a + b;
    case 1: return a * b;
    case 4: return a - b;
    case 5: return b - a;
    case 6: return a / b;
    default: return b / a;
    }
}

static long double round_guest_integer(long double value, unsigned mode)
{
    switch (mode) {
    case 1: return floorl(value);
    case 2: return ceill(value);
    case 3: return truncl(value);
    default: {
        long double lower = floorl(value);
        long double fraction = value - lower;
        return fraction > 0.5L || (fraction == 0.5L && fmodl(lower, 2) != 0)
            ? lower + 1 : lower;
    }
    }
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
    unsigned group = (code >> 3) & 7;
    u8 opcode = in->x87_opcode;
    bool integer = opcode == 0xdb || opcode == 0xdf;
    bool extended = opcode == 0xdb && (group == 5 || group == 7);

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
        unsigned width = extended ? 10 : opcode == 0xdc || opcode == 0xdd ||
                         (opcode == 0xdf && group >= 5) ? 8 : opcode == 0xdf ? 2 : 4;
        void *slot = oah_guest_access(img, address, width, in->rm_dest ? PROT_WRITE : PROT_READ);
        if (!slot) {
            return false;
        }
        if (in->rm_dest) {
            if (!(state[4] & (1u << top))) {
                return false;
            }
            if (extended) {
                memcpy(slot, st, 10);
            } else if (integer) {
                long double rounded = round_guest_integer(x87_to_host(st), state[1] >> 2 & 3);
                long double bound = ldexpl(1.0L, width * 8 - 1);
                u64 converted = rounded >= -bound && rounded < bound ?
                    (u64)(s64)rounded : 1ull << (width * 8 - 1);
                memcpy(slot, &converted, width);
            } else if (width == 4) {
                float converted = (float)x87_to_host(st);
                memcpy(slot, &converted, width);
            } else {
                double converted = (double)x87_to_host(st);
                memcpy(slot, &converted, width);
            }
            pop = group == 3 || group == 7;
        } else if (extended) {
            memcpy(value, slot, 10);
            push = true;
        } else {
            long double operand;
            if (integer) {
                u64 bits = 0;
                memcpy(&bits, slot, width);
                operand = signed_operand(bits, width);
            } else if (width == 4) {
                float input;
                memcpy(&input, slot, width);
                operand = input;
            } else {
                double input;
                memcpy(&input, slot, width);
                operand = input;
            }
            if (opcode == 0xd8 || opcode == 0xdc) {
                if (!(state[4] & (1u << top))) {
                    return false;
                }
                x87_from_host(st, x87_arithmetic(group, x87_to_host(st), operand));
            } else {
                x87_from_host(value, operand);
                push = true;
            }
        }
    } else if (opcode == 0xda || opcode == 0xdb) {
        static const u8 conditions[] = {2, 4, 6, 10}; /* B, E, BE, P */
        u8 cc = conditions[group] ^ (opcode == 0xdb);
        if (oah_condition_holds(cc, g->rflags)) {
            unsigned tags = (1u << top) | (1u << ((top + reg) & 7));
            if ((state[4] & tags) != tags) {
                return false;
            }
            if (reg) {
                memcpy(st, st + 16 * reg, 16);
            }
        }
    } else if (opcode == 0xd8 || opcode == 0xdc || opcode == 0xde) {
        unsigned tags = (1u << top) | (1u << ((top + reg) & 7));
        if ((state[4] & tags) != tags) {
            return false;
        }
        u8 *destination = opcode == 0xd8 ? st : st + 16 * reg;
        if (opcode != 0xd8 && group >= 4) {
            group ^= 1;
        }
        x87_from_host(destination, x87_arithmetic(group, x87_to_host(destination),
                      x87_to_host(opcode == 0xd8 ? st + 16 * reg : st)));
        pop = opcode == 0xde;
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
#if defined(__APPLE__)
        oah_darwin_guest_tick(g);
        oah_sys_status signal_status = oah_guest_signal_poll(g, img);
        if (signal_status != OAH_SYS_CONTINUE) {
            r.status = signal_status == OAH_SYS_EXIT ? OAH_INTERP_EXIT : OAH_INTERP_FAULT;
            r.exit_code = (int)(g->gpr[OAH_X86_RDI] & 0xff);
            return r;
        }
#endif
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
        case OAH_OP_EMPTY_MMX:
            g->legacy_fx[4] = 0;
            g->rip = next;
            break;
        case OAH_OP_FLAGS_STACK: {
            u64 *stack = &g->gpr[OAH_X86_RSP];
            u64 address = insn.rm_dest ? *stack - insn.opsize : *stack;
            void *slot = oah_guest_access(img, address, insn.opsize,
                                          insn.rm_dest ? PROT_WRITE : PROT_READ);
            if (!slot) {
                r.status = OAH_INTERP_FAULT;
                return r;
            }
            if (insn.rm_dest) {
                u64 flags = g->rflags & ~((1ull << 16) | (1ull << 17));
                memcpy(slot, &flags, insn.opsize);
                *stack = address;
            } else {
                u64 flags = 0;
                memcpy(&flags, slot, insn.opsize);
                u64 mask = 0x00000dd5ull | (1ull << 8);
                if (insn.opsize == 8) {
                    mask |= (1ull << 18) | (1ull << 21);
                }
                g->rflags = (g->rflags & ~mask) | (flags & mask) | 2;
                *stack += insn.opsize;
            }
            g->rip = next;
            break;
        }
        case OAH_OP_SET_DIRECTION:
            g->rflags = (g->rflags & ~OAH_RFLAGS_DF) | (insn.imm ? OAH_RFLAGS_DF : 0);
            g->rip = next;
            break;
        case OAH_OP_STORE_FENCE:
            atomic_thread_fence(memory_order_release);
            g->rip = next;
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
        case OAH_OP_SIGN_HIGH:
            write_gpr(g, OAH_X86_RDX, insn.opsize,
                      signed_operand(g->gpr[OAH_X86_RAX], insn.opsize) < 0 ? UINT64_MAX : 0);
            g->rip = next;
            break;
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
