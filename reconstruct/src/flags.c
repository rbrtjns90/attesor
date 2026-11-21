#include "oah/flags.h"

bool oah_set_nzcv(u32 *cpsr, u32 nzcv)
{
    /* FUN_80000004077c ThreadState.h:0x37 */
    if ((nzcv & 0x03ffffffu) != 0) {
        return false;
    }
    *cpsr = (*cpsr & 0x03ffffffu) | nzcv;
    return true;
}

u32 oah_nzcv_from_rflags(u64 rflags)
{
    /* FUN_800000040650 */
    return ((u32)rflags & 0xc0u) << 24 |
           ((u32)~rflags & 1u) << 29 |
           (((u32)rflags >> 11) & 1u) << 28;
}

u64 oah_pack_aux_flags(u64 rflags)
{
    /* FUN_800000040650 param_3[0x11] */
    return (rflags >> 9 & 2) |
           (~rflags >> 2 & 1) |
           (rflags >> 16 & 4) |
           (rflags >> 18 & 8) |
           (rflags >> 4 & 0x10);
}

void oah_host_flags_from_rflags(oah_host_flags *out, u64 rflags)
{
    out->nzcv = oah_nzcv_from_rflags(rflags);
    out->aux_flags = oah_pack_aux_flags(rflags);
    out->trap_flag = (u8)((rflags >> 8) & 1);
}

/* width is the operand size in bytes (1, 2, 4, or 8). */
u64 oah_logic_rflags(u64 rflags, u64 result, u8 width)
{
    u64 sign = 1ull << (width * 8 - 1);
    result &= sign | (sign - 1);
    /* AF is architecturally undefined after a logical operation. */
    rflags &= ~(OAH_RFLAGS_CF | OAH_RFLAGS_OF | OAH_RFLAGS_AF |
                OAH_RFLAGS_ZF | OAH_RFLAGS_SF | OAH_RFLAGS_PF);
    if (!result) {
        rflags |= OAH_RFLAGS_ZF;
    }
    if (result & sign) {
        rflags |= OAH_RFLAGS_SF;
    }
    if (!__builtin_parity((unsigned)(u8)result)) {
        rflags |= OAH_RFLAGS_PF;
    }
    return rflags;
}

u64 oah_cmp_rflags(u64 rflags, u64 lhs, u64 rhs, u8 width)
{
    u64 sign = 1ull << (width * 8 - 1);
    u64 mask = sign | (sign - 1);
    lhs &= mask;
    rhs &= mask;
    u64 result = lhs - rhs;
    rflags = oah_logic_rflags(rflags, result, width);
    if (lhs < rhs) {
        rflags |= OAH_RFLAGS_CF;
    }
    if ((lhs ^ rhs) & (lhs ^ result) & sign) {
        rflags |= OAH_RFLAGS_OF;
    }
    if ((lhs ^ rhs ^ result) & 0x10) {
        rflags |= OAH_RFLAGS_AF;
    }
    return rflags;
}
