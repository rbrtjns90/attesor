#include "oah/condition.h"
#include "oah/flags.h"

/* high: DAT_800000012e1c */
const u8 oah_cc_arm_table[16] = {
    6, 7, 3, 2, 0, 1, 9, 8, 4, 5, 6, 7, 11, 10, 13, 12
};

bool oah_translate_condition_code(oah_x86_cc cc, oah_arm_cc *out)
{
    /* FUN_800000057bc8 Translator.h:0x264 / 0x266 */
    if ((u8)cc > 15) {
        return false;
    }
    if (((u8)cc & 0xfe) == 10) {
        /* P and NP must be special-cased (no direct ARM cond). */
        return false;
    }

    *out = (oah_arm_cc)oah_cc_arm_table[cc];
    return true;
}

const char *oah_condition_code_to_string(oah_x86_cc cc)
{
    /* FUN_80000002ac58 Operand.cpp:0x2c — PTR_DAT_800000013240 */
    static const char *const names[16] = {
        "o", "no", "b", "ae", "e", "ne", "be", "a",
        "s", "ns", "p", "np", "l", "ge", "le", "g"
    };
    if ((unsigned)cc > 15) {
        return 0;
    }
    return names[cc];
}

bool oah_condition_holds(u8 cc, u64 rflags)
{
    bool carry = (rflags & OAH_RFLAGS_CF) != 0;
    bool zero = (rflags & OAH_RFLAGS_ZF) != 0;
    bool sign = (rflags & OAH_RFLAGS_SF) != 0;
    bool overflow = (rflags & OAH_RFLAGS_OF) != 0;
    bool holds;

    switch (cc >> 1) {
    case 0: holds = overflow; break;
    case 1: holds = carry; break;
    case 2: holds = zero; break;
    case 3: holds = carry || zero; break;
    case 4: holds = sign; break;
    case 5: holds = (rflags & OAH_RFLAGS_PF) != 0; break;
    case 6: holds = sign != overflow; break;
    case 7: holds = zero || sign != overflow; break;
    default: return false;
    }
    return holds != ((cc & 1) != 0);
}
