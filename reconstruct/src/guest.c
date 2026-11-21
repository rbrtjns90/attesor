#include "oah/guest.h"

#include <string.h>

void oah_guest_init(oah_guest *g, u64 entry, u64 rsp)
{
    memset(g, 0, sizeof(*g));
    g->rip = entry;
    g->gpr[OAH_X86_RSP] = rsp;
    g->rflags = OAH_RFLAGS_INIT;
    const u16 control = 0x037f;
    const u32 mxcsr = 0x1f80;
    const u32 mxcsr_mask = 0xffff;
    memcpy(g->legacy_fx, &control, sizeof(control));
    memcpy(g->legacy_fx + 24, &mxcsr, sizeof(mxcsr));
    memcpy(g->legacy_fx + 28, &mxcsr_mask, sizeof(mxcsr_mask));
}
