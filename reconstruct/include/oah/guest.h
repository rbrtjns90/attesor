#ifndef OAH_GUEST_H
#define OAH_GUEST_H

#include "oah/register.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OAH_GUEST_SIGNAL_COUNT 64

typedef struct {
    u64 handler;
    u64 flags;
    u64 restorer;
    u64 mask;
} oah_guest_signal_action;

/*
 * Guest x86_64 integer state. GPR order matches Linux user_regs_struct
 * (RAX..R15) recovered from FUN_800000040650.
 *
 * The original runtime then copies these into host Xn (see
 * oah_host_xn_for_x86_gpr). The interpreter keeps them in this file and
 * only applies that map when a JIT exists.
 */
typedef struct {
    u64 gpr[OAH_X86_GPR_COUNT];
    u8 xmm[16][16];
    u8 legacy_fx[160]; /* FXSAVE header and x87 register slots. */
    u64 rip;
    u64 rflags;
    u64 fs_base;
    u64 gs_base;
    oah_guest_signal_action signal_actions[OAH_GUEST_SIGNAL_COUNT];
    u64 signal_mask;
    u64 pending_signals;
    u64 thread_signals;
    u64 signal_stack_base;
    u64 signal_stack_size;
#if defined(__APPLE__)
    oah_guest_signal_action *shared_signal_actions;
    u64 clear_tid;
    u32 tid;
    unsigned quantum;
    u64 jit_owner; /* serial: fragments bake per-thread bases, keyed by this */
    bool thread_exit;
#endif
    /* Mid-fragment fault replay: while nonzero, guest RIPs in
     * [replay_from, replay_until] run under the interpreter with stores
     * suppressed (the JIT already committed them). Set by the fragment
     * fault handler; the interpreter clears it at replay_until. */
    u64 replay_from;
    u64 replay_until;
} oah_guest;

static inline oah_guest_signal_action *oah_guest_actions(oah_guest *g)
{
#if defined(__APPLE__)
    if (g->shared_signal_actions) {
        return g->shared_signal_actions;
    }
#endif
    return g->signal_actions;
}

/* Linux userspace default: bit 1 reserved-1, bit 9 IF. */
#define OAH_RFLAGS_INIT 0x202ull

void oah_guest_init(oah_guest *g, u64 entry, u64 rsp);

/*
 * derived: FUN_800000040650
 * Copy RAX..R15 into the host Xn that hold them at runtime (and back).
 */
void oah_pack_runtime_x(u64 x[16], const oah_guest *g);
void oah_unpack_runtime_x(oah_guest *g, const u64 x[16]);

#ifdef __cplusplus
}
#endif

#endif /* OAH_GUEST_H */
