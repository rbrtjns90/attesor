#include "oah/syscall_bridge.h"

#include "oah/flags.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Linux x86-64 kernel ABI, independent of the host's libc signal structs. */
enum {
    X86_SA_SIGINFO = 4,
    X86_SA_ONSTACK = 0x08000000u,
    X86_SA_RESTART = 0x10000000u,
    X86_SA_NODEFER = 0x40000000u,
    X86_SA_RESETHAND = 0x80000000u,
    X86_SA_RESTORER = 0x04000000u,
    X86_SA_NOCLDSTOP = 1,
    X86_SA_NOCLDWAIT = 2,
    X86_SS_ONSTACK = 1,
    X86_SS_DISABLE = 2,
    X86_ENOSYS = 38,
    X86_EOPNOTSUPP = 95
};

typedef struct {
    u64 general[16];
    u64 ip, flags;
    u16 cs, gs, fs, ss;
    u64 error, trap, oldmask, cr2, fpstate;
    u64 reserved[8];
} x86_sigcontext;

typedef struct {
    u64 pointer;
    u32 flags, pad;
    u64 size;
} x86_signal_stack;

typedef struct {
    u64 flags, link;
    x86_signal_stack stack;
    x86_sigcontext machine;
    u64 mask;
} x86_ucontext;

typedef struct {
    s32 signum, error, code, padding, pid;
    u32 uid;
    u8 reserved[104];
} x86_siginfo;

typedef struct {
    u64 restorer;
    x86_ucontext context;
    x86_siginfo info;
} x86_signal_frame;

_Static_assert(sizeof(oah_guest_signal_action) == 32, "x86 sigaction layout");
_Static_assert(sizeof(x86_sigcontext) == 256, "x86 sigcontext layout");
_Static_assert(offsetof(x86_ucontext, machine) == 40, "x86 ucontext machine offset");
_Static_assert(offsetof(x86_signal_frame, info) == 312, "x86 rt_sigframe info offset");
_Static_assert(sizeof(x86_signal_frame) == 440, "x86 rt_sigframe layout");

static const u8 frame_gprs[] = {
    OAH_X86_R8, OAH_X86_R9, OAH_X86_R10, OAH_X86_R11,
    OAH_X86_R12, OAH_X86_R13, OAH_X86_R14, OAH_X86_R15,
    OAH_X86_RDI, OAH_X86_RSI, OAH_X86_RBP, OAH_X86_RBX,
    OAH_X86_RDX, OAH_X86_RAX, OAH_X86_RCX, OAH_X86_RSP
};

static u64 signal_bit(unsigned signum)
{
    return 1ull << (signum - 1);
}

static u64 blockable(u64 mask)
{
    return mask & ~(signal_bit(9) | signal_bit(19));
}

static bool on_signal_stack(const oah_guest *g, u64 sp)
{
    return sp > g->signal_stack_base && sp - g->signal_stack_base <= g->signal_stack_size;
}

static x86_signal_stack current_signal_stack(const oah_guest *g)
{
    return (x86_signal_stack){
        .pointer = g->signal_stack_base,
        .flags = !g->signal_stack_size ? X86_SS_DISABLE :
                 on_signal_stack(g, g->gpr[OAH_X86_RSP]) ? X86_SS_ONSTACK : 0,
        .size = g->signal_stack_size
    };
}

static bool valid_altstack(const x86_signal_stack *stack)
{
    return stack->pointer != 0 && stack->size >= 2048 &&
           stack->size <= UINT64_MAX - stack->pointer;
}

static bool default_ignore(unsigned signum)
{
    /* SIGCHLD, SIGCONT, SIGURG, SIGWINCH. This runner has no stopped state. */
    return signum == 17 || signum == 18 || signum == 23 || signum == 28;
}

static bool default_stop(unsigned signum)
{
    return signum >= 19 && signum <= 22;
}

static bool install_frame(oah_guest *g, oah_image *img, unsigned signum,
                          const oah_guest_signal_action *action)
{
    u64 stack = g->gpr[OAH_X86_RSP];
    bool already_on_alt = on_signal_stack(g, stack);
    bool start_on_alt = !already_on_alt && g->signal_stack_size &&
                        (action->flags & X86_SA_ONSTACK);
    if (start_on_alt) {
        stack = g->signal_stack_base + g->signal_stack_size;
    }
    u64 red_zone = start_on_alt ? 0 : 128;
    if (stack < red_zone + 512 + sizeof(x86_signal_frame) + 40 ||
        !(action->flags & X86_SA_RESTORER) ||
        !oah_guest_access(img, action->handler, 1, PROT_EXEC) ||
        !oah_guest_access(img, action->restorer, 1, PROT_EXEC)) {
        return false;
    }
    /* Respect the x86-64 red zone and enter the handler with RSP % 16 == 8. */
    u64 fp_address = (stack - red_zone - 512) & ~15ull;
    u64 frame_address = ((fp_address - sizeof(x86_signal_frame)) & ~15ull) - 8;
    if ((start_on_alt || already_on_alt) && frame_address < g->signal_stack_base) {
        return false;
    }
    u8 *fp = oah_guest_access(img, fp_address, 512, PROT_WRITE);
    void *destination = oah_guest_access(img, frame_address, sizeof(x86_signal_frame), PROT_WRITE);
    if (!fp || !destination) {
        return false;
    }
    x86_signal_frame frame = {0};
    frame.restorer = action->restorer;
    frame.context.flags = 6; /* UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS */
    frame.context.stack = current_signal_stack(g);
    frame.context.mask = g->signal_mask;
    frame.context.machine.ip = g->rip;
    frame.context.machine.flags = g->rflags;
    frame.context.machine.cs = 0x33;
    frame.context.machine.ss = 0x2b;
    frame.context.machine.oldmask = g->signal_mask;
    frame.context.machine.fpstate = fp_address;
    for (unsigned i = 0; i < 16; i++) {
        frame.context.machine.general[i] = g->gpr[frame_gprs[i]];
    }
    if (action->flags & X86_SA_SIGINFO) {
        frame.info.signum = (s32)signum;
        frame.info.code = (g->thread_signals & signal_bit(signum)) ? -6 : 0;
        frame.info.pid = (s32)getpid();
        frame.info.uid = (u32)getuid();
    }
    memset(fp, 0, 512);
    memcpy(fp, g->legacy_fx, sizeof(g->legacy_fx));
    memcpy(fp + 160, g->xmm, sizeof(g->xmm));
    memcpy(destination, &frame, sizeof(frame));

    g->gpr[OAH_X86_RAX] = 0;
    g->gpr[OAH_X86_RDI] = signum;
    g->gpr[OAH_X86_RSI] = frame_address + offsetof(x86_signal_frame, info);
    g->gpr[OAH_X86_RDX] = frame_address + offsetof(x86_signal_frame, context);
    g->gpr[OAH_X86_RSP] = frame_address;
    g->rip = action->handler;
    g->rflags &= ~(OAH_RFLAGS_DF | OAH_RFLAGS_TF | OAH_RFLAGS_RF);
    g->signal_mask |= blockable(action->mask);
    if (!(action->flags & X86_SA_NODEFER)) {
        g->signal_mask |= signal_bit(signum);
    }
    return true;
}

static oah_sys_status deliver_ready(oah_guest *g, oah_image *img)
{
    u64 ready = g->pending_signals & ~g->signal_mask;
    while (ready) {
        unsigned signum = (unsigned)__builtin_ctzll(ready) + 1;
        u64 bit = signal_bit(signum);
        oah_guest_signal_action *action = &g->signal_actions[signum - 1];
        g->pending_signals &= ~bit;
        if (action->handler == 1 || (!action->handler && default_ignore(signum))) {
            g->thread_signals &= ~bit;
            ready &= ~bit;
            continue;
        }
        if (!action->handler) {
            if (default_stop(signum)) {
                return OAH_SYS_FATAL;
            }
            g->gpr[OAH_X86_RDI] = 128 + signum;
            return OAH_SYS_EXIT;
        }
        if (!install_frame(g, img, signum, action)) {
            return OAH_SYS_FATAL;
        }
        g->thread_signals &= ~bit;
        if (action->flags & X86_SA_RESETHAND) {
            *action = (oah_guest_signal_action){0};
        }
        return OAH_SYS_CONTINUE;
    }
    return OAH_SYS_CONTINUE;
}

static oah_sys_status restore_frame(oah_guest *g, oah_image *img)
{
    u64 sp = g->gpr[OAH_X86_RSP];
    const void *source = sp < 8 ? NULL :
        oah_guest_access(img, sp - 8, sizeof(x86_signal_frame), PROT_READ);
    x86_signal_frame frame;
    if (!source) {
        return OAH_SYS_FATAL;
    }
    memcpy(&frame, source, sizeof(frame));
    const x86_sigcontext *saved = &frame.context.machine;
    const x86_signal_stack *stack = &frame.context.stack;
    if (!oah_guest_access(img, saved->ip, 1, PROT_EXEC) ||
        (stack->flags != X86_SS_DISABLE &&
         ((stack->flags & ~X86_SS_ONSTACK) || !valid_altstack(stack)))) {
        return OAH_SYS_FATAL;
    }
    const u8 *fp = NULL;
    if (saved->fpstate) {
        u32 mxcsr;
        fp = oah_guest_access(img, saved->fpstate, 512, PROT_READ);
        if (!fp) {
            return OAH_SYS_FATAL;
        }
        memcpy(&mxcsr, fp + 24, sizeof(mxcsr));
        if (mxcsr & ~0xffffu) {
            return OAH_SYS_FATAL;
        }
    }
    if (fp) {
        memcpy(g->legacy_fx, fp, 28);
        memcpy(g->legacy_fx + 32, fp + 32, sizeof(g->legacy_fx) - 32);
        memcpy(g->xmm, fp + 160, sizeof(g->xmm));
    } else {
        const u16 control = 0x037f;
        const u32 mxcsr = 0x1f80;
        memset(g->legacy_fx, 0, 28);
        memset(g->legacy_fx + 32, 0, sizeof(g->legacy_fx) - 32);
        memset(g->xmm, 0, sizeof(g->xmm));
        memcpy(g->legacy_fx, &control, sizeof(control));
        memcpy(g->legacy_fx + 24, &mxcsr, sizeof(mxcsr));
    }
    for (unsigned i = 0; i < 16; i++) {
        g->gpr[frame_gprs[i]] = saved->general[i];
    }
    const u64 user_flags = OAH_RFLAGS_CF | OAH_RFLAGS_PF | OAH_RFLAGS_AF |
                           OAH_RFLAGS_ZF | OAH_RFLAGS_SF | OAH_RFLAGS_TF |
                           OAH_RFLAGS_DF | OAH_RFLAGS_OF | OAH_RFLAGS_RF |
                           OAH_RFLAGS_AC;
    g->rflags = OAH_RFLAGS_INIT | (saved->flags & user_flags);
    g->rip = saved->ip;
    g->signal_stack_base = stack->flags == X86_SS_DISABLE ? 0 : stack->pointer;
    g->signal_stack_size = stack->flags == X86_SS_DISABLE ? 0 : stack->size;
    g->signal_mask = blockable(frame.context.mask);
    return deliver_ready(g, img);
}

static s64 signal_action(oah_guest *g, oah_image *img, u64 signum,
                         u64 new_address, u64 old_address)
{
    if (!signum || signum > OAH_GUEST_SIGNAL_COUNT ||
        (new_address && (signum == 9 || signum == 19))) {
        return -EINVAL;
    }
    oah_guest_signal_action *action = &g->signal_actions[signum - 1];
    oah_guest_signal_action next;
    const void *input = oah_guest_access(img, new_address, sizeof(next), PROT_READ);
    void *output = oah_guest_access(img, old_address, sizeof(next), PROT_WRITE);
    if ((new_address && !input) || (old_address && !output)) {
        return -EFAULT;
    }
    if (input) {
        memcpy(&next, input, sizeof(next));
        const u64 flags = X86_SA_SIGINFO | X86_SA_RESTART | X86_SA_RESTORER | X86_SA_ONSTACK |
                          X86_SA_NODEFER | X86_SA_RESETHAND | X86_SA_NOCLDSTOP |
                          X86_SA_NOCLDWAIT;
        next.flags &= flags;
        next.mask = blockable(next.mask);
    }
    if (output) {
        memcpy(output, action, sizeof(*action));
    }
    if (input) {
        *action = next;
        if (next.handler == 1 || (!next.handler && default_ignore((unsigned)signum))) {
            g->pending_signals &= ~signal_bit((unsigned)signum);
            g->thread_signals &= ~signal_bit((unsigned)signum);
        }
    }
    return 0;
}

static s64 signal_mask(oah_guest *g, oah_image *img, int how, u64 new_address, u64 old_address)
{
    const void *input = oah_guest_access(img, new_address, 8, PROT_READ);
    void *output = oah_guest_access(img, old_address, 8, PROT_WRITE);
    if ((new_address && !input) || (old_address && !output)) {
        return -EFAULT;
    }
    u64 next = g->signal_mask;
    if (input) {
        u64 mask;
        memcpy(&mask, input, sizeof(mask));
        switch (how) {
        case 0: next |= mask; break; /* SIG_BLOCK */
        case 1: next &= ~mask; break; /* SIG_UNBLOCK */
        case 2: next = mask; break; /* SIG_SETMASK */
        default: return -EINVAL;
        }
    }
    if (output) {
        memcpy(output, &g->signal_mask, 8);
    }
    g->signal_mask = blockable(next);
    return 0;
}

static s64 signal_altstack(oah_guest *g, oah_image *img, u64 new_address, u64 old_address)
{
    x86_signal_stack next;
    const void *input = oah_guest_access(img, new_address, sizeof(next), PROT_READ);
    void *output = oah_guest_access(img, old_address, sizeof(next), PROT_WRITE);
    if ((new_address && !input) || (old_address && !output)) {
        return -EFAULT;
    }
    x86_signal_stack old = current_signal_stack(g);
    if (input) {
        if (old.flags == X86_SS_ONSTACK) {
            return -EPERM;
        }
        memcpy(&next, input, sizeof(next));
        if (next.flags != 0 && next.flags != X86_SS_DISABLE) {
            return -EINVAL;
        }
        if (next.flags == 0 && next.size < 2048) {
            return -ENOMEM;
        }
        if (next.flags == 0 && !valid_altstack(&next)) {
            return -EINVAL;
        }
    }
    if (output) {
        memcpy(output, &old, sizeof(old));
    }
    if (input) {
        g->signal_stack_base = next.flags == X86_SS_DISABLE ? 0 : next.pointer;
        g->signal_stack_size = next.flags == X86_SS_DISABLE ? 0 : next.size;
    }
    return 0;
}

static s64 queue_self_signal(oah_guest *g, u64 number, int pid, int tid, bool thread)
{
    if (number > OAH_GUEST_SIGNAL_COUNT) {
        return -EINVAL;
    }
    if (pid != getpid() || tid != getpid()) {
        return -ESRCH;
    }
    if (!number) {
        return 0;
    }
    if (number >= 32) {
        return -X86_EOPNOTSUPP; /* Realtime signals require a queue rather than a bitset. */
    }
    unsigned signum = (unsigned)number;
    u64 bit = signal_bit(signum);
    u64 handler = g->signal_actions[signum - 1].handler;
    if (!handler && default_stop(signum)) {
        return -X86_EOPNOTSUPP;
    }
    if (handler == 1 || (!handler && default_ignore(signum))) {
        return 0;
    }
    if (!(g->pending_signals & bit) && thread) {
        g->thread_signals |= bit;
    }
    g->pending_signals |= bit;
    return 0;
}

oah_sys_status oah_guest_signal_syscall(oah_guest *g, oah_image *img)
{
    u64 nr = g->gpr[OAH_X86_RAX];
    u64 a0 = g->gpr[OAH_X86_RDI], a1 = g->gpr[OAH_X86_RSI];
    u64 a2 = g->gpr[OAH_X86_RDX], a3 = g->gpr[OAH_X86_R10];
    s64 result;
    switch (nr) {
    case 13:
        result = a3 == 8 ? signal_action(g, img, a0, a1, a2) : -EINVAL;
        break;
    case 14:
        result = a3 == 8 ? signal_mask(g, img, (int)a0, a1, a2) : -EINVAL;
        break;
    case 15:
        return restore_frame(g, img);
    case 127: {
        void *output = a1 <= 8 ? oah_guest_access(img, a0, a1, PROT_WRITE) : NULL;
        u64 pending = g->pending_signals & g->signal_mask;
        result = a1 > 8 ? -EINVAL : (!a1 || output) ? 0 : -EFAULT;
        if (output) {
            memcpy(output, &pending, a1);
        }
        break;
    }
    case 131:
        result = signal_altstack(g, img, a0, a1);
        break;
    case 62:
    case 200:
        result = queue_self_signal(g, a1, (int)a0, (int)a0, nr == 200);
        break;
    case 234:
        result = queue_self_signal(g, a2, (int)a0, (int)a1, true);
        break;
    default:
        result = -X86_ENOSYS;
        break;
    }
    g->gpr[OAH_X86_RAX] = (u64)result;
    return result == 0 ? deliver_ready(g, img) : OAH_SYS_CONTINUE;
}
