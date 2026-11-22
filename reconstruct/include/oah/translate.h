#ifndef OAH_TRANSLATE_H
#define OAH_TRANSLATE_H

#include "oah/assembler_buffer.h"
#include "oah/elf_map.h"
#include "oah/guest.h"
#include "oah/interp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Translate one x86_64 block into ARM64 using the runtime GPR map
 * (FUN_800000040650) and a runtime_syscall shuffle + `svc #0`.
 *
 * Fragments end with RET (LR=0 returns to the C dispatcher). With
 * OAH_XLAT_DISPATCH_STATE, translation stops before operations that need
 * dispatcher-managed state. If one is at the entry, success appends no
 * code and leaves next_rip there.
 *
 * flags:
 *   OAH_XLAT_HOST_SVC — rewrite x86_64 NR in X8 to the aarch64 NR before
 *   `svc #0`, for native/QEMU execution. Unit tests leave this off so
 *   oah_arm_exec still sees x86 numbers.
 */
#define OAH_XLAT_HOST_SVC 1u
#define OAH_XLAT_DISPATCH_STATE 2u

bool oah_translate_block(oah_asm_buf *buf, oah_image *img, u64 rip, u64 *next_rip);
bool oah_translate_block_flags(oah_asm_buf *buf, oah_image *img, u64 rip,
                               u64 *next_rip, u32 flags);

/* Shuffle runtime Xn into Linux SVC ABI and `svc #0`, then restore. */
bool oah_emit_runtime_syscall(oah_asm_buf *buf);
/* Same shuffle, then x86 NR → aarch64 NR compares before `svc #0`. */
bool oah_emit_runtime_syscall_host(oah_asm_buf *buf);

/*
 * Cached-fragment translator (the "real" JIT path).
 *
 * Fragments run under a different register contract than oah_translate_block:
 *   host x0–x15  guest GPRs (oah_host_xn_for_x86_gpr)
 *   host x19     guest RFLAGS — full x86 status flags, eagerly maintained
 *   host x20     next guest RIP — every fragment sets it, then RET
 *   host x16,x17,x21–x28  scratch
 *
 * Guest memory is accessed at its guest virtual address directly
 * (identity mappings on this host). FS/GS bases are baked in as constants;
 * the caller must invalidate the cache if they change.
 */
/* Site of a fixed 4-instruction movz/movk materialization in emitted code
 * whose value must be patched when a cached fragment is reused at a
 * different guest load address. */
typedef struct {
    u32 off;   /* byte offset into the fragment's code */
    u32 kind;  /* OAH_RELOC_* */
    u8 rd;     /* host register the materialization writes */
    u64 value; /* GVA: guest absolute address emitted */
} oah_frag_reloc;

enum { OAH_RELOC_GVA = 0, OAH_RELOC_FS = 1, OAH_RELOC_GS = 2,
       OAH_RELOC_XMMBASE = 3 };
#define OAH_FRAG_MAX_RELOCS 24

typedef struct {
    u32 insns;       /* guest instructions emitted */
    u32 interp_next; /* nonzero: run one interpreter step at the exit RIP */
    u32 nrelocs;     /* relocatable immediates recorded */
    u32 reloc_overflow; /* nonzero: too many relocs — do not persist */
    u32 nexits;      /* chainable constant-RIP exits recorded */
    u32 exit_off[2]; /* byte offset of each exit's ret insn */
    u64 exit_rip[2]; /* constant guest target of each exit */
    oah_frag_reloc relocs[OAH_FRAG_MAX_RELOCS];
} oah_frag_info;

bool oah_translate_frag(oah_asm_buf *buf, oah_image *img, const oah_guest *g,
                        u64 rip, oah_frag_info *info);

/* Gate SSE translation: callers enable it only for entry ABIs where the
 * xmm shadow address emitted via OAH_RELOC_XMMBASE stays valid at run
 * time (i.e. the guest object outlives its cached fragments). */
void oah_translate_enable_sse(bool on);

/* Dispatcher: pack GPRs, translate+interpret fragments until guest exit. */
oah_interp_result oah_jit_run(oah_guest *g, oah_image *img, u64 max_insns);

/*
 * Same dispatcher, but mmap/BLR the fragment on aarch64. `svc` is real
 * (including exit). On other hosts this is the interpreter path.
 */
oah_interp_result oah_jit_run_native(oah_guest *g, oah_image *img, u64 max_insns);

/*
 * Caching fragment JIT (MAP_JIT arena + RIP->code hash table).
 * aot=true pretranslates all PROT_EXEC segments before running.
 */
oah_interp_result oah_jit_run_cached(oah_guest *g, oah_image *img,
                                     u64 max_insns, bool aot);

/* Drop all cached fragments (guest memory/protection changed). */
void oah_jit_cache_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* OAH_TRANSLATE_H */
