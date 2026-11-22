#include "oah/translate.h"

#include "oah/arm_exec.h"
#include "oah/assembler.h"

#include <string.h>

static oah_interp_result jit_loop(oah_guest *g, oah_image *img, u64 max_insns,
                                  int native
#if defined(__APPLE__) && defined(__aarch64__)
                                  , oah_arm_native_buffer *arena
#endif
                                  )
{
    oah_interp_result r, one;
    oah_arm_state st;
    u64 budget = max_insns ? max_insns : OAH_INTERP_MAX_INSNS;
    u32 flags = OAH_XLAT_DISPATCH_STATE;

    r.status = OAH_INTERP_OK;
    r.exit_code = 0;
    r.insns = 0;
    memset(&st, 0, sizeof(st));

    while (r.insns < budget) {
#if defined(__APPLE__)
        oah_darwin_guest_tick(g);
        oah_sys_status signal_status = oah_guest_signal_poll(g, img);
        if (signal_status != OAH_SYS_CONTINUE) {
            r.status = signal_status == OAH_SYS_EXIT ? OAH_INTERP_EXIT : OAH_INTERP_FAULT;
            r.exit_code = (int)(g->gpr[OAH_X86_RDI] & 0xff);
            return r;
        }
#endif
        oah_asm_buf buf;
        u64 next = g->rip;

        oah_asm_buf_init(&buf);
        oah_pack_runtime_x(st.x, g);
        if (!native) {
            st.x[30] = 0;
        }
        if (!oah_translate_block_flags(&buf, img, g->rip, &next, flags)) {
            oah_asm_buf_destroy(&buf);
            r.status = OAH_INTERP_DECODE;
            return r;
        }
        if (buf.size == 0) {
            /* Execute one instruction that needs dispatcher-managed guest state. */
            oah_asm_buf_destroy(&buf);
            one = oah_interp_run(g, img, 1);
            r.insns += one.insns;
            if (one.status != OAH_INTERP_LIMIT) {
                r.status = one.status;
                r.exit_code = one.exit_code;
                return r;
            }
            continue;
        }
        if (native) {
#if defined(__APPLE__) && defined(__aarch64__)
            one = oah_arm_exec_native_buffered(arena, &st, buf.data, buf.size);
#else
            one = oah_arm_exec_native(&st, buf.data, buf.size);
#endif
        } else {
            one = oah_arm_exec(&st, buf.data, buf.size, img, budget - r.insns);
        }
        oah_unpack_runtime_x(g, st.x);
        oah_asm_buf_destroy(&buf);
        r.insns += one.insns;

        if (one.status == OAH_INTERP_EXIT) {
            r.status = OAH_INTERP_EXIT;
            r.exit_code = one.exit_code;
            return r;
        }
        if (one.status != OAH_INTERP_OK) {
            r.status = one.status;
            return r;
        }
        g->rip = next;
        if (one.insns == 0) {
            r.status = OAH_INTERP_FAULT;
            return r;
        }
    }
    r.status = OAH_INTERP_LIMIT;
    return r;
}

oah_interp_result oah_jit_run(oah_guest *g, oah_image *img, u64 max_insns)
{
#if defined(__APPLE__) && defined(__aarch64__)
    return jit_loop(g, img, max_insns, 0, NULL);
#else
    return jit_loop(g, img, max_insns, 0);
#endif
}

oah_interp_result oah_jit_run_native(oah_guest *g, oah_image *img, u64 max_insns)
{
#if defined(__APPLE__) && defined(__aarch64__)
    oah_arm_native_buffer arena = {0};
    oah_interp_result result = jit_loop(g, img, max_insns, 1, &arena);
    oah_arm_native_buffer_destroy(&arena);
    return result;
#elif defined(__aarch64__)
    return jit_loop(g, img, max_insns, 1);
#else
    return jit_loop(g, img, max_insns, 0);
#endif
}

/* ================= Cached-fragment JIT =================
 *
 * Rosetta-style fragment cache: guest RIP -> translated ARM64 code in a
 * MAP_JIT arena. Fragments run under the oah_jit_native_enter contract:
 *   x0–x15 guest GPRs, x19 guest RFLAGS, x20 next guest RIP.
 * The dispatcher runs a fragment, reads x20, looks up the next fragment
 * (translating on a miss), and falls back to the checked interpreter for
 * one instruction whenever a block ends on an unhandled operation.
 */

#if defined(__APPLE__) && defined(__aarch64__)

#include "oah/decode_insn.h"
#include "oah/icache.h"

#include <libkern/OSCacheControl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

#define OAH_JIT_ARENA (32u << 20)
#define OAH_JIT_TABLE_BITS 15
#define OAH_JIT_TABLE_SIZE (1u << OAH_JIT_TABLE_BITS)

#define OAH_FRAG_FALLBACK 1u /* run one interp step at exit RIP */

typedef struct {
    u64 rip;
    u32 insns;
    u32 flags;
    u32 code_off;
    u32 code_len;
    u32 stub_off; /* checkpoint stub; chained exits branch here */
    u32 nexits;
    u32 exit_off[2];
    u64 exit_rip[2];
} oah_frag_entry;

/* Chain accounting: a patched exit branches to the target's stub,
 * which adds the target's guest-insn count to acc and continues the
 * chain while acc <= limit; otherwise it rets to the dispatcher.
 * This bounds every native entry to at most `limit` guest insns so
 * the budget check and signal poll in the dispatch loop still run. */
static struct { u64 acc, limit; } chain_ctl;
#define OAH_CHAIN_WINDOW (64u << 10) /* guest insns between checkpoints */

void oah_jit_native_enter(u64 *x, const void *code);

static oah_frag_entry jit_table[OAH_JIT_TABLE_SIZE];
static u8 *jit_arena;
unsigned char *oah_jit_arena_for_debug;

static size_t jit_arena_size;
static size_t jit_arena_used;

static u64 jit_hash(u64 rip)
{
    return (rip * 0x9e3779b97f4a7c15ull) >> (64 - OAH_JIT_TABLE_BITS);
}

static oah_frag_entry *jit_lookup(u64 rip)
{
    u64 idx = jit_hash(rip);
    for (unsigned i = 0; i < OAH_JIT_TABLE_SIZE; i++) {
        oah_frag_entry *e = &jit_table[(idx + i) & (OAH_JIT_TABLE_SIZE - 1)];
        if (!e->rip) {
            return NULL;
        }
        if (e->rip == rip) {
            return e;
        }
    }
    return NULL;
}

static void jit_insert(const oah_frag_entry *entry)
{
    u64 idx = jit_hash(entry->rip);
    for (unsigned i = 0; i < OAH_JIT_TABLE_SIZE; i++) {
        oah_frag_entry *e = &jit_table[(idx + i) & (OAH_JIT_TABLE_SIZE - 1)];
        if (!e->rip || e->rip == entry->rip) {
            *e = *entry;
            return;
        }
    }
}

/* The fragment the dispatcher last entered — its unlinked constant exits
 * are repatched to `b` the next fragment when the target is already
 * translated (Rosetta-style block repatching). */
static oah_frag_entry *chain_prev;
static bool jit_chain = true;
static u64 fallback_steps; /* interpreter steps at fragment boundaries */
static u64 stats_insns;
static u64 stats_ops[64]; /* decoded op of each boundary insn */
static u64 stats_scalar[64]; /* OAH_SC_* subtype within OAH_OP_SCALAR */
static bool jit_stats;
static int stats_fd = -1; /* dup'd stderr: guests close fd 2 during cleanup */

static void jit_stats_print(void)
{
    static bool printed;
    if (printed) {
        return;
    }
    printed = true;
    int out = stats_fd >= 0 ? stats_fd : STDERR_FILENO;
    dprintf(out,
            "jit stats: insns=%llu boundary_interp_steps=%llu (%.1f%%)\n",
            (unsigned long long)stats_insns,
            (unsigned long long)fallback_steps,
            stats_insns ? 100.0 * (double)fallback_steps / (double)stats_insns
                        : 0.0);
    if (getenv("OAH_JIT_STATS_OPS")) {
        for (int i = 0; i < 64; i++) {
            if (stats_ops[i]) {
                dprintf(out, "  op %-4d %llu (%.1f%%)\n", i,
                        (unsigned long long)stats_ops[i],
                        100.0 * (double)stats_ops[i] / (double)fallback_steps);
            }
        }
        for (int i = 0; i < 64; i++) {
            if (stats_scalar[i]) {
                dprintf(out, "  scalar %-4d %llu (%.1f%%)\n", i,
                        (unsigned long long)stats_scalar[i],
                        100.0 * (double)stats_scalar[i] /
                            (double)fallback_steps);
            }
        }
    }
}

/* Rewrite an exit's `ret` into `b <target>` when it is in range. */
static void jit_chain_patch(oah_frag_entry *e, u32 slot, u32 target_off)
{
    u8 *site = jit_arena + e->code_off + e->exit_off[slot];
    s64 diff = (s64)(jit_arena + target_off - site) >> 2;
    if (diff < -(1ll << 25) || diff >= (1ll << 25)) {
        return;
    }
    pthread_jit_write_protect_np(0);
    *(u32 *)site = 0x14000000u | (u32)((u64)diff & 0x3ffffff);
    sys_icache_invalidate(site, 4);
    pthread_jit_write_protect_np(1);
    e->exit_off[slot] = 0;
}

void oah_jit_cache_flush(void)
{
    memset(jit_table, 0, sizeof(jit_table));
    jit_arena_used = 0;
    chain_prev = NULL;
}

static bool jit_arena_init(void)
{
    if (jit_arena) {
        return true;
    }
#if defined(__APPLE__)
    jit_arena_size = OAH_JIT_ARENA;
    jit_arena = mmap(NULL, jit_arena_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    oah_jit_arena_for_debug = jit_arena;
    return jit_arena != MAP_FAILED;
#else
    return false;
#endif
}

/* ================= Persistent fragment cache =================
 *
 * Each mapped guest ELF (exe, interpreter, libraries) gets a per-module
 * .oahjc file under the cache dir. Entries carry relocations describing
 * the fixed-length movz/movk materializations in the emitted code, so a
 * cached fragment rebinds to the module's new load address at materialize
 * time. Keyed by dev/ino/size/mtime — a changed file gets a new name and
 * the stale file is reclaimed by normal eviction or manual clearing.
 */

#define OAH_PCACHE_VERSION 4u
/* Cache files are tied to the translator build: a rebuilt binary may emit
 * different code for the same guest, so old files must not be reused.
 * oah_build_key() is generated into src/build_key.c each build so every
 * object shares one identity (a per-TU define would let incremental
 * builds mix stale keys). */
unsigned oah_build_key(void);
static const u8 pcache_magic[8] = {'O', 'A', 'H', 'J', 'C', '0', '0', '1'};

typedef struct {
    u32 off;
    u32 kind;
    u8 rd;
    u8 pad[7];
    u64 value; /* GVA: module-relative offset of the target */
} pcache_rel;

typedef struct {
    u64 off; /* disk: module-relative rip; pend: absolute rip */
    u32 code_len;
    u32 nrel;
    u32 insns;
    u32 interp_next;
    u32 nexits;
    u32 exit_off[2];
    u64 exit_rip[2]; /* disk: module-relative; pend: absolute */
    u8 *code;
    pcache_rel *rel;
} pcache_ent;

typedef struct {
    u8 *blob;
    size_t blob_size;
    pcache_ent *disk;
    u32 n_disk;
    pcache_ent *pend;
    u32 n_pend;
    u32 cap_pend;
} pcache;

static bool jit_persist = true;

static int pcache_mkdirs(const char *dir)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static const char *pcache_dir(char *out, size_t size)
{
    const char *env = getenv("OAH_CACHE_DIR");
    if (env && *env) {
        snprintf(out, size, "%s", env);
    } else {
        const char *home = getenv("HOME");
        if (!home || !*home) {
            return NULL;
        }
        snprintf(out, size, "%s/Library/Caches/Attesor/jit", home);
    }
    return pcache_mkdirs(out) == 0 ? out : NULL;
}

static void pcache_path_in(const char *dir, const oah_module *m, char *out,
                           size_t size)
{
    const char *base = strrchr(m->path, '/');
    base = base ? base + 1 : m->path;
    snprintf(out, size, "%s/%s-%016llx.oahjc", dir, base,
             (unsigned long long)m->key);
}

static void pcache_path(const oah_module *m, char *out, size_t size)
{
    char dir[PATH_MAX];
    if (!pcache_dir(dir, sizeof(dir))) {
        out[0] = 0;
        return;
    }
    pcache_path_in(dir, m, out, size);
}

/* An explicit OAH_CACHE_DIR is authoritative: no fallback to the
 * default cache, so tests and benchmarks get predictable cold-cache
 * behavior. */

/* Read and index the module's .oahjc (once). A non-NULL pcache with no
 * disk entries means "no usable file", distinct from a parse failure. */
static pcache *pcache_open(oah_image *img, int module)
{
    oah_module *m = &img->modules[module];
    if (!jit_persist) {
        return NULL;
    }
    if (m->jit_cache_tried) {
        return m->jit_cache;
    }
    m->jit_cache_tried = true;
    pcache *pc = calloc(1, sizeof(*pc));
    m->jit_cache = pc;
    char path[PATH_MAX];
    pcache_path(m, path, sizeof(path));
    FILE *f = path[0] ? fopen(path, "rb") : NULL;
    if (!f) {
        return pc;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    /* Bound the size before allocating: a cache file is a small index
     * of fragments, never tens of megabytes. */
    if (len < 32 || len > (64L << 20)) {
        fclose(f);
        return pc;
    }
    u8 *blob = malloc((size_t)len);
    if (!blob || fread(blob, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        free(blob);
        return pc;
    }
    fclose(f);
    if (len < 32 || memcmp(blob, pcache_magic, 8) ||
        ((const u32 *)blob)[2] != OAH_PCACHE_VERSION ||
        ((const u32 *)blob)[6] != oah_build_key() ||
        ((const u64 *)blob)[2] != m->key) {
        free(blob);
        return pc;
    }
    u32 n = ((const u32 *)blob)[3];
    if ((u64)n > (u64)len / 24) {
        free(blob);
        return pc;
    }
    const u8 *p = blob + 32, *end = blob + len;
    pcache_ent *ents = calloc(n, sizeof(*ents));
    if (!ents) {
        free(blob);
        return pc;
    }
    u32 count = 0;
    for (u32 i = 0; i < n && p + 24 <= end; i++) {
        pcache_ent *e = &ents[count];
        e->off = ((const u64 *)p)[0];
        e->code_len = ((const u32 *)p)[2];
        e->nrel = ((const u32 *)p)[3];
        e->insns = ((const u32 *)p)[4];
        e->interp_next = ((const u32 *)p)[5];
        p += 24;
        if ((size_t)(end - p) < (size_t)e->code_len) {
            break;
        }
        e->code = (u8 *)p;
        p += e->code_len;
        if (e->nrel > OAH_FRAG_MAX_RELOCS ||
            e->nrel * sizeof(pcache_rel) > (size_t)(end - p)) {
            break;
        }
        e->rel = (pcache_rel *)p;
        p += e->nrel * sizeof(pcache_rel);
        if (p + 32 > end) {
            break;
        }
        e->nexits = ((const u32 *)p)[0];
        if (e->nexits > 2) {
            break;
        }
        e->exit_off[0] = ((const u32 *)p)[1];
        e->exit_off[1] = ((const u32 *)p)[2];
        e->exit_rip[0] = ((const u64 *)p)[2];
        e->exit_rip[1] = ((const u64 *)p)[3];
        p += 32;
        count++;
    }
    pc->blob = blob;
    pc->blob_size = (size_t)len;
    pc->disk = ents;
    pc->n_disk = count;
    return pc;
}

static const pcache_ent *pcache_find(pcache *pc, u64 off)
{
    u32 lo = 0, hi = pc->n_disk;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (pc->disk[mid].off < off) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < pc->n_disk && pc->disk[lo].off == off ? &pc->disk[lo] : NULL;
}

/* Re-emit the fixed 4-insn movz/movk materialization with a new value. */
static void patch_imm64(u8 *dst, u8 rd, u64 val)
{
    u32 *p = (u32 *)dst;
    p[0] = 0xd2800000u | ((u32)(val & 0xffff) << 5) | rd;
    p[1] = 0xf2800000u | (1u << 21) | ((u32)((val >> 16) & 0xffff) << 5) | rd;
    p[2] = 0xf2800000u | (2u << 21) | ((u32)((val >> 32) & 0xffff) << 5) | rd;
    p[3] = 0xf2800000u | (3u << 21) | ((u32)((val >> 48) & 0xffff) << 5) | rd;
}

/* Record a freshly translated fragment for the module's cache file.
 * Persists only when every GVA reloc resolves inside the same module.
 * rip and reloc values stay absolute here; they become module-relative
 * at flush (the module base may still shift while more segs are tagged). */
static void pcache_pend(oah_image *img, int module, u64 rip,
                        const u8 *code, size_t code_len,
                        const oah_frag_info *info)
{
    if (info->reloc_overflow) {
        return;
    }
    u64 base = img->modules[module].base;
    for (u32 i = 0; i < info->nrelocs; i++) {
        const oah_frag_reloc *r = &info->relocs[i];
        if (r->kind == OAH_RELOC_GVA &&
            (r->value < base || oah_image_module_at(img, r->value) != module)) {
            return; /* cross-module target: cannot rebase — skip */
        }
    }
    pcache *pc = pcache_open(img, module);
    if (!pc || pcache_find(pc, rip - base)) {
        return; /* already persisted */
    }
    if (pc->n_pend == pc->cap_pend) {
        u32 cap = pc->cap_pend ? pc->cap_pend * 2 : 64;
        pcache_ent *np = realloc(pc->pend, cap * sizeof(*np));
        if (!np) {
            return;
        }
        pc->pend = np;
        pc->cap_pend = cap;
    }
    pcache_ent *e = &pc->pend[pc->n_pend];
    e->off = rip;
    e->code_len = (u32)code_len;
    e->nrel = info->nrelocs;
    e->insns = info->insns;
    e->interp_next = info->interp_next;
    e->nexits = info->nexits > 2 ? 0 : info->nexits;
    for (u32 i = 0; i < e->nexits; i++) {
        e->exit_off[i] = info->exit_off[i];
        e->exit_rip[i] = info->exit_rip[i];
    }
    e->code = malloc(code_len ? code_len : 1);
    e->rel = malloc(info->nrelocs ? info->nrelocs * sizeof(*e->rel) : 1);
    if (!e->code || !e->rel) {
        free(e->code);
        free(e->rel);
        return;
    }
    memcpy(e->code, code, code_len);
    for (u32 i = 0; i < info->nrelocs; i++) {
        e->rel[i].off = info->relocs[i].off;
        e->rel[i].kind = info->relocs[i].kind;
        e->rel[i].rd = info->relocs[i].rd;
        e->rel[i].value = info->relocs[i].value;
    }
    pc->n_pend++;
}

static int pcache_ent_cmp(const void *a, const void *b)
{
    u64 x = ((const pcache_ent *)a)->off, y = ((const pcache_ent *)b)->off;
    return x < y ? -1 : x > y;
}

/* Merge pending fragments over the disk set and rewrite the file. */
static void pcache_flush_module(oah_module *m)
{
    pcache *pc = m->jit_cache;
    if (!pc || !pc->n_pend) {
        return;
    }
    u32 total = pc->n_disk + pc->n_pend;
    pcache_ent *all = malloc(total * sizeof(*all));
    if (!all) {
        return;
    }
    memcpy(all, pc->disk, pc->n_disk * sizeof(*all));
    memcpy(all + pc->n_disk, pc->pend, pc->n_pend * sizeof(*all));
    char path[PATH_MAX], tmp[PATH_MAX];
    pcache_path(m, path, sizeof(path));
    if (!path[0]) {
        free(all);
        return;
    }
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        free(all);
        return;
    }
    u8 hdr[32];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, pcache_magic, 8);
    ((u32 *)hdr)[2] = OAH_PCACHE_VERSION;
    ((u32 *)hdr)[6] = oah_build_key();
    ((u64 *)hdr)[2] = m->key;
    if (fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        unlink(tmp);
        free(all);
        return;
    }
    /* Pending entries hold absolute addresses; disk entries are already
     * module-relative. Normalize everything to module-relative, using the
     * final base so late tags cannot skew earlier pending entries. */
    u64 base = m->base;
    for (u32 i = pc->n_disk; i < total; i++) {
        all[i].off -= base;
        for (u32 j = 0; j < all[i].nrel; j++) {
            if (all[i].rel[j].kind == OAH_RELOC_GVA) {
                all[i].rel[j].value -= base;
            }
        }
        for (u32 j = 0; j < all[i].nexits; j++) {
            all[i].exit_rip[j] -= base;
        }
    }
    qsort(all, total, sizeof(*all), pcache_ent_cmp);
    u32 out = 0;
    int bad = 0;
    for (u32 i = 0; i < total && !bad; i++) {
        if (out && all[i].off == all[i - 1].off) {
            continue; /* duplicate: first (sorted) copy wins */
        }
        u8 ent[24];
        memset(ent, 0, sizeof(ent));
        ((u64 *)ent)[0] = all[i].off;
        ((u32 *)ent)[2] = all[i].code_len;
        ((u32 *)ent)[3] = all[i].nrel;
        ((u32 *)ent)[4] = all[i].insns;
        ((u32 *)ent)[5] = all[i].interp_next;
        u8 trailer[32];
        memset(trailer, 0, sizeof(trailer));
        ((u32 *)trailer)[0] = all[i].nexits;
        ((u32 *)trailer)[1] = all[i].exit_off[0];
        ((u32 *)trailer)[2] = all[i].exit_off[1];
        ((u64 *)trailer)[2] = all[i].exit_rip[0];
        ((u64 *)trailer)[3] = all[i].exit_rip[1];
        bad = fwrite(ent, 1, sizeof(ent), f) != sizeof(ent) ||
              fwrite(all[i].code, 1, all[i].code_len, f) != all[i].code_len ||
              fwrite(all[i].rel, sizeof(*all[i].rel), all[i].nrel, f) != all[i].nrel ||
              fwrite(trailer, 1, sizeof(trailer), f) != sizeof(trailer);
        out++;
    }
    if (!bad && (fseek(f, 12, SEEK_SET) != 0 || fwrite(&out, 4, 1, f) != 1)) {
        bad = 1;
    }
    fclose(f);
    if (bad || rename(tmp, path) != 0) {
        unlink(tmp);
    }
    free(all);
}

static void pcache_flush(oah_image *img)
{
    if (!jit_persist || !img) {
        return;
    }
    for (unsigned i = 0; i < img->nmodule; i++) {
        pcache_flush_module(&img->modules[i]);
    }
}

/* Emit a chain checkpoint stub at `at` for a fragment whose code starts
 * at arena offset `target_off`. Chained exits branch to the stub; it
 * charges frag_insns to chain_ctl.acc and either tails into the
 * fragment or rets to the dispatcher when over the window. Uses only
 * x16/x17/x21/x22, all free-clobber per the fragment register contract.
 * Returns bytes written (<= OAH_STUB_SIZE). */
#define OAH_STUB_SIZE 48
static u32 jit_emit_stub(u8 *at, u32 frag_insns, u32 target_off)
{
    u64 pc = (u64)(uintptr_t)at;
    u64 base = (u64)(uintptr_t)&chain_ctl;
    u32 *w = (u32 *)at;
    int n = 0;
    s64 pdelta = ((s64)(base & ~0xfffull) - (s64)(pc & ~0xfffull)) >> 12;
    if (pdelta >= -(1 << 20) && pdelta < (1 << 20)) {
        w[n++] = 0x90000010u | (((u32)pdelta & 3) << 29) |
                 ((((u32)pdelta >> 2) & 0x7ffff) << 5); /* adrp x16 */
        w[n++] = 0x91000210u | ((u32)(base & 0xfff) << 10); /* add x16,lo */
    } else {
        /* Arena too far from .bss for adrp: materialize the address. */
        w[n++] = 0xd2800010u | ((u32)(base & 0xffff) << 5);     /* movz */
        w[n++] = 0xf2a00010u | ((u32)((base >> 16) & 0xffff) << 5);
        w[n++] = 0xf2c00010u | ((u32)((base >> 32) & 0xffff) << 5);
        w[n++] = 0xf2e00010u | ((u32)((base >> 48) & 0xffff) << 5);
    }
    w[n++] = 0xf9400211u;                          /* ldr x17, [x16] (acc) */
    if (frag_insns <= 4095) {
        w[n++] = 0x91000231u | (frag_insns << 10); /* add x17, x17, #insns */
    } else {
        if (frag_insns > 65535) {
            frag_insns = 65535;
        }
        w[n++] = 0xd2800016u | (frag_insns << 5);  /* movz x22, #insns */
        w[n++] = 0x8b160231u;                      /* add x17, x17, x22 */
    }
    w[n++] = 0xf9400615u;                          /* ldr x21, [x16,#8] */
    w[n++] = 0xeb15023fu;                          /* cmp x17, x21 */
    w[n++] = 0x54000068u;                          /* b.hi +12 -> ret */
    w[n++] = 0xf9000211u;                          /* str x17, [x16] */
    s64 diff = ((s64)((u64)(uintptr_t)jit_arena + target_off)
                - (s64)(pc + (u64)n * 4)) >> 2;
    w[n++] = 0x14000000u | ((u32)diff & 0x3ffffff); /* b fragment */
    w[n++] = 0xd65f03c0u;                          /* ret (bail) */
    return (u32)n * 4;
}

/* Copy code into the executable arena and index it. Shared by translation,
 * AOT prewarm, and persistent-cache materialization. */
static const oah_frag_entry *jit_install(u64 rip, const oah_frag_info *info,
                                         const u8 *code, size_t code_len)
{
    if (code_len + OAH_STUB_SIZE > jit_arena_size - jit_arena_used) {
        /* Arena full: drop everything and retranslate on demand. */
        oah_jit_cache_flush();
    }
    if (code_len + OAH_STUB_SIZE > jit_arena_size) {
        return NULL;
    }
    oah_frag_entry e = {
        .rip = rip,
        .insns = info->insns,
        .flags = info->interp_next ? OAH_FRAG_FALLBACK : 0,
        .code_off = (u32)jit_arena_used,
        .code_len = (u32)code_len,
        .stub_off = (u32)jit_arena_used + (u32)code_len,
        .nexits = info->nexits > 2 ? 0 : info->nexits,
    };
    for (u32 i = 0; i < e.nexits; i++) {
        e.exit_off[i] = info->exit_off[i];
        e.exit_rip[i] = info->exit_rip[i];
    }
    pthread_jit_write_protect_np(0);
    memcpy(jit_arena + jit_arena_used, code, code_len);
    u32 stub_len = jit_emit_stub(jit_arena + e.stub_off,
                                 e.insns ? e.insns : 1, e.code_off);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(jit_arena + jit_arena_used, code_len + stub_len);
    jit_arena_used += code_len + stub_len;
    jit_insert(&e);
    return jit_lookup(rip);
}

/* Materialize a persisted fragment: rebase relocations onto the module's
 * current load address (and live FS/GS bases), then install. */
static const oah_frag_entry *jit_materialize(oah_image *img,
                                             const oah_guest *g, int module,
                                             u64 rip, const pcache_ent *e)
{
    u8 *code = malloc(e->code_len);
    if (!code) {
        return NULL;
    }
    memcpy(code, e->code, e->code_len);
    u64 base = img->modules[module].base;
    for (u32 i = 0; i < e->nrel; i++) {
        const pcache_rel *r = &e->rel[i];
        if (r->off > e->code_len || e->code_len - r->off < 16) {
            free(code);
            return NULL;
        }
        u64 val = r->kind == OAH_RELOC_GVA ? base + r->value
                  : r->kind == OAH_RELOC_FS ? g->fs_base
                  : r->kind == OAH_RELOC_GS ? g->gs_base
                  : r->kind == OAH_RELOC_XMMBASE
                    ? (u64)(uintptr_t)&g->xmm[0][0] : ~(u64)0;
        if (val == ~(u64)0) {
            free(code);
            return NULL;
        }
        patch_imm64(code + r->off, r->rd, val);
    }
    oah_frag_info info = {.insns = e->insns ? e->insns : 1,
                          .interp_next = e->interp_next};
    for (u32 i = 0; i < e->nexits && i < 2; i++) {
        if (e->exit_off[i] > e->code_len || e->code_len - e->exit_off[i] < 4) {
            break;
        }
        info.exit_off[info.nexits] = e->exit_off[i];
        info.exit_rip[info.nexits] = base + e->exit_rip[i];
        info.nexits++;
    }
    const oah_frag_entry *res = jit_install(rip, &info, code, e->code_len);
    free(code);
    return res;
}

/* Translate one fragment at rip and install it. NULL when undecodable. */
static const oah_frag_entry *jit_translate(oah_image *img, const oah_guest *g,
                                           u64 rip)
{
    int module = oah_image_module_at(img, rip);
    if (module >= 0) {
        u64 off = rip - img->modules[module].base;
        pcache *pc = pcache_open(img, module);
        const pcache_ent *e = pc ? pcache_find(pc, off) : NULL;
        if (e) {
            const oah_frag_entry *frag = jit_materialize(img, g, module,
                                                       rip, e);
            if (frag) {
                return frag;
            }
        }
    }
    oah_asm_buf buf;
    oah_frag_info info;
    oah_asm_buf_init(&buf);
    if (!oah_translate_frag(&buf, img, g, rip, &info) || !buf.size) {
        oah_asm_buf_destroy(&buf);
        return NULL;
    }
    const char *trace = getenv("OAH_JIT_TRACE");
    if (trace) {
        u64 avail = 15;
        const u8 *pc = oah_guest_span(img, rip, &avail);
        if ((u64)(uintptr_t)pc != rip) {
            fprintf(stderr, "SPAN NONIDENT rip=%llx pc=%p avail=%llu\n",
                    (unsigned long long)rip, pc, (unsigned long long)avail);
            for (unsigned i = 0; i < img->nseg; i++) {
                const oah_load_seg *s = &img->segs[i];
                if (rip >= s->gva && rip - s->gva < s->size) {
                    fprintf(stderr, "  seg%u gva=%llx host=%p size=%llx prot=%d\n",
                            i, (unsigned long long)s->gva, s->host,
                            (unsigned long long)s->size, s->prot);
                }
            }
        }
        fprintf(stderr, "frag %llx insns=%u fallback=%u bytes:",
                (unsigned long long)rip, info.insns, info.interp_next);
        for (u64 i = 0; pc && i < avail && i < 8; i++) {
            fprintf(stderr, " %02x", pc[i]);
        }
        fputc('\n', stderr);
        if (trace[0] == '2') {
            for (size_t i = 0; i < buf.size; i += 4) {
                fprintf(stderr, "  %02zu: %02x%02x%02x%02x\n", i / 4,
                        buf.data[i], buf.data[i + 1], buf.data[i + 2],
                        buf.data[i + 3]);
            }
        }
    }
    const oah_frag_entry *frag = jit_install(rip, &info, buf.data, buf.size);
    if (frag && module >= 0) {
        pcache_pend(img, module, rip, buf.data, buf.size, &info);
    }
    oah_asm_buf_destroy(&buf);
    return frag;
}

/* Length in bytes covered by a translated block (for the prewarm scan). */
static u64 in_block_len(oah_image *img, u64 rip, u32 insns)
{
    u64 len = 0;
    u64 cur = rip;
    for (u32 i = 0; i < insns; i++) {
        u64 avail = OAH_X86_MAX_INSN;
        const u8 *pc = oah_guest_span(img, cur, &avail);
        oah_insn in;
        if (!pc || !oah_decode_insn(pc, pc + avail, &in)) {
            break;
        }
        len += in.length;
        cur += in.length;
    }
    return len ? len : 1;
}

/* AOT: scan each executable segment and pretranslate discovered blocks. */
static void jit_prewarm(oah_image *img, const oah_guest *g)
{
    for (unsigned i = 0; i < img->nseg; i++) {
        const oah_load_seg *seg = &img->segs[i];
        if ((seg->prot & (PROT_EXEC | PROT_READ)) != (PROT_EXEC | PROT_READ)) {
            continue;
        }
        for (u64 off = 0; off < seg->size;) {
            u64 rip = seg->gva + off;
            oah_asm_buf buf;
            oah_frag_info info;
            oah_asm_buf_init(&buf);
            if (oah_translate_frag(&buf, img, g, rip, &info) && buf.size) {
                if (buf.size <= jit_arena_size - jit_arena_used) {
                    jit_install(rip, &info, buf.data, buf.size);
                }
                if (seg->module >= 0) {
                    pcache_pend(img, seg->module, rip, buf.data, buf.size,
                                &info);
                }
                /* advance by decoded bytes for coverage without re-decoding */
                off += in_block_len(img, rip, info.insns);
            } else {
                off++;
            }
            oah_asm_buf_destroy(&buf);
        }
    }
    sys_icache_invalidate(jit_arena, jit_arena_used);
}

static oah_interp_result jit_run_cached_inner(oah_guest *g, oah_image *img,
                                              u64 max_insns, bool aot)
{
    oah_interp_result r = {.status = OAH_INTERP_OK, .exit_code = 0, .insns = 0};
    u64 budget = max_insns ? max_insns : OAH_INTERP_MAX_INSNS;
    u64 ctx[24];

    if (!jit_arena_init()) {
        return oah_jit_run_native(g, img, max_insns);
    }
    /* Cached fragments reach &g->xmm via an OAH_RELOC_XMMBASE immediate
     * rebound at materialize time, so SSE translation is safe here. */
    oah_translate_enable_sse(true);
    if (aot) {
        jit_prewarm(img, g);
    }

    /* Differential debug: OAH_JIT_VERIFY runs a reference interpreter
     * alongside and reports the first divergent instruction. */
    oah_guest g_ref;
    bool verify = getenv("OAH_JIT_VERIFY") != NULL;
    bool chain = jit_chain && !getenv("OAH_JIT_NOCHAIN") && !verify;
    if (verify) {
        g_ref = *g;
    }

    while (r.insns < budget) {
        u64 entry_rip = g->rip;
        if (verify && g_ref.rip != g->rip) {
            fprintf(stderr,
                    "JIT drift before frag: jit=%llx ref=%llx\n",
                    (unsigned long long)g->rip,
                    (unsigned long long)g_ref.rip);
        }
        static u64 maxfrags = ~0ull, fragcount = 0;
        if (maxfrags == ~0ull && getenv("OAH_JIT_MAXFRAGS")) {
            maxfrags = strtoull(getenv("OAH_JIT_MAXFRAGS"), NULL, 0);
            fprintf(stderr, "maxfrags=%llu\n", (unsigned long long)maxfrags);
        }
        const oah_frag_entry *frag = jit_lookup(g->rip);
        if (!frag) {
            frag = jit_translate(img, g, g->rip);
            if (!frag) {
                /* Undecodable: let the interpreter run it and report. */
                oah_interp_result one = oah_interp_run(g, img, 1);
                r.insns += one.insns;
                if (verify) {
                    (void)oah_interp_run(&g_ref, img, 1);
                }
                if (one.status != OAH_INTERP_LIMIT) {
                    fprintf(stderr,
                            "jit stop1 status=%d rip=%llx off=%llx\n"
                            " rax=%llx rbx=%llx rcx=%llx rdx=%llx\n"
                            " rsp=%llx rbp=%llx rsi=%llx rdi=%llx\n",
                            one.status, (unsigned long long)g->rip,
                            (unsigned long long)(g->rip - img->interp_base),
                            (unsigned long long)g->gpr[OAH_X86_RAX],
                            (unsigned long long)g->gpr[OAH_X86_RBX],
                            (unsigned long long)g->gpr[OAH_X86_RCX],
                            (unsigned long long)g->gpr[OAH_X86_RDX],
                            (unsigned long long)g->gpr[OAH_X86_RSP],
                            (unsigned long long)g->gpr[OAH_X86_RBP],
                            (unsigned long long)g->gpr[OAH_X86_RSI],
                            (unsigned long long)g->gpr[OAH_X86_RDI]);
                    r.status = one.status;
                    r.exit_code = one.exit_code;
                    return r;
                }
                continue;
            }
        }
        if (fragcount++ >= maxfrags) {
            oah_interp_result one = oah_interp_run(g, img, 1);
            r.insns += one.insns;
            if (one.status != OAH_INTERP_LIMIT) {
                r.status = one.status;
                r.exit_code = one.exit_code;
                return r;
            }
            continue;
        }
        if (chain && !verify && chain_prev) {
            for (u32 i = 0; i < chain_prev->nexits; i++) {
                if (chain_prev->exit_off[i] &&
                    chain_prev->exit_rip[i] == frag->rip) {
                    jit_chain_patch(chain_prev, i, frag->stub_off);
                }
            }
        }
        chain_prev = (oah_frag_entry *)frag;
        oah_pack_runtime_x(ctx, g);
        ctx[16] = g->rflags;
        ctx[17] = g->rip;
        /* Bounded chaining: every native entry runs at most
         * OAH_CHAIN_WINDOW (or the remaining budget) guest insns
         * before returning for accounting and signal polling. */
        chain_ctl.acc = 0;
        u64 room = budget > r.insns ? budget - r.insns : 0;
        chain_ctl.limit = room > OAH_CHAIN_WINDOW ? OAH_CHAIN_WINDOW : room;
        oah_jit_native_enter(ctx, jit_arena + frag->code_off);
        oah_unpack_runtime_x(g, ctx);
        g->rflags = ctx[16];
        g->rip = ctx[17];
        r.insns += frag->insns + chain_ctl.acc;

#if defined(__APPLE__)
        oah_darwin_guest_tick(g);
        oah_sys_status signal_status = oah_guest_signal_poll(g, img);
        if (signal_status != OAH_SYS_CONTINUE) {
            fprintf(stderr,
                    "jit sigstop status=%d rip=%llx off=%llx\n"
                    " rax=%llx rbx=%llx rcx=%llx rdx=%llx\n"
                    " rsp=%llx rbp=%llx rsi=%llx rdi=%llx\n",
                    signal_status, (unsigned long long)g->rip,
                    (unsigned long long)(g->rip - img->interp_base),
                    (unsigned long long)g->gpr[OAH_X86_RAX],
                    (unsigned long long)g->gpr[OAH_X86_RBX],
                    (unsigned long long)g->gpr[OAH_X86_RCX],
                    (unsigned long long)g->gpr[OAH_X86_RDX],
                    (unsigned long long)g->gpr[OAH_X86_RSP],
                    (unsigned long long)g->gpr[OAH_X86_RBP],
                    (unsigned long long)g->gpr[OAH_X86_RSI],
                    (unsigned long long)g->gpr[OAH_X86_RDI]);
            r.status = signal_status == OAH_SYS_EXIT ? OAH_INTERP_EXIT
                                                   : OAH_INTERP_FAULT;
            r.exit_code = (int)(g->gpr[OAH_X86_RDI] & 0xff);
            return r;
        }
#endif
        u64 interp_rip = ctx[17];
        if (frag->flags & OAH_FRAG_FALLBACK) {
            fallback_steps++;
            if (jit_stats) {
                u64 avail = OAH_X86_MAX_INSN;
                const u8 *opc = oah_guest_span(img, interp_rip, &avail);
                oah_insn oin;
                if (opc && oah_decode_insn(opc, opc + avail, &oin) &&
                    oin.op < 64) {
                    stats_ops[oin.op]++;
                    if (oin.op == OAH_OP_SCALAR && oin.scalar < 64) {
                        stats_scalar[oin.scalar]++;
                    }
                }
            }
            oah_interp_result one = oah_interp_run(g, img, 1);
            r.insns += one.insns;
            if (one.status != OAH_INTERP_LIMIT) {
                if (one.status != OAH_INTERP_EXIT || getenv("OAH_STOP_TRACE")) {
                    fprintf(stderr,
                        "jit stop2 status=%d rip=%llx off=%llx\n"
                        " rax=%llx rbx=%llx rcx=%llx rdx=%llx\n"
                        " rsp=%llx rbp=%llx rsi=%llx rdi=%llx\n",
                        one.status, (unsigned long long)g->rip,
                        (unsigned long long)(g->rip - img->interp_base),
                        (unsigned long long)g->gpr[OAH_X86_RAX],
                        (unsigned long long)g->gpr[OAH_X86_RBX],
                        (unsigned long long)g->gpr[OAH_X86_RCX],
                        (unsigned long long)g->gpr[OAH_X86_RDX],
                        (unsigned long long)g->gpr[OAH_X86_RSP],
                        (unsigned long long)g->gpr[OAH_X86_RBP],
                        (unsigned long long)g->gpr[OAH_X86_RSI],
                        (unsigned long long)g->gpr[OAH_X86_RDI]);
                }
                r.status = one.status;
                r.exit_code = one.exit_code;
                return r;
            }
        }

        if (verify) {
            /* RDTSC is non-deterministic — sync timestamp regs afterward. */
            bool skip_tsc = false;
            if (frag->flags & OAH_FRAG_FALLBACK) {
                u64 avail = OAH_X86_MAX_INSN;
                const u8 *pc = oah_guest_span(img, interp_rip, &avail);
                oah_insn in;
                if (pc && oah_decode_insn(pc, pc + avail, &in) &&
                    in.op == OAH_OP_RDTSC) {
                    skip_tsc = true;
                }
            }
            /* Run the reference one insn at a time; compare each step. */
            u64 steps = frag->insns + ((frag->flags & OAH_FRAG_FALLBACK) ? 1 : 0);
            for (u64 s = 0; s < steps; s++) {
                u64 ref_rip = g_ref.rip;
                /* The jit side already executed boundary syscalls; replaying
                 * them would double their side effects. Sync instead. */
                u64 avail = OAH_X86_MAX_INSN;
                const u8 *rpc = oah_guest_span(img, ref_rip, &avail);
                oah_insn rin;
                if (rpc && oah_decode_insn(rpc, rpc + avail, &rin) &&
                    rin.op == OAH_OP_SYSCALL) {
                    g_ref = *g;
                    break;
                }
                oah_interp_result ref = oah_interp_run(&g_ref, img, 1);
                if (ref.status != OAH_INTERP_LIMIT &&
                    ref.status != OAH_INTERP_OK) {
                    fprintf(stderr,
                            "ref-side stop status=%d entry=%llx ref_rip=%llx jit_rip=%llx\n",
                            ref.status, (unsigned long long)entry_rip,
                            (unsigned long long)g_ref.rip,
                            (unsigned long long)g->rip);
                    fprintf(stderr,
                            "ref: rax=%llx rcx=%llx rdi=%llx rsi=%llx\n",
                            (unsigned long long)g_ref.gpr[0],
                            (unsigned long long)g_ref.gpr[1],
                            (unsigned long long)g_ref.gpr[7],
                            (unsigned long long)g_ref.gpr[6]);
                    fprintf(stderr,
                            "jit: rax=%llx rcx=%llx rdi=%llx rsi=%llx\n",
                            (unsigned long long)g->gpr[0],
                            (unsigned long long)g->gpr[1],
                            (unsigned long long)g->gpr[7],
                            (unsigned long long)g->gpr[6]);
                    r.status = ref.status;
                    r.exit_code = ref.exit_code;
                    return r;
                }
                (void)ref_rip;
            }
            if (skip_tsc) {
                g_ref.gpr[OAH_X86_RAX] = g->gpr[OAH_X86_RAX];
                g_ref.gpr[OAH_X86_RDX] = g->gpr[OAH_X86_RDX];
            }
            for (int i = 0; i < 16; i++) {
                if (g->gpr[i] != g_ref.gpr[i] || g->rip != g_ref.rip ||
                    g->rflags != g_ref.rflags) {
                    fprintf(stderr,
                            "JIT divergence @%llx: g%d jit=%llx ref=%llx "
                            "rip jit=%llx ref=%llx flags jit=%llx ref=%llx\n",
                            (unsigned long long)entry_rip, i,
                            (unsigned long long)g->gpr[i],
                            (unsigned long long)g_ref.gpr[i],
                            (unsigned long long)g->rip,
                            (unsigned long long)g_ref.rip,
                            (unsigned long long)g->rflags,
                            (unsigned long long)g_ref.rflags);
                    *g = g_ref;
                    r.status = OAH_INTERP_FAULT;
                    return r;
                }
            }
        }
    }
    r.status = OAH_INTERP_LIMIT;
    return r;
}

oah_interp_result oah_jit_run_cached(oah_guest *g, oah_image *img,
                                     u64 max_insns, bool aot)
{
    static bool env_checked = false;
    if (!env_checked) {
        jit_stats = getenv("OAH_JIT_STATS") != NULL;
        if (jit_stats) {
            stats_fd = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 64);
            atexit(jit_stats_print);
        }
        env_checked = true;
        if (getenv("OAH_JIT_NOCACHE")) {
            jit_persist = false;
        }
        if (getenv("OAH_JIT_CACHE_INFO")) {
            char dir[PATH_MAX];
            fprintf(stderr, "jit cache dir: %s\n",
                    pcache_dir(dir, sizeof(dir)) ? dir : "(unavailable)");
        }
    }
    oah_interp_result r = jit_run_cached_inner(g, img, max_insns, aot);
    stats_insns += r.insns;
    pcache_flush(img);
    /* Worker-bearing guests exit via _Exit in oah_main (skips atexit),
     * so print on terminal status here as well as at normal exit. */
    if (jit_stats && r.status != OAH_INTERP_LIMIT && r.status != OAH_INTERP_OK) {
        jit_stats_print();
    }
    return r;
}

#else /* !(__APPLE__ && __aarch64__) */

oah_interp_result oah_jit_run_cached(oah_guest *g, oah_image *img,
                                     u64 max_insns, bool aot)
{
    (void)aot;
    return oah_jit_run_native(g, img, max_insns);
}

void oah_jit_cache_flush(void)
{
}

#endif /* __APPLE__ && __aarch64__ */
