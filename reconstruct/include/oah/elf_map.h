#ifndef OAH_ELF_MAP_H
#define OAH_ELF_MAP_H

#include "oah/types.h"

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OAH_MAX_LOAD_SEGS 4096
#define OAH_MAX_MODULES 64
#define OAH_X86_PAGE_SIZE 4096u

/* A mapped guest ELF (executable, interpreter, or guest-mmapped library).
 * Gives persisted JIT fragments a stable identity across runs. */
typedef struct {
    char path[PATH_MAX];  /* host path actually mapped */
    u64 key;              /* stat-based identity hash for cache file naming */
    u64 base;             /* lowest guest VA of the module's segments */
    void *jit_cache;      /* opaque per-module disk-cache index (jit.c) */
    bool jit_cache_tried;
} oah_module;

typedef struct {
    u64 gva;     /* guest virtual address of mapping */
    u64 size;    /* bytes, page-rounded */
    u8 *host;    /* host pointer; identity when MAP_FIXED at gva */
    u32 prot;    /* PROT_* */
    bool file_mapping; /* guest MAP_PRIVATE reservation, replaceable by the loader */
    int module;  /* oah_module index, -1 for anonymous mappings */
#if defined(__APPLE__)
    u8 *allocation; /* One host reservation can back several 4 KiB guest ranges. */
    u64 allocation_size;
#endif
} oah_load_seg;

typedef struct {
    oah_load_seg segs[OAH_MAX_LOAD_SEGS];
    unsigned nseg;
    oah_module modules[OAH_MAX_MODULES];
    unsigned nmodule;
    u64 entry;
    u64 phdr;        /* guest VA of program headers */
    u16 phnum;
    u16 phentsize;
    u64 load_end;    /* first byte after last PT_LOAD (for brk) */
    u64 brk;
    int fd;
    u8 *load_mapping;
    u64 load_mapping_size;
    u64 load_gva;
    u8 *interp_mapping;
    u64 interp_mapping_size;
    u64 interp_entry;
    u64 interp_base;
    const char *sysroot;
#if defined(__APPLE__)
    const char *launcher;
    bool interpret;
    u64 instruction_limit;
#endif
    unsigned load_segments;
    u8 *heap_mapping;
    u64 heap_capacity;
    u64 heap_guard;
    /* Fake root state for writable sysroots: set*id syscalls record the
     * ids the guest asked for so get*id reports the drop took effect. */
    u32 guest_uid[3];   /* real, effective, saved */
    u32 guest_gid[3];
    u32 guest_groups[64];
    int guest_ngroups;
} oah_image;

/* Load a little-endian x86-64 static ELF and populate its guest mappings.
 * ET_EXEC keeps its linked address; ET_DYN is slid as a single span. */
bool oah_map_elf(oah_image *img, const char *path);
bool oah_map_elf_sysroot(oah_image *img, const char *path, const char *sysroot);

/* Module identity for the persistent translation cache. Returns the module
 * index for host_path (registering it on first use) or -1. */
int oah_image_module_register(oah_image *img, const char *host_path);
/* Set .module on all segs overlapping [gva, gva+size). */
void oah_image_tag_module(oah_image *img, u64 gva, u64 size, int module);
/* Module index of the seg containing gva, or -1 for anonymous/none. */
int oah_image_module_at(const oah_image *img, u64 gva);
/* Guest VA of a module-relative offset (base + off). */
u64 oah_module_gva(const oah_image *img, int module, u64 off);
int oah_sysroot_open(const char *sysroot, const char *path, int flags, u32 mode);
bool oah_sysroot_readpath(const char *sysroot, const char *path,
                          char *resolved, size_t capacity);
bool oah_sysroot_hostpath(const char *sysroot, const char *path,
                          char *resolved, size_t capacity);
/* Guest-visible path of the mapped executable ("" before mapping), for
 * the synthesized /proc/self/exe link. */
const char *oah_proc_self_exe(void);
#if defined(__APPLE__)
#define OAH_SCRIPT_DEPTH 4
#define OAH_SCRIPT_PREFIX (2 * OAH_SCRIPT_DEPTH + 1)

typedef struct {
    char executable[PATH_MAX];
    struct {
        char path[PATH_MAX];
        char directive[256];
        char *interpreter;
        char *option;
    } scripts[OAH_SCRIPT_DEPTH];
    unsigned depth;
} oah_darwin_program;

bool oah_darwin_resolve_program(oah_darwin_program *program, const char *sysroot,
                               const char *path, bool guest_exec);
size_t oah_darwin_program_prefix(oah_darwin_program *program, char **argv);
#endif
void oah_unmap_elf(oah_image *img);

/* Return up to *len contiguous guest bytes and update *len to their count. */
/* Validate both address range and guest memory permissions. */
void *oah_guest_access(const oah_image *img, u64 gva, u64 len, u32 prot);
/* While set, PROT_WRITE accesses resolve to a scratch buffer instead of
 * the guest mapping: JIT fault recovery replays a committed range under
 * the interpreter without double-applying its stores. */
extern __thread bool oah_suppress_guest_stores;
const u8 *oah_guest_span(const oah_image *img, u64 gva, u64 *len);

/* Translate a guest pointer; NULL if not in a guest mapping. */
void *oah_guest_to_host(const oah_image *img, u64 gva, u64 len);

#ifdef __cplusplus
}
#endif

#endif /* OAH_ELF_MAP_H */
