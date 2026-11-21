#ifndef OAH_ELF_MAP_H
#define OAH_ELF_MAP_H

#include "oah/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OAH_MAX_LOAD_SEGS 128

typedef struct {
    u64 gva;     /* guest virtual address of mapping */
    u64 size;    /* bytes, page-rounded */
    u8 *host;    /* host pointer; identity when MAP_FIXED at gva */
    u32 prot;    /* PROT_* */
} oah_load_seg;

typedef struct {
    oah_load_seg segs[OAH_MAX_LOAD_SEGS];
    unsigned nseg;
    u64 entry;
    u64 phdr;        /* guest VA of program headers */
    u16 phnum;
    u16 phentsize;
    u64 load_end;    /* first byte after last PT_LOAD (for brk) */
    u64 brk;
    int fd;
    u8 *load_mapping;
    u64 load_mapping_size;
    unsigned load_segments;
    u8 *heap_mapping;
    u64 heap_capacity;
    u64 heap_guard;
} oah_image;

/* Load a little-endian x86-64 static ELF and populate its guest mappings.
 * ET_EXEC keeps its linked address; ET_DYN is slid as a single span. */
bool oah_map_elf(oah_image *img, const char *path);
void oah_unmap_elf(oah_image *img);

/* Return up to *len contiguous guest bytes and update *len to their count. */
/* Validate both address range and guest memory permissions. */
void *oah_guest_access(const oah_image *img, u64 gva, u64 len, u32 prot);
const u8 *oah_guest_span(const oah_image *img, u64 gva, u64 *len);

/* Translate a guest pointer; NULL if not in a guest mapping. */
void *oah_guest_to_host(const oah_image *img, u64 gva, u64 len);

#ifdef __cplusplus
}
#endif

#endif /* OAH_ELF_MAP_H */
