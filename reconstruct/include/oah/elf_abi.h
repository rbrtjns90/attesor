#ifndef OAH_ELF_ABI_H
#define OAH_ELF_ABI_H

#if defined(__linux__)
#include <elf.h>
#else
#include "oah/types.h"

/* ELF64 disk layouts and Linux auxiliary vector tags used by the loader. */
enum {
    EI_CLASS = 4, EI_DATA = 5, ELFCLASS64 = 2, ELFDATA2LSB = 1,
    SELFMAG = 4, EV_CURRENT = 1, EM_X86_64 = 62,
    ET_EXEC = 2, ET_DYN = 3, PT_LOAD = 1, PT_INTERP = 3,
    PF_X = 1, PF_W = 2, PF_R = 4,
    AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5,
    AT_PAGESZ = 6, AT_BASE = 7, AT_ENTRY = 9, AT_UID = 11,
    AT_EUID = 12, AT_GID = 13, AT_EGID = 14, AT_SECURE = 23,
    AT_RANDOM = 25, AT_EXECFN = 31
};
#define ELFMAG "\177ELF"

typedef struct {
    u8 e_ident[16];
    u16 e_type, e_machine;
    u32 e_version;
    u64 e_entry, e_phoff, e_shoff;
    u32 e_flags;
    u16 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    u32 p_type, p_flags;
    u64 p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;

_Static_assert(sizeof(Elf64_Ehdr) == 64, "ELF64 file header layout");
_Static_assert(sizeof(Elf64_Phdr) == 56, "ELF64 program header layout");
#endif

#endif
