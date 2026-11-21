#include "oah/elf_map.h"
#include "oah/guest.h"
#include "oah/translate.h"

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [--interpret] <x86_64-elf> [args...]\n", argv0);
}

static u64 setup_stack(oah_image *img, int argc, char **argv, char **envp)
{
    const size_t stack_size = 8u << 20;
    u8 random[16];
    size_t envc = 0, bytes = sizeof(random);
    while (envp[envc]) {
        envc++;
    }
    size_t entries = (size_t)argc + envc;
    if (entries > stack_size / sizeof(u64) ||
        getrandom(random, sizeof(random), 0) != sizeof(random)) {
        return 0;
    }
    for (size_t i = 0; i < entries; i++) {
        size_t len = strlen(i < (size_t)argc ? argv[i] : envp[i - argc]) + 1;
        if (len > stack_size - bytes) {
            return 0;
        }
        bytes += len;
    }
    if ((entries + 32) * sizeof(u64) + 15 > stack_size - bytes ||
        img->nseg >= OAH_MAX_LOAD_SEGS) {
        return 0;
    }

    u8 *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        return 0;
    }
    img->segs[img->nseg++] = (oah_load_seg){
        .gva = (u64)(uintptr_t)stack, .size = stack_size,
        .host = stack, .prot = PROT_READ | PROT_WRITE
    };

    u8 *strings = stack + stack_size - bytes;
    memcpy(strings, random, sizeof(random));
    u64 random_addr = (u64)(uintptr_t)strings;
    strings += sizeof(random);
    const u64 aux[] = {
        AT_PHDR, img->phdr, AT_PHENT, img->phentsize, AT_PHNUM, img->phnum,
        AT_PAGESZ, (u64)sysconf(_SC_PAGESIZE), AT_ENTRY, img->entry,
        AT_UID, getuid(), AT_EUID, geteuid(), AT_GID, getgid(), AT_EGID, getegid(),
        AT_SECURE, 0, AT_RANDOM, random_addr, AT_EXECFN, (u64)(uintptr_t)strings,
        AT_NULL, 0
    };
    size_t words = entries + 3 + sizeof(aux) / sizeof(aux[0]);
    u64 *sp = (u64 *)(((uintptr_t)(stack + stack_size - bytes) -
                       words * sizeof(u64)) & ~(uintptr_t)15);
    u64 *slot = sp;
    *slot++ = (u64)argc;
    for (size_t i = 0; i < entries; i++) {
        if (i == (size_t)argc) {
            *slot++ = 0;
        }
        const char *source = i < (size_t)argc ? argv[i] : envp[i - argc];
        size_t len = strlen(source) + 1;
        memcpy(strings, source, len);
        *slot++ = (u64)(uintptr_t)strings;
        strings += len;
    }
    if (!envc) {
        *slot++ = 0;
    }
    *slot++ = 0;
    memcpy(slot, aux, sizeof(aux));
    return (u64)(uintptr_t)sp;
}

int main(int argc, char **argv, char **envp)
{
    oah_image img;
    oah_guest guest;
    oah_interp_result run;
    u64 rsp;

    bool interpret = argc > 1 && strcmp(argv[1], "--interpret") == 0;
    int guest_arg = interpret ? 2 : 1;

    if (argc <= guest_arg) {
        usage(argv[0]);
        return 2;
    }

    if (!oah_map_elf(&img, argv[guest_arg])) {
        fprintf(stderr, "oah: cannot load %s (%s)\n", argv[guest_arg],
                errno == ENOTSUP ? "dynamic ELF is unsupported" : "invalid or unavailable static x86-64 ELF");
        return 127;
    }

    rsp = setup_stack(&img, argc - guest_arg, argv + guest_arg, envp);
    if (!rsp) {
        fprintf(stderr, "oah: failed to allocate guest stack\n");
        oah_unmap_elf(&img);
        return 127;
    }

    oah_guest_init(&guest, img.entry, rsp);
    run = interpret ? oah_jit_run(&guest, &img, OAH_INTERP_MAX_INSNS)
                    : oah_jit_run_native(&guest, &img, OAH_INTERP_MAX_INSNS);

    if (run.status == OAH_INTERP_EXIT) {
        oah_unmap_elf(&img);
        return run.exit_code;
    }
    fprintf(stderr, "oah: guest stopped (%d) after %llu insns rip=%llx",
            (int)run.status, (unsigned long long)run.insns,
            (unsigned long long)guest.rip);
    if (run.status == OAH_INTERP_DECODE) {
        u64 available = 15;
        const u8 *bytes = oah_guest_span(&img, guest.rip, &available);
        if (bytes) {
            fputs(" bytes:", stderr);
            for (u64 i = 0; i < available; i++) {
                fprintf(stderr, " %02x", bytes[i]);
            }
        }
    }
    fputc('\n', stderr);
    oah_unmap_elf(&img);
    return 126;
}
