#include "oah/elf_map.h"
#include "oah/guest.h"
#include "oah/translate.h"

#include "oah/elf_abi.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#if defined(__APPLE__)
#include <limits.h>
#include <mach-o/dyld.h>
#endif

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [--interpret] [--sysroot DIR] <x86_64-elf> [args...]\n", argv0);
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
    if (entries > stack_size / sizeof(u64)) {
        return 0;
    }
#if defined(__APPLE__)
    arc4random_buf(random, sizeof(random));
#else
    if (getentropy(random, sizeof(random)) != 0) {
        return 0;
    }
#endif
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
#if defined(__APPLE__)
    u64 guest_page = OAH_X86_PAGE_SIZE;
#else
    u64 guest_page = (u64)sysconf(_SC_PAGESIZE);
#endif
    const u64 aux[] = {
        AT_PHDR, img->phdr, AT_PHENT, img->phentsize, AT_PHNUM, img->phnum,
        AT_PAGESZ, guest_page, AT_ENTRY, img->entry, AT_BASE, img->interp_base,
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

    bool interpret = false;
    const char *sysroot = NULL;
    const char *exec_path = NULL;
#if defined(__APPLE__)
    size_t exec_env_count = 0;
#endif
    int guest_arg = 1;
    while (guest_arg < argc) {
        const char *option = argv[guest_arg];
        if (strcmp(option, "--interpret") == 0) {
            interpret = true;
            guest_arg++;
        } else if (strcmp(option, "--sysroot") == 0 && guest_arg + 1 < argc) {
            sysroot = argv[guest_arg + 1];
            guest_arg += 2;
#if defined(__APPLE__)
        } else if (strcmp(option, "--guest-exec") == 0 && guest_arg + 2 < argc) {
            exec_path = argv[guest_arg + 1];
            char *end;
            unsigned long count = strtoul(argv[guest_arg + 2], &end, 10);
            if (end == argv[guest_arg + 2] || *end || count >= (unsigned long)argc) {
                return 2;
            }
            exec_env_count = count;
            guest_arg += 3;
#endif
        } else if (strcmp(option, "--") == 0) {
            guest_arg++;
            break;
        } else {
            break;
        }
    }

#if defined(__APPLE__)
    if (exec_path) {
        if (guest_arg >= argc || exec_env_count >= (size_t)(argc - guest_arg)) {
            return 2;
        }
        envp = argv + guest_arg;
        guest_arg += (int)exec_env_count;
        argv[guest_arg++] = NULL;
    }
#endif
    if (argc <= guest_arg) {
        usage(argv[0]);
        return 2;
    }

#if defined(__APPLE__)
    char root[PATH_MAX], executable[PATH_MAX], launcher[PATH_MAX];
    uint32_t executable_size = sizeof(executable);
    if (sysroot && !realpath(sysroot, root)) {
        fprintf(stderr, "oah: cannot resolve sysroot %s (%s)\n", sysroot, strerror(errno));
        return 127;
    }
    if (sysroot) {
        sysroot = root;
    }
#endif
    const char *program = exec_path ? exec_path : argv[guest_arg];
    if (!oah_map_elf_sysroot(&img, program, sysroot)) {
        fprintf(stderr, "oah: cannot load %s (%s)\n", program,
                errno == ENOTSUP ? "dynamic ELF requires --sysroot"
                : errno ? strerror(errno) : "invalid x86-64 ELF");
        return 127;
    }

#if defined(__APPLE__)
    img.interpret = interpret;
    if (_NSGetExecutablePath(executable, &executable_size) == 0 && realpath(executable, launcher)) {
        img.launcher = launcher;
    }
#endif

    rsp = setup_stack(&img, argc - guest_arg, argv + guest_arg, envp);
    if (!rsp) {
        fprintf(stderr, "oah: failed to allocate guest stack\n");
        oah_unmap_elf(&img);
        return 127;
    }

    const u64 instruction_limit = 100000000ull;
    oah_guest_init(&guest, img.interp_entry ? img.interp_entry : img.entry, rsp);
#if defined(__APPLE__)
    run = interpret ? oah_interp_run(&guest, &img, instruction_limit)
                    : oah_jit_run_native(&guest, &img, instruction_limit);
#else
    run = interpret ? oah_jit_run(&guest, &img, instruction_limit)
                    : oah_jit_run_native(&guest, &img, instruction_limit);
#endif

    if (run.status == OAH_INTERP_EXIT) {
        oah_unmap_elf(&img);
        return run.exit_code;
    }
    fprintf(stderr, "oah: guest stopped (%d) after %llu insns rip=%llx",
            (int)run.status, (unsigned long long)run.insns,
            (unsigned long long)guest.rip);
    if (img.interp_mapping &&
        guest.rip - (u64)(uintptr_t)img.interp_mapping < img.interp_mapping_size) {
        fprintf(stderr, " interp+%llx", (unsigned long long)(guest.rip - img.interp_base));
    } else if (guest.rip - img.load_gva < img.load_end - img.load_gva) {
        fprintf(stderr, " image+%llx", (unsigned long long)(guest.rip - img.load_gva));
    }
    if (run.status == OAH_INTERP_DECODE || run.status == OAH_INTERP_FAULT) {
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
