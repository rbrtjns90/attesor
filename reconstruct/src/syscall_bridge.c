#include "oah/syscall_bridge.h"
#include "oah/linux_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

/*
 * x86_64 → AArch64 asm-generic numbers for dispatched syscalls.
 * arch_prctl has no ARM equivalent (handled in-process).
 */
u32 oah_x86_syscall_to_host(u32 x86_nr)
{
#if defined(__aarch64__)
    switch (x86_nr) {
    case OAH_X86_NR_READ:       return 63;
    case OAH_X86_NR_WRITE:      return 64;
    case OAH_X86_NR_CLOSE:      return 57;
    case OAH_X86_NR_BRK:        return 214;
    case OAH_X86_NR_EXIT:       return 93;
    case OAH_X86_NR_UNAME:      return 160;
    case OAH_X86_NR_EXIT_GROUP: return 94;
    case OAH_X86_NR_OPENAT:     return 56;
    case OAH_X86_NR_GETRANDOM:  return 278;
    default:                    return (u32)-1;
    }
#else
    /* Host already uses the x86_64 numbering. */
    return x86_nr;
#endif
}

static u64 set_errno_ret(s64 rc)
{
    if (rc < 0) {
        return (u64)(s64)(-errno);
    }
    return (u64)rc;
}

static const char *guest_path(const oah_image *img, u64 addr)
{
    u64 count = 4096;
    const u8 *bytes = oah_guest_span(img, addr, &count);
    return bytes && oah_guest_access(img, addr, count, PROT_READ) &&
           memchr(bytes, 0, count) ? (const char *)bytes : NULL;
}

static u64 guest_brk(oah_image *img, u64 addr)
{
    if (!img || !addr || addr < img->load_end || addr - img->load_end > (64u << 20)) {
        return img ? img->brk : 0;
    }
    u64 page = (u64)sysconf(_SC_PAGESIZE);
    u64 mask = page - 1;
    u64 old = (img->brk - img->load_end + mask) & ~mask;
    u64 end = (addr - img->load_end + mask) & ~mask;
    if (!img->heap_mapping && end != 0) {
        u64 capacity = 64u << 20;
        void *address = (void *)(uintptr_t)img->load_end;
        void *heap = mmap(address, capacity, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (heap != address) {
            if (heap != MAP_FAILED) {
                munmap(heap, capacity);
            }
            return img->brk;
        }
        img->heap_mapping = heap;
        img->heap_capacity = capacity;
    }
    unsigned index = img->load_segments;
    while (index < img->nseg && img->segs[index].gva != img->load_end + img->heap_guard) {
        index++;
    }
    if (end < img->heap_guard || (end > img->heap_guard && index == OAH_MAX_LOAD_SEGS)) {
        return img->brk;
    }
    if (end > old &&
        mprotect(img->heap_mapping + old, end - old, PROT_READ | PROT_WRITE) != 0) {
        return img->brk;
    }
    if (end < old) {
        if (mprotect(img->heap_mapping + end, old - end, PROT_NONE) != 0) {
            return img->brk;
        }
        madvise(img->heap_mapping + end, old - end, MADV_DONTNEED);
    }
    if (end > img->heap_guard) {
        if (index == img->nseg) {
            img->nseg++;
        }
        img->segs[index] = (oah_load_seg){
            .gva = img->load_end + img->heap_guard, .size = end - img->heap_guard,
            .host = img->heap_mapping + img->heap_guard, .prot = PROT_READ | PROT_WRITE
        };
    } else if (index < img->nseg) {
        img->segs[index] = img->segs[--img->nseg];
    }
    img->brk = addr;
    return addr;
}

static u64 guest_mmap(oah_image *img, u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    u64 page = (u64)sysconf(_SC_PAGESIZE);
    if (!len || len > (1ull << 30) || (prot & ~7ull) ||
        (flags != 0x22 && flags != 0x32) || fd != UINT64_MAX || off != 0) {
        return (u64)(s64)-EINVAL;
    }
    len = (len + page - 1) & ~(page - 1);
    if (flags == 0x32) {
        /* musl reserves a guard page at the start of its own brk arena. */
        if (addr != img->load_end || len != page || prot || img->heap_guard ||
            !img->heap_mapping || img->brk - img->load_end <= page) {
            return (u64)(s64)-EINVAL;
        }
        for (unsigned i = img->load_segments; i < img->nseg; i++) {
            oah_load_seg *seg = &img->segs[i];
            if (seg->gva == addr) {
                if (mprotect(seg->host, page, PROT_NONE) != 0) {
                    return set_errno_ret(-1);
                }
                madvise(seg->host, page, MADV_DONTNEED);
                seg->gva += page;
                seg->host += page;
                seg->size -= page;
                img->heap_guard = page;
                return addr;
            }
        }
        return (u64)(s64)-EINVAL;
    }
    if (img->nseg == OAH_MAX_LOAD_SEGS) {
        return (u64)(s64)-ENOMEM;
    }
    void *ptr = mmap(NULL, len, (int)prot & ~PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        return set_errno_ret(-1);
    }
    img->segs[img->nseg++] = (oah_load_seg){
        .gva = (u64)(uintptr_t)ptr, .host = ptr, .size = len, .prot = (u32)prot
    };
    return (u64)(uintptr_t)ptr;
}

static s64 guest_memory_change(oah_image *img, u64 addr, u64 len, u64 prot, bool unmap)
{
    u64 page = (u64)sysconf(_SC_PAGESIZE);
    if (!len || len > UINT64_MAX - page || (prot & ~7ull)) {
        return -EINVAL;
    }
    len = (len + page - 1) & ~(page - 1);
    unsigned first = unmap ? img->load_segments : 0;
    for (unsigned i = first; i < img->nseg; i++) {
        oah_load_seg *seg = &img->segs[i];
        if (seg->gva != addr || seg->size != len) {
            continue;
        }
        if (unmap) {
            if (img->heap_mapping && addr - img->load_end < img->heap_capacity) {
                return -EINVAL;
            }
            if (munmap(seg->host, len) != 0) {
                return -errno;
            }
            *seg = img->segs[--img->nseg];
        } else {
            if (mprotect(seg->host, len, (int)prot & ~PROT_EXEC) != 0) {
                return -errno;
            }
            seg->prot = (u32)prot;
        }
        return 0;
    }
    return -EINVAL;
}

oah_sys_status oah_guest_syscall(oah_guest *g, oah_image *img)
{
    u64 nr = g->gpr[OAH_X86_RAX];
    u64 a0 = g->gpr[OAH_X86_RDI];
    u64 a1 = g->gpr[OAH_X86_RSI];
    u64 a2 = g->gpr[OAH_X86_RDX];
    u64 a3 = g->gpr[OAH_X86_R10];
    u64 a4 = g->gpr[OAH_X86_R8];
    u64 a5 = g->gpr[OAH_X86_R9];
    u32 host_nr;
    long rc;

    /* SYSCALL: RCX = rip (return), R11 = RFLAGS. */
    g->gpr[OAH_X86_RCX] = g->rip;
    g->gpr[OAH_X86_R11] = g->rflags;

    switch (nr) {
    case OAH_X86_NR_EXIT:
    case OAH_X86_NR_EXIT_GROUP:
        return OAH_SYS_EXIT;

    case OAH_X86_NR_BRK:
        g->gpr[OAH_X86_RAX] = guest_brk(img, a0);
        return OAH_SYS_CONTINUE;
    case 9: /* mmap */
        g->gpr[OAH_X86_RAX] = img ? guest_mmap(img, a0, a1, a2, a3, a4, a5) : (u64)(s64)-EINVAL;
        return OAH_SYS_CONTINUE;
    case 10: /* mprotect */
    case 11: /* munmap */
        g->gpr[OAH_X86_RAX] = img ? (u64)guest_memory_change(img, a0, a1,
                                      nr == 11 ? 0 : a2, nr == 11) : (u64)(s64)-EINVAL;
        return OAH_SYS_CONTINUE;
    case 102: /* getuid */
        g->gpr[OAH_X86_RAX] = getuid();
        return OAH_SYS_CONTINUE;
    case 104: /* getgid */
        g->gpr[OAH_X86_RAX] = getgid();
        return OAH_SYS_CONTINUE;
    case 107: /* geteuid */
        g->gpr[OAH_X86_RAX] = geteuid();
        return OAH_SYS_CONTINUE;
    case 108: /* getegid */
        g->gpr[OAH_X86_RAX] = getegid();
        return OAH_SYS_CONTINUE;
    case 218: /* set_tid_address */
        g->gpr[OAH_X86_RAX] = !a0 || oah_guest_access(img, a0, 4, PROT_WRITE)
                            ? (u64)getpid() : (u64)(s64)-EFAULT;
        return OAH_SYS_CONTINUE;
    case 2: { /* open */
        const char *path = guest_path(img, a0);
        u32 flags = (u32)a1;
#if defined(__aarch64__)
        flags = oah_translate_open_flags(flags);
#endif
        g->gpr[OAH_X86_RAX] = path ? set_errno_ret(open(path, (int)flags, (mode_t)a2))
                                  : (u64)(s64)-EFAULT;
        return OAH_SYS_CONTINUE;
    }
    case 40: { /* sendfile */
        off_t *offset = a2 ? oah_guest_access(img, a2, sizeof(*offset), PROT_READ | PROT_WRITE) : NULL;
        g->gpr[OAH_X86_RAX] = a2 && !offset ? (u64)(s64)-EFAULT
                              : set_errno_ret(sendfile((int)a0, (int)a1, offset, (size_t)a3));
        return OAH_SYS_CONTINUE;
    }
    case 16: { /* ioctl, terminal geometry only */
        struct winsize *size = oah_guest_access(img, a2, sizeof(*size), PROT_WRITE);
        g->gpr[OAH_X86_RAX] = a1 != 0x5413 ? (u64)(s64)-ENOTTY
                            : !size ? (u64)(s64)-EFAULT
                            : set_errno_ret(ioctl((int)a0, TIOCGWINSZ, size));
        return OAH_SYS_CONTINUE;
    }
    case 20: { /* writev */
        struct { u64 base, len; } guest_iov;
        struct iovec iov[1024];
        if (a2 > sizeof(iov) / sizeof(iov[0])) {
            g->gpr[OAH_X86_RAX] = (u64)(s64)-EINVAL;
            return OAH_SYS_CONTINUE;
        }
        const u8 *array = oah_guest_access(img, a1, a2 * sizeof(guest_iov), PROT_READ);
        if (a2 && !array) {
            g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
            return OAH_SYS_CONTINUE;
        }
        for (u64 i = 0; i < a2; i++) {
            memcpy(&guest_iov, array + i * sizeof(guest_iov), sizeof(guest_iov));
            iov[i].iov_len = guest_iov.len;
            iov[i].iov_base = oah_guest_access(img, guest_iov.base, guest_iov.len, PROT_READ);
            if (guest_iov.len && !iov[i].iov_base) {
                g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
                return OAH_SYS_CONTINUE;
            }
        }
        g->gpr[OAH_X86_RAX] = set_errno_ret(writev((int)a0, iov, (int)a2));
        return OAH_SYS_CONTINUE;
    }

    case OAH_X86_NR_ARCH_PRCTL:
        if (a0 == OAH_ARCH_SET_FS) {
            g->fs_base = a1;
            g->gpr[OAH_X86_RAX] = 0;
        } else if (a0 == OAH_ARCH_GET_FS) {
            void *out = oah_guest_access(img, a1, 8, PROT_WRITE);
            if (!out) {
                g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
            } else {
                memcpy(out, &g->fs_base, sizeof(g->fs_base));
                g->gpr[OAH_X86_RAX] = 0;
            }
        } else {
            g->gpr[OAH_X86_RAX] = (u64)(s64)-EINVAL;
        }
        return OAH_SYS_CONTINUE;

    case OAH_X86_NR_WRITE:
    case OAH_X86_NR_READ: {
        void *buf = oah_guest_access(img, a1, a2, nr == OAH_X86_NR_READ ? PROT_WRITE : PROT_READ);
        if (a2 != 0 && !buf) {
            g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
            return OAH_SYS_CONTINUE;
        }
        host_nr = oah_x86_syscall_to_host((u32)nr);
        errno = 0;
        rc = syscall((long)host_nr, (long)a0, buf, (long)a2);
        g->gpr[OAH_X86_RAX] = set_errno_ret(rc);
        return OAH_SYS_CONTINUE;
    }

    case OAH_X86_NR_UNAME: {
        struct utsname *un = oah_guest_access(img, a0, sizeof(*un), PROT_WRITE);
        if (!un) {
            g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
            return OAH_SYS_CONTINUE;
        }
        host_nr = oah_x86_syscall_to_host((u32)nr);
        errno = 0;
        rc = syscall((long)host_nr, un);
        g->gpr[OAH_X86_RAX] = set_errno_ret(rc);
        return OAH_SYS_CONTINUE;
    }

    case OAH_X86_NR_CLOSE:
    case OAH_X86_NR_GETRANDOM:
    case OAH_X86_NR_OPENAT:
        host_nr = oah_x86_syscall_to_host((u32)nr);
        if (host_nr == (u32)-1) {
            g->gpr[OAH_X86_RAX] = (u64)(s64)-ENOSYS;
            return OAH_SYS_CONTINUE;
        }
        if (nr == OAH_X86_NR_OPENAT) {
            const char *path = guest_path(img, a1);
            u32 flags = (u32)a2;
            if (!path) {
                g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
                return OAH_SYS_CONTINUE;
            }
#if defined(__aarch64__)
            flags = oah_translate_open_flags(flags);
#endif
            errno = 0;
            rc = syscall((long)host_nr, (long)a0, path, (long)flags, (long)a3);
        } else if (nr == OAH_X86_NR_GETRANDOM) {
            void *buf = oah_guest_access(img, a0, a1, PROT_WRITE);
            if (a1 != 0 && !buf) {
                g->gpr[OAH_X86_RAX] = (u64)(s64)-EFAULT;
                return OAH_SYS_CONTINUE;
            }
            errno = 0;
            rc = syscall((long)host_nr, buf, (long)a1, (long)a2);
        } else {
            errno = 0;
            rc = syscall((long)host_nr, (long)a0, (long)a1, (long)a2,
                         (long)a3, (long)a4, (long)a5);
        }
        g->gpr[OAH_X86_RAX] = set_errno_ret(rc);
        return OAH_SYS_CONTINUE;

    default:
        if (getenv("OAH_TRACE_UNSUPPORTED")) {
            fprintf(stderr, "oah: unsupported syscall %llu at rip=%llx\n",
                    (unsigned long long)nr, (unsigned long long)(g->rip - 2));
        }
        g->gpr[OAH_X86_RAX] = (u64)(s64)-ENOSYS;
        return OAH_SYS_CONTINUE;
    }
}
