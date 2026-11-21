#include "oah/syscall_bridge.h"
#include "oah/linux_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
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

/* Linux x86-64 kernel struct stat, independent of the host libc layout. */
typedef struct {
    u64 dev, ino, nlink;
    u32 mode, uid, gid, pad;
    u64 rdev;
    s64 size, blksize, blocks;
    s64 atime_sec, atime_nsec, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec;
    s64 reserved[3];
} x86_stat;

_Static_assert(sizeof(x86_stat) == 144, "x86-64 Linux stat layout");

static s64 guest_fstat(const oah_image *img, int fd, u64 address)
{
    void *output = oah_guest_access(img, address, sizeof(x86_stat), PROT_WRITE);
    struct stat st;
    if (!output) {
        return -EFAULT;
    }
    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    x86_stat converted = {
        .dev = st.st_dev, .ino = st.st_ino, .nlink = st.st_nlink, .mode = st.st_mode,
        .uid = st.st_uid, .gid = st.st_gid, .rdev = st.st_rdev, .size = st.st_size,
        .blksize = st.st_blksize, .blocks = st.st_blocks,
        .atime_sec = st.st_atim.tv_sec, .atime_nsec = st.st_atim.tv_nsec,
        .mtime_sec = st.st_mtim.tv_sec, .mtime_nsec = st.st_mtim.tv_nsec,
        .ctime_sec = st.st_ctim.tv_sec, .ctime_nsec = st.st_ctim.tv_nsec
    };
    memcpy(output, &converted, sizeof(converted));
    return 0;
}

static const char *guest_path(const oah_image *img, u64 addr)
{
    u64 count = 4096;
    const u8 *bytes = oah_guest_span(img, addr, &count);
    return bytes && oah_guest_access(img, addr, count, PROT_READ) &&
           memchr(bytes, 0, count) ? (const char *)bytes : NULL;
}

static int open_guest_path(const oah_image *img, int dirfd, const char *path,
                           int flags, u32 mode)
{
    if (img->sysroot && (strncmp(path, "/lib/", 5) == 0 ||
        strncmp(path, "/lib64/", 7) == 0 || strncmp(path, "/usr/lib/", 9) == 0 ||
        strncmp(path, "/usr/lib64/", 11) == 0 || strncmp(path, "/etc/ld.", 8) == 0 ||
        strncmp(path, "/etc/ld-musl-", 13) == 0)) {
        if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC))) {
            errno = EROFS;
            return -1;
        }
        return oah_sysroot_open(img->sysroot, path, flags, mode);
    }
    return openat(dirfd, path, flags, mode);
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

static void split_mapping(oah_image *img, unsigned i, u64 addr, u64 len, u32 prot)
{
    oah_load_seg *seg = &img->segs[i];
    oah_load_seg original = *seg;
    u64 left = addr - seg->gva;
    u64 right = seg->size - left - len;
    u8 *host = seg->host + left;
    unsigned extra = (left != 0) + (right != 0);
    memmove(seg + 1 + extra, seg + 1, (img->nseg - i - 1) * sizeof(*seg));
    if (left) {
        *seg = original;
        seg->size = left;
        seg++;
    }
    *seg++ = (oah_load_seg){addr, len, host, prot, original.file_mapping};
    if (right) {
        *seg = (oah_load_seg){addr + len, right, host + len, original.prot, original.file_mapping};
    }
    img->nseg += extra;
    if (i < img->load_segments) {
        img->load_segments += extra;
    }
}

static u64 guest_file_mmap(oah_image *img, u64 addr, u64 len, u32 prot,
                           bool fixed, int fd, u64 offset)
{
    long page = sysconf(_SC_PAGESIZE);
    struct stat st;
    unsigned index = img->nseg;
    if ((offset & (page - 1)) || offset > INT64_MAX) {
        return (u64)(s64)-EINVAL;
    }
    if (fstat(fd, &st) != 0) {
        return set_errno_ret(-1);
    }
    if (!S_ISREG(st.st_mode)) {
        return (u64)(s64)-ENODEV;
    }
    if (fixed) {
        if (addr & (page - 1)) {
            return (u64)(s64)-EINVAL;
        }
        for (unsigned i = img->load_segments; i < img->nseg; i++) {
            const oah_load_seg *seg = &img->segs[i];
            if (seg->file_mapping && addr >= seg->gva && addr - seg->gva < seg->size &&
                len <= seg->size - (addr - seg->gva)) {
                unsigned extra = (addr != seg->gva) + (len != seg->size - (addr - seg->gva));
                if (extra > OAH_MAX_LOAD_SEGS - img->nseg) {
                    return (u64)(s64)-ENOMEM;
                }
                index = i;
                break;
            }
        }
        if (index == img->nseg) {
            return (u64)(s64)-EINVAL;
        }
    } else if (img->nseg == OAH_MAX_LOAD_SEGS) {
        return (u64)(s64)-ENOMEM;
    }

    u8 *staged = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (staged == MAP_FAILED) {
        return set_errno_ret(-1);
    }
    u64 bytes = offset < (u64)st.st_size ? (u64)st.st_size - offset : 0;
    if (bytes > len) {
        bytes = len;
    }
    for (u64 pos = 0; pos < bytes;) {
        ssize_t count = pread(fd, staged + pos, bytes - pos, (off_t)(offset + pos));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            int error = errno;
            munmap(staged, len);
            return (u64)(s64)-error;
        }
        if (!count) {
            break;
        }
        pos += (u64)count;
    }
    if (mprotect(staged, len, (int)prot & ~PROT_EXEC) != 0) {
        int error = errno;
        munmap(staged, len);
        return (u64)(s64)-error;
    }
    if (fixed) {
        if (mremap(staged, len, len, MREMAP_MAYMOVE | MREMAP_FIXED,
                   (void *)(uintptr_t)addr) == MAP_FAILED) {
            int error = errno;
            munmap(staged, len);
            return (u64)(s64)-error;
        }
        split_mapping(img, index, addr, len, prot);
        return addr;
    }
    img->segs[img->nseg++] = (oah_load_seg){
        .gva = (u64)(uintptr_t)staged, .size = len, .host = staged,
        .prot = prot, .file_mapping = true
    };
    return (u64)(uintptr_t)staged;
}

static u64 guest_mmap(oah_image *img, u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    u64 page = (u64)sysconf(_SC_PAGESIZE);
    if (!len || len > (1ull << 30) || (prot & ~7ull)) {
        return (u64)(s64)-EINVAL;
    }
    len = (len + page - 1) & ~(page - 1);
    if (flags == 0x02 || flags == 0x12) {
        return guest_file_mmap(img, addr, len, (u32)prot, flags == 0x12, (int)fd, off);
    }
    if ((flags != 0x22 && flags != 0x32) || (int)fd != -1 || off != 0) {
        return (u64)(s64)-EINVAL;
    }
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
        if (addr < seg->gva || addr - seg->gva >= seg->size ||
            len > seg->size - (addr - seg->gva) || (addr & (page - 1))) {
            continue;
        }
        u64 left = addr - seg->gva;
        u64 right = seg->size - left - len;
        if (unmap) {
            if (left || right ||
                (img->heap_mapping && addr - img->load_end < img->heap_capacity)) {
                return -EINVAL;
            }
            if (munmap(seg->host, len) != 0) {
                return -errno;
            }
            *seg = img->segs[--img->nseg];
        } else {
            /* Preserve the original range and its ownership on either side. */
            unsigned extra = (left != 0) + (right != 0);
            if (extra > OAH_MAX_LOAD_SEGS - img->nseg) {
                return -ENOMEM;
            }
            u8 *host = seg->host + left;
            if (mprotect(host, len, (int)prot & ~PROT_EXEC) != 0) {
                return -errno;
            }
            split_mapping(img, i, addr, len, (u32)prot);
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
    case 5: /* fstat */
        g->gpr[OAH_X86_RAX] = (u64)guest_fstat(img, (int)a0, a1);
        return OAH_SYS_CONTINUE;
    case 72: /* fcntl, descriptor flags */
        g->gpr[OAH_X86_RAX] = a1 == F_GETFD || a1 == F_SETFD
                            ? set_errno_ret(fcntl((int)a0, (int)a1, (int)a2))
                            : (u64)(s64)-EINVAL;
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
        g->gpr[OAH_X86_RAX] = path ? set_errno_ret(open_guest_path(img, AT_FDCWD, path, (int)flags, (u32)a2))
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
            rc = open_guest_path(img, (int)a0, path, (int)flags, (u32)a3);
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
