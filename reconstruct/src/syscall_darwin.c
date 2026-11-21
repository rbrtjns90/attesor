#include "oah/syscall_bridge.h"
#include "oah/elf_abi.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/* x86-64 Linux error numbers that differ from Darwin's. */
enum {
    LINUX_EAGAIN = 11, LINUX_EDEADLK = 35, LINUX_ENAMETOOLONG = 36,
    LINUX_ENOSYS = 38, LINUX_ENOTEMPTY = 39, LINUX_ELOOP = 40,
    LINUX_EOVERFLOW = 75, LINUX_ENOTSOCK = 88, LINUX_EPROTOTYPE = 91,
    LINUX_EPROTONOSUPPORT = 93, LINUX_ESOCKTNOSUPPORT = 94, LINUX_EOPNOTSUPP = 95,
    LINUX_EAFNOSUPPORT = 97, LINUX_ENOTCONN = 107, LINUX_ETIMEDOUT = 110
};

static s64 linux_error(int error)
{
    switch (error) {
    case EAGAIN: return -LINUX_EAGAIN;
    case EDEADLK: return -LINUX_EDEADLK;
    case ENAMETOOLONG: return -LINUX_ENAMETOOLONG;
    case ENOSYS: return -LINUX_ENOSYS;
    case ENOTEMPTY: return -LINUX_ENOTEMPTY;
    case ELOOP: return -LINUX_ELOOP;
    case EOVERFLOW: return -LINUX_EOVERFLOW;
    case ENOTSUP:
    case EOPNOTSUPP: return -LINUX_EOPNOTSUPP;
    case ENOTSOCK: return -LINUX_ENOTSOCK;
    case EPROTOTYPE: return -LINUX_EPROTOTYPE;
    case EPROTONOSUPPORT: return -LINUX_EPROTONOSUPPORT;
    case ESOCKTNOSUPPORT: return -LINUX_ESOCKTNOSUPPORT;
    case EAFNOSUPPORT: return -LINUX_EAFNOSUPPORT;
    case ENOTCONN: return -LINUX_ENOTCONN;
    case ETIMEDOUT: return -LINUX_ETIMEDOUT;
    default:
        /* The POSIX errors through ERANGE share numbers except those above. */
        return error > 0 && error <= ERANGE ? -error : -EIO;
    }
}

static s64 host_result(s64 result)
{
    return result == -1 ? linux_error(errno) : result;
}

static volatile sig_atomic_t host_alarm_pending;
static volatile sig_atomic_t host_child_pending;
static bool signal_handlers_installed;
static bool posix_timer_created;

typedef struct guest_child {
    pid_t pid;
    struct guest_child *next;
} guest_child;

static guest_child *children;

static void record_signal(int signal)
{
    if (signal == SIGALRM) {
        host_alarm_pending = 1;
    } else if (signal == SIGCHLD) {
        host_child_pending = 1;
    }
}

static void bridged_signal_set(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGALRM);
    sigaddset(set, SIGCHLD);
}

static int install_signal_handlers(void)
{
    if (!signal_handlers_installed) {
        struct sigaction action = {.sa_handler = record_signal};
        bridged_signal_set(&action.sa_mask);
        if (sigaction(SIGALRM, &action, NULL) < 0 ||
            sigaction(SIGCHLD, &action, NULL) < 0) {
            return -1;
        }
        signal_handlers_installed = true;
    }
    return 0;
}

u64 oah_darwin_pending_signals(void)
{
    if (!host_alarm_pending && !host_child_pending) {
        return 0;
    }
    sigset_t blocked, previous;
    bridged_signal_set(&blocked);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) < 0) {
        return 0;
    }
    u64 pending = (host_alarm_pending ? 1ull << 13 : 0) |
                  (host_child_pending ? 1ull << 16 : 0);
    host_alarm_pending = host_child_pending = 0;
    sigprocmask(SIG_SETMASK, &previous, NULL);
    return pending;
}

s64 oah_darwin_wait_signal(void)
{
    sigset_t blocked, previous;
    bridged_signal_set(&blocked);
    if (install_signal_handlers() < 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) < 0) {
        return linux_error(errno);
    }
    if (!host_alarm_pending && !host_child_pending) {
        sigset_t waiting = previous;
        sigdelset(&waiting, SIGALRM);
        sigdelset(&waiting, SIGCHLD);
        sigsuspend(&waiting);
    }
    sigprocmask(SIG_SETMASK, &previous, NULL);
    return 0;
}

static guest_child **child_link(pid_t pid)
{
    guest_child **link = &children;
    while (*link && (*link)->pid != pid) {
        link = &(*link)->next;
    }
    return link;
}

static void forget_child(pid_t pid)
{
    guest_child **link = child_link(pid);
    if (*link) {
        guest_child *entry = *link;
        *link = entry->next;
        free(entry);
    }
}

static s64 guest_fork(void)
{
    if (install_signal_handlers() < 0) {
        return linux_error(errno);
    }
    guest_child *entry = malloc(sizeof(*entry));
    if (!entry) {
        return -ENOMEM;
    }
    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        free(entry);
        return linux_error(error);
    }
    if (!pid) {
        free(entry);
        while (children) {
            forget_child(children->pid);
        }
        host_alarm_pending = host_child_pending = 0;
        posix_timer_created = false;
    } else {
        *entry = (guest_child){pid, children};
        children = entry;
    }
    return pid;
}

static s64 guest_kill_children(oah_guest *g, pid_t target, u64 number)
{
    int signal;
    switch (number) {
    case 0: signal = 0; break;
    case 1: signal = SIGHUP; break;
    case 2: signal = SIGINT; break;
    case 3: signal = SIGQUIT; break;
    case 9: signal = SIGKILL; break;
    case 15: signal = SIGTERM; break;
    case 18: signal = SIGCONT; break;
    default: return number > 64 ? -EINVAL : -LINUX_EOPNOTSUPP;
    }
    if (target > 0) {
        return *child_link(target) ? host_result(kill(target, signal)) : -ESRCH;
    }
    pid_t group = target == 0 ? getpgrp() : target == -1 ? 0 : (pid_t)-(s64)target;
    s64 result = -ESRCH;
    if (group && group == getpgrp()) {
        if (number) {
            g->pending_signals |= 1ull << (number - 1);
        }
        result = 0;
    }
    for (guest_child *entry = children; entry; entry = entry->next) {
        if (!group || getpgid(entry->pid) == group) {
            if (kill(entry->pid, signal) == 0) {
                result = 0;
            } else if (result) {
                result = linux_error(errno);
            }
        }
    }
    return result;
}

typedef struct {
    s64 sec, nsec;
} linux_timespec;

typedef struct {
    linux_timespec interval, value;
} linux_itimerspec;

static bool timer_timeval(linux_timespec input, struct timeval *out)
{
    if (input.sec < 0 || input.nsec < 0 || input.nsec >= 1000000000L) {
        return false;
    }
    s64 usec = (input.nsec + 999) / 1000;
    if (usec == 1000000 && input.sec == INT64_MAX) {
        return false;
    }
    out->tv_sec = input.sec + usec / 1000000;
    out->tv_usec = (suseconds_t)(usec % 1000000);
    return true;
}

static s64 guest_timer_create(oah_image *img, u64 clock, u64 event, u64 id)
{
    void *output = oah_guest_access(img, id, sizeof(s32), PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    if (event) {
        s32 header[4];
        const void *input = oah_guest_access(img, event, sizeof(header), PROT_READ);
        if (!input) {
            return -EFAULT;
        }
        memcpy(header, input, sizeof(header));
        if (header[2] != 14 || header[3] != 0) {
            return -LINUX_EOPNOTSUPP;
        }
    }
    if (clock > 1) {
        return -LINUX_EOPNOTSUPP;
    }
    if (posix_timer_created) {
        return -LINUX_EAGAIN;
    }
    if (install_signal_handlers() < 0) {
        return linux_error(errno);
    }
    const s32 timer_id = 0;
    memcpy(output, &timer_id, sizeof(timer_id));
    posix_timer_created = true;
    return 0;
}

static linux_itimerspec linux_timer_value(const struct itimerval *timer)
{
    return (linux_itimerspec){
        {timer->it_interval.tv_sec, (s64)timer->it_interval.tv_usec * 1000},
        {timer->it_value.tv_sec, (s64)timer->it_value.tv_usec * 1000}
    };
}

static s64 guest_timer_set(oah_image *img, u64 id, u64 flags, u64 value, u64 old)
{
    if (id || !posix_timer_created) {
        return -EINVAL;
    }
    if (flags) {
        return -LINUX_EOPNOTSUPP;
    }
    linux_itimerspec request;
    const void *input = oah_guest_access(img, value, sizeof(request), PROT_READ);
    void *output = old ? oah_guest_access(img, old, sizeof(request), PROT_WRITE) : NULL;
    if (!input || (old && !output)) {
        return -EFAULT;
    }
    memcpy(&request, input, sizeof(request));
    struct itimerval timer, previous;
    if (!timer_timeval(request.value, &timer.it_value) ||
        !timer_timeval(request.interval, &timer.it_interval)) {
        return -EINVAL;
    }
    if (setitimer(ITIMER_REAL, &timer, &previous) < 0) {
        return linux_error(errno);
    }
    if (output) {
        linux_itimerspec old_timer = linux_timer_value(&previous);
        memcpy(output, &old_timer, sizeof(old_timer));
    }
    return 0;
}

static const char *guest_path(oah_image *img, u64 addr)
{
    u64 available = 4096;
    const u8 *bytes = oah_guest_span(img, addr, &available);
    return bytes && memchr(bytes, 0, available) ? (const char *)bytes : NULL;
}

static bool sysroot_path(const oah_image *img, const char *path)
{
    return img->sysroot && (strncmp(path, "/lib/", 5) == 0 ||
           strncmp(path, "/lib64/", 7) == 0 || strncmp(path, "/usr/lib/", 9) == 0 ||
           strncmp(path, "/usr/lib64/", 11) == 0 || strncmp(path, "/usr/libexec/", 13) == 0 || strncmp(path, "/etc/ld.", 8) == 0 ||
           strncmp(path, "/etc/ld-musl-", 13) == 0);
}

static int open_guest_path(oah_image *img, int dirfd, const char *path, int host_flags, u64 mode)
{
    if (sysroot_path(img, path)) {
        if ((host_flags & O_ACCMODE) != O_RDONLY || (host_flags & (O_CREAT | O_TRUNC))) {
            errno = EROFS;
            return -1;
        }
        return oah_sysroot_open(img->sysroot, path, host_flags, (u32)mode);
    }
    return openat(dirfd == -100 ? AT_FDCWD : dirfd, path, host_flags, (mode_t)mode);
}

static const struct { u32 guest; int host; } open_flags[] = {
    {0x40, O_CREAT}, {0x80, O_EXCL}, {0x100, O_NOCTTY}, {0x200, O_TRUNC},
    {0x400, O_APPEND}, {0x800, O_NONBLOCK}, {0x10000, O_DIRECTORY},
    {0x20000, O_NOFOLLOW}, {0x80000, O_CLOEXEC}
};

static s64 guest_open(oah_image *img, int dirfd, u64 address, u64 flags, u64 mode)
{
    const char *path = guest_path(img, address);
    if (!path) {
        return -EFAULT;
    }
    if ((flags & 3) == 3) {
        return -EINVAL;
    }
    int host_flags = (int)(flags & 3);
    /* O_NOATIME is an advisory optimization here. */
    flags &= ~(3ull | 0x8000ull | 0x40000ull);
    for (unsigned i = 0; i < sizeof(open_flags) / sizeof(open_flags[0]); i++) {
        if (flags & open_flags[i].guest) {
            host_flags |= open_flags[i].host;
            flags &= ~open_flags[i].guest;
        }
    }
    if (flags) {
        if (getenv("OAH_TRACE_UNSUPPORTED")) {
            fprintf(stderr, "oah: unsupported open flags %#llx\n", (unsigned long long)flags);
        }
        return -EINVAL;
    }
    return host_result(open_guest_path(img, dirfd, path, host_flags, mode));
}

/* Linux x86-64 stat is 144 bytes and differs from Darwin's stat. */
typedef struct {
    u64 dev, ino, nlink;
    u32 mode, uid, gid, pad;
    u64 rdev;
    s64 size, blksize, blocks;
    s64 atime_sec, atime_nsec, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec;
    s64 reserved[3];
} linux_stat;

_Static_assert(sizeof(linux_stat) == 144, "x86-64 Linux stat layout");

static u64 linux_device(dev_t number)
{
    u64 minor_number = (u64)minor(number);
    return ((u64)major(number) << 8) | (minor_number & 0xff) |
           ((minor_number & ~0xffull) << 12);
}

static s64 guest_stat(oah_image *img, int dirfd, const char *path, u64 addr, u64 flags)
{
    void *output = oah_guest_access(img, addr, sizeof(linux_stat), PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    if (flags & ~0x1900ull) { /* AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW. */
        return -EINVAL;
    }
    struct stat st;
    int result;
    if (!path || (!*path && (flags & 0x1000) && dirfd != -100)) {
        result = fstat(dirfd, &st);
    } else if (sysroot_path(img, path)) {
        int fd = open_guest_path(img, dirfd, path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
        if (fd < 0) {
            return linux_error(errno);
        }
        result = fstat(fd, &st);
        int error = errno;
        close(fd);
        errno = error;
    } else {
        result = fstatat(dirfd == -100 ? AT_FDCWD : dirfd,
                         !*path && (flags & 0x1000) ? "." : path, &st,
                         flags & 0x100 ? AT_SYMLINK_NOFOLLOW : 0);
    }
    if (result < 0) {
        return linux_error(errno);
    }
    linux_stat converted = {
        .dev = linux_device(st.st_dev), .ino = st.st_ino, .nlink = st.st_nlink,
        .mode = st.st_mode, .uid = st.st_uid, .gid = st.st_gid,
        .rdev = linux_device(st.st_rdev), .size = st.st_size,
        .blksize = st.st_blksize, .blocks = st.st_blocks,
        .atime_sec = st.st_atimespec.tv_sec, .atime_nsec = st.st_atimespec.tv_nsec,
        .mtime_sec = st.st_mtimespec.tv_sec, .mtime_nsec = st.st_mtimespec.tv_nsec,
        .ctime_sec = st.st_ctimespec.tv_sec, .ctime_nsec = st.st_ctimespec.tv_nsec
    };
    memcpy(output, &converted, sizeof(converted));
    return 0;
}

static u64 guest_brk(oah_image *img, u64 addr)
{
    const u64 capacity = 64u << 20;
    if (!addr || addr < img->load_end || addr - img->load_end > capacity) {
        return img->brk;
    }
    const u64 mask = OAH_X86_PAGE_SIZE - 1;
    u64 end = (addr - img->load_end + mask) & ~mask;
    u64 old = (img->brk - img->load_end + mask) & ~mask;
    unsigned index = img->load_segments;
    while (index < img->nseg &&
           (!img->heap_mapping || img->segs[index].host != img->heap_mapping + img->heap_guard)) {
        index++;
    }
    if (end < img->heap_guard || (end > img->heap_guard && index == OAH_MAX_LOAD_SEGS)) {
        return img->brk;
    }
    if (!img->heap_mapping && end) {
        u8 *backing = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (backing == MAP_FAILED) {
            return img->brk;
        }
        img->heap_mapping = backing;
        img->heap_capacity = capacity;
    }
    if (end < old) {
        memset(img->heap_mapping + end, 0, old - end);
    }
    if (end > img->heap_guard) {
        if (index == img->nseg) {
            img->nseg++;
        }
        img->segs[index] = (oah_load_seg){
            .gva = img->load_end + img->heap_guard,
            .size = end - img->heap_guard,
            .host = img->heap_mapping + img->heap_guard,
            .prot = PROT_READ | PROT_WRITE
        };
    } else if (index < img->nseg) {
        img->segs[index] = img->segs[--img->nseg];
    }
    img->brk = addr;
    return addr;
}

/* Isolate a guest subrange without changing its underlying host reservation. */
static void split_mapping(oah_image *img, unsigned index, u64 addr, u64 len, u32 prot)
{
    oah_load_seg *seg = &img->segs[index];
    oah_load_seg original = *seg;
    u64 left = addr - original.gva;
    u64 right = original.size - left - len;
    unsigned extra = (left != 0) + (right != 0);
    memmove(seg + 1 + extra, seg + 1, (img->nseg - index - 1) * sizeof(*seg));
    if (left) {
        seg->size = left;
        seg++;
    }
    *seg = original;
    seg->gva = addr;
    seg->size = len;
    seg->host += left;
    seg->prot = prot;
    if (right) {
        seg++;
        *seg = original;
        seg->gva = addr + len;
        seg->size = right;
        seg->host += left + len;
    }
    img->nseg += extra;
    if (index < img->load_segments) {
        img->load_segments += extra;
    }
}

static bool load_file(u8 *backing, u64 size, int fd, u64 offset)
{
    u64 pos = 0;
    while (pos < size) {
        ssize_t count = pread(fd, backing + pos, size - pos, (off_t)(offset + pos));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        pos += (u64)count;
    }
    return true;
}

static s64 guest_mmap(oah_image *img, u64 address, u64 size, u64 prot, u64 flags, int fd, u64 offset)
{
    flags &= ~(0x800ull | 0x20000ull); /* Linux MAP_DENYWRITE and MAP_STACK. */
    if (!size || size > (1ull << 30) || (prot & ~7ull) ||
        (flags != 0x02 && flags != 0x12 && flags != 0x22 && flags != 0x32)) {
        return -EINVAL;
    }
    const u64 mask = OAH_X86_PAGE_SIZE - 1;
    size = (size + mask) & ~mask;
    bool file = !(flags & 0x20);
    bool fixed = (flags & 0x10) != 0;
    if (file) {
        if ((offset & mask) || offset > INT64_MAX - size) {
            return -EINVAL;
        }
        struct stat metadata;
        if (fstat(fd, &metadata) != 0) {
            return linux_error(errno);
        }
        if (!S_ISREG(metadata.st_mode)) {
            return -ENODEV;
        }
    } else if (fd != -1 || offset) {
        return -EINVAL;
    }
    if (fixed && !file && address == img->load_end) {
        /* musl marks the first page of the brk arena as a guard. */
        if (size != OAH_X86_PAGE_SIZE || prot || !img->heap_mapping || img->heap_guard) {
            return -EINVAL;
        }
        for (unsigned i = img->load_segments; i < img->nseg; i++) {
            oah_load_seg *seg = &img->segs[i];
            if (seg->host == img->heap_mapping && seg->size > size) {
                seg->gva += size;
                seg->host += size;
                seg->size -= size;
                img->heap_guard = size;
                return (s64)address;
            }
        }
        return -EINVAL;
    }
    if (fixed) {
        if (address & mask) {
            return -EINVAL;
        }
        for (unsigned i = img->load_segments; i < img->nseg; i++) {
            oah_load_seg *seg = &img->segs[i];
            if (!seg->file_mapping || address < seg->gva || address - seg->gva >= seg->size ||
                size > seg->size - (address - seg->gva)) {
                continue;
            }
            u64 left = address - seg->gva;
            unsigned extra = (left != 0) + (size != seg->size - left);
            if (extra > OAH_MAX_LOAD_SEGS - img->nseg) {
                return -ENOMEM;
            }
            /* MAP_FIXED changes only bytes inside this guest-owned reservation. */
            if (file) {
                u8 *staged = calloc(1, size);
                if (!staged) {
                    return -ENOMEM;
                }
                bool loaded = load_file(staged, size, fd, offset);
                int error = errno;
                if (loaded) {
                    memcpy(seg->host + left, staged, size);
                }
                free(staged);
                if (!loaded) {
                    return linux_error(error);
                }
            } else {
                memset(seg->host + left, 0, size);
            }
            split_mapping(img, i, address, size, (u32)prot);
            return (s64)address;
        }
        return -EINVAL;
    }
    if (img->nseg == OAH_MAX_LOAD_SEGS) {
        return -ENOMEM;
    }
    u8 *backing = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (backing == MAP_FAILED) {
        return linux_error(errno);
    }
    if (file && !load_file(backing, size, fd, offset)) {
        int error = errno;
        munmap(backing, size);
        return linux_error(error);
    }
    img->segs[img->nseg++] = (oah_load_seg){
        .gva = (u64)(uintptr_t)backing, .host = backing, .size = size, .prot = (u32)prot,
        .file_mapping = file, .allocation = backing, .allocation_size = size
    };
    return (s64)(uintptr_t)backing;
}

static s64 memory_change(oah_image *img, u64 addr, u64 len, u64 prot, bool unmap)
{
    const u64 mask = OAH_X86_PAGE_SIZE - 1;
    if (!len || len > UINT64_MAX - mask || (prot & ~7ull) || (addr & mask)) {
        return -EINVAL;
    }
    len = (len + mask) & ~mask;
    if (unmap) {
        for (unsigned i = img->load_segments; i < img->nseg; i++) {
            const oah_load_seg *seg = &img->segs[i];
            if (seg->allocation && (u64)(uintptr_t)seg->allocation == addr &&
                seg->allocation_size == len) {
                u8 *allocation = seg->allocation;
                if (munmap(allocation, len) != 0) {
                    return linux_error(errno);
                }
                for (unsigned j = img->load_segments; j < img->nseg;) {
                    if (img->segs[j].allocation == allocation) {
                        img->segs[j] = img->segs[--img->nseg];
                    } else {
                        j++;
                    }
                }
                return 0;
            }
        }
        return -EINVAL;
    }
    for (unsigned i = 0; i < img->nseg; i++) {
        oah_load_seg *seg = &img->segs[i];
        if (addr < seg->gva || addr - seg->gva >= seg->size ||
            len > seg->size - (addr - seg->gva)) {
            continue;
        }
        u64 left = addr - seg->gva;
        unsigned extra = (left != 0) + (len != seg->size - left);
        if ((extra && i >= img->load_segments && !seg->allocation) ||
            extra > OAH_MAX_LOAD_SEGS - img->nseg) {
            return -EINVAL;
        }
        split_mapping(img, i, addr, len, (u32)prot);
        return 0;
    }
    return -EINVAL;
}

static s64 guest_vector_io(oah_image *img, int fd, u64 address, u64 count, bool reading)
{
    struct guest_iovec { u64 address, size; } entry;
    struct iovec vectors[1024];
    if (count > sizeof(vectors) / sizeof(vectors[0])) {
        return -EINVAL;
    }
    const u8 *input = oah_guest_access(img, address, count * sizeof(entry), PROT_READ);
    if (count && !input) {
        return -EFAULT;
    }
    for (u64 i = 0; i < count; i++) {
        memcpy(&entry, input + i * sizeof(entry), sizeof(entry));
        if (entry.size > SSIZE_MAX) {
            return -EINVAL;
        }
        vectors[i].iov_base = oah_guest_access(img, entry.address, entry.size,
                                              reading ? PROT_WRITE : PROT_READ);
        vectors[i].iov_len = entry.size;
        if (entry.size && !vectors[i].iov_base) {
            return -EFAULT;
        }
    }
    return host_result(reading ? readv(fd, vectors, (int)count) :
                                 writev(fd, vectors, (int)count));
}

typedef struct {
    s32 fd;
    u16 events, revents;
} linux_pollfd;

_Static_assert(sizeof(linux_pollfd) == 8, "Linux x86-64 pollfd layout");

static s64 guest_poll(oah_image *img, u64 address, u64 count, int timeout)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
        return linux_error(errno);
    }
    if (count > limit.rlim_cur || count > UINT32_MAX) {
        return -EINVAL;
    }
    u8 *guest = oah_guest_access(img, address, count * sizeof(linux_pollfd),
                                PROT_READ | PROT_WRITE);
    if (count && !guest) {
        return -EFAULT;
    }
    struct pollfd *fds = count ? calloc(count, sizeof(*fds)) : NULL;
    if (count && !fds) {
        return -ENOMEM;
    }
    enum { LINUX_POLLWRNORM = 0x100, LINUX_POLLWRBAND = 0x200 };
    const unsigned shared_events = POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLRDBAND;
    const unsigned always_reported = POLLERR | POLLHUP | POLLNVAL;
    for (u64 i = 0; i < count; i++) {
        linux_pollfd entry;
        memcpy(&entry, guest + i * sizeof(entry), sizeof(entry));
        /* Darwin shares the base bits. Its POLLWRNORM aliases POLLOUT. */
        fds[i].fd = entry.fd;
        fds[i].events = entry.events & shared_events;
        if (entry.events & LINUX_POLLWRNORM) {
            fds[i].events |= POLLOUT;
        }
        if (entry.events & LINUX_POLLWRBAND) {
            fds[i].events |= POLLWRBAND;
        }
    }
    s64 result = host_result(poll(fds, (nfds_t)count, timeout < 0 ? -1 : timeout));
    if (result >= 0) {
        result = 0;
        for (u64 i = 0; i < count; i++) {
            linux_pollfd entry;
            u8 *slot = guest + i * sizeof(entry);
            memcpy(&entry, slot, sizeof(entry));
            entry.revents = fds[i].revents & (always_reported | (entry.events & shared_events));
            if ((entry.events & LINUX_POLLWRNORM) && (fds[i].revents & POLLOUT)) {
                entry.revents |= LINUX_POLLWRNORM;
            }
            if ((entry.events & LINUX_POLLWRBAND) && (fds[i].revents & POLLWRBAND)) {
                entry.revents |= LINUX_POLLWRBAND;
            }
            result += entry.revents != 0;
            memcpy(slot + offsetof(linux_pollfd, revents), &entry.revents, sizeof(entry.revents));
        }
    }
    free(fds);
    return result;
}

typedef struct guest_dir {
    int fd;
    DIR *stream;
    struct guest_dir *next;
} guest_dir;

static guest_dir *directories;

static void forget_directory(int fd)
{
    guest_dir **link = &directories;
    while (*link && (*link)->fd != fd) {
        link = &(*link)->next;
    }
    if (*link) {
        guest_dir *entry = *link;
        *link = entry->next;
        closedir(entry->stream);
        free(entry);
    }
}

static s64 guest_getdents(oah_image *img, int fd, u64 address, u64 size)
{
    u8 *output = oah_guest_access(img, address, size, PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    guest_dir *dir = directories;
    while (dir && dir->fd != fd) {
        dir = dir->next;
    }
    if (!dir) {
        int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (copy < 0) {
            return linux_error(errno);
        }
        DIR *stream = fdopendir(copy);
        if (!stream) {
            int error = errno;
            close(copy);
            return linux_error(error);
        }
        dir = malloc(sizeof(*dir));
        if (!dir) {
            closedir(stream);
            return -ENOMEM;
        }
        *dir = (guest_dir){fd, stream, directories};
        directories = dir;
    }
    u64 written = 0;
    for (;;) {
        long position = telldir(dir->stream);
        errno = 0;
        const struct dirent *entry = readdir(dir->stream);
        if (!entry) {
            return written || !errno ? (s64)written : linux_error(errno);
        }
        u16 length = (19 + entry->d_namlen + 1 + 7) & ~7u;
        if (length > size - written) {
            seekdir(dir->stream, position);
            return written ? (s64)written : -EINVAL;
        }
        u64 ino = entry->d_ino;
        s64 next = telldir(dir->stream);
        u8 *record = output + written;
        memset(record, 0, length);
        memcpy(record, &ino, 8);
        memcpy(record + 8, &next, 8);
        memcpy(record + 16, &length, 2);
        record[18] = entry->d_type;
        memcpy(record + 19, entry->d_name, entry->d_namlen);
        written += length;
    }
}

static s64 guest_fd_pair(oah_image *img, u64 address, u64 flags, int socket_type)
{
    if (flags & ~(0x800ull | 0x80000ull)) {
        return -EINVAL;
    }
    void *output = oah_guest_access(img, address, 8, PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    int fds[2];
    if ((socket_type ? socketpair(AF_UNIX, socket_type, 0, fds) : pipe(fds)) < 0) {
        return linux_error(errno);
    }
    for (unsigned i = 0; i < 2; i++) {
        if (((flags & 0x800) && fcntl(fds[i], F_SETFL, O_NONBLOCK) < 0) ||
            ((flags & 0x80000) && fcntl(fds[i], F_SETFD, FD_CLOEXEC) < 0)) {
            int error = errno;
            close(fds[0]);
            close(fds[1]);
            return linux_error(error);
        }
    }
    memcpy(output, fds, sizeof(fds));
    return 0;
}

/* The vectors are host-owned. Their strings stay in the guest image
 * until execve copies them into the new process. */
static s64 guest_exec_vector(oah_image *img, u64 address, char **vector,
                             size_t capacity, size_t *bytes, bool argv)
{
    for (size_t i = 0; i < capacity; i++) {
        u64 pointer = 0;
        if (address) {
            u64 offset = i * sizeof(pointer);
            const void *slot = address <= UINT64_MAX - offset ?
                oah_guest_access(img, address + offset, sizeof(pointer), PROT_READ) : NULL;
            if (!slot) {
                return -EFAULT;
            }
            memcpy(&pointer, slot, sizeof(pointer));
        }
        if (!pointer) {
            if (!i && argv) {
                vector[i++] = "";
            }
            vector[i] = NULL;
            return 0;
        }
        u64 span = *bytes;
        const u8 *text = oah_guest_span(img, pointer, &span);
        const u8 *end = text ? memchr(text, 0, span) : NULL;
        if (!end) {
            return !text || span < *bytes ? -EFAULT : -E2BIG;
        }
        *bytes -= (size_t)(end - text) + 1;
        vector[i] = (char *)text;
    }
    return -E2BIG;
}

static s64 guest_exec(oah_image *img, u64 path_arg, u64 argv_arg, u64 env_arg)
{
    const char *path = guest_path(img, path_arg);
    if (!path || !img->launcher || !*path) {
        return !path ? -EFAULT : !*path ? -ENOENT : -LINUX_ENOSYS;
    }
    int fd = -1;
    if (path[0] == '/' && img->sysroot) {
        fd = oah_sysroot_open(img->sysroot, path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
        if (fd < 0 && errno != ENOENT && errno != ENOTDIR) {
            return linux_error(errno);
        }
    }
    if (fd < 0) {
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    }
    if (fd < 0) {
        return linux_error(errno);
    }
    struct stat st;
    Elf64_Ehdr header;
    char target[PATH_MAX];
    s64 result = 0;
    if (fstat(fd, &st) < 0 || fcntl(fd, F_GETPATH, target) < 0) {
        result = linux_error(errno);
    } else if (!S_ISREG(st.st_mode) || access(target, X_OK) < 0) {
        result = -EACCES;
    } else if (pread(fd, &header, sizeof(header), 0) != sizeof(header) ||
               memcmp(header.e_ident, ELFMAG, SELFMAG) ||
               header.e_ident[EI_CLASS] != ELFCLASS64 ||
               header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64) {
        result = -ENOEXEC;
    }
    close(fd);
    if (result) {
        return result;
    }

    enum { MAX_VECTOR = 4096, LAUNCH_ARGS = 10 };
    char **args = calloc(2 * MAX_VECTOR + LAUNCH_ARGS, sizeof(*args));
    if (!args) {
        return -ENOMEM;
    }
    size_t count = 0, bytes = 192 * 1024;
    args[count++] = (char *)img->launcher;
    if (img->interpret) {
        args[count++] = "--interpret";
    }
    if (img->sysroot) {
        args[count++] = "--sysroot";
        args[count++] = (char *)img->sysroot;
    }
    args[count++] = "--guest-exec";
    args[count++] = target;
    char env_count_text[16];
    args[count++] = env_count_text;
    args[count++] = "--";

    /* Pass guest variables as payload so the host loader never reads them. */
    result = guest_exec_vector(img, env_arg, args + count, MAX_VECTOR, &bytes, false);
    if (!result) {
        size_t env_count = 0;
        while (args[count + env_count]) {
            env_count++;
        }
        snprintf(env_count_text, sizeof(env_count_text), "%zu", env_count);
        count += env_count;
        args[count++] = "";
        result = guest_exec_vector(img, argv_arg, args + count, MAX_VECTOR, &bytes, true);
    }
    if (!result) {
        char *const host_env[] = {NULL};
        struct itimerval timer;
        const struct itimerval stopped = {0};
        if (posix_timer_created && setitimer(ITIMER_REAL, &stopped, &timer) < 0) {
            result = linux_error(errno);
        } else {
            result = host_result(execve(img->launcher, args, host_env));
            if (posix_timer_created) {
                setitimer(ITIMER_REAL, &timer, NULL);
            }
        }
    }
    free(args);
    return result;
}

static int darwin_dirfd(u64 guest_fd)
{
    return (int)guest_fd == -100 ? AT_FDCWD : (int)guest_fd;
}

static s64 guest_allocate(int fd, u64 mode, u64 offset, u64 length)
{
    if ((s64)offset < 0 || (s64)length <= 0 || offset > INT64_MAX - length) {
        return -EINVAL;
    }
    if (mode || offset) {
        return -LINUX_EOPNOTSUPP;
    }
    struct stat file;
    if (fstat(fd, &file) < 0) {
        return linux_error(errno);
    }
    /* Darwin preallocates beyond the physical EOF. An empty file lets
     * this cover the requested range without assuming how holes map. */
    if (!S_ISREG(file.st_mode) || file.st_size || file.st_blocks) {
        return -LINUX_EOPNOTSUPP;
    }
    fstore_t storage = {
        .fst_flags = F_ALLOCATEALL,
        .fst_posmode = F_PEOFPOSMODE,
        .fst_length = (off_t)length
    };
    if (fcntl(fd, F_PREALLOCATE, &storage) < 0) {
        return linux_error(errno);
    }
    return host_result(ftruncate(fd, (off_t)length));
}

static bool guest_clock(u64 id, clockid_t *host)
{
    switch (id) {
    case 0: *host = CLOCK_REALTIME; return true;
    case 1: *host = CLOCK_MONOTONIC; return true;
    case 2: *host = CLOCK_PROCESS_CPUTIME_ID; return true;
    case 3: *host = CLOCK_THREAD_CPUTIME_ID; return true;
    case 4: *host = CLOCK_MONOTONIC_RAW; return true;
    default: return false;
    }
}

static s64 guest_sleep(oah_image *img, u64 id, u64 flags, u64 request, u64 remain)
{
    /* Linux permits absolute sleeps against the realtime and monotonic clocks. */
    clockid_t clock;
    if (id > 1 || !guest_clock(id, &clock) || (flags & ~1ull)) {
        return -EINVAL;
    }
    struct timespec interval;
    const void *input = oah_guest_access(img, request, sizeof(interval), PROT_READ);
    if (!input) {
        return -EFAULT;
    }
    memcpy(&interval, input, sizeof(interval));
    if (interval.tv_sec < 0 || interval.tv_nsec < 0 || interval.tv_nsec >= 1000000000L) {
        return -EINVAL;
    }
    if (flags) {
        struct timespec now;
        if (clock_gettime(clock, &now) < 0) {
            return linux_error(errno);
        }
        if (now.tv_sec > interval.tv_sec ||
            (now.tv_sec == interval.tv_sec && now.tv_nsec >= interval.tv_nsec)) {
            return 0;
        }
        interval.tv_sec -= now.tv_sec;
        interval.tv_nsec -= now.tv_nsec;
        if (interval.tv_nsec < 0) {
            interval.tv_sec--;
            interval.tv_nsec += 1000000000L;
        }
    }
    struct timespec remaining;
    if (nanosleep(&interval, &remaining) == 0) {
        return 0;
    }
    int error = errno;
    if (error == EINTR && remain && !flags) {
        void *output = oah_guest_access(img, remain, sizeof(remaining), PROT_WRITE);
        if (!output) {
            return -EFAULT;
        }
        memcpy(output, &remaining, sizeof(remaining));
    }
    return linux_error(error);
}

oah_sys_status oah_guest_syscall(oah_guest *g, oah_image *img)
{
    u64 nr = g->gpr[OAH_X86_RAX];
    u64 a0 = g->gpr[OAH_X86_RDI], a1 = g->gpr[OAH_X86_RSI];
    u64 a2 = g->gpr[OAH_X86_RDX], a3 = g->gpr[OAH_X86_R10];
    u64 a4 = g->gpr[OAH_X86_R8], a5 = g->gpr[OAH_X86_R9];
    s64 result;
    g->gpr[OAH_X86_RCX] = g->rip;
    g->gpr[OAH_X86_R11] = g->rflags;

    switch (nr) {
    case OAH_X86_NR_EXIT:
    case OAH_X86_NR_EXIT_GROUP:
        return OAH_SYS_EXIT;
    case 13: case 14: case 15: case 127: case 130: case 131: case 200: case 234:
        return oah_guest_signal_syscall(g, img);
    case OAH_X86_NR_READ:
    case OAH_X86_NR_WRITE: {
        void *buffer = oah_guest_access(img, a1, a2,
                         nr == OAH_X86_NR_READ ? PROT_WRITE : PROT_READ);
        if (a2 && !buffer) {
            result = -EFAULT;
        } else {
            result = host_result(nr == OAH_X86_NR_READ ? read((int)a0, buffer, a2)
                                                       : write((int)a0, buffer, a2));
        }
        break;
    }
    case 2: /* open */
        result = guest_open(img, AT_FDCWD, a0, a1, a2);
        break;
    case OAH_X86_NR_OPENAT:
        result = guest_open(img, (int)a0, a1, a2, a3);
        break;
    case OAH_X86_NR_CLOSE:
        forget_directory((int)a0);
        result = host_result(close((int)a0));
        break;
    case 4: /* stat */
    case 6: /* lstat */
    case 262: { /* newfstatat */
        const char *path = guest_path(img, nr == 262 ? a1 : a0);
        result = !path ? -EFAULT : guest_stat(img, nr == 262 ? (int)a0 : -100,
                      path, nr == 262 ? a2 : a1, nr == 262 ? a3 : nr == 6 ? 0x100 : 0);
        break;
    }
    case 5: /* fstat */
        result = guest_stat(img, (int)a0, NULL, a1, 0);
        break;
    case 8: /* lseek */
        result = host_result(lseek((int)a0, (off_t)a1, (int)a2));
        break;
    case 9: /* mmap */
        result = guest_mmap(img, a0, a1, a2, a3, (int)a4, a5);
        break;
    case 10: /* mprotect */
    case 11: /* munmap */
        result = memory_change(img, a0, a1, nr == 11 ? 0 : a2, nr == 11);
        break;
    case OAH_X86_NR_BRK:
        result = (s64)guest_brk(img, a0);
        break;
    case 7: /* poll */
        result = guest_poll(img, a0, a1, (s32)a2);
        break;
    case 16: { /* ioctl */
        if (a1 == 0x541b) { /* FIONREAD */
            int count;
            void *output = oah_guest_access(img, a2, sizeof(count), PROT_WRITE);
            result = output ? host_result(ioctl((int)a0, FIONREAD, &count)) : -EFAULT;
            if (!result) {
                memcpy(output, &count, sizeof(count));
            }
            break;
        }
        struct winsize *size = oah_guest_access(img, a2, sizeof(*size), PROT_WRITE);
        result = a1 != 0x5413 ? -ENOTTY : !size ? -EFAULT
                            : host_result(ioctl((int)a0, TIOCGWINSZ, size));
        break;
    }
    case 17: case 18: { /* pread64, pwrite64 */
        bool reading = nr == 17;
        void *buffer = oah_guest_access(img, a1, a2, reading ? PROT_WRITE : PROT_READ);
        result = a2 && !buffer ? -EFAULT :
                 host_result(reading ? pread((int)a0, buffer, a2, (off_t)a3) :
                                       pwrite((int)a0, buffer, a2, (off_t)a3));
        break;
    }
    case 21: { /* access */
        const char *path = guest_path(img, a0);
        if (!path) {
            result = -EFAULT;
        } else if (a1 & ~7ull) {
            result = -EINVAL;
        } else if (sysroot_path(img, path)) {
            int fd = open_guest_path(img, AT_FDCWD, path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
            result = fd < 0 ? linux_error(errno) : 0;
            if (fd >= 0) {
                close(fd);
            }
        } else {
            result = host_result(access(path, (int)a1));
        }
        break;
    }
    case 19: case 20: /* readv, writev */
        result = guest_vector_io(img, (int)a0, a1, a2, nr == 19);
        break;
    case 22: case 293: /* pipe, pipe2 */
        result = guest_fd_pair(img, a0, nr == 293 ? a1 : 0, 0);
        break;
    case 32: /* dup */
        result = host_result(dup((int)a0));
        break;
    case 33: /* dup2 */
        result = host_result(dup2((int)a0, (int)a1));
        if (result >= 0 && a0 != a1) {
            forget_directory((int)a1);
        }
        break;
    case 48: /* shutdown */
        result = a1 > 2 ? -EINVAL : host_result(shutdown((int)a0, (int)a1));
        break;
    case 53: { /* socketpair */
        u64 type = a1 & 0xf;
        if (a0 != 1) {
            result = -LINUX_EAFNOSUPPORT;
        } else if (a2) {
            result = -LINUX_EPROTONOSUPPORT;
        } else if (type != 1 && type != 2) {
            result = -LINUX_ESOCKTNOSUPPORT;
        } else {
            result = guest_fd_pair(img, a3, a1 & ~0xfull,
                                   type == 1 ? SOCK_STREAM : SOCK_DGRAM);
        }
        break;
    }
    case 56: /* process clone as used by glibc fork */
        if ((a0 & ~0x1200000ull) != 17 || a1 || a2 || a4) {
            result = -LINUX_ENOSYS;
            break;
        }
        if ((a0 & 0x1000000) && !oah_guest_access(img, a3, 4, PROT_WRITE)) {
            result = -EFAULT;
            break;
        }
        result = guest_fork();
        if (!result && (a0 & 0x1000000)) {
            u32 tid = getpid();
            memcpy(oah_guest_access(img, a3, 4, PROT_WRITE), &tid, sizeof(tid));
        }
        break;
    case 57: /* fork */
        result = guest_fork();
        break;
    case 59: result = guest_exec(img, a0, a1, a2); break;
    case 61: { /* wait4 */
        void *output = a1 ? oah_guest_access(img, a1, 4, PROT_WRITE) : NULL;
        int status;
        if ((a1 && !output) || a3 || (a2 & ~3ull)) {
            result = a1 && !output ? -EFAULT : -EINVAL;
            break;
        }
        int options = (a2 & 1 ? WNOHANG : 0) | (a2 & 2 ? WUNTRACED : 0);
        result = host_result(waitpid((pid_t)a0, &status, options));
        if (result > 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                forget_child((pid_t)result);
            }
            if (output) {
                memcpy(output, &status, sizeof(status));
            }
        }
        break;
    }
    case 62: /* kill */
        if ((pid_t)a0 == getpid()) {
            return oah_guest_signal_syscall(g, img);
        }
        result = guest_kill_children(g, (pid_t)a0, a1);
        break;
    case 109: { /* setpgid, scoped to the guest process and its children */
        pid_t pid = (pid_t)a0, group = (pid_t)a1;
        result = pid && pid != getpid() && !*child_link(pid) ? -ESRCH :
                 host_result(setpgid(pid, group));
        break;
    }
    case 222: result = guest_timer_create(img, a0, a1, a2); break;
    case 223: result = guest_timer_set(img, a0, a1, a2, a3); break;
    case 224: { /* timer_gettime */
        void *output = oah_guest_access(img, a1, sizeof(linux_itimerspec), PROT_WRITE);
        struct itimerval timer;
        result = a0 || !posix_timer_created ? -EINVAL :
                 !output ? -EFAULT : host_result(getitimer(ITIMER_REAL, &timer));
        if (!result) {
            linux_itimerspec value = linux_timer_value(&timer);
            memcpy(output, &value, sizeof(value));
        }
        break;
    }
    case 226: { /* timer_delete */
        const struct itimerval stopped = {0};
        result = a0 || !posix_timer_created ? -EINVAL :
                 host_result(setitimer(ITIMER_REAL, &stopped, NULL));
        if (!result) {
            posix_timer_created = false;
        }
        break;
    }
    case 35: /* nanosleep */
        result = guest_sleep(img, 1, 0, a0, a1);
        break;
    case 73: { /* flock */
        unsigned kind = a1 & ~4ull;
        int operation = kind == 1 ? LOCK_SH : kind == 2 ? LOCK_EX : LOCK_UN;
        result = (a1 & ~15ull) || (kind != 1 && kind != 2 && kind != 8) ? -EINVAL :
                 host_result(flock((int)a0, operation | (a1 & 4 ? LOCK_NB : 0)));
        break;
    }
    case 74: case 75: /* fsync, fdatasync */
        result = host_result(fsync((int)a0));
        break;
    case 228: case 229: { /* clock_gettime, clock_getres */
        clockid_t clock;
        struct timespec value;
        void *output = a1 ? oah_guest_access(img, a1, sizeof(value), PROT_WRITE) : NULL;
        if (!guest_clock(a0, &clock)) {
            result = -EINVAL;
        } else if (!output && (a1 || nr == 228)) {
            result = -EFAULT;
        } else {
            result = host_result(nr == 228 ? clock_gettime(clock, &value) : clock_getres(clock, &value));
            if (!result && output) {
                memcpy(output, &value, sizeof(value));
            }
        }
        break;
    }
    case 285: result = guest_allocate((int)a0, a1, a2, a3); break;
    case 230: /* clock_nanosleep */
        result = guest_sleep(img, a0, a1, a2, a3);
        break;
    case 79: { /* getcwd */
        char *buffer = oah_guest_access(img, a0, a1, PROT_WRITE);
        result = !a1 ? -EINVAL : !buffer ? -EFAULT :
                 getcwd(buffer, a1) ? (s64)strlen(buffer) + 1 : linux_error(errno);
        break;
    }
    case 80: { /* chdir */
        const char *path = guest_path(img, a0);
        result = path ? host_result(chdir(path)) : -EFAULT;
        break;
    }
    case 81: result = host_result(fchdir((int)a0)); break;
    case 76: { /* truncate */
        const char *path = guest_path(img, a0);
        result = path ? host_result(truncate(path, (off_t)a1)) : -EFAULT;
        break;
    }
    case 77: result = host_result(ftruncate((int)a0, (off_t)a1)); break;
    case 82: case 264: case 316: { /* rename, renameat, renameat2 */
        const char *source = guest_path(img, nr == 82 ? a0 : a1);
        const char *target = guest_path(img, nr == 82 ? a1 : a3);
        int from = nr == 82 ? AT_FDCWD : darwin_dirfd(a0);
        int to = nr == 82 ? AT_FDCWD : darwin_dirfd(a2);
        if (!source || !target) {
            result = -EFAULT;
        } else if (nr != 316 || !a4) {
            result = host_result(renameat(from, source, to, target));
        } else if (a4 == 1 || a4 == 2) {
            result = host_result(renameatx_np(from, source, to, target,
                                              a4 == 1 ? RENAME_EXCL : RENAME_SWAP));
        } else {
            result = -EINVAL;
        }
        break;
    }
    case 84: case 87: case 263: { /* rmdir, unlink, unlinkat */
        const char *path = guest_path(img, nr == 263 ? a1 : a0);
        int fd = nr == 263 ? darwin_dirfd(a0) : AT_FDCWD;
        u64 flags = nr == 263 ? a2 : nr == 84 ? 0x200 : 0;
        result = !path ? -EFAULT : flags & ~0x200ull ? -EINVAL :
                 host_result(unlinkat(fd, path, flags ? AT_REMOVEDIR : 0));
        break;
    }
    case 86: case 265: { /* link, linkat */
        const char *source = guest_path(img, nr == 86 ? a0 : a1);
        const char *target = guest_path(img, nr == 86 ? a1 : a3);
        int from = nr == 86 ? AT_FDCWD : darwin_dirfd(a0);
        int to = nr == 86 ? AT_FDCWD : darwin_dirfd(a2);
        u64 flags = nr == 86 ? 0 : a4;
        result = !source || !target ? -EFAULT : flags & ~0x400ull ? -EINVAL :
                 host_result(linkat(from, source, to, target, flags ? AT_SYMLINK_FOLLOW : 0));
        break;
    }
    case 88: case 266: { /* symlink, symlinkat */
        const char *source = guest_path(img, a0);
        const char *target = guest_path(img, nr == 88 ? a1 : a2);
        int fd = nr == 88 ? AT_FDCWD : darwin_dirfd(a1);
        result = source && target ? host_result(symlinkat(source, fd, target)) : -EFAULT;
        break;
    }
    case 90: case 268: case 452: { /* chmod, fchmodat, fchmodat2 */
        const char *path = guest_path(img, nr == 90 ? a0 : a1);
        u64 flags = nr == 452 ? a3 : 0;
        int fd = nr == 90 ? AT_FDCWD : darwin_dirfd(a0);
        result = !path ? -EFAULT : flags & ~0x100ull ? -EINVAL :
                 host_result(fchmodat(fd, path, (mode_t)(nr == 90 ? a1 : a2),
                                      flags ? AT_SYMLINK_NOFOLLOW : 0));
        break;
    }
    case 91: result = host_result(fchmod((int)a0, (mode_t)a1)); break;
    case 93: result = host_result(fchown((int)a0, (uid_t)a1, (gid_t)a2)); break;
    case 95: result = umask((mode_t)a0); break;
    case 133: case 259: { /* mknod, mknodat, FIFO only */
        const char *path = guest_path(img, nr == 133 ? a0 : a1);
        mode_t mode = (mode_t)(nr == 133 ? a1 : a2);
        int fd = nr == 133 ? AT_FDCWD : darwin_dirfd(a0);
        result = !path ? -EFAULT : !S_ISFIFO(mode) ? -LINUX_ENOSYS :
                 host_result(mkfifoat(fd, path, mode & 07777));
        break;
    }
    case 202: { /* futex wake in the single-threaded guest */
        u64 operation = a1 & ~128ull;
        if ((a0 & 3) || !oah_guest_access(img, a0, 4, PROT_READ)) {
            result = (a0 & 3) ? -EINVAL : -EFAULT;
        } else {
            result = operation == 1 ? 0 : -LINUX_ENOSYS;
        }
        if (result == -LINUX_ENOSYS && getenv("OAH_TRACE_UNSUPPORTED")) {
            fprintf(stderr, "oah: unsupported Linux futex operation %llu\n", (unsigned long long)a1);
        }
        break;
    }
    case 83: case 258: { /* mkdir, mkdirat */
        const char *path = guest_path(img, nr == 83 ? a0 : a1);
        int fd = nr == 83 ? -100 : (int)a0;
        result = !path ? -EFAULT : host_result(mkdirat(fd == -100 ? AT_FDCWD : fd,
                     path, (mode_t)(nr == 83 ? a1 : a2)));
        break;
    }
    case 89: case 267: { /* readlink, readlinkat */
        const char *path = guest_path(img, nr == 89 ? a0 : a1);
        u64 size = nr == 89 ? a2 : a3;
        char *buffer = oah_guest_access(img, nr == 89 ? a1 : a2, size, PROT_WRITE);
        int fd = nr == 89 ? -100 : (int)a0;
        result = !size ? -EINVAL : !path || !buffer ? -EFAULT :
                 host_result(readlinkat(fd == -100 ? AT_FDCWD : fd, path, buffer, size));
        break;
    }
    case 280: { /* utimensat */
        const char *path = a1 ? guest_path(img, a1) : NULL;
        const u8 *input = a2 ? oah_guest_access(img, a2, 32, PROT_READ) : NULL;
        struct timespec times[2];
        if ((a1 && !path) || (a2 && !input)) {
            result = -EFAULT;
        } else if (a3 & ~0x100ull) {
            result = -EINVAL;
        } else {
            if (input) {
                memcpy(times, input, sizeof(times));
                for (unsigned i = 0; i < 2; i++) {
                    if (times[i].tv_nsec == 1073741823) {
                        times[i].tv_nsec = UTIME_NOW;
                    } else if (times[i].tv_nsec == 1073741822) {
                        times[i].tv_nsec = UTIME_OMIT;
                    }
                }
            }
            int fd = (int)a0 == -100 ? AT_FDCWD : (int)a0;
            result = host_result(path ? utimensat(fd, path, input ? times : NULL,
                                                  a3 ? AT_SYMLINK_NOFOLLOW : 0)
                                      : futimens(fd, input ? times : NULL));
        }
        break;
    }
    case 96: { /* gettimeofday */
        void *output = a0 ? oah_guest_access(img, a0, 16, PROT_WRITE) : NULL;
        void *zone = a1 ? oah_guest_access(img, a1, 8, PROT_WRITE) : NULL;
        struct timeval tv;
        struct timezone tz;
        result = (a0 && !output) || (a1 && !zone) ? -EFAULT :
                 host_result(gettimeofday(&tv, zone ? &tz : NULL));
        if (!result && output) {
            s64 converted[2] = {tv.tv_sec, tv.tv_usec};
            memcpy(output, converted, sizeof(converted));
        }
        if (!result && zone) {
            memcpy(zone, &tz, sizeof(tz));
        }
        break;
    }
    case 201: { /* time */
        void *output = a0 ? oah_guest_access(img, a0, 8, PROT_WRITE) : NULL;
        result = a0 && !output ? -EFAULT : host_result(time(NULL));
        if (result >= 0 && output) {
            memcpy(output, &result, sizeof(result));
        }
        break;
    }
    case 110: result = getppid(); break;
    case 217: /* getdents64 */
        result = guest_getdents(img, (int)a0, a1, a2);
        break;
    case 39: /* getpid */
    case 186: /* gettid, single guest thread */
        result = getpid();
        break;
    case 40: /* Linux sendfile to a general descriptor has no Darwin equivalent. */
        result = -EINVAL;
        break;
    case OAH_X86_NR_UNAME: {
        char *name = oah_guest_access(img, a0, 6 * 65, PROT_WRITE);
        struct utsname host;
        if (!name) {
            result = -EFAULT;
        } else if (uname(&host) != 0) {
            result = linux_error(errno);
        } else {
            memset(name, 0, 6 * 65);
            snprintf(name, 65, "Linux");
            snprintf(name + 65, 65, "%.64s", host.nodename);
            snprintf(name + 260, 65, "x86_64");
            result = 0;
        }
        break;
    }
    case 72: /* fcntl, descriptor flags */
        if (a1 == 0 || a1 == 1030) {
            result = host_result(fcntl((int)a0, a1 == 0 ? F_DUPFD : F_DUPFD_CLOEXEC, (int)a2));
        } else if (a1 == 1 || a1 == 2) {
            result = host_result(fcntl((int)a0, a1 == 1 ? F_GETFD : F_SETFD, (int)a2));
        } else if (a1 == 3) {
            int flags = fcntl((int)a0, F_GETFL);
            result = host_result(flags);
            if (flags >= 0) {
                result = flags & O_ACCMODE;
                for (unsigned i = 0; i < sizeof(open_flags) / sizeof(open_flags[0]); i++) {
                    if ((flags & open_flags[i].host) && open_flags[i].host != O_CLOEXEC) {
                        result |= open_flags[i].guest;
                    }
                }
            }
        } else if (a1 == 4) {
            int flags = (a2 & 0x400 ? O_APPEND : 0) | (a2 & 0x800 ? O_NONBLOCK : 0);
            result = host_result(fcntl((int)a0, F_SETFL, flags));
        } else {
            result = -EINVAL;
        }
        break;
    case 102: result = getuid(); break;
    case 104: result = getgid(); break;
    case 107: result = geteuid(); break;
    case 108: result = getegid(); break;
    case OAH_X86_NR_ARCH_PRCTL:
        if (a0 == OAH_ARCH_SET_FS) {
            g->fs_base = a1;
            result = 0;
        } else if (a0 == OAH_ARCH_GET_FS) {
            void *output = oah_guest_access(img, a1, 8, PROT_WRITE);
            result = output ? 0 : -EFAULT;
            if (output) {
                memcpy(output, &g->fs_base, 8);
            }
        } else {
            result = -EINVAL;
        }
        break;
    case 218: /* set_tid_address */
        result = !a0 || oah_guest_access(img, a0, 4, PROT_WRITE) ? getpid() : -EFAULT;
        break;
    case 302: { /* prlimit64, query the current process stack limit */
        void *output = a3 ? oah_guest_access(img, a3, 16, PROT_WRITE) : NULL;
        struct rlimit limit;
        if (a0 || a2) {
            result = -EPERM;
        } else if (a1 != 3) {
            result = -LINUX_ENOSYS;
        } else if (a3 && !output) {
            result = -EFAULT;
        } else if (getrlimit(RLIMIT_STACK, &limit) != 0) {
            result = linux_error(errno);
        } else {
            const u64 values[2] = {limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX : limit.rlim_cur,
                                   limit.rlim_max == RLIM_INFINITY ? UINT64_MAX : limit.rlim_max};
            if (output) {
                memcpy(output, values, sizeof(values));
            }
            result = 0;
        }
        break;
    }
    case OAH_X86_NR_GETRANDOM: {
        void *buffer = oah_guest_access(img, a0, a1, PROT_WRITE);
        if (a2 & ~3ull || a1 > INT32_MAX) {
            result = -EINVAL;
        } else if (a1 && !buffer) {
            result = -EFAULT;
        } else {
            if (a1) {
                arc4random_buf(buffer, a1);
            }
            result = (s64)a1;
        }
        break;
    }
    default:
        if (getenv("OAH_TRACE_UNSUPPORTED")) {
            fprintf(stderr, "oah: unsupported Linux syscall %llu on macOS at rip=%llx\n",
                    (unsigned long long)nr, (unsigned long long)(g->rip - 2));
        }
        result = -LINUX_ENOSYS;
        break;
    }
    g->gpr[OAH_X86_RAX] = (u64)result;
    return OAH_SYS_CONTINUE;
}
