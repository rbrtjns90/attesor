#include "oah/elf_map.h"

#include "oah/elf_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#if defined(__linux__)
#include <linux/openat2.h>
#include <sys/syscall.h>
#endif
#include <stdio.h>
#include <stdlib.h>
extern unsigned char *oah_jit_arena_for_debug;
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static u32 prot_from_ph(u32 flags)
{
    return ((flags & PF_R) ? PROT_READ : 0) |
           ((flags & PF_W) ? PROT_WRITE : 0) |
           ((flags & PF_X) ? PROT_EXEC | PROT_READ : 0);
}

/* ---------- Module identity (persistent JIT cache) ---------- */

static u64 module_key(const struct stat *st)
{
    u64 h = 1469598103934665603ull;
    const u64 vals[] = {(u64)st->st_dev, (u64)st->st_ino, (u64)st->st_size,
#if defined(__APPLE__)
                        (u64)st->st_mtimespec.tv_sec,
                        (u64)st->st_mtimespec.tv_nsec
#else
                        (u64)st->st_mtim.tv_sec,
                        (u64)st->st_mtim.tv_nsec
#endif
    };
    for (unsigned i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        h = (h ^ vals[i]) * 1099511628211ull;
    }
    return h ? h : 1;
}

int oah_image_module_register(oah_image *img, const char *host_path)
{
    if (!img || !host_path || img->nmodule == OAH_MAX_MODULES) {
        return -1;
    }
    struct stat st;
    if (stat(host_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -1;
    }
    u64 key = module_key(&st);
    for (unsigned i = 0; i < img->nmodule; i++) {
        if (img->modules[i].key == key) {
            return (int)i;
        }
    }
    oah_module *m = &img->modules[img->nmodule];
    snprintf(m->path, sizeof(m->path), "%s", host_path);
    m->key = key;
    m->base = ~(u64)0;
    m->jit_cache = NULL;
    m->jit_cache_tried = false;
    return (int)img->nmodule++;
}

void oah_image_tag_module(oah_image *img, u64 gva, u64 size, int module)
{
    if (!img || module < 0 || module >= (int)img->nmodule) {
        return;
    }
    for (unsigned i = 0; i < img->nseg; i++) {
        oah_load_seg *s = &img->segs[i];
        if (s->gva >= gva && s->gva < gva + size) {
            s->module = module;
            if (s->gva < img->modules[module].base) {
                img->modules[module].base = s->gva;
            }
        }
    }
}

int oah_image_module_at(const oah_image *img, u64 gva)
{
    if (!img) {
        return -1;
    }
    for (unsigned i = 0; i < img->nseg; i++) {
        const oah_load_seg *s = &img->segs[i];
        if (gva >= s->gva && gva - s->gva < s->size) {
            return s->module;
        }
    }
    return -1;
}

u64 oah_module_gva(const oah_image *img, int module, u64 off)
{
    if (!img || module < 0 || module >= (int)img->nmodule) {
        return 0;
    }
    u64 base = img->modules[module].base;
    return base == ~(u64)0 ? 0 : base + off;
}

void oah_unmap_elf(oah_image *img)
{
    if (!img) {
        return;
    }
    for (unsigned i = img->load_segments; i < img->nseg; i++) {
#if defined(__APPLE__)
        const oah_load_seg *seg = &img->segs[i];
        if (seg->allocation) {
            bool first = true;
            for (unsigned j = img->load_segments; j < i; j++) {
                if (img->segs[j].allocation == seg->allocation) {
                    first = false;
                    break;
                }
            }
            if (first) {
                munmap(seg->allocation, seg->allocation_size);
            }
            continue;
        }
#endif
        uintptr_t backing = (uintptr_t)img->segs[i].host;
        uintptr_t heap = (uintptr_t)img->heap_mapping;
        if (backing && img->segs[i].size &&
            !(heap && backing >= heap && backing - heap < img->heap_capacity)) {
            munmap(img->segs[i].host, (size_t)img->segs[i].size);
        }
    }
    if (img->interp_mapping) {
        munmap(img->interp_mapping, (size_t)img->interp_mapping_size);
    }
    if (img->load_mapping) {
        munmap(img->load_mapping, (size_t)img->load_mapping_size);
    }
    if (img->heap_mapping) {
        munmap(img->heap_mapping, (size_t)img->heap_capacity);
    }
    if (img->fd >= 0) {
        close(img->fd);
    }
    memset(img, 0, sizeof(*img));
    img->fd = -1;
}

void *oah_guest_to_host(const oah_image *img, u64 gva, u64 len)
{
    unsigned i;
    if (!img || len == 0) {
        return 0;
    }
    if (gva + len < gva) {
        return 0;
    }
    for (i = 0; i < img->nseg; i++) {
        u64 s = img->segs[i].gva;
        u64 e = s + img->segs[i].size;
        if (gva >= s && gva + len <= e) {
            return img->segs[i].host + (gva - s);
        }
    }
    return 0;
}

const u8 *oah_guest_span(const oah_image *img, u64 gva, u64 *len)
{
    for (unsigned i = 0; i < img->nseg; i++) {
        const oah_load_seg *seg = &img->segs[i];
        /* Instruction fetch: x86 PROT_EXEC implies readable, so exec-only
         * segments (JIT'd code pools) are valid spans. */
        if ((seg->prot & (PROT_READ | PROT_EXEC)) && gva >= seg->gva &&
            gva - seg->gva < seg->size) {
            u64 offset = gva - seg->gva;
            u64 remaining = seg->size - offset;
            if (*len > remaining) {
                *len = remaining;
            }
            return seg->host + offset;
        }
    }
    return NULL;
}

const u8 *oah_guest_code(const oah_image *img, u64 gva, u64 *len, u8 *buf)
{
    u64 want = *len;
    const u8 *p = oah_guest_span(img, gva, &want);
    if (!p || want == *len) {
        return p;
    }
    /* An insn can straddle a seg boundary (code at the last byte of one
     * guest page continues into the next mapping). Copy across adjacent
     * exec-capable segs so the decoder sees the whole instruction. */
    u64 have = want;
    memcpy(buf, p, have);
    while (have < *len) {
        u64 n = *len - have;
        p = oah_guest_span(img, gva + have, &n);
        if (!p) {
            break;
        }
        memcpy(buf + have, p, n);
        have += n;
    }
    *len = have;
    return buf;
}

__thread bool oah_suppress_guest_stores;

static void *guest_access_lookup(const oah_image *img, u64 gva, u64 len, u32 prot)
{
    for (unsigned i = 0; img && i < img->nseg; i++) {
        const oah_load_seg *seg = &img->segs[i];
        if (len && gva >= seg->gva && gva - seg->gva < seg->size &&
            len <= seg->size - (gva - seg->gva) && (seg->prot & prot) == prot) {
            return seg->host + (gva - seg->gva);
        }
    }
    /* Accesses can straddle adjacent guest mappings (e.g. a 16-byte SSE
     * store spanning two mmaps). Allow the range when every byte is
     * covered and the host side is contiguous. */
    if (img && len && gva + len > gva) {
        u64 cur = gva, end = gva + len;
        u8 *first = NULL;
        while (cur < end) {
            const oah_load_seg *seg = NULL;
            for (unsigned i = 0; i < img->nseg; i++) {
                const oah_load_seg *s = &img->segs[i];
                if (cur >= s->gva && cur - s->gva < s->size &&
                    (s->prot & prot) == prot) {
                    seg = s;
                    break;
                }
            }
            if (!seg) {
                break;
            }
            u8 *h = seg->host + (cur - seg->gva);
            if (!first) {
                first = h;
            } else if (h != first + (cur - gva)) {
                break;
            }
            cur = seg->gva + seg->size;
        }
        if (cur >= end && first) {
            return first;
        }
    }
    if (getenv("OAH_SEG_DEBUG")) {
        fprintf(stderr, "access MISS gva=%llx len=%llu prot=%u nseg=%u heap=%p guard=%llx brk=%llx\n",
                (unsigned long long)gva, (unsigned long long)len, prot,
                img ? img->nseg : 0, img ? img->heap_mapping : 0,
                img ? (unsigned long long)img->heap_guard : 0,
                img ? (unsigned long long)img->brk : 0);

        for (unsigned i = 0; img && i < img->nseg; i++) {
            s64 delta = (s64)(img->segs[i].gva - gva);
            if (delta > -(s64)0x100000 && delta < (s64)0x100000) {
                fprintf(stderr, "  seg[%u] gva=%llx size=%llx prot=%x host=%p\n", i,
                        (unsigned long long)img->segs[i].gva,
                        (unsigned long long)img->segs[i].size,
                        img->segs[i].prot, img->segs[i].host);
            }
        }
    }
    return NULL;
}

void *oah_guest_access(const oah_image *img, u64 gva, u64 len, u32 prot)
{
    void *p = guest_access_lookup(img, gva, len, prot);
    if (p && (prot & PROT_WRITE) && oah_suppress_guest_stores) {
        /* The store already committed under the JIT; replaying it would
         * double-apply non-idempotent writes (RMWs, pushes). Return a
         * scratch buffer pre-filled with the real bytes: callers that
         * read through this pointer (RMW semantics) still compute the
         * right register state, while their writes are absorbed. The
         * mapping check above still ran, so unmapped writes fault
         * exactly as they would unsuppressed. */
        static __thread u8 scratch[256];
        if (len > sizeof(scratch)) {
            return p;
        }
        memcpy(scratch, p, len);
        return scratch;
    }
    return p;
}

#if defined(__linux__)
int oah_sysroot_open(const char *sysroot, const char *path, int flags, u32 mode)
{
    int root = open(sysroot, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) {
        return -1;
    }
    struct open_how options = {
        .flags = (u64)flags,
        .mode = (flags & O_CREAT) ? mode : 0,
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
    };
    int fd = (int)syscall(SYS_openat2, root, path, &options, sizeof(options));
    int error = errno;
    close(root);
    errno = error;
    return fd;
}
#elif defined(__APPLE__)
/* Walk `path` under `root` like Linux RESOLVE_IN_ROOT: ".." is clamped
 * at root, intermediate components fully resolve, and absolute symlink
 * targets re-anchor at root instead of escaping to the host fs.
 * With leaf_follow a trailing symlink resolves too; otherwise the leaf
 * stays literal (lstat semantics, for rename/unlink/lstat callers).
 * Nonexistent leaf components are appended literally so O_CREAT and
 * mkdir land in the right directory. Returns 0 or -errno. */
/* Guest-visible path of the running executable, for /proc/self/exe. */
static char oah_proc_self_exe_path[PATH_MAX];

const char *oah_proc_self_exe(void)
{
    return oah_proc_self_exe_path;
}

static int resolve_in_root(const char *root, const char *path, char *out,
                           size_t cap, bool leaf_follow)
{
    char pending[PATH_MAX * 2];
    size_t root_len = strlen(root);
    if (snprintf(pending, sizeof(pending), "%s", path) >=
        (int)sizeof(pending) || root_len + 2 > cap) {
        return -ENAMETOOLONG;
    }
    strcpy(out, root);
    /* Paths a guest already resolved once (dpkg hands debconf a
     * host-rooted maintainer-script path) get re-anchored to
     * guest-absolute instead of nesting beneath the root. */
    {
        size_t plen = strlen(pending);
        if (plen > root_len && !strncmp(pending, root, root_len) &&
            pending[root_len] == '/') {
            memmove(pending, pending + root_len, plen - root_len + 1);
        }
    }
    /* /proc/self/exe is synthesized per process — substitute the mapped
     * executable's guest path so open/stat land on the real file. */
    if (oah_proc_self_exe_path[0] &&
        (!strcmp(pending, "/proc/self/exe") ||
         !strcmp(pending, "/proc/thread-self/exe"))) {
        snprintf(pending, sizeof(pending), "%s", oah_proc_self_exe_path);
    }
    int links = 0;
    while (*pending) {
        char *p = pending;
        while (*p == '/') { p++; }
        if (!*p) { break; }
        char *slash = strchr(p, '/');
        bool last = !slash;
        if (slash) { *slash = 0; }
        char *rest = slash ? slash + 1 : p + strlen(p);
        if (!strcmp(p, ".")) {
            memmove(pending, rest, strlen(rest) + 1);
            continue;
        }
        if (!strcmp(p, "..")) {
            size_t out_len = strlen(out);
            if (out_len > root_len) {
                char *s = strrchr(out, '/');
                *s = 0;
                if (!out[0]) { strcpy(out, "/"); }
            }
            memmove(pending, rest, strlen(rest) + 1);
            continue;
        }
        char cand[PATH_MAX];
        if (snprintf(cand, sizeof(cand), "%s/%s", out, p) >=
            (int)sizeof(cand)) {
            return -ENAMETOOLONG;
        }
        struct stat st;
        bool exists = lstat(cand, &st) == 0;
        if (exists && S_ISLNK(st.st_mode) && (!last || leaf_follow)) {
            if (++links > 40) { return -ELOOP; }
            char target[PATH_MAX];
            ssize_t n = readlink(cand, target, sizeof(target) - 1);
            if (n < 0) { return -errno; }
            target[n] = 0;
            if (target[0] == '/') {
                /* Re-anchor at root: absolute targets stay in the root. */
                out[root_len] = 0;
            }
            /* rest aliases pending — compose in a separate buffer. */
            char next[PATH_MAX * 2];
            if (snprintf(next, sizeof(next), "%s%s%s", target,
                         *rest ? "/" : "", rest) >= (int)sizeof(next)) {
                return -ENAMETOOLONG;
            }
            strcpy(pending, next);
            continue;
        }
        if (!exists && !last) { return -ENOENT; }
        if (exists && !S_ISDIR(st.st_mode) && !last) { return -ENOTDIR; }
        size_t out_len = strlen(out);
        if (out_len + 1 + strlen(p) + 1 > cap) { return -ENAMETOOLONG; }
        out[out_len] = '/';
        strcpy(out + out_len + 1, p);
        memmove(pending, rest, strlen(rest) + 1);
    }
    return 0;
}

int oah_sysroot_open(const char *sysroot, const char *path, int flags, u32 mode)
{
    char root[PATH_MAX], resolved[PATH_MAX];
    if (path[0] != '/' || !realpath(sysroot, root)) {
        errno = EINVAL;
        return -1;
    }
    int rc = resolve_in_root(root, path, resolved, sizeof(resolved), true);
    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return open(resolved, flags | O_NOFOLLOW, (mode_t)mode);
}

/* Same as oah_sysroot_open but returns the host path, following the leaf
 * symlink too — for read calls (stat without NOFOLLOW, access, chdir) that
 * follow links and need the target resolved inside the root. */
bool oah_sysroot_readpath(const char *sysroot, const char *path,
                          char *resolved, size_t capacity)
{
    char root[PATH_MAX];
    if (path[0] != '/' || !realpath(sysroot, root)) {
        return false;
    }
    int rc = resolve_in_root(root, path, resolved, capacity, true);
    if (rc < 0) {
        errno = -rc;
        return false;
    }
    return true;
}

/* Same resolution as oah_sysroot_open but returns the host path for calls
 * that take paths (mkdirat, renameat, ...) rather than fds. */
bool oah_sysroot_hostpath(const char *sysroot, const char *path,
                          char *resolved, size_t capacity)
{
    char root[PATH_MAX];
    if (path[0] != '/' || !realpath(sysroot, root)) {
        errno = EINVAL;
        return false;
    }
    /* Resolve only the parent directory: the leaf must keep lstat
     * semantics so mutating calls (rename, unlink, lstat) never follow a
     * symlink to its target. Intermediate components resolve, with
     * absolute symlink targets re-anchored inside the root. */
    int rc = resolve_in_root(root, path, resolved, capacity, false);
    if (rc < 0) {
        errno = -rc;
        return false;
    }
    size_t root_len = strlen(root);
    return strcmp(root, "/") == 0 ||
           (strncmp(resolved, root, root_len) == 0 &&
            (resolved[root_len] == '/' || resolved[root_len] == 0));
}
/* Resolve the guest program without passing a guest script to a host shell. */
bool oah_darwin_resolve_program(oah_darwin_program *program, const char *sysroot,
                               const char *path, bool guest_exec)
{
    program->depth = 0;
    /* dpkg -> debconf can hand us an already-rooted maintainer-script
     * path; re-anchor it as a guest path beneath the sysroot. */
    if (guest_exec && sysroot && path[0] == '/' && getenv("OAH_SYSROOT_STRICT")) {
        size_t root_len = strlen(sysroot);
        if (!strncmp(path, sysroot, root_len) && path[root_len] == '/') {
            path += root_len;
        }
    }
    for (;;) {
        char *resolved = program->executable;
        int fd = -1;
        if (guest_exec && sysroot && path[0] == '/') {
            fd = oah_sysroot_open(sysroot, path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
            if (fd < 0 && errno != ENOENT && errno != ENOTDIR) {
                return false;
            }
        }
        if (fd < 0) {
            /* Strict sysroot mode: a missing guest program is ENOENT, never
             * a host fallback to a same-named host binary. */
            if (guest_exec && sysroot && getenv("OAH_SYSROOT_STRICT")) {
                errno = ENOENT;
                return false;
            }
            fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        }
        if (fd < 0) {
            return false;
        }
        struct stat st;
        char bytes[256];
        ssize_t length = -1;
        int error = 0;
        if (fstat(fd, &st) < 0 || fcntl(fd, F_GETPATH, resolved) < 0) {
            error = errno;
        } else if (!S_ISREG(st.st_mode) || (guest_exec && access(resolved, X_OK) < 0)) {
            error = EACCES;
        } else {
            length = pread(fd, bytes, sizeof(bytes), 0);
            if (length < 0) {
                error = errno;
            }
        }
        close(fd);
        if (error) {
            errno = error;
            return false;
        }
        if (length >= 2 && bytes[0] == '#' && bytes[1] == '!') {
            if (program->depth == OAH_SCRIPT_DEPTH) {
                errno = ELOOP;
                return false;
            }
            unsigned depth = program->depth++;
            char *line = program->scripts[depth].directive;
            const char *newline = memchr(bytes, '\n', length);
            size_t size = newline ? (size_t)(newline - bytes) : (size_t)length;
            if (size >= sizeof(bytes)) {
                errno = ENOEXEC;
                return false;
            }
            memcpy(line, bytes, size);
            while (size > 2 && (line[size - 1] == ' ' || line[size - 1] == '\t')) {
                size--;
            }
            line[size] = 0;
            char *interpreter = line + 2 + strspn(line + 2, " \t");
            if (!*interpreter) {
                errno = ENOEXEC;
                return false;
            }
            char *option = interpreter + strcspn(interpreter, " \t");
            if (*option) {
                *option++ = 0;
                option += strspn(option, " \t");
            }
            /* Script paths become guest-visible arguments ($0, argv[0]):
             * report the guest path, not the host-rooted one. */
            {
                const char *guest_path = resolved;
                if (sysroot) {
                    size_t rl = strlen(sysroot);
                    if (!strncmp(guest_path, sysroot, rl) &&
                        guest_path[rl] == '/') {
                        guest_path += rl;
                    }
                }
                strcpy(program->scripts[depth].path, guest_path);
            }
            program->scripts[depth].interpreter = interpreter;
            program->scripts[depth].option = *option ? option : NULL;
            path = interpreter;
            guest_exec = true;
            continue;
        }
        Elf64_Ehdr header;
        if (length >= (ssize_t)sizeof(header)) {
            memcpy(&header, bytes, sizeof(header));
            if (!memcmp(header.e_ident, ELFMAG, SELFMAG) &&
                header.e_ident[EI_CLASS] == ELFCLASS64 &&
                header.e_ident[EI_DATA] == ELFDATA2LSB && header.e_machine == EM_X86_64) {
                return true;
            }
        }
        errno = ENOEXEC;
        return false;
    }
}

size_t oah_darwin_program_prefix(oah_darwin_program *program, char **argv)
{
    unsigned depth = program->depth;
    if (!depth) {
        return 0;
    }
    size_t count = 0;
    argv[count++] = program->scripts[depth - 1].interpreter;
    while (depth) {
        depth--;
        if (program->scripts[depth].option) {
            argv[count++] = program->scripts[depth].option;
        }
        argv[count++] = program->scripts[depth].path;
    }
    return count;
}

#endif

static bool map_elf_fd(oah_image *img, int fd, char *interp, u64 *bias)
{
    Elf64_Ehdr eh;
    Elf64_Phdr ph[128];
    struct stat st;
    long host_page = sysconf(_SC_PAGESIZE);
    u64 mask, ph_bytes, low = UINT64_MAX, high = 0, phdr = 0;
    bool has_headers = false;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    u8 *pages = NULL;
    bool success = false;

    int open_error = fd < 0 ? errno : 0;
    errno = 0;
    memset(img, 0, sizeof(*img));
    img->fd = fd;
    if (fd < 0) {
        errno = open_error;
        return false;
    }
    if (host_page <= 0 || (host_page & (host_page - 1))) {
        goto done;
    }
#if defined(__APPLE__)
    const bool software_pages = true;
#else
    const bool software_pages = false;
#endif
    u64 image_page = software_pages ? OAH_X86_PAGE_SIZE : (u64)host_page;
    mask = image_page - 1;
    if (fstat(img->fd, &st) != 0 ||
        pread(img->fd, &eh, sizeof(eh), 0) != sizeof(eh)) {
        goto done;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_machine != EM_X86_64 || eh.e_version != EV_CURRENT ||
        (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        eh.e_phnum > sizeof(ph) / sizeof(ph[0])) {
        goto done;
    }
    ph_bytes = (u64)eh.e_phnum * sizeof(ph[0]);
    if (eh.e_phoff > (u64)st.st_size || ph_bytes > (u64)st.st_size - eh.e_phoff ||
        pread(img->fd, ph, ph_bytes, (off_t)eh.e_phoff) != (ssize_t)ph_bytes) {
        goto done;
    }
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        const Elf64_Phdr *seg = &ph[i];
        if (seg->p_type == PT_INTERP) {
            if (!interp) {
                errno = ENOTSUP;
                goto done;
            }
            if (*interp || seg->p_filesz < 2 || seg->p_filesz > PATH_MAX ||
                seg->p_offset > (u64)st.st_size ||
                seg->p_filesz > (u64)st.st_size - seg->p_offset ||
                pread(fd, interp, seg->p_filesz, (off_t)seg->p_offset) !=
                    (ssize_t)seg->p_filesz ||
                interp[0] != '/' || memchr(interp, 0, seg->p_filesz) !=
                    interp + seg->p_filesz - 1) {
                errno = ENOEXEC;
                goto done;
            }
        }
        if (seg->p_type != PT_LOAD) {
            continue;
        }
        if (seg->p_memsz < seg->p_filesz || seg->p_offset > (u64)st.st_size ||
            seg->p_filesz > (u64)st.st_size - seg->p_offset ||
            seg->p_vaddr > UINT64_MAX - mask ||
            seg->p_memsz > UINT64_MAX - mask - seg->p_vaddr ||
            (seg->p_align > 1 && ((seg->p_align & (seg->p_align - 1)) ||
             ((seg->p_vaddr ^ seg->p_offset) & (seg->p_align - 1))))) {
            goto done;
        }
        if (!seg->p_memsz) {
            continue;
        }
        for (unsigned j = 0; j < i; j++) {
            const Elf64_Phdr *prior = &ph[j];
            if (prior->p_type == PT_LOAD && prior->p_memsz &&
                seg->p_vaddr < prior->p_vaddr + prior->p_memsz &&
                prior->p_vaddr < seg->p_vaddr + seg->p_memsz) {
                goto done;
            }
        }
        u64 start = seg->p_vaddr & ~mask;
        u64 end = (seg->p_vaddr + seg->p_memsz + mask) & ~mask;
        if (start < low) {
            low = start;
        }
        if (end > high) {
            high = end;
        }
        if (eh.e_phoff >= seg->p_offset &&
            eh.e_phoff - seg->p_offset <= seg->p_filesz &&
            ph_bytes <= seg->p_filesz - (eh.e_phoff - seg->p_offset)) {
            phdr = seg->p_vaddr + (eh.e_phoff - seg->p_offset);
            has_headers = true;
        }
    }
    if (low >= high || !has_headers || eh.e_entry < low || eh.e_entry >= high ||
        high - low > (1ull << 30)) {
        goto done;
    }

#if defined(MAP_FIXED_NOREPLACE)
    if (eh.e_type == ET_EXEC) {
        flags |= MAP_FIXED_NOREPLACE;
    }
#endif
    u64 span = high - low;
#if defined(__APPLE__)
    /* The brk heap is always identity-reserved on Darwin so translated
     * fragments can address it with raw guest pointers. */
    u64 heap_reserve = 64u << 20;
#else
    u64 heap_reserve = interp && *interp ? (64u << 20) : 0;
#endif
    u64 host_mask = (u64)host_page - 1;
    u64 allocation = (span + host_mask) & ~host_mask;
    bool identity_required = !software_pages && eh.e_type == ET_EXEC;
    int initial_prot = software_pages ? PROT_READ | PROT_WRITE : PROT_NONE;
    u8 *map = mmap(identity_required ? (void *)(uintptr_t)low : NULL,
                   allocation + heap_reserve, initial_prot, flags, -1, 0);
    if (map == MAP_FAILED) {
        goto done;
    }
    img->load_mapping = map;
    img->load_mapping_size = allocation;
    img->load_gva = eh.e_type == ET_EXEC ? low : (u64)(uintptr_t)map;
    if (heap_reserve) {
        img->heap_mapping = map + allocation;
        img->heap_capacity = heap_reserve;
    }
    if (identity_required && (u64)(uintptr_t)map != low) {
        goto done;
    }
    u64 page_count = span / image_page;
    pages = calloc(page_count, 1);
    if (!pages) {
        goto done;
    }
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        const Elf64_Phdr *seg = &ph[i];
        if (seg->p_type != PT_LOAD || !seg->p_memsz) {
            continue;
        }
        u64 offset = seg->p_vaddr - low;
        u64 start = offset & ~mask;
        u64 end = (offset + seg->p_memsz + mask) & ~mask;
        if ((!software_pages && mprotect(map + start, end - start, PROT_READ | PROT_WRITE) != 0) ||
            (seg->p_filesz &&
             pread(img->fd, map + offset, seg->p_filesz, (off_t)seg->p_offset) !=
                 (ssize_t)seg->p_filesz)) {
            goto done;
        }
        for (u64 p = start / image_page; p < end / image_page; p++) {
            pages[p] |= (u8)(prot_from_ph(seg->p_flags) | 0x80);
        }
    }

    for (u64 first = 0; first < page_count;) {
        u64 end = first + 1;
        while (end < page_count && pages[end] == pages[first]) {
            end++;
        }
        if (pages[first]) {
            u8 *host = map + first * image_page;
            u64 size = (end - first) * image_page;
            u32 prot = pages[first] & 0x7f;
            /* Execute permission is guest metadata. The host executes translated code. */
            if (img->nseg == OAH_MAX_LOAD_SEGS ||
                (!software_pages && mprotect(host, size, prot & ~PROT_EXEC) != 0)) {
                goto done;
            }
            img->segs[img->nseg++] = (oah_load_seg){
                .gva = img->load_gva + first * image_page, .size = size,
                .host = host, .prot = prot, .module = -1
            };
            img->load_segments = img->nseg;
        }
        first = end;
    }
    img->entry = img->load_gva + (eh.e_entry - low);
    img->phdr = img->load_gva + (phdr - low);
    img->phnum = eh.e_phnum;
    img->phentsize = eh.e_phentsize;
    img->load_end = img->load_gva + span;
    img->brk = img->load_end;
#if defined(__APPLE__)
    if (img->heap_mapping) {
        img->brk = (u64)(uintptr_t)img->heap_mapping;
    }
#endif
    success = oah_guest_access(img, img->entry, 1, PROT_EXEC) != NULL;
    if (success) {
        if (bias) {
            *bias = img->load_gva - low;
        }
        close(img->fd);
        img->fd = -1;
    }

done:
    free(pages);
    if (!success) {
        int error = errno;
        oah_unmap_elf(img);
        errno = error;
    }
    return success;
}

bool oah_map_elf_sysroot(oah_image *img, const char *path, const char *sysroot)
{
    char interp_path[PATH_MAX] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    char exe_host[PATH_MAX];
    exe_host[0] = 0;
#if defined(__APPLE__)
    if (fd >= 0) {
        (void)fcntl(fd, F_GETPATH, exe_host);
    }
#endif
    if (!map_elf_fd(img, fd, sysroot ? interp_path : NULL, NULL)) {
        return false;
    }
    if (sysroot) {
        /* Anchor the sysroot as an absolute path so it stays valid after
         * the guest chdirs (strict mode confines relative paths too). */
        char abs[PATH_MAX];
        img->sysroot = realpath(sysroot, abs) ? strdup(abs) : sysroot;
        /* /proc/self/exe reports the guest path, not the host-rooted one
         * the launcher passed. */
        const char *exe = exe_host[0] ? exe_host : path;
        size_t root_len = strlen(img->sysroot);
        if (!strncmp(exe, img->sysroot, root_len) &&
            (exe[root_len] == '/' || !exe[root_len])) {
            exe += root_len;
            if (!*exe) { exe = "/"; }
        }
        snprintf(oah_proc_self_exe_path, sizeof(oah_proc_self_exe_path),
                 "%s", exe);
    }
    int module = oah_image_module_register(
        img, exe_host[0] ? exe_host : path);
    if (module >= 0) {
        oah_image_tag_module(img, img->load_gva, img->load_end - img->load_gva,
                             module);
    }
    if (!*interp_path) {
        return true;
    }

    oah_image interpreter;
    fd = oah_sysroot_open(sysroot, interp_path, O_RDONLY | O_CLOEXEC, 0);
    char interp_host[PATH_MAX];
    interp_host[0] = 0;
#if defined(__APPLE__)
    if (fd >= 0) {
        (void)fcntl(fd, F_GETPATH, interp_host);
    }
#endif
    if (!map_elf_fd(&interpreter, fd, NULL, &img->interp_base)) {
        int error = errno;
        oah_unmap_elf(img);
        errno = error ? error : ENOEXEC;
        return false;
    }
    if (interpreter.nseg > OAH_MAX_LOAD_SEGS - img->nseg) {
        oah_unmap_elf(&interpreter);
        oah_unmap_elf(img);
        errno = ENOMEM;
        return false;
    }
    memcpy(img->segs + img->nseg, interpreter.segs,
           interpreter.nseg * sizeof(interpreter.segs[0]));
    img->nseg += interpreter.nseg;
    img->load_segments = img->nseg;
    module = oah_image_module_register(
        img, interp_host[0] ? interp_host : interp_path);
    if (module >= 0) {
        u64 lo = ~(u64)0, hi = 0;
        for (unsigned i = 0; i < interpreter.nseg; i++) {
            u64 g = interpreter.segs[i].gva;
            if (g < lo) {
                lo = g;
            }
            if (g + interpreter.segs[i].size > hi) {
                hi = g + interpreter.segs[i].size;
            }
        }
        oah_image_tag_module(img, lo, hi - lo, module);
    }
    img->interp_mapping = interpreter.load_mapping;
    img->interp_mapping_size = interpreter.load_mapping_size;
    img->interp_entry = interpreter.entry;
    return true;
}

bool oah_map_elf(oah_image *img, const char *path)
{
    return oah_map_elf_sysroot(img, path, NULL);
}
