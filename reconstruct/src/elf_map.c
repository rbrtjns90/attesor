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
        if ((seg->prot & PROT_READ) && gva >= seg->gva && gva - seg->gva < seg->size) {
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

void *oah_guest_access(const oah_image *img, u64 gva, u64 len, u32 prot)
{
    for (unsigned i = 0; img && i < img->nseg; i++) {
        const oah_load_seg *seg = &img->segs[i];
        if (len && gva >= seg->gva && gva - seg->gva < seg->size &&
            len <= seg->size - (gva - seg->gva) && (seg->prot & prot) == prot) {
            return seg->host + (gva - seg->gva);
        }
    }
    return NULL;
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
int oah_sysroot_open(const char *sysroot, const char *path, int flags, u32 mode)
{
    char root[PATH_MAX], request[PATH_MAX], resolved[PATH_MAX];
    if (path[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (!realpath(sysroot, root)) {
        return -1;
    }
    int length = snprintf(request, sizeof(request), "%s%s", root, path);
    if (length < 0 || (size_t)length >= sizeof(request)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!realpath(request, resolved)) {
        return -1;
    }
    size_t root_len = strlen(root);
    if (strcmp(root, "/") != 0 &&
        (strncmp(resolved, root, root_len) != 0 ||
         (resolved[root_len] != '/' && resolved[root_len] != 0))) {
        errno = EACCES;
        return -1;
    }
    return open(resolved, flags | O_NOFOLLOW, (mode_t)mode);
}
/* Resolve the guest program without passing a guest script to a host shell. */
bool oah_darwin_resolve_program(oah_darwin_program *program, const char *sysroot,
                               const char *path, bool guest_exec)
{
    program->depth = 0;
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
            strcpy(program->scripts[depth].path, resolved);
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
             ((seg->p_vaddr ^ seg->p_offset) & (seg->p_align - 1)) ||
             (eh.e_type == ET_DYN && seg->p_align > image_page)))) {
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
    u64 heap_reserve = interp && *interp ? (64u << 20) : 0;
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
                .gva = img->load_gva + first * image_page, .size = size, .host = host, .prot = prot
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
    if (!map_elf_fd(img, fd, sysroot ? interp_path : NULL, NULL)) {
        return false;
    }
    img->sysroot = sysroot;
    if (!*interp_path) {
        return true;
    }

    oah_image interpreter;
    fd = oah_sysroot_open(sysroot, interp_path, O_RDONLY | O_CLOEXEC, 0);
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
    img->interp_mapping = interpreter.load_mapping;
    img->interp_mapping_size = interpreter.load_mapping_size;
    img->interp_entry = interpreter.entry;
    return true;
}

bool oah_map_elf(oah_image *img, const char *path)
{
    return oah_map_elf_sysroot(img, path, NULL);
}
