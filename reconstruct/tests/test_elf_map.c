#include "oah/elf_map.h"
#include "test_common.h"

#include "oah/elf_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    {
        oah_image img;
        CHECK(!oah_map_elf(&img, "/no/such/file"));
    }

    if (access("bin/rosetta", R_OK) == 0) {
        oah_image img;
        CHECK(!oah_map_elf(&img, "bin/rosetta"));
    }

    {
        char path[] = "/tmp/oah-helloXXXXXX";
        char cmd[256];
        int fd = mkstemp(path);
        oah_image img;
        CHECK(fd >= 0);
        close(fd);
        snprintf(cmd, sizeof(cmd), "python3 tools/mk_hello_elf.py %s", path);
        CHECK_EQ_U64((u64)system(cmd), 0);
        CHECK(oah_map_elf(&img, path));
        CHECK(img.nseg >= 1);
        CHECK_EQ_U64(img.segs[0].gva, 0x400000);
        CHECK(oah_guest_to_host(&img, img.entry, 2) != 0);
        CHECK(oah_guest_access(&img, img.entry, 2, PROT_WRITE) == NULL);
#if defined(__APPLE__)
        CHECK(img.load_gva != (u64)(uintptr_t)img.load_mapping);
        CHECK(img.load_mapping_size >= (u64)sysconf(_SC_PAGESIZE));
#endif
        oah_unmap_elf(&img);

        fd = open(path, O_RDWR);
        Elf64_Ehdr header;
        Elf64_Phdr segment;
        CHECK(fd >= 0);
        CHECK(pread(fd, &header, sizeof(header), 0) == sizeof(header));
        CHECK(pread(fd, &segment, sizeof(segment), header.e_phoff) == sizeof(segment));
        Elf64_Phdr original = segment;

#if !defined(__APPLE__)
        void *collision = mmap((void *)(uintptr_t)segment.p_vaddr, 4096,
                               PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(collision == (void *)(uintptr_t)segment.p_vaddr);
        if (collision != MAP_FAILED) {
            *(u8 *)collision = 0x5a;
            CHECK(!oah_map_elf(&img, path));
            CHECK_EQ_U64(*(u8 *)collision, 0x5a);
            munmap(collision, 4096);
        }
#endif

        segment.p_memsz = segment.p_filesz + 8192;
        segment.p_flags |= PF_W;
        CHECK(pwrite(fd, &segment, sizeof(segment), header.e_phoff) == sizeof(segment));
        CHECK(oah_map_elf(&img, path));
        u8 *bss = oah_guest_access(&img, segment.p_vaddr + segment.p_filesz, 8192, PROT_WRITE);
        CHECK(bss != NULL);
        if (bss) {
            const u8 zeros[8192] = {0};
            CHECK(memcmp(bss, zeros, sizeof(zeros)) == 0);
        }
        oah_unmap_elf(&img);

        segment = original;
        segment.p_filesz += 1;
        segment.p_memsz += 1;
        CHECK(pwrite(fd, &segment, sizeof(segment), header.e_phoff) == sizeof(segment));
        CHECK(!oah_map_elf(&img, path));
        CHECK_EQ_U64(img.nseg, 0);

        segment = original;
        segment.p_type = PT_INTERP;
        CHECK(pwrite(fd, &segment, sizeof(segment), header.e_phoff) == sizeof(segment));
        CHECK(!oah_map_elf(&img, path));
        CHECK_EQ_U64(errno, ENOTSUP);

        /* Adjacent Linux pages may share one Darwin backing page. */
        header.e_phnum = 2;
        header.e_entry = original.p_vaddr + 256;
        Elf64_Phdr pages[2] = {original, original};
        pages[0].p_filesz = pages[0].p_memsz = OAH_X86_PAGE_SIZE;
        pages[1].p_offset = OAH_X86_PAGE_SIZE;
        pages[1].p_vaddr += OAH_X86_PAGE_SIZE;
        pages[1].p_flags = PF_R | PF_W;
        pages[1].p_filesz = pages[1].p_memsz = OAH_X86_PAGE_SIZE;
        CHECK(ftruncate(fd, 2 * OAH_X86_PAGE_SIZE) == 0);
        CHECK(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
        CHECK(pwrite(fd, pages, sizeof(pages), header.e_phoff) == sizeof(pages));
        CHECK(oah_map_elf(&img, path));
        void *code = oah_guest_access(&img, img.entry, 1, PROT_EXEC);
        void *data = oah_guest_access(&img, pages[1].p_vaddr, 1, PROT_WRITE);
        CHECK(code != NULL && data != NULL);
        CHECK(oah_guest_access(&img, img.entry, 1, PROT_WRITE) == NULL);
        CHECK(oah_guest_access(&img, pages[1].p_vaddr, 1, PROT_EXEC) == NULL);
#if defined(__APPLE__)
        uintptr_t host_page = (uintptr_t)sysconf(_SC_PAGESIZE);
        if (host_page >= 2 * OAH_X86_PAGE_SIZE && code && data) {
            uintptr_t host_mask = ~(host_page - 1);
            CHECK_EQ_U64((uintptr_t)code & host_mask, (uintptr_t)data & host_mask);
        }
#endif
        oah_unmap_elf(&img);

        CHECK(ftruncate(fd, 8) == 0);
        CHECK(!oah_map_elf(&img, path));
        close(fd);
        unlink(path);
    }

    return test_report("elf_map");
}
