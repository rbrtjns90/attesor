#include "oah/elf_map.h"
#include "test_common.h"

#include <elf.h>
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
        oah_unmap_elf(&img);

        fd = open(path, O_RDWR);
        Elf64_Ehdr header;
        Elf64_Phdr segment;
        CHECK(fd >= 0);
        CHECK(pread(fd, &header, sizeof(header), 0) == sizeof(header));
        CHECK(pread(fd, &segment, sizeof(segment), header.e_phoff) == sizeof(segment));
        Elf64_Phdr original = segment;

        void *collision = mmap((void *)(uintptr_t)segment.p_vaddr, 4096,
                               PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(collision == (void *)(uintptr_t)segment.p_vaddr);
        if (collision != MAP_FAILED) {
            *(u8 *)collision = 0x5a;
            CHECK(!oah_map_elf(&img, path));
            CHECK_EQ_U64(*(u8 *)collision, 0x5a);
            munmap(collision, 4096);
        }

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

        CHECK(ftruncate(fd, 8) == 0);
        CHECK(!oah_map_elf(&img, path));
        close(fd);
        unlink(path);
    }

    return test_report("elf_map");
}
