#include "oah/assembler.h"
#include "oah/elf_map.h"
#include "oah/guest.h"
#include "oah/translate.h"
#include "test_common.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void image_identity(oah_image *img, u8 *buf, size_t n)
{
    memset(img, 0, sizeof(*img));
    img->fd = -1;
    img->nseg = 1;
    img->segs[0].gva = (u64)(uintptr_t)buf;
    img->segs[0].size = n;
    img->segs[0].host = buf;
    img->segs[0].prot = PROT_READ | PROT_EXEC;
    img->entry = (u64)(uintptr_t)buf;
    img->load_end = img->entry + n;
    img->brk = img->load_end;
}

static void test_nested_calls(bool native)
{
    u8 code[] = {
        0xb8, 1, 0, 0, 0,        /* mov eax,1 */
        0xe8, 1, 0, 0, 0,        /* call outer */
        0xcc,                    /* stop after returning */
        0xe8, 1, 0, 0, 0,        /* outer: call inner */
        0xc3,                    /* ret */
        0xb8, 42, 0, 0, 0,       /* inner: mov eax,42 */
        0xc3                     /* ret */
    };
    u8 stack[32] = {0};
    u64 top = (u64)(uintptr_t)(stack + sizeof(stack));
    oah_image img;
    oah_guest g;
    oah_interp_result result;
    u64 return_address;

    image_identity(&img, code, sizeof(code));
    img.segs[1] = (oah_load_seg){.gva = (u64)(uintptr_t)stack,
                                .size = sizeof(stack), .host = stack,
                                .prot = PROT_READ | PROT_WRITE};
    img.nseg = 2;
    oah_guest_init(&g, img.entry, top);
    result = native ? oah_jit_run_native(&g, &img, 100)
                    : oah_jit_run(&g, &img, 100);
    CHECK_EQ_U64(result.status, OAH_INTERP_DECODE);
    CHECK_EQ_U64(g.rip, img.entry + 10);
    CHECK_EQ_U64(g.gpr[OAH_X86_RAX], 42);
    CHECK_EQ_U64(g.gpr[OAH_X86_RSP], top);
    memcpy(&return_address, stack + sizeof(stack) - 16, sizeof(return_address));
    CHECK_EQ_U64(return_address, img.entry + 16);

    oah_guest_init(&g, img.entry + 5, 0);
    result = oah_jit_run(&g, &img, 100);
    CHECK_EQ_U64(result.status, OAH_INTERP_FAULT);
    CHECK_EQ_U64(g.rip, img.entry + 5);
    CHECK_EQ_U64(g.gpr[OAH_X86_RSP], 0);

    img.segs[0].size = 6; /* Only the opcode byte of the first CALL is mapped. */
    oah_guest_init(&g, img.entry, top);
    result = oah_jit_run(&g, &img, 100);
    CHECK_EQ_U64(result.status, OAH_INTERP_DECODE);
    CHECK_EQ_U64(g.rip, img.entry + 5);
    CHECK_EQ_U64(g.gpr[OAH_X86_RSP], top);
}

static void test_flag_branches(bool native)
{
    u8 code[] = {
        0xb8, 0, 0, 0, 0x80,        /* mov eax,0x80000000 */
        0x83, 0xf8, 1,             /* cmp eax,1 (OF=1, SF=0, CF=0) */
        0x0f, 0x8c, 1, 0, 0, 0,    /* jl .signed_less */
        0xcc,
        0x72, 12,                  /* .signed_less: jb (must fall through) */
        0x31, 0xc0,                /* xor eax,eax (ZF=PF=1, OF=CF=0) */
        0x7b, 8,                   /* jnp (must fall through) */
        0x75, 6,                   /* jne (must fall through) */
        0xb8, 42, 0, 0, 0,         /* mov eax,42 */
        0xcc,
        0xcc
    };
    oah_image img;
    oah_guest g;
    oah_interp_result result;

    image_identity(&img, code, sizeof(code));
    oah_guest_init(&g, img.entry, 0);
    result = native ? oah_jit_run_native(&g, &img, 100)
                    : oah_jit_run(&g, &img, 100);
    CHECK_EQ_U64(result.status, OAH_INTERP_DECODE);
    CHECK_EQ_U64(g.rip, img.entry + 28);
    CHECK_EQ_U64(g.gpr[OAH_X86_RAX], 42);
}

static void test_checked_memory(bool native)
{
    u8 code[] = {
        0x64, 0x48, 0x8b, 0x04, 0x25, 0x08, 0, 0, 0, /* mov rax,fs:[8] */
        0x48, 0x89, 0x44, 0xcf, 0x08,               /* mov [rdi+rcx*8+8],rax */
        0xcc
    };
    u64 memory[] = {0, 42, 0, 0};
    oah_image img;
    oah_guest guest;
    oah_interp_result result;
    image_identity(&img, code, sizeof(code));
    img.segs[1] = (oah_load_seg){.gva = 0x1000, .size = sizeof(memory),
                                .host = (u8 *)memory, .prot = PROT_READ | PROT_WRITE};
    img.nseg = 2;
    oah_guest_init(&guest, img.entry, 0);
    guest.fs_base = 0x1000;
    guest.gpr[OAH_X86_RDI] = 0x1000;
    guest.gpr[OAH_X86_RCX] = 2;
    result = native ? oah_jit_run_native(&guest, &img, 32) : oah_jit_run(&guest, &img, 32);
    CHECK_EQ_U64(result.status, OAH_INTERP_DECODE);
    CHECK_EQ_U64(guest.rip, img.entry + sizeof(code) - 1);
    CHECK_EQ_U64(memory[3], 42);
    img.segs[1].prot = PROT_READ;
    memory[3] = 0;
    guest.rip = img.entry;
    result = native ? oah_jit_run_native(&guest, &img, 32) : oah_jit_run(&guest, &img, 32);
    CHECK_EQ_U64(result.status, OAH_INTERP_FAULT);
    CHECK_EQ_U64(guest.rip, img.entry + 9);
    CHECK_EQ_U64(memory[3], 0);

    guest.gpr[OAH_X86_RAX] = OAH_X86_NR_READ;
    guest.gpr[OAH_X86_RSI] = 0x1000;
    guest.gpr[OAH_X86_RDX] = 1;
    CHECK_EQ_U64(oah_guest_syscall(&guest, &img), OAH_SYS_CONTINUE);
    CHECK_EQ_U64(guest.gpr[OAH_X86_RAX], (u64)(s64)-EFAULT);
}

int main(void)
{
    {
        u8 bytes[] = {0xb8, 0x01, 0x00, 0x00, 0x00, 0x90}; /* mov eax,1; nop */
        oah_image img;
        oah_asm_buf buf;
        u32 first;
        u64 next = 0;
        image_identity(&img, bytes, sizeof(bytes));
        oah_asm_buf_init(&buf);
        CHECK(oah_translate_block(&buf, &img, (u64)(uintptr_t)bytes, &next));
        CHECK(buf.size >= 8);
        memcpy(&first, buf.data, 4);
        CHECK_EQ_U64(first, 0x52800028u); /* movz w8, #1 */
        oah_asm_buf_destroy(&buf);
    }

    {
        int p[2];
        u8 buf[64];
        u8 *c, *msg, *disp_at;
        oah_image img;
        oah_guest g;
        oah_interp_result r;
        u8 got[8];
        ssize_t n;
        s32 rel;

        CHECK(pipe(p) == 0);
        memset(buf, 0xcc, sizeof(buf));
        c = buf;
        memcpy(c, "\xb8\x01\x00\x00\x00", 5);
        c += 5;
        *c++ = 0xbf;
        memcpy(c, &p[1], 4);
        c += 4;
        *c++ = 0x48;
        *c++ = 0x8d;
        *c++ = 0x35;
        disp_at = c;
        c += 4;
        memcpy(c, "\xba\x02\x00\x00\x00", 5);
        c += 5;
        memcpy(c, "\x0f\x05", 2);
        c += 2;
        memcpy(c, "\xb8\x3c\x00\x00\x00", 5);
        c += 5;
        memcpy(c, "\xbf\x07\x00\x00\x00", 5);
        c += 5;
        memcpy(c, "\x0f\x05", 2);
        c += 2;
        msg = c;
        memcpy(msg, "hi", 2);
        rel = (s32)(msg - (disp_at + 4));
        memcpy(disp_at, &rel, 4);

        image_identity(&img, buf, sizeof(buf));
        oah_guest_init(&g, (u64)(uintptr_t)buf, 0);
        r = oah_jit_run(&g, &img, 10000);
        CHECK_EQ_U64(r.status, OAH_INTERP_EXIT);
        CHECK_EQ_U64((u64)r.exit_code, 7);
        close(p[1]);
        n = read(p[0], got, sizeof(got));
        CHECK_EQ_U64((u64)n, 2);
        CHECK(got[0] == 'h' && got[1] == 'i');
        close(p[0]);
    }

    {
        /* Host remap: cmp x8,#1 / movz x8,#64 before svc. */
        oah_asm_buf buf;
        u32 w;
        unsigned i;
        int saw_cmp1 = 0;
        int saw_mov64 = 0;
        int saw_svc = 0;

        oah_asm_buf_init(&buf);
        CHECK(oah_emit_runtime_syscall_host(&buf));
        CHECK((buf.size & 3u) == 0);
        for (i = 0; i + 4 <= buf.size; i += 4) {
            memcpy(&w, buf.data + i, 4);
            if (w == 0xf100051fu) {
                saw_cmp1 = 1;
            }
            if (w == 0xd2800808u) {
                saw_mov64 = 1;
            }
            if (w == 0xd4000001u) {
                saw_svc = 1;
            }
        }
        CHECK(saw_cmp1);
        CHECK(saw_mov64);
        CHECK(saw_svc);
        oah_asm_buf_destroy(&buf);
    }

    test_nested_calls(false);
    test_flag_branches(false);
    test_checked_memory(false);
#if defined(__aarch64__)
    test_nested_calls(true);
    test_flag_branches(true);
    test_checked_memory(true);
#endif

    return test_report("translate");
}
