extern int attesor_fixture_add(int);

__attribute__((noreturn)) void _start(void)
{
    int status = attesor_fixture_add(4);
    __asm__ volatile("syscall" : : "a"(60), "D"(status) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
