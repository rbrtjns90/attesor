/* Freestanding x86-64 Linux guest for the compiler-built smoke test. */
static __attribute__((noinline, noclone)) void report(int value)
{
    const char *message;
    if (value == 42) {
        message = "branch ok\n";
    } else {
        message = "branch no\n";
    }
    __asm__ volatile("syscall" : : "a"(1), "D"(1), "S"(message), "d"(10)
                     : "rcx", "r11", "memory");
}

__attribute__((noreturn)) void _start(void)
{
    report(42);
    report(41);
    __asm__ volatile("syscall" : : "a"(60), "D"(7) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
