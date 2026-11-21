#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t handled;
static volatile sig_atomic_t nested;
static volatile sig_atomic_t sender;
static volatile sig_atomic_t used_altstack;
static _Alignas(16) unsigned char handler_stack[32768];

static void inner(int signum)
{
    if (signum == SIGUSR2) {
        nested++;
    }
}

static void outer(int signum, siginfo_t *info, void *context)
{
    if (signum == SIGUSR1 && info && context) {
        handled++;
        sender = info->si_pid;
        stack_t active;
        uintptr_t sp = (uintptr_t)&active;
        uintptr_t base = (uintptr_t)handler_stack;
        used_altstack = sp >= base && sp - base < sizeof(handler_stack) &&
                        sigaltstack(NULL, &active) == 0 && (active.ss_flags & SS_ONSTACK);
        if (raise(SIGUSR2) != 0) {
            handled = -1;
        }
    }
}

int main(void)
{
    stack_t stack = {.ss_sp = handler_stack, .ss_size = sizeof(handler_stack)};
    if (sigaltstack(&stack, NULL)) {
        return 8;
    }
    struct sigaction action = {0}, previous;
    sigset_t mask, pending;
    action.sa_handler = inner;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR2, &action, NULL)) {
        return 2;
    }
    action.sa_sigaction = outer;
    action.sa_flags = SA_SIGINFO | SA_RESETHAND | SA_ONSTACK;
    if (sigaction(SIGUSR1, &action, NULL)) {
        return 3;
    }
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) || raise(SIGUSR1) || raise(SIGUSR1) ||
        handled || sigpending(&pending) || !sigismember(&pending, SIGUSR1)) {
        return 4;
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) || handled != 1 ||
        nested != 1 || sender != getpid() || !used_altstack) {
        return 5;
    }
    if (sigaction(SIGUSR1, NULL, &previous) || previous.sa_handler != SIG_DFL ||
        sigpending(&pending) || sigismember(&pending, SIGUSR1)) {
        return 6;
    }
    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    if (sigaction(SIGUSR1, &action, NULL) || kill(getpid(), SIGUSR1) || handled != 1) {
        return 7;
    }
    stack_t disable = {.ss_flags = SS_DISABLE};
    if (sigaltstack(&disable, &stack) || stack.ss_flags & SS_ONSTACK ||
        stack.ss_sp != handler_stack || stack.ss_size != sizeof(handler_stack)) {
        return 9;
    }
    puts("signals: ok");
    return 0;
}
