#include "oah/syscall_bridge.h"
#include "oah/elf_abi.h"
#include "oah/interp.h"
#include "oah/translate.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/clonefile.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/termios.h>
#include <termios.h>
#include <sys/xattr.h>
#include <sys/time.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* x86-64 Linux error numbers that differ from Darwin's. */
enum {
    LINUX_EAGAIN = 11, LINUX_EROFS = 30, LINUX_EDEADLK = 35, LINUX_ENAMETOOLONG = 36,
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
    case EADDRINUSE: return -98;
    case EADDRNOTAVAIL: return -99;
    case ENETUNREACH: return -101;
    case ECONNABORTED: return -103;
    case ECONNRESET: return -104;
    case EISCONN: return -106;
    case ENOTCONN: return -LINUX_ENOTCONN;
    case ECONNREFUSED: return -111;
    case EHOSTUNREACH: return -113;
    case EALREADY: return -114;
    case EINPROGRESS: return -115;
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

/* Host signal number -> Linux x86-64 signal number, for wait status. */
static int guest_wait_sig(int host)
{
    switch (host) {
    case SIGEMT:   return 4;  /* SIGILL */
    case SIGBUS:   return 7;
    case SIGSYS:   return 31;
    case SIGURG:   return 23;
    case SIGSTOP:  return 19;
    case SIGTSTP:  return 20;
    case SIGCONT:  return 18;
    case SIGCHLD:  return 17;
    case SIGIO:    return 29;
    case SIGINFO:  return 30; /* SIGPWR */
    case SIGUSR1:  return 10;
    case SIGUSR2:  return 12;
    default:       return host; /* 1-6,8,9,11,13-15,24-28 match */
    }
}

static volatile sig_atomic_t host_alarm_pending;
static volatile sig_atomic_t host_child_pending;
static bool signal_handlers_installed;
static bool posix_timer_created;
/* Emulated controlling tty: Darwin never auto-acquires a pty slave as ctty
 * on open the way Linux does for a session leader, so /dev/tty is backed by
 * a dup'd fd recorded at slave-open/TIOCSCTTY time. */
static char guest_ctty_path[64];
static bool guest_session_leader;

/* termios layout differs everywhere between the ABIs: Linux uses u32 flags
 * + 19 c_cc + u32 speeds (44 bytes) with its own flag bits and c_cc order;
 * Darwin uses u64 flags/speeds + 20 c_cc in a different order. Translate
 * field by field; bits with no counterpart are dropped. */
typedef struct {
    u32 c_iflag, c_oflag, c_cflag, c_lflag;
    u8 c_line, c_cc[19];
} linux_termios; /* 36 bytes — the TCGETS/TCSETS ABI; speeds are termios2-only */

typedef struct { u32 lin; tcflag_t dar; } termios_bit;

static void termios_flags_to_host(u32 lin, tcflag_t *dar, const termios_bit *map, size_t count)
{
    tcflag_t out = 0;
    for (size_t i = 0; i < count; i++) {
        if (lin & map[i].lin) {
            out |= map[i].dar;
        }
    }
    *dar = out;
}

static u32 termios_flags_to_guest(tcflag_t dar, const termios_bit *map, size_t count)
{
    u32 out = 0;
    for (size_t i = 0; i < count; i++) {
        if (dar & map[i].dar) {
            out |= map[i].lin;
        }
    }
    return out;
}

static const termios_bit termios_iflag[] = {
    {0x1, IGNBRK}, {0x2, BRKINT}, {0x4, IGNPAR}, {0x8, PARMRK},
    {0x10, INPCK}, {0x20, ISTRIP}, {0x40, INLCR}, {0x80, IGNCR},
    {0x100, ICRNL}, {0x400, IXON}, {0x800, IXANY}, {0x1000, IXOFF},
    {0x2000, IMAXBEL}, {0x4000, IUTF8},
};

static const termios_bit termios_oflag[] = {
    {0x1, OPOST}, {0x4, ONLCR}, {0x8, OCRNL}, {0x10, ONOCR}, {0x20, ONLRET},
};

static const termios_bit termios_cflag[] = {
    {0x10, CS6}, {0x20, CS7}, {0x30, CS8}, {0x40, CSTOPB}, {0x80, CREAD},
    {0x100, PARENB}, {0x200, PARODD}, {0x400, HUPCL}, {0x800, CLOCAL},
    {0x80000000, CCTS_OFLOW | CRTS_IFLOW},
};

static const termios_bit termios_lflag[] = {
    {0x1, ISIG}, {0x2, ICANON}, {0x8, ECHO}, {0x10, ECHOE}, {0x20, ECHOK},
    {0x40, ECHONL}, {0x80, NOFLSH}, {0x100, TOSTOP}, {0x200, ECHOCTL},
    {0x400, ECHOPRT}, {0x800, ECHOKE}, {0x1000, FLUSHO}, {0x4000, PENDIN},
    {0x8000, IEXTEN}, {0x10000, EXTPROC},
};

/* guest c_cc index -> host c_cc index (-1: no counterpart). */
static const int termios_cc_to_host[] = {
    8, 9, 3, 5, 0, 17, 16, -1, 12, 13, 10, 1, 6, 15, 4, 14, 2, -1, -1,
};

#define MAP_LEN(a) (sizeof(a) / sizeof((a)[0]))

static const u32 baud_rate[] = {
    0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
    9600, 19200, 38400,
};
static const u32 baud_rate_ext[] = {
    57600, 115200, 230400, 460800, 500000, 576000, 921600, 1000000,
    1152000, 1500000, 2000000,
};

static u32 termios_baud_from_speed(speed_t speed)
{
    for (size_t i = 0; i < MAP_LEN(baud_rate); i++) {
        if (baud_rate[i] == speed) {
            return (u32)i;
        }
    }
    for (size_t i = 0; i < MAP_LEN(baud_rate_ext); i++) {
        if (baud_rate_ext[i] == speed) {
            return 0x1000 | (u32)(i + 1); /* CBAUDEX base */
        }
    }
    return 0xf; /* B38400 default */
}

static speed_t termios_speed_from_baud(u32 baud)
{
    u32 index = baud & 0x100f;
    if ((index & 0x1000) && (index & 0xf) <= MAP_LEN(baud_rate_ext)) {
        return baud_rate_ext[(index & 0xf) - 1];
    }
    return index < MAP_LEN(baud_rate) ? baud_rate[index] : 38400;
}

static void termios_to_host(const linux_termios *lt, struct termios *ht)
{
    memset(ht, 0, sizeof(*ht));
    termios_flags_to_host(lt->c_iflag, &ht->c_iflag,
                          termios_iflag, MAP_LEN(termios_iflag));
    termios_flags_to_host(lt->c_oflag, &ht->c_oflag,
                          termios_oflag, MAP_LEN(termios_oflag));
    termios_flags_to_host(lt->c_cflag, &ht->c_cflag,
                          termios_cflag, MAP_LEN(termios_cflag));
    termios_flags_to_host(lt->c_lflag, &ht->c_lflag,
                          termios_lflag, MAP_LEN(termios_lflag));
    for (size_t i = 0; i < MAP_LEN(termios_cc_to_host); i++) {
        if (termios_cc_to_host[i] >= 0) {
            ht->c_cc[termios_cc_to_host[i]] = lt->c_cc[i];
        }
    }
    speed_t speed = termios_speed_from_baud(lt->c_cflag);
    ht->c_ispeed = speed;
    ht->c_ospeed = speed;
}

static void termios_to_guest(const struct termios *ht, linux_termios *lt)
{
    memset(lt, 0, sizeof(*lt));
    lt->c_iflag = termios_flags_to_guest(ht->c_iflag,
                                       termios_iflag, MAP_LEN(termios_iflag));
    lt->c_oflag = termios_flags_to_guest(ht->c_oflag,
                                       termios_oflag, MAP_LEN(termios_oflag));
    lt->c_cflag = termios_flags_to_guest(ht->c_cflag,
                                       termios_cflag, MAP_LEN(termios_cflag));
    lt->c_lflag = termios_flags_to_guest(ht->c_lflag,
                                       termios_lflag, MAP_LEN(termios_lflag));
    for (size_t i = 0; i < MAP_LEN(termios_cc_to_host); i++) {
        if (termios_cc_to_host[i] >= 0) {
            lt->c_cc[i] = ht->c_cc[termios_cc_to_host[i]];
        }
    }
    u32 baud = termios_baud_from_speed(ht->c_ospeed ? ht->c_ospeed : ht->c_ispeed);
    lt->c_cflag = (lt->c_cflag & ~0x100fu) | baud;
}

typedef struct guest_child {
    pid_t pid;
    struct guest_child *next;
} guest_child;

static guest_child *children;
static int vfork_release_fd = -1;

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

static void guest_fork_child_cleanup(void);

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
        if (vfork_release_fd >= 0) {
            close(vfork_release_fd);
            vfork_release_fd = -1;
        }
        free(entry);
        while (children) {
            forget_child(children->pid);
        }
        host_alarm_pending = host_child_pending = 0;
        posix_timer_created = false;
        guest_fork_child_cleanup();
    } else {
        *entry = (guest_child){pid, children};
        children = entry;
    }
    return pid;
}

/* The child has a private address space, but the parent resumes only
 * after the child's exec or exit closes the notification descriptor. */
static s64 guest_vfork(void)
{
    int notification[2];
    if (pipe(notification) < 0) {
        return linux_error(errno);
    }
    if (fcntl(notification[1], F_SETFD, FD_CLOEXEC) < 0) {
        int error = errno;
        close(notification[0]);
        close(notification[1]);
        return linux_error(error);
    }
    s64 pid = guest_fork();
    if (!pid) {
        close(notification[0]);
        vfork_release_fd = notification[1];
    } else {
        close(notification[1]);
        if (pid > 0) {
            char ignored;
            ssize_t count;
            do {
                count = read(notification[0], &ignored, sizeof(ignored));
            } while (count > 0 || (count < 0 && errno == EINTR));
        }
        close(notification[0]);
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

/* Run guest instructions and mutate guest mappings under one lock. A host
 * thread releases it at scheduler boundaries and while blocked in a futex. */
static pthread_mutex_t guest_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t workers_exited = PTHREAD_COND_INITIALIZER;
static unsigned workers;
static u32 next_thread_id = 0x10000000;
static u64 next_jit_owner = 1; /* 0 = main thread (guest_init zeroes it) */

/* Wall time when this host thread last acquired guest_lock — the basis
 * for slice accounting in oah_darwin_guest_tick. Thread-local because the
 * hold belongs to the runner, not any guest struct. */
static __thread u64 lock_hold_ns;

/* Turn-taking for guest_lock: a yielder parks on sched_cv until a
 * different thread reports an acquisition (sched_generation bump) or a
 * short timeout fires when no peer is runnable. Without this a yielder
 * that merely sleeps races its own reacquire — a psynch waiter cannot
 * wake and win the lock inside a microsecond sleep window.
 *
 * guest_lock_waiters counts threads blocked in pthread_mutex_lock so a
 * holder can skip yielding entirely while every peer is asleep in a futex
 * or blocking call — the common case for SDL's idle worker threads. */
static pthread_mutex_t sched_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sched_cv = PTHREAD_COND_INITIALIZER;
static unsigned sched_waiting;
static unsigned guest_lock_waiters;
static u64 sched_generation;

/* Max contiguous wall time a thread may hold guest_lock before handing
 * off to a waiter. Short enough that a thread returning from a blocking
 * syscall isn't stalled behind a busy worker's slice — the SDL audio
 * worker is CPU-bound and would otherwise add ~4ms latency to every
 * reacquire the main thread makes, which stalls interactive drawing. */
#define OAH_GUEST_SLICE_NS 300000ull /* ~0.3ms */

void oah_darwin_guest_enter(void)
{
    __atomic_fetch_add(&guest_lock_waiters, 1, __ATOMIC_RELAXED);
    pthread_mutex_lock(&guest_lock);
    __atomic_fetch_sub(&guest_lock_waiters, 1, __ATOMIC_RELAXED);
    if (sched_waiting) {
        pthread_mutex_lock(&sched_mu);
        sched_generation++;
        pthread_cond_broadcast(&sched_cv);
        pthread_mutex_unlock(&sched_mu);
    }
    /* Refresh the slice stamp only after a real gap off the lock. A thread
     * that bounces out and back in under OAH_GUEST_SLICE_NS (the SDL audio
     * worker does a blocking writei every few ms) would otherwise restart
     * its slice on every reacquire and starve waiters indefinitely. */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    u64 now_ns = (u64)now.tv_sec * 1000000000ull + (u64)now.tv_nsec;
    if (!lock_hold_ns || now_ns - lock_hold_ns >= OAH_GUEST_SLICE_NS) {
        lock_hold_ns = now_ns;
    }
}

void oah_darwin_guest_leave(void)
{
    pthread_mutex_unlock(&guest_lock);
}

bool oah_darwin_has_workers(void)
{
    return workers != 0;
}

/* Fair guest-lock sharing. guest_lock serializes all guest execution, so
 * every runner periodically hands it off. The slice is wall time, not
 * guest instructions: a JIT thread executes millions of insns per second
 * while an interpreted worker manages thousands, so counting insns would
 * give the fast thread tiny slices and let workers convoy the lock. A
 * holder may keep the lock up to OAH_GUEST_SLICE_NS of contiguous wall
 * time before handing off — but only when a peer is actually blocked
 * acquiring it (guest_lock_waiters); workers parked in futex or blocking
 * syscalls don't need a slice, and yielding to nobody just stalls the
 * only runnable thread. */
#define OAH_GUEST_CHECK_INSNS (8u << 10) /* insns between clock checks */

void oah_darwin_guest_tick(oah_guest *g, u64 insns)
{
    if (!workers || (g->quantum += (unsigned)insns) < OAH_GUEST_CHECK_INSNS) {
        return;
    }
    g->quantum = 0;
    if (__atomic_load_n(&guest_lock_waiters, __ATOMIC_RELAXED) == 0) {
        lock_hold_ns = 0; /* uncontended; next waiter's arrival restarts the slice */
        return;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    u64 now_ns = (u64)now.tv_sec * 1000000000ull + (u64)now.tv_nsec;
    if (!lock_hold_ns) {
        lock_hold_ns = now_ns; /* no stamp yet; grant a full slice */
        return;
    }
    if (now_ns - lock_hold_ns < OAH_GUEST_SLICE_NS) {
        return;
    }
    static int trace_sched = -1;
    if (trace_sched < 0) {
        trace_sched = getenv("OAH_TRACE_SCHED") != NULL;
    }
    if (trace_sched) {
        fprintf(stderr, "sched yield tid=%u hold=%llums\n", g->tid,
                (unsigned long long)((now_ns - lock_hold_ns) / 1000000ull));
    }
    /* Park until the waiter queue drains: a yielding thread stays out of
     * the mutex queue while peers are still blocked acquiring the lock,
     * so an interactive thread can chain several lock/syscall cycles in
     * one turn. A CPU-bound worker (SDL audio pump) otherwise re-enters
     * after a single handoff and the interactive thread pays a full
     * slice of latency on every syscall. The deadline keeps a
     * permanently-contended lock from starving the yielder. */
    pthread_mutex_lock(&sched_mu);
    sched_waiting++;
    struct timespec deadline = {
        .tv_sec = now.tv_sec, .tv_nsec = now.tv_nsec + 8000000L,
    };
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    oah_darwin_guest_leave();
    while (__atomic_load_n(&guest_lock_waiters, __ATOMIC_RELAXED) != 0 &&
           pthread_cond_timedwait(&sched_cv, &sched_mu, &deadline) == 0) {
    }
    sched_waiting--;
    pthread_mutex_unlock(&sched_mu);
    /* Grace window before re-entering the mutex queue: the drained moment
     * is usually a waiter's brief gap between releasing the lock for a
     * host call and re-queueing, not the end of its burst. Sleeping lets
     * that burst finish (or settle into a long block) before this thread
     * competes again. Only threads that burn a full slice reach this
     * path — a CPU-bound worker pays the grace on every yield, throttling
     * it to a minority share, while an interactive thread mostly returns
     * through blocking syscalls and never sees it. */
    {
        struct timespec grace = {.tv_sec = 0, .tv_nsec = 1500000L};
        nanosleep(&grace, NULL);
    }
    oah_darwin_guest_enter();
}

static bool begin_blocking_call(void)
{
    bool released = oah_darwin_has_workers();
    if (released) {
        oah_darwin_guest_leave();
    }
    return released;
}

static void finish_blocking_call(bool released)
{
    if (released) {
        int saved = errno;
        oah_darwin_guest_enter();
        errno = saved;
    }
}

/* Blocking host I/O cannot keep a pointer into a guest mapping that
 * another guest thread may unmap before the call returns. */
static s64 guest_blocking_io(oah_image *img, int fd, u64 address, u64 size,
                             bool reading, bool socket_io, int flags)
{
    {
        static int stdin_trace = -1;
        if (stdin_trace < 0) {
            stdin_trace = getenv("OAH_STDIN_TRACE") != NULL;
        }
        if (stdin_trace && fd == 0 && reading) {
            fprintf(stderr, "stdin read entry size=%llu addr=%llx\n",
                    (unsigned long long)size, (unsigned long long)address);
        }
    }
    u32 protection = reading ? PROT_WRITE : PROT_READ;
    void *guest = oah_guest_access(img, address, size, protection);
    if (size && !guest) {
        static int io_trace = -1;
        if (io_trace < 0) {
            io_trace = getenv("OAH_IO_TRACE") != NULL;
        }
        if (io_trace) {
            fprintf(stderr,
                    "io-EFAULT fd=%d read=%d addr=%llx size=%llu\n",
                    fd, reading, (unsigned long long)address,
                    (unsigned long long)size);
        }
        return -EFAULT;
    }
    bool bounce = workers && size;
    void *buffer = bounce ? malloc(size) : guest;
    if (bounce && !buffer) {
        return -ENOMEM;
    }
    if (bounce && !reading) {
        memcpy(buffer, guest, size);
    }
    bool released = begin_blocking_call();
    ssize_t bytes = socket_io ? (reading ? recv(fd, buffer, size, flags) : send(fd, buffer, size, flags))
                  : reading ? read(fd, buffer, size) : write(fd, buffer, size);
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st && socket_io) {
            fprintf(stderr, "sockio recv=%d fd=%d size=%llu flags=%x -> %zd\n",
                    reading, fd, (unsigned long long)size, flags, bytes);
        }
    }
    {
        static int stdin_trace = -1;
        if (stdin_trace < 0) {
            stdin_trace = getenv("OAH_STDIN_TRACE") != NULL;
        }
        if (stdin_trace && fd == 0) {
            fprintf(stderr, "stdin io read=%d size=%llu -> %zd errno=%d\n",
                    reading, (unsigned long long)size, bytes,
                    bytes < 0 ? errno : 0);
        }
    }
    (void)0;
    finish_blocking_call(released);
    s64 result = host_result(bytes);
    if (bounce) {
        if (reading && bytes > 0) {
            guest = oah_guest_access(img, address, (u64)bytes, protection);
            if (guest) {
                memcpy(guest, buffer, (size_t)bytes);
            } else {
                result = -EFAULT;
            }
        }
        free(buffer);
    }
    return result;
}

typedef struct guest_futex_waiter {
    u64 address;
    u32 bits;
    bool ready;
    pthread_cond_t condition;
    struct guest_futex_waiter *next;
} guest_futex_waiter;

static guest_futex_waiter *futex_waiters;

/* The parent's guest threads do not exist in a forked child: drop their
 * bookkeeping so the single-threaded child can fork and exec, and rebuild
 * the guest lock since a dead thread may have held it at the moment of
 * fork. Re-acquire it because the calling thread's syscall path still runs
 * under the lock. */
static void guest_fork_child_cleanup(void)
{
    workers = 0;
    futex_waiters = NULL;
    guest_session_leader = false; /* ctty is inherited; leadership is not */
    pthread_mutex_init(&guest_lock, NULL);
    pthread_mutex_lock(&guest_lock);
}

static s64 guest_futex_wake(u64 address, u32 count, u32 bits)
{
    u32 woke = 0;
    for (guest_futex_waiter *w = futex_waiters; w && woke < count; w = w->next) {
        if (!w->ready && w->address == address && (w->bits & bits)) {
            w->ready = true;
            pthread_cond_signal(&w->condition);
            woke++;
        }
    }
    return woke;
}

static bool valid_futex_time(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static s64 guest_futex_wait(u64 address, u32 bits, const struct timespec *deadline, clockid_t clock)
{
    guest_futex_waiter waiter = {.address = address, .bits = bits, .next = futex_waiters};
    int error = pthread_cond_init(&waiter.condition, NULL);
    if (error) {
        return linux_error(error);
    }
    futex_waiters = &waiter;
    while (!waiter.ready && !error) {
        if (!deadline) {
            error = pthread_cond_wait(&waiter.condition, &guest_lock);
            continue;
        }
        struct timespec now;
        if (clock_gettime(clock, &now) < 0) {
            error = errno;
            break;
        }
        if (now.tv_sec > deadline->tv_sec ||
            (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
            error = ETIMEDOUT;
            break;
        }
        struct timespec remaining = {
            .tv_sec = deadline->tv_sec - now.tv_sec,
            .tv_nsec = deadline->tv_nsec - now.tv_nsec
        };
        if (remaining.tv_nsec < 0) {
            remaining.tv_sec--;
            remaining.tv_nsec += 1000000000L;
        }
        error = pthread_cond_timedwait_relative_np(&waiter.condition, &guest_lock, &remaining);
    }
    guest_futex_waiter **link = &futex_waiters;
    while (*link != &waiter) {
        link = &(*link)->next;
    }
    *link = waiter.next;
    pthread_cond_destroy(&waiter.condition);
    return waiter.ready ? 0 : linux_error(error);
}

static s64 guest_futex(oah_image *img, u64 address, u64 operation, u32 value, u64 timeout, u32 bitset)
{
    u64 command = operation & ~384ull;
    if ((address & 3) || ((operation & 256) && command != 9)) {
        return -EINVAL;
    }
    const void *word = oah_guest_access(img, address, 4, PROT_READ);
    if (!word) {
        return -EFAULT;
    }
    u32 bits = command == 9 || command == 10 ? bitset : UINT32_MAX;
    if (!bits) {
        return -EINVAL;
    }
    if (command == 1 || command == 10) {
        return (s32)value < 0 ? -EINVAL : guest_futex_wake(address, value, bits);
    }
    if (command != 0 && command != 9) {
        return -LINUX_ENOSYS;
    }
    u32 actual;
    memcpy(&actual, word, sizeof(actual));
    if (actual != value) {
        return -LINUX_EAGAIN;
    }
    struct timespec deadline;
    clockid_t clock = operation & 256 ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    if (timeout) {
        const void *input = oah_guest_access(img, timeout, sizeof(deadline), PROT_READ);
        if (!input) {
            return -EFAULT;
        }
        memcpy(&deadline, input, sizeof(deadline));
        if (!valid_futex_time(&deadline)) {
            return -EINVAL;
        }
        if (!command) {
            struct timespec now;
            if (clock_gettime(clock, &now) < 0) {
                return linux_error(errno);
            }
            deadline.tv_nsec += now.tv_nsec;
            s64 carry = deadline.tv_nsec / 1000000000L;
            if (deadline.tv_sec > INT64_MAX - now.tv_sec - carry) {
                return -EINVAL;
            }
            deadline.tv_sec += now.tv_sec + carry;
            deadline.tv_nsec %= 1000000000L;
        }
    }
    return guest_futex_wait(address, bits, timeout ? &deadline : NULL, clock);
}

enum {
    X86_CLONE_THREAD = 0x10000, X86_CLONE_SETTLS = 0x80000,
    X86_CLONE_PARENT_SETTID = 0x100000, X86_CLONE_CHILD_CLEARTID = 0x200000,
    X86_CLONE_CHILD_SETTID = 0x1000000
};

typedef struct {
    oah_guest guest;
    oah_image *image;
} guest_worker;

static void clear_guest_tid(oah_guest *g, oah_image *img)
{
    if (g->clear_tid) {
        void *output = oah_guest_access(img, g->clear_tid, 4, PROT_WRITE);
        if (output) {
            u32 zero = 0;
            memcpy(output, &zero, sizeof(zero));
            guest_futex_wake(g->clear_tid, 1, UINT32_MAX);
        }
        g->clear_tid = 0;
    }
}

static void *run_guest_thread(void *opaque)
{
    guest_worker *thread = opaque;
    sigset_t blocked;
    bridged_signal_set(&blocked);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    oah_darwin_guest_enter();
    if (getenv("OAH_TRACE_THREADS")) {
        fprintf(stderr, "oah: worker %u started rip=%llx\n",
                thread->guest.tid, (unsigned long long)thread->guest.rip);
    }
    /* OAH_WORKER_JIT opts worker threads into the cached fragment JIT.
     * The interpreter remains the default until worker JIT is proven. */
    static int worker_jit = -1;
    if (worker_jit < 0) {
        worker_jit = getenv("OAH_WORKER_JIT") != NULL;
    }
    oah_interp_result result =
        worker_jit
            ? oah_jit_run_worker(&thread->guest, thread->image,
                                 thread->image->instruction_limit)
            : oah_interp_run(&thread->guest, thread->image,
                             thread->image->instruction_limit);
    if (result.status != OAH_INTERP_EXIT) {
        fprintf(stderr, "oah: guest thread %u stopped (%d) at rip=%llx",
                thread->guest.tid, result.status, (unsigned long long)thread->guest.rip);
        u64 length = 15;
        const u8 *code = oah_guest_span(thread->image, thread->guest.rip, &length);
        if (code) {
            fputs(" bytes:", stderr);
            for (u64 i = 0; i < length; i++) {
                fprintf(stderr, " %02x", code[i]);
            }
        }
        fputc('\n', stderr);
        _exit(126);
    }
    if (!thread->guest.thread_exit) {
        _exit(result.exit_code);
    }
    clear_guest_tid(&thread->guest, thread->image);
    workers--;
    pthread_cond_broadcast(&workers_exited);
    free(thread);
    oah_darwin_guest_leave();
    return NULL;
}

static s64 guest_clone_thread(oah_guest *g, oah_image *img, u64 flags, u64 stack,
                              u64 parent_tid, u64 child_tid, u64 tls)
{
    /* CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD.
     * CLONE_SYSVSEM is harmless until the runtime implements SysV semaphores. */
    const u64 required = 0x10f00;
    const u64 optional = 0x40000 | X86_CLONE_SETTLS | X86_CLONE_PARENT_SETTID |
                         X86_CLONE_CHILD_CLEARTID | X86_CLONE_CHILD_SETTID;
    if ((flags & required) != required || flags & ~(required | optional)) {
        return -LINUX_ENOSYS;
    }
    if (stack < 8 || !oah_guest_access(img, stack - 8, 8, PROT_WRITE)) {
        return -EFAULT;
    }
    void *parent_output = flags & X86_CLONE_PARENT_SETTID ?
                          oah_guest_access(img, parent_tid, 4, PROT_WRITE) : NULL;
    void *child_output = flags & X86_CLONE_CHILD_SETTID ?
                         oah_guest_access(img, child_tid, 4, PROT_WRITE) : NULL;
    if (((flags & X86_CLONE_PARENT_SETTID) && !parent_output) ||
        ((flags & X86_CLONE_CHILD_SETTID) && !child_output)) {
        return -EFAULT;
    }
    if (next_thread_id == INT32_MAX) {
        return -LINUX_EAGAIN;
    }
    guest_worker *thread = malloc(sizeof(*thread));
    if (!thread) {
        return -ENOMEM;
    }
    u32 tid = next_thread_id++;
    *thread = (guest_worker){.guest = *g, .image = img};
    thread->guest.gpr[OAH_X86_RAX] = 0;
    thread->guest.gpr[OAH_X86_RSP] = stack;
    thread->guest.shared_signal_actions = oah_guest_actions(g);
    thread->guest.pending_signals = thread->guest.thread_signals = 0;
    thread->guest.signal_stack_base = thread->guest.signal_stack_size = 0;
    thread->guest.clear_tid = flags & X86_CLONE_CHILD_CLEARTID ? child_tid : 0;
    thread->guest.tid = tid;
    thread->guest.quantum = 0;
    thread->guest.jit_owner = next_jit_owner++;
    thread->guest.thread_exit = false;
    if (flags & X86_CLONE_SETTLS) {
        thread->guest.fs_base = tls;
    }
    pthread_t host;
    int error = pthread_create(&host, NULL, run_guest_thread, thread);
    if (error) {
        free(thread);
        return linux_error(error);
    }
    pthread_detach(host);
    workers++;
    if (parent_output) {
        memcpy(parent_output, &tid, sizeof(tid));
    }
    if (child_output) {
        memcpy(child_output, &tid, sizeof(tid));
    }
    return tid;
}

static s64 guest_clone3(oah_guest *g, oah_image *img, u64 address, u64 size)
{
    struct {
        u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
        u64 set_tid, set_tid_size, cgroup;
    } args = {0};
    if (size < 64 || size > OAH_X86_PAGE_SIZE) {
        return size < 64 ? -EINVAL : -E2BIG;
    }
    const u8 *input = oah_guest_access(img, address, size, PROT_READ);
    if (!input) {
        return -EFAULT;
    }
    size_t known = size < sizeof(args) ? size : sizeof(args);
    memcpy(&args, input, known);
    for (u64 i = known; i < size; i++) {
        if (input[i]) {
            return -E2BIG;
        }
    }
    if (!(args.flags & X86_CLONE_THREAD) || args.pidfd || args.exit_signal ||
        args.set_tid || args.set_tid_size || args.cgroup) {
        return -LINUX_ENOSYS;
    }
    if (!args.stack || !args.stack_size || args.stack_size > UINT64_MAX - args.stack) {
        return -EINVAL;
    }
    return guest_clone_thread(g, img, args.flags, args.stack + args.stack_size,
                              args.parent_tid, args.child_tid, args.tls);
}

static s64 guest_pselect(oah_guest *g, oah_image *img, u64 count,
                        const u64 addresses[3],
                        const struct timespec *timeout, u64 signal_address)
{
    if (count > FD_SETSIZE) {
        return -EINVAL;
    }
    u64 saved_mask = 0;
    bool masked = false;
    if (signal_address) {
        /* Linux pselect6 sigmask: {const sigset_t *mask; size_t size}. */
        const u64 *pair = oah_guest_access(img, signal_address, 16, PROT_READ);
        if (!pair) {
            return -EFAULT;
        }
        const u64 *mask = pair[0] ? oah_guest_access(img, pair[0], 8, PROT_READ) : NULL;
        if (pair[0] && !mask) {
            return -EFAULT;
        }
        if (mask) {
            saved_mask = g->signal_mask;
            g->signal_mask = *mask;
            masked = true;
        }
    }
    size_t bytes = ((count + 63) / 64) * 8;
    fd_set sets[3] = {0};
    fd_set *args[3] = {NULL};
    for (unsigned i = 0; i < 3; i++) {
        if (addresses[i] && bytes) {
            const void *input = oah_guest_access(img, addresses[i], bytes, PROT_READ | PROT_WRITE);
            if (!input) {
                return -EFAULT;
            }
            memcpy(&sets[i], input, bytes);
            args[i] = &sets[i];
        }
    }
    {
        static int stdin_trace = -1;
        if (stdin_trace < 0) {
            stdin_trace = getenv("OAH_STDIN_TRACE") != NULL;
        }
        if (stdin_trace) {
            fprintf(stderr, "pselect nfds=%llu rd0=%d wr0=%d\n",
                    (unsigned long long)count,
                    args[0] ? FD_ISSET(0, args[0]) : -1,
                    args[1] ? FD_ISSET(0, args[1]) : -1);
        }
    }
    bool released = begin_blocking_call();
    int ready = pselect((int)count, args[0], args[1], args[2], timeout, NULL);
    finish_blocking_call(released);
    if (masked) {
        g->signal_mask = saved_mask;
    }
    if (ready < 0) {
        return linux_error(errno);
    }
    for (unsigned i = 0; i < 3; i++) {
        if (args[i]) {
            void *output = oah_guest_access(img, addresses[i], bytes, PROT_WRITE);
            if (!output) {
                return -EFAULT;
            }
            memcpy(output, args[i], bytes);
        }
    }
    return ready;
}

static s64 guest_interval_timer(oah_image *img, u64 which, u64 value, u64 old)
{
    if (which != 0 || posix_timer_created) {
        return -LINUX_EOPNOTSUPP;
    }
    struct { s64 interval_sec, interval_usec, value_sec, value_usec; } request, previous;
    const void *input = value ? oah_guest_access(img, value, sizeof(request), PROT_READ) : NULL;
    void *output = old ? oah_guest_access(img, old, sizeof(previous), PROT_WRITE) : NULL;
    if ((value && !input) || (old && !output)) {
        return -EFAULT;
    }
    struct itimerval timer = {0}, old_timer;
    if (input) {
        memcpy(&request, input, sizeof(request));
        if (request.interval_sec < 0 || request.value_sec < 0 ||
            request.interval_usec < 0 || request.interval_usec >= 1000000 ||
            request.value_usec < 0 || request.value_usec >= 1000000) {
            return -EINVAL;
        }
        timer.it_interval = (struct timeval){request.interval_sec, (suseconds_t)request.interval_usec};
        timer.it_value = (struct timeval){request.value_sec, (suseconds_t)request.value_usec};
    }
    if (install_signal_handlers() < 0 ||
        setitimer(ITIMER_REAL, &timer, output ? &old_timer : NULL) < 0) {
        return linux_error(errno);
    }
    if (output) {
        previous.interval_sec = old_timer.it_interval.tv_sec;
        previous.interval_usec = old_timer.it_interval.tv_usec;
        previous.value_sec = old_timer.it_value.tv_sec;
        previous.value_usec = old_timer.it_value.tv_usec;
        memcpy(output, &previous, sizeof(previous));
    }
    return 0;
}

static const char *guest_path(oah_image *img, u64 addr)
{
    u64 available = 4096;
    const u8 *bytes = oah_guest_span(img, addr, &available);
    return bytes && memchr(bytes, 0, available) ? (const char *)bytes : NULL;
}

static bool sysroot_writable(const oah_image *img)
{
    if (!img->sysroot) {
        return false;
    }
    char marker[PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/.attesor-writable", img->sysroot);
    return access(marker, F_OK) == 0;
}

/* Strict sysroot mode (OAH_SYSROOT_STRICT=1): the package-install
 * contract. Every absolute path resolves inside the sysroot — no host
 * fallback for missing files, no mutating passthrough — except real
 * device nodes which map to host devices. */
static bool sysroot_strict(const oah_image *img)
{
    static int strict = -1;
    if (strict < 0) {
        strict = getenv("OAH_SYSROOT_STRICT") != NULL;
    }
    return strict > 0 && img->sysroot != NULL;
}

static bool guest_device_path(const char *path)
{
    static const char *devs[] = {
        "/dev/null", "/dev/zero", "/dev/full", "/dev/random",
        "/dev/urandom", "/dev/tty", "/dev/stdin", "/dev/stdout",
        "/dev/stderr", "/dev/ptmx",
    };
    for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
        if (!strcmp(path, devs[i])) {
            return true;
        }
    }
    return !strncmp(path, "/dev/fd/", 8) || !strncmp(path, "/dev/pts/", 9);
}

static bool sysroot_path(const oah_image *img, const char *path)
{
    if (!img->sysroot) {
        return false;
    }
    if (sysroot_strict(img)) {
        return path[0] == '/' && !guest_device_path(path);
    }
    /* FHS dirs resolve inside the sysroot. Reads fall back to the host when
     * the file is absent there; writes need the writable marker. */
    static const char *dirs[] = {
        "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
        "/etc/", "/var/", "/opt/", "/boot/", "/run/", "/root/",
        "/media/", "/mnt/", "/srv/", "/home/",
    };
    if (path[0] != '/') {
        return false;
    }
    if (path[1] == 0) {
        return true; /* guest "/" is the sysroot itself */
    }
    /* macOS-private trees under FHS prefixes stay on the host. */
    static const char *host_only[] = {"/var/folders", "/var/select"};
    for (size_t i = 0; i < sizeof(host_only) / sizeof(host_only[0]); i++) {
        if (strncmp(path, host_only[i], strlen(host_only[i])) == 0) {
            return false;
        }
    }
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (strncmp(path, dirs[i], strlen(dirs[i])) == 0 ||
            (strlen(path) == strlen(dirs[i]) - 1 &&
             strncmp(path, dirs[i], strlen(dirs[i]) - 1) == 0)) {
            return true;
        }
    }
    return false;
}

/* macOS rejects F_WRLCK on an O_WRONLY fd (EBADF); Linux guests open lock
 * files write-only and lock them anyway. Reopen regular files O_RDWR so
 * record locking works; other fd types keep write-only semantics. */
static int guest_lockable_fd(int fd, int host_flags)
{
    if (fd < 0 || (host_flags & O_ACCMODE) != O_WRONLY) {
        return fd;
    }
    struct stat st;
    char path[PATH_MAX];
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
        fcntl(fd, F_GETPATH, path) < 0) {
        return fd;
    }
    int flags = (host_flags & ~(O_ACCMODE | O_EXCL)) | O_RDWR;
    int rw = open(path, flags);
    if (rw < 0) {
        return fd;
    }
    close(fd);
    return rw;
}

/* /dev/dsp OSS emulation over CoreAudio (src/dsp_darwin.c). */
bool oah_dsp_owns(int fd);
int oah_dsp_open(int flags);
int oah_dsp_close(int fd);
s64 oah_dsp_write(oah_image *img, int fd, u64 gva, u64 len);
s64 oah_dsp_ioctl(oah_image *img, int fd, u64 req, u64 arg);
bool oah_alsa_owns(int fd);
int oah_alsa_open(const char *path, int flags);
int oah_alsa_close(int fd);
s64 oah_alsa_write(oah_image *img, int fd, u64 gva, u64 len);
s64 oah_alsa_ioctl(oah_image *img, int fd, u64 req, u64 arg);
int oah_alsa_poll(int fd, int events);
void oah_alsa_note_flags(int fd, int host_flags);

static int open_guest_path(oah_image *img, int dirfd, const char *path, int host_flags, u64 mode)
{
    /* OAH_DISABLE_AUDIO makes the emulated sound devices absent: SDL's
     * audio init then fails cleanly instead of spawning the CPU-bound
     * pump thread that contends guest_lock with the UI thread. */
    static int audio_disabled = -1;
    if (audio_disabled < 0) {
        audio_disabled = getenv("OAH_DISABLE_AUDIO") != NULL;
    }
    /* Linux /dev/ptmx slaves are openable immediately; Darwin requires
     * grantpt (chown to caller) + unlockpt on the master first, and guests
     * may open the slave without a TIOCSPTLCK ioctl (xterm's child retry
     * path). Unlock at master-open time to match Linux. */
    bool is_ptmx = !strcmp(path, "/dev/ptmx");
    /* Linux /dev/tty is the caller's controlling terminal; Darwin's is the
     * host session's, and a guest session leader's slave open does not
     * register a ctty there. Return the recorded guest ctty when set. */
    if (!strcmp(path, "/dev/tty") && guest_ctty_path[0]) {
        return open(guest_ctty_path, host_flags, (mode_t)mode);
    }
    /* Linux pts slaves are /dev/pts/N; Darwin names them /dev/ttysNNN.
     * TIOCGPTN hands guests the unit number, which they open as
     * /dev/pts/N — translate it to the Darwin slave device. */
    if (!strncmp(path, "/dev/pts/", 9)) {
        int unit = -1;
        if (sscanf(path + 9, "%d", &unit) == 1 && unit >= 0) {
            char slave[64];
            snprintf(slave, sizeof(slave), "/dev/ttys%03d", unit);
            int fd = open(slave, host_flags, (mode_t)mode);
            /* A session leader without a ctty acquires the slave as its
             * controlling terminal on a plain open (no O_NOCTTY). Darwin
             * never does this, so record it for /dev/tty emulation. */
            if (fd >= 0 && guest_session_leader && !guest_ctty_path[0] &&
                !(host_flags & O_NOCTTY)) {
                strlcpy(guest_ctty_path, slave, sizeof(guest_ctty_path));
            }
            if (fd >= 0 || (errno != ENOENT && errno != ENOTDIR)) {
                return guest_lockable_fd(fd, host_flags);
            }
        }
    }
    bool is_sound = !strcmp(path, "/dev/dsp") || !strcmp(path, "/dev/sound/dsp") ||
                    !strcmp(path, "/dev/audio") || !strcmp(path, "/dev/audio1") ||
                    !strncmp(path, "/dev/snd/", 9);
    if (is_sound) {
        if (audio_disabled) {
            errno = ENODEV;
            return -1;
        }
        int fd = !strncmp(path, "/dev/snd/", 9)
            ? oah_alsa_open(path, host_flags)
            : oah_dsp_open(host_flags);
        if (fd >= 0) {
            return fd;
        }
        errno = fd < -1 ? -fd : ENODEV;
        return -1;
    }
    if (sysroot_path(img, path)) {
        bool writing = (host_flags & O_ACCMODE) != O_RDONLY ||
                       (host_flags & (O_CREAT | O_TRUNC));
        if (writing && !sysroot_writable(img)) {
            errno = EROFS;
            return -1;
        }
        int fd = oah_sysroot_open(img->sysroot, path, host_flags, (u32)mode);
        fd = guest_lockable_fd(fd, host_flags);
        /* Reads fall back to the host when the sysroot lacks the file.
         * Strict mode never falls back: ENOENT is the honest answer. */
        if (sysroot_strict(img) || fd >= 0 || writing ||
            (errno != ENOENT && errno != ENOTDIR)) {
            return fd;
        }
    }
    int fd = openat(dirfd == -100 ? AT_FDCWD : dirfd, path, host_flags,
                    (mode_t)mode);
    if (fd >= 0 && is_ptmx) {
        grantpt(fd);
        unlockpt(fd);
    }
    return guest_lockable_fd(fd, host_flags);
}

/* Guest-root emulation: a writable sysroot marked .attesor-guest-root
 * presents uid/gid 0 so package tools (dpkg, apt, maintainer scripts)
 * behave; id-changing calls become no-ops since the host user owns all
 * sysroot files. Plain writable sysroots (e.g. freeciv) keep the host
 * uid — some programs refuse to run as root. */
static bool guest_root(const oah_image *img)
{
    if (!img->sysroot || !sysroot_writable(img)) {
        return false;
    }
    char marker[PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/.attesor-guest-root", img->sysroot);
    return access(marker, F_OK) == 0;
}

/* mkdir -p the parent chain of a resolved sysroot path: writes into FHS
 * dirs create them so host-fallback stat can't hide missing sysroot dirs. */
static void ensure_parents(const char *resolved)
{
    char copy[PATH_MAX];
    strlcpy(copy, resolved, sizeof(copy));
    for (char *p = copy + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }
        *p = 0;
        mkdir(copy, 0755);
        *p = '/';
    }
}

/* Overlay copy-up: a mutation's FHS source exists only on the host (e.g.
 * dpkg's backup link of a "lower layer" file). Materialise it in the
 * sysroot so the mutation succeeds. Returns 0 on success. */
static int copy_up(const char *host_src, const char *sysroot_dst)
{
    struct stat st;
    if (lstat(host_src, &st) < 0) {
        return -1;
    }
    struct stat dst_st;
    if (lstat(sysroot_dst, &dst_st) == 0) {
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        char linkbuf[PATH_MAX];
        ssize_t n = readlink(host_src, linkbuf, sizeof(linkbuf) - 1);
        if (n <= 0) {
            return -1;
        }
        linkbuf[n] = 0;
        return symlink(linkbuf, sysroot_dst);
    }
    if (!S_ISREG(st.st_mode)) {
        return -1;
    }
    if (clonefile(host_src, sysroot_dst, 0) == 0) {
        return 0;
    }
    int in = open(host_src, O_RDONLY);
    if (in < 0) {
        return -1;
    }
    int out = open(sysroot_dst, O_WRONLY | O_CREAT | O_EXCL,
                   st.st_mode & 07777);
    if (out < 0) {
        close(in);
        return -1;
    }
    char buf[65536];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            rc = -1;
            break;
        }
    }
    if (n < 0) {
        rc = -1;
    }
    close(in);
    close(out);
    if (rc < 0) {
        unlink(sysroot_dst);
    }
    return rc;
}

/* For a *mutating* path-taking call: FHS paths inside a writable sysroot
 * resolve to a host path there; anything else uses the host path. Returns 1
 * when `out` was filled, 0 to pass `path` through, or a negative errno. */
static int resolve_mut_path(const oah_image *img, const char *path,
                            char *out, size_t capacity)
{
    if (!path || path[0] != '/' || !sysroot_path(img, path)) {
        return 0;
    }
    if (!sysroot_writable(img)) {
        return -LINUX_EROFS;
    }
    if (oah_sysroot_hostpath(img->sysroot, path, out, capacity)) {
        ensure_parents(out);
        return 1;
    }
    return linux_error(errno);
}

/* Recorded ownership for sysroot files: guest chown writes the
 * requested uid/gid into xattrs so stat reports them back and package
 * metadata is verifiable, without claiming host ownership changed. */
static int record_guest_owner(const char *hostpath, u64 uid, u64 gid,
                              bool nofollow)
{
    char buf[16];
    u32 opts = nofollow ? XATTR_NOFOLLOW : 0;
    int n = snprintf(buf, sizeof(buf), "%llu", (unsigned long long)uid);
    /* macOS requires write permission on the file for user xattrs; package
     * extraction legitimately chowns files still at mode 000, so briefly
     * raise the mode and restore it when the first write is refused. */
    int retries = 0;
    struct stat st;
    for (;;) {
        if (setxattr(hostpath, "user.oah.uid", buf, (size_t)n, 0, opts) == 0) {
            n = snprintf(buf, sizeof(buf), "%llu", (unsigned long long)gid);
            if (setxattr(hostpath, "user.oah.gid", buf, (size_t)n, 0,
                         opts) == 0) {
                if (retries) {
                    chmod(hostpath, st.st_mode);
                }
                return 0;
            }
        }
        int error = errno;
        if (retries++ || (error != EACCES && error != EPERM) ||
            lstat(hostpath, &st) < 0 ||
            (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) ||
            chmod(hostpath, (st.st_mode & ~S_IFMT) |
                            (S_ISDIR(st.st_mode) ? 0700 : 0600)) < 0) {
            errno = error;
            return linux_error(errno);
        }
    }
}

/* True when `abs` (an absolute host path) lies inside the sysroot. */
static bool under_sysroot(const oah_image *img, const char *abs)
{
    static const char *root_for;
    static char root_abs[PATH_MAX];
    if (!img->sysroot) {
        return false;
    }
    if (root_for != img->sysroot) {
        if (!realpath(img->sysroot, root_abs)) {
            return false;
        }
        root_for = img->sysroot;
    }
    size_t rl = strlen(root_abs);
    return !strncmp(abs, root_abs, rl) &&
           (abs[rl] == '/' || abs[rl] == 0);
}

/* Read recorded ownership back; returns true when xattrs present. */
static bool recorded_owner(const char *hostpath, u32 *uid, u32 *gid)
{
    char buf[16];
    ssize_t u = getxattr(hostpath, "user.oah.uid", buf, sizeof(buf) - 1, 0, 0);
    if (u <= 0) {
        return false;
    }
    buf[u] = 0;
    *uid = (u32)strtoul(buf, NULL, 10);
    ssize_t g = getxattr(hostpath, "user.oah.gid", buf, sizeof(buf) - 1, 0, 0);
    if (g > 0) {
        buf[g] = 0;
        *gid = (u32)strtoul(buf, NULL, 10);
    }
    return true;
}

/* For *reading* path calls (chdir, readlink, ...): resolve FHS paths into
 * the sysroot when the entry exists there, else keep the host path. */
static int resolve_read_path(const oah_image *img, const char *path,
                             char *out, size_t capacity, bool leaf_follow)
{
    if (!path || path[0] != '/' || !sysroot_path(img, path)) {
        return 0;
    }
    /* leaf_follow resolves a trailing symlink inside the sysroot too, for
     * calls that follow links; leaf-literal keeps it for lstat/readlink/
     * mutating calls so the host sees the link itself. */
    bool ok = leaf_follow
        ? oah_sysroot_readpath(img->sysroot, path, out, capacity)
        : oah_sysroot_hostpath(img->sysroot, path, out, capacity);
    if (ok) {
        struct stat st;
        if (sysroot_strict(img)) {
            return 1; /* strict: no host fallback; ENOENT comes from out */
        }
        return lstat(out, &st) == 0 ? 1 : 0;
    }
    return sysroot_strict(img) ? linux_error(errno) : 0;
}

/* Resolve a chown/chmod-style path to a host path inside the sysroot for
 * recorded-ownership handling. Handles absolute paths (component walk),
 * relative paths (anchored at dirfd or the guest cwd, which strict mode
 * keeps inside the sysroot), and AT_EMPTY_PATH (dirfd is the target).
 * Returns 1 when `out` holds a sysroot path to record on, 0 when the target
 * lies outside the sysroot (host semantics apply), <0 on resolution error
 * which the caller must propagate. */
static int owner_record_path(const oah_image *img, int dirfd,
                             const char *path, bool empty_path,
                             char *out, size_t capacity)
{
    if (!img->sysroot || !path) {
        return 0;
    }
    if (!*path) {
        if (!empty_path || dirfd == AT_FDCWD ||
            fcntl(dirfd, F_GETPATH, out) < 0) {
            return 0;
        }
        return under_sysroot(img, out) ? 1 : 0;
    }
    if (path[0] == '/') {
        int rr = resolve_read_path(img, path, out, capacity, true);
        if (rr < 0) {
            return rr;
        }
        return rr > 0 ? 1 : 0;
    }
    char base[PATH_MAX], joined[PATH_MAX], real[PATH_MAX];
    if (dirfd == AT_FDCWD) {
        if (!getcwd(base, sizeof(base))) {
            return false;
        }
    } else if (fcntl(dirfd, F_GETPATH, base) < 0) {
        return false;
    }
    if (snprintf(joined, sizeof(joined), "%s/%s", base, path) >=
            (int)sizeof(joined) ||
        !realpath(joined, real)) {
        return sysroot_strict(img) ? linux_error(errno) : 0;
    }
    if (!under_sysroot(img, real)) {
        return sysroot_strict(img) ? -ENOENT : 0;
    }
    snprintf(out, capacity, "%s", real);
    return 1;
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

/* ==================== virtual /proc ====================
 * A growing set of guests probe /proc (LibreOffice opens
 * /proc/version at startup, Boehm GC reads /proc/stat, glib reads
 * /proc/mounts, dbus reads /proc/sys/net/core/somaxconn). Nothing in
 * the sysroot backs those paths, so synthesize them: files are served
 * through an unlinked temp fd, directories through an empty temp dir.
 * /proc/self and /proc/<our-pid> collapse to the same synthesized
 * target; other pids report ENOENT. */

static bool proc_path_rel(const char *path, const char **rel)
{
    if (!strcmp(path, "/proc")) {
        *rel = "";
        return true;
    }
    if (!strncmp(path, "/proc/", 6)) {
        *rel = path + 6;
        return true;
    }
    return false;
}

/* Fold self/thread-self/<our-pid> prefixes into "self/...". */
static const char *proc_rel_canon(const char *rel, char *buf, size_t cap)
{
    if (!strncmp(rel, "self/", 5) || !strcmp(rel, "self")) {
        return rel;
    }
    if (!strncmp(rel, "thread-self/", 12)) {
        snprintf(buf, cap, "self/%s", rel + 12);
        return buf;
    }
    char *end;
    unsigned long pid = strtoul(rel, &end, 10);
    if (end != rel && pid == (unsigned long)getpid()) {
        if (!*end) {
            return "self";
        }
        if (*end == '/') {
            snprintf(buf, cap, "self/%s", end + 1);
            return buf;
        }
    }
    return rel;
}

static bool proc_is_dir(const char *rel)
{
    static const char *dirs[] = {
        "", "self", "self/fd", "self/task", "sys", "sys/kernel",
        "sys/kernel/random", "sys/vm", "sys/fs", "sys/net", "sys/net/core",
        "sys/crypto",
    };
    for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (!strcmp(rel, dirs[i])) {
            return true;
        }
    }
    return false;
}

static bool proc_is_link(const char *rel)
{
    return !strcmp(rel, "self/exe") || !strncmp(rel, "self/fd/", 8);
}

/* Fills buf with the synthesized content of a /proc file. Returns the
 * length or -ENOENT for an unknown path. */
static s64 procfs_synth(const oah_image *img, const char *rel,
                        u8 *buf, size_t cap)
{
    size_t n;
    pid_t pid = getpid();
    const char *exe = oah_proc_self_exe();
    if (!exe || !*exe) {
        exe = "oah";
    }
    const char *comm = strrchr(exe, '/');
    comm = comm ? comm + 1 : exe;
    char short_comm[16];
    snprintf(short_comm, sizeof(short_comm), "%.15s", comm);

#define PROC_S(...) do { \
        int w = snprintf((char *)buf + n, cap - n, __VA_ARGS__); \
        if (w < 0) return -EIO; \
        if ((size_t)w >= cap - n) return -EOVERFLOW; \
        n += (size_t)w; \
    } while (0)

    n = 0;
    if (!strcmp(rel, "version")) {
        PROC_S("Linux version 6.1.0-31-amd64 (debian-kernel@lists.debian.org) "
               "(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for "
               "Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.128-1 "
               "(2025-02-07)\n");
        return (s64)n;
    }
    if (!strcmp(rel, "meminfo")) {
        u64 memsize = 4ull << 30;
        size_t sz = sizeof(memsize);
        if (sysctlbyname("hw.memsize", &memsize, &sz, NULL, 0) < 0) {
            memsize = 4ull << 30;
        }
        u64 total = memsize / 1024, free_amt = total / 4;
        PROC_S("MemTotal:       %8llu kB\n"
               "MemFree:        %8llu kB\n"
               "MemAvailable:   %8llu kB\n"
               "Buffers:               0 kB\n"
               "Cached:         %8llu kB\n"
               "SwapCached:            0 kB\n"
               "Active:         %8llu kB\n"
               "Inactive:       %8llu kB\n"
               "SwapTotal:             0 kB\n"
               "SwapFree:              0 kB\n"
               "HugePages_Total:       0\n",
               (unsigned long long)total, (unsigned long long)free_amt,
               (unsigned long long)(total / 2), (unsigned long long)free_amt,
               (unsigned long long)(total / 4), (unsigned long long)free_amt);
        return (s64)n;
    }
    if (!strcmp(rel, "cpuinfo")) {
        int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) {
            ncpu = 1;
        }
        for (int i = 0; i < ncpu; i++) {
            PROC_S("processor\t: %d\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
                   "model\t\t: 158\nmodel name\t: Virtual CPU @ 2.40GHz\n"
                   "stepping\t: 10\ncpu MHz\t\t: 2400.000\ncache size\t: 4096 KB\n"
                   "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep "
                   "mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 "
                   "ss ht syscall nx pdpe1gb rdtscp lm constant_tsc "
                   "rep_good nopl xtopology cpuid tsc_known_freq pni "
                   "pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic "
                   "movbe popcnt aes xsave avx f16c rdrand hypervisor "
                   "lahf_lm abm 3dnowprefetch fsgsbase bmi1 hle avx2 "
                   "bmi2 erms invpcid rtm rdseed adx clflushopt\n\n", i);
        }
        return (s64)n;
    }
    if (!strcmp(rel, "stat")) {
        int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) {
            ncpu = 1;
        }
        PROC_S("cpu  0 0 0 0 0 0 0 0 0 0\n");
        for (int i = 0; i < ncpu; i++) {
            PROC_S("cpu%d 0 0 0 0 0 0 0 0 0 0\n", i);
        }
        PROC_S("intr 0\nctxt 0\nbtime %lld\nprocesses %d\n"
               "procs_running 1\nprocs_blocked 0\n",
               (long long)time(NULL) - 3600, pid);
        return (s64)n;
    }
    if (!strcmp(rel, "uptime")) {
        PROC_S("3600.00 14000.00\n");
        return (s64)n;
    }
    if (!strcmp(rel, "loadavg")) {
        PROC_S("0.10 0.20 0.30 1/100 %d\n", pid);
        return (s64)n;
    }
    if (!strcmp(rel, "mounts")) {
        PROC_S("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
               "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
               "/dev/vda1 / ext4 rw,relatime,errors=remount-ro 0 1\n"
               "devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
               "tmpfs /tmp tmpfs rw,relatime 0 0\n");
        return (s64)n;
    }
    if (!strcmp(rel, "filesystems")) {
        PROC_S("nodev\tsysfs\nnodev\tproc\nnodev\ttmpfs\nnodev\tdevtmpfs\n"
               "\text4\n\text3\n\text2\n\tvfat\n\tiso9660\n");
        return (s64)n;
    }
    if (!strcmp(rel, "self/cmdline")) {
        n = strlen(exe);
        if (n + 2 > cap) {
            return -EOVERFLOW;
        }
        memcpy(buf, exe, n);
        buf[n++] = 0;
        return (s64)n;
    }
    if (!strcmp(rel, "self/environ")) {
        return 0; /* empty */
    }
    if (!strcmp(rel, "self/comm")) {
        PROC_S("%s\n", short_comm);
        return (s64)n;
    }
    if (!strcmp(rel, "self/stat")) {
        PROC_S("%d (%s) S %d %d %d 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 "
               "%lld %llu 256 18446744073709551615 4194304 4194304 "
               "140736000000000 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0\n",
               (int)pid, short_comm, (int)getppid(), (int)pid, (int)pid,
               (long long)(time(NULL) - 10), (unsigned long long)(64 << 20));
        return (s64)n;
    }
    if (!strcmp(rel, "self/status")) {
        u32 uid = img->guest_uid[0], gid = img->guest_gid[0];
        PROC_S("Name:\t%s\nState:\tS (sleeping)\nTgid:\t%d\nNgid:\t0\nPid:\t%d\n"
               "PPid:\t%d\nTracerPid:\t0\nUid:\t%u\t%u\t%u\t%u\n"
               "Gid:\t%u\t%u\t%u\t%u\nUtrace:\t0\n"
               "FDSize:\t256\nGroups:\t%u \n"
               "VmPeak:\t  131072 kB\nVmSize:\t  131072 kB\nVmRSS:\t    8192 kB\n"
               "Threads:\t1\nSigQ:\t1/64000\n"
               "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
               "CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n"
               "Seccomp:\t0\nSpeculation_Store_Bypass:\tnot vulnerable\n",
               short_comm, (int)pid, (int)pid, (int)getppid(),
               uid, uid, uid, uid, gid, gid, gid, gid, gid);
        return (s64)n;
    }
    if (!strcmp(rel, "self/maps")) {
        for (unsigned i = 0; i < img->nseg; i++) {
            const oah_load_seg *s = &img->segs[i];
            char perms[5] = "----";
            perms[0] = s->prot & PROT_READ ? 'r' : '-';
            perms[1] = s->prot & PROT_WRITE ? 'w' : '-';
            perms[2] = s->prot & PROT_EXEC ? 'x' : '-';
            perms[3] = 'p';
            PROC_S("%08llx-%08llx %s %08llx 00:00 0\n",
                   (unsigned long long)s->gva,
                   (unsigned long long)(s->gva + s->size),
                   perms, 0ull);
        }
        return (s64)n;
    }
    if (!strcmp(rel, "self/limits")) {
        struct rlimit rl;
        u64 nofile = 1024;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            nofile = rl.rlim_cur == RLIM_INFINITY ? ~0ull : (u64)rl.rlim_cur;
        }
        PROC_S("Limit                     Soft Limit           Hard Limit           Units\n"
               "Max cpu time              unlimited            unlimited            seconds\n"
               "Max file size             unlimited            unlimited            bytes\n"
               "Max data size             unlimited            unlimited            bytes\n"
               "Max stack size            8388608              unlimited            bytes\n"
               "Max core file size        0                    unlimited            bytes\n"
               "Max resident set          unlimited            unlimited            bytes\n"
               "Max processes             64000                64000                processes\n"
               "Max open files            %-20llu %-20llu files\n"
               "Max locked memory         65536                65536                bytes\n"
               "Max address space         unlimited            unlimited            bytes\n"
               "Max file locks            unlimited            unlimited            locks\n"
               "Max pending signals       64000                64000                signals\n"
               "Max msgqueue size         819200               819200               bytes\n"
               "Max nice priority         0                    0                    \n"
               "Max realtime priority     0                    0                    \n"
               "Max realtime timeout      unlimited            unlimited            us\n",
               (unsigned long long)nofile, (unsigned long long)nofile);
        return (s64)n;
    }
    if (!strcmp(rel, "self/cgroup")) {
        PROC_S("0::/\n");
        return (s64)n;
    }
    if (!strcmp(rel, "cgroup")) {
        PROC_S("#subsys_name\thierarchy\tnum_cgroups\tenabled\n"
               "cpuset\t0\t1\t1\ncpu\t0\t1\t1\nmemory\t0\t1\t1\n");
        return (s64)n;
    }
    if (!strcmp(rel, "self/loginuid")) {
        PROC_S("4294967295\n");
        return (s64)n;
    }
    if (!strcmp(rel, "self/oom_score_adj") || !strcmp(rel, "self/oom_score")) {
        PROC_S("0\n");
        return (s64)n;
    }
    if (!strcmp(rel, "self/personality")) {
        PROC_S("00000000\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/ostype")) {
        PROC_S("Linux\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/osrelease")) {
        PROC_S("6.1.0-31-amd64\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/hostname")) {
        char host[256] = "attesor";
        gethostname(host, sizeof(host) - 1);
        PROC_S("%s\n", host);
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/ngroups_max")) {
        PROC_S("65536\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/pid_max")) {
        PROC_S("4194304\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/threads-max")) {
        PROC_S("128000\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/random/boot_id")) {
        /* Stable per-machine id: dbus-daemon falls back to this. */
        PROC_S("61747473-6f72-0000-8000-000000000000\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/net/core/somaxconn")) {
        PROC_S("4096\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/vm/max_map_count")) {
        PROC_S("262144\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/vm/overcommit_memory")) {
        PROC_S("0\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/fs/file-max") || !strcmp(rel, "sys/fs/nr_open")) {
        PROC_S("1073741816\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/crypto/fips_enabled")) {
        PROC_S("0\n");
        return (s64)n;
    }
    if (!strcmp(rel, "sys/kernel/yama/ptrace_scope")) {
        PROC_S("0\n");
        return (s64)n;
    }
    return -ENOENT;
#undef PROC_S
}

/* Paths under /proc/self that accept writes (into the void). */
static bool proc_writable(const char *rel)
{
    return !strcmp(rel, "self/oom_score_adj") ||
           !strcmp(rel, "self/loginuid") ||
           !strcmp(rel, "self/coredump_filter");
}

/* Serve a /proc open. Files go through an unlinked temp fd so reads,
 * seeks, and fstat behave naturally; dirs through an empty temp dir
 * (getdents yields an empty listing). Returns fd or -errno; caller has
 * already confirmed the path lives under /proc. */
static s64 procfs_open(const oah_image *img, const char *rel,
                       int host_flags, u64 mode)
{
    char canon[256];
    rel = proc_rel_canon(rel, canon, sizeof(canon));
    bool wants_write = (host_flags & O_ACCMODE) != O_RDONLY;
    if (host_flags & O_DIRECTORY) {
        if (!proc_is_dir(rel) && strcmp(rel, "self/exe")) {
            return proc_is_link(rel) || procfs_synth(img, rel, (u8[1]){0}, 1) != -ENOENT
                       ? -ENOTDIR : -ENOENT;
        }
        wants_write = false;
    }
    if (proc_is_dir(rel)) {
        if (wants_write) {
            return -EISDIR;
        }
        char tmpl[] = "/tmp/oah-procdir-XXXXXX";
        if (!mkdtemp(tmpl)) {
            return -ENOMEM;
        }
        int fd = open(tmpl, O_RDONLY | O_DIRECTORY);
        int keep = errno;
        rmdir(tmpl);
        return fd < 0 ? linux_error(keep) : fd;
    }
    if (proc_is_link(rel)) {
        /* readlink handles these; opening the link itself means "target". */
        return -ENOENT;
    }
    if (wants_write && !proc_writable(rel)) {
        return -EACCES;
    }
    u8 *content = malloc(1u << 20);
    if (!content) {
        return -ENOMEM;
    }
    s64 len = procfs_synth(img, rel, content, 1u << 20);
    if (len < 0) {
        free(content);
        if (wants_write && proc_writable(rel)) {
            len = 0; /* writable node with no synth entry: start empty */
        } else {
            return len;
        }
    }
    char tmpl[] = "/tmp/oah-proc-XXXXXX";
    int fd = mkstemp(tmpl);
    int keep = errno;
    unlink(tmpl);
    if (fd < 0) {
        free(content);
        return linux_error(keep);
    }
    bool bad = len && write(fd, content, (size_t)len) != len;
    free(content);
    if (bad || lseek(fd, 0, SEEK_SET) < 0) {
        keep = errno;
        close(fd);
        return linux_error(keep);
    }
    if (host_flags & O_NONBLOCK) {
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }
    if (host_flags & O_CLOEXEC) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    return fd;
}

/* Fill a linux_stat for a virtual /proc path. Returns 0, -ENOENT, or
 * -EFALLTHROUGH sentinel meaning "let normal resolution run" (used for
 * /proc/self/exe with follow-symlink semantics). */
#define PROC_STAT_PASSTHROUGH ((s64)-77777)

static s64 procfs_stat(const oah_image *img, const char *rel,
                       linux_stat *out, bool nofollow)
{
    char canon[256];
    rel = proc_rel_canon(rel, canon, sizeof(canon));
    u32 mode;
    s64 size = 0;
    if (proc_is_dir(rel)) {
        mode = S_IFDIR | 0555;
    } else if (proc_is_link(rel)) {
        if (!nofollow && !strcmp(rel, "self/exe")) {
            return PROC_STAT_PASSTHROUGH; /* stat the real exe */
        }
        mode = S_IFLNK | 0777;
        size = 64;
    } else {
        u8 scratch[4096];
        s64 len = procfs_synth(img, rel, scratch, sizeof(scratch));
        if (len < 0) {
            /* Content may exceed the scratch cap — retry at full size. */
            u8 *big = malloc(1u << 20);
            if (!big) {
                return -ENOMEM;
            }
            len = procfs_synth(img, rel, big, 1u << 20);
            free(big);
            if (len < 0) {
                return len;
            }
        }
        mode = S_IFREG | 0444;
        size = len;
    }
    u64 ino = 5381;
    for (const char *p = rel; *p; p++) {
        ino = ino * 33 ^ (u8)*p;
    }
    u64 now = (u64)time(NULL);
    *out = (linux_stat){
        .dev = 0x13, .ino = ino, .nlink = (mode & S_IFMT) == S_IFDIR ? 2 : 1,
        .mode = mode, .uid = img->guest_uid[0], .gid = img->guest_gid[0],
        .size = size, .blksize = 4096, .blocks = (size + 511) / 512,
        .atime_sec = (s64)now, .mtime_sec = (s64)now, .ctime_sec = (s64)now,
    };
    return 0;
}

static const struct { u32 guest; int host; } open_flags[] = {
    {0x40, O_CREAT}, {0x80, O_EXCL}, {0x100, O_NOCTTY}, {0x200, O_TRUNC},
    {0x400, O_APPEND}, {0x800, O_NONBLOCK}, {0x10000, O_DIRECTORY},
    {0x20000, O_NOFOLLOW}, {0x80000, O_CLOEXEC}, {0x200000, 0} /* O_PATH */
};

/* Guest fd -> canonical host path, for tagging file-backed guest mmaps with
 * their module so translated fragments can persist across runs. */
#define OAH_FD_PATH_MAX 1024
static char fd_path[OAH_FD_PATH_MAX][PATH_MAX];
/* memfd_create emulation: Darwin has no file sealing, so seals are tracked
 * here and enforced at the ftruncate/mmap call sites. */
static u8 fd_seals[OAH_FD_PATH_MAX];
static bool fd_is_memfd[OAH_FD_PATH_MAX];
#define OAH_F_SEAL_SEAL  0x01
#define OAH_F_SEAL_SHRINK 0x02
#define OAH_F_SEAL_GROW  0x04
#define OAH_F_SEAL_WRITE 0x08
#define OAH_F_SEAL_FUTURE_WRITE 0x10

static void track_fd_path(int fd)
{
    if (fd < 0 || fd >= OAH_FD_PATH_MAX) {
        return;
    }
    fd_path[fd][0] = 0;
    (void)fcntl(fd, F_GETPATH, fd_path[fd]);
    fd_path[fd][PATH_MAX - 1] = 0;
}

static void untrack_fd_path(int fd)
{
    if (fd >= 0 && fd < OAH_FD_PATH_MAX) {
        fd_path[fd][0] = 0;
        fd_seals[fd] = 0;
        fd_is_memfd[fd] = false;
    }
}

static const char *tracked_fd_path(int fd)
{
    return fd >= 0 && fd < OAH_FD_PATH_MAX && fd_path[fd][0] ? fd_path[fd] : NULL;
}

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
    const char *prel;
    char canon[256];
    if (path[0] == '/' && proc_path_rel(path, &prel)) {
        prel = proc_rel_canon(prel, canon, sizeof(canon));
        if (!strcmp(prel, "self/exe")) {
            /* open follows the link to the real executable. */
            path = oah_proc_self_exe();
        } else if (!strncmp(prel, "self/fd/", 8) &&
                   !(host_flags & O_NOFOLLOW)) {
            /* open("/proc/self/fd/N") is dup(N). */
            char *end;
            long fdn = strtol(prel + 8, &end, 10);
            if (end == prel + 8 || *end) {
                return -ENOENT;
            }
            s64 r = host_result(fcntl((int)fdn,
                                      host_flags & O_CLOEXEC ? F_DUPFD_CLOEXEC
                                                             : F_DUPFD, 0));
            if (r >= 0 && fdn < OAH_FD_PATH_MAX && r < OAH_FD_PATH_MAX) {
                fd_seals[(int)r] = fd_seals[fdn];
                fd_is_memfd[(int)r] = fd_is_memfd[fdn];
            }
            { static int t = -1;
              if (t < 0) { t = getenv("OAH_MFD_TRACE") != NULL; }
              if (t) { fprintf(stderr, "proc/self/fd open fd=%ld flags=%x -> %lld\n",
                               fdn, host_flags, (long long)r); } }
            return r;
        } else {
            return procfs_open(img, prel, host_flags, mode);
        }
    }
    s64 result = host_result(open_guest_path(img, dirfd, path, host_flags, mode));
    if (result >= 0) {
        track_fd_path((int)result);
    }
    static int open_trace = -1;
    if (open_trace < 0) {
        open_trace = getenv("OAH_OPEN_TRACE") != NULL;
    }
    if (open_trace) {
        fprintf(stderr, "open(%s) = %lld\n", path, (long long)result);
    }
    return result;
}

static u64 linux_device(dev_t number)
{
    u64 minor_number = (u64)minor(number);
    return ((u64)major(number) << 8) | (minor_number & 0xff) |
           ((minor_number & ~0xffull) << 12);
}

static s64 guest_stat(oah_image *img, int dirfd, const char *path, u64 addr, u64 flags)
{
    {
        static int open_trace = -1;
        if (open_trace < 0) {
            open_trace = getenv("OAH_OPEN_TRACE") != NULL;
        }
        if (open_trace) {
            fprintf(stderr, "stat-in(%s,fd=%d,fl=%llx)\n", path ? path : "?",
                    dirfd, (unsigned long long)flags);
        }
    }
    void *output = oah_guest_access(img, addr, sizeof(linux_stat), PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    if (flags & ~0x1900ull) { /* AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW. */
        return -EINVAL;
    }
    char pts[64];
    int unit = -1;
    if (path && !strncmp(path, "/dev/pts/", 9) &&
        sscanf(path + 9, "%d", &unit) == 1) {
        snprintf(pts, sizeof(pts), "/dev/ttys%03d", unit);
        path = pts;
    }
    struct stat st;
    int result;
    const char *owner_path = NULL;
    char resolved[PATH_MAX];
    const char *prel;
    if (path && path[0] == '/' && proc_path_rel(path, &prel)) {
        linux_stat pst;
        s64 pr = procfs_stat(img, prel, &pst, (flags & 0x100) != 0);
        if (pr == PROC_STAT_PASSTHROUGH) {
            path = oah_proc_self_exe(); /* stat follows to the real exe */
        } else {
            if (pr < 0) {
                return pr;
            }
            memcpy(output, &pst, sizeof(pst));
            return 0;
        }
    }
    if (!path || (!*path && (flags & 0x1000) && dirfd != -100)) {
        result = fstat(dirfd, &st);
        /* statx(AT_EMPTY_PATH)/fstat on a sysroot-opened fd: recover the
         * host path so recorded ownership still applies. */
        static char fd_path[PATH_MAX];
        if (result == 0 &&
            fcntl(dirfd, F_GETPATH, fd_path) == 0 &&
            under_sysroot(img, fd_path)) {
            owner_path = fd_path;
        }
    } else if (sysroot_path(img, path)) {
        /* Resolve through the sysroot first (component walk keeps the leaf
         * symlink intact for AT_SYMLINK_NOFOLLOW and makes relative links
         * resolve inside the sysroot); fall back to the host on ENOENT. */
        int rr = resolve_read_path(img, path, resolved, sizeof(resolved), !(flags & 0x100));
        if (rr < 0) {
            return rr;
        }
        const char *sp = rr ? resolved : path;
        owner_path = rr ? resolved : NULL;
        result = fstatat(dirfd == -100 ? AT_FDCWD : dirfd, sp, &st,
                         flags & 0x100 ? AT_SYMLINK_NOFOLLOW : 0);
    } else {
        result = fstatat(dirfd == -100 ? AT_FDCWD : dirfd,
                         !*path && (flags & 0x1000) ? "." : path, &st,
                         flags & 0x100 ? AT_SYMLINK_NOFOLLOW : 0);
    }
    {
        static int open_trace = -1;
        if (open_trace < 0) {
            open_trace = getenv("OAH_OPEN_TRACE") != NULL;
        }
        if (open_trace) {
            fprintf(stderr, "stat(%s,fd=%d,fl=%llx) = %d\n", path ? path : "?",
                    dirfd, (unsigned long long)flags, result);
        }
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
    if (owner_path) {
        u32 uid, gid;
        if (recorded_owner(owner_path, &uid, &gid)) {
            converted.uid = uid;
            converted.gid = gid;
        }
    }
    memcpy(output, &converted, sizeof(converted));
    return 0;
}

static u64 guest_brk(oah_image *img, u64 addr)
{
    const u64 capacity = 64u << 20;
    /* The brk heap is identity-mapped on Darwin: the guest VA of its first
     * byte is the host address of the backing reservation, so translated
     * fragments can use raw guest addresses. */
    u64 heap_base = img->heap_mapping ? (u64)(uintptr_t)img->heap_mapping
                                    : img->load_end;
    if (!addr || addr < heap_base || addr - heap_base > capacity) {
        return img->brk;
    }
    const u64 mask = OAH_X86_PAGE_SIZE - 1;
    u64 end = (addr - heap_base + mask) & ~mask;
    u64 old = (img->brk - heap_base + mask) & ~mask;
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
        /* Rebase: heap gva is the backing's host address. */
        heap_base = (u64)(uintptr_t)backing;
        img->brk = heap_base;
        end = old = img->heap_guard;
    }
    if (end < old) {
        memset(img->heap_mapping + end, 0, old - end);
    }
    if (end > img->heap_guard) {
        if (index == img->nseg) {
            img->nseg++;
        }
        img->segs[index] = (oah_load_seg){
            .gva = heap_base + img->heap_guard,
            .size = end - img->heap_guard,
            .host = img->heap_mapping + img->heap_guard,
            .prot = PROT_READ | PROT_WRITE, .module = -1
        };
    } else if (index < img->nseg) {
        img->segs[index] = img->segs[--img->nseg];
    }
    if (getenv("OAH_SEG_DEBUG")) {
        fprintf(stderr, "brk addr=%llx end=%llx old=%llx index=%u nseg=%u\n",
                (unsigned long long)addr, (unsigned long long)end,
                (unsigned long long)old, index, img->nseg);
    }
    img->brk = addr;
    return addr;
}

/* Host protection mirroring a guest prot value. JIT'd accesses run as
 * bare host loads/stores, so hardware must enforce guest permissions:
 * a store to a PROT_READ guest page faults and the fault handler routes
 * it back through the interpreter for the guest-visible fault. Guest
 * PROT_EXEC never maps to host exec (translated code runs from the code
 * cache) but implies host read so the translator can fetch guest bytes.
 */
static int host_prot_for(u64 prot)
{
    int p = (int)(prot & (PROT_READ | PROT_WRITE));
    if (prot & PROT_EXEC) {
        p |= PROT_READ;
    }
    return p;
}

/* Recompute host permissions for each host page touching [gva,gva+len).
 * Host pages are 16KB while guest pages are 4KB and mprotect requires a
 * host-page-aligned start, so guest permissions cannot be mirrored one
 * for one inside a shared host page. Each host page therefore gets the
 * OR of the guest permissions across its subpages: a guest-writable
 * subpage keeps the host page writable so legitimate stores never
 * fault, while a page that is entirely guest-read-only or unmapped ends
 * up host-read-only or inaccessible, so JIT'd stores fault and are
 * routed back through the interpreter like unmapped accesses. */
static void host_sync_prot(oah_image *img, u64 gva, u64 len)
{
    const u64 hmask = (u64)getpagesize() - 1;
    for (u64 p = gva & ~hmask; p < gva + len; p += hmask + 1) {
        int prot = 0;
        for (u64 s = 0; s <= hmask; s += OAH_X86_PAGE_SIZE) {
            u64 sub = p + s;
            for (unsigned i = 0; i < img->nseg; i++) {
                const oah_load_seg *seg = &img->segs[i];
                if (sub >= seg->gva && sub < seg->gva + seg->size) {
                    prot |= (int)seg->prot;
                    break;
                }
            }
        }
        mprotect((void *)(uintptr_t)p, hmask + 1, host_prot_for(prot));
    }
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
    if (original.host) {
        host_sync_prot(img, addr, len);
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

/* Tag a file-backed guest mapping with its source module so translated
 * fragments for it can persist on disk. */
static void tag_mapped_module(oah_image *img, u64 gva, u64 size, int fd)
{
    const char *path = tracked_fd_path(fd);
    if (path) {
        int module = oah_image_module_register(img, path);
        if (module >= 0) {
            oah_image_tag_module(img, gva, size, module);
        }
    }
}

static s64 guest_mmap(oah_image *img, u64 address, u64 size, u64 prot, u64 flags, int fd, u64 offset)
{
    flags &= ~(0x800ull | 0x20000ull); /* Linux MAP_DENYWRITE and MAP_STACK. */
    /* Advisory flags we can safely ignore: MAP_32BIT (0x40),
     * MAP_GROWSDOWN (0x100), MAP_LOCKED (0x2000), MAP_NORESERVE
     * (0x4000), MAP_POPULATE (0x8000), MAP_NONBLOCK (0x10000).
     * MAP_32BIT only constrains host address choice; the guest
     * address space is ours anyway. */
    flags &= ~(0x40ull | 0x100ull | 0x2000ull | 0x4000ull | 0x8000ull | 0x10000ull);
    if ((flags & 0x3) == 0x3) {
        /* MAP_SHARED_VALIDATE == MAP_SHARED for our purposes. */
        flags = (flags & ~0x3ull) | 0x1;
    }
    if (!size || size > (1ull << 42) || (prot & ~7ull) ||
        (flags != 0x01 && flags != 0x11 && flags != 0x21 && flags != 0x31 &&
         flags != 0x02 && flags != 0x12 && flags != 0x22 && flags != 0x32)) {
        { static int t = -1; if (t < 0) { t = getenv("OAH_MMAP_TRACE") != NULL; }
          if (t) { fprintf(stderr, "mmap einval addr=%llx sz=%llx fl=%llx\n",
                           (unsigned long long)address, (unsigned long long)size,
                           (unsigned long long)flags); } }
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
        /* Darwin POSIX shm objects (memfd backing) report S_IFMT == 0. */
        if (!S_ISREG(metadata.st_mode) && (metadata.st_mode & S_IFMT)) {
            return -ENODEV;
        }
    } else if (fd != -1 || offset) {
        return -EINVAL;
    }
    if (fixed && !file && img->heap_mapping &&
        address == (u64)(uintptr_t)img->heap_mapping) {
        /* musl marks the first page of the brk arena as a guard. */
        if (size != OAH_X86_PAGE_SIZE || prot || img->heap_guard) {
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
            if (!seg->allocation || address < seg->gva || address - seg->gva >= seg->size ||
                size > seg->size - (address - seg->gva)) {
                continue;
            }
            u64 left = address - seg->gva;
            unsigned extra = (left != 0) + (size != seg->size - left);
            if (extra > OAH_MAX_LOAD_SEGS - img->nseg) {
                return -ENOMEM;
            }
            /* Stage by replacing the covered host pages with fresh
             * anonymous pages — Linux MAP_FIXED replaces pages, it does
             * not modify them in place. mprotect cannot do this job:
             * the reservation may contain host-side holes or file-backed
             * pages whose max protection forbids writes. Host mmap/munmap
             * need host-page (16KB) granularity, so a page is replaced
             * only when it lies wholly inside this seg's host range —
             * munmap'ing a page that extends past the seg would destroy
             * neighbouring mappings. A partial tail page is instead
             * written in place at 4KB granularity. Within a replaced
             * page, bytes outside the covered range are preserved when
             * the guest can still read them. */
            {
                const uintptr_t hmask = (uintptr_t)getpagesize() - 1;
                uintptr_t h = (uintptr_t)(seg->host + left);
                uintptr_t hend = h + size;
                uintptr_t seg_lo = (uintptr_t)seg->host;
                uintptr_t seg_hi = seg_lo + seg->size;
                size_t span = ((hend + hmask) & ~hmask) - (h & ~hmask);
                u8 *staged = calloc(1, span);
                if (!staged) {
                    return -ENOMEM;
                }
                bool ok = true;
                int error = 0;
                if (file && !load_file(staged + (h & hmask), size, fd,
                                       offset)) {
                    ok = false;
                    error = errno;
                }
                for (uintptr_t p = h & ~hmask; ok && p < hend;
                     p += hmask + 1) {
                    uintptr_t ps = hmask + 1;
                    uintptr_t c_lo = p > h ? p : h;
                    uintptr_t c_hi = p + ps < hend ? p + ps : hend;
                    u8 *dst = staged + (p - (h & ~hmask));
                    if (p < seg_lo || p + ps > seg_hi) {
                        /* Page reaches past the seg's host range: write
                         * the covered bytes in place — the rest belongs
                         * to other mappings, so it cannot be replaced.
                         * Raising the whole host page to RW briefly
                         * over-permits the untouched bytes; the
                         * host_sync_prot in split_mapping restores the
                         * merged protections right after staging. */
                        if (mprotect((void *)p, ps,
                                     PROT_READ | PROT_WRITE) != 0) {
                            ok = false;
                            error = errno;
                            break;
                        }
                        memcpy((void *)c_lo, dst + (c_lo - p),
                               c_hi - c_lo);
                        continue;
                    }
                    /* Whole host page is this seg's: replace it after
                     * stashing guest-readable bytes the mapping does
                     * not cover. */
                    u64 g_lo = address - (h - p);
                    for (u64 q = 0; q < ps; q += OAH_X86_PAGE_SIZE) {
                        if (q >= c_lo - p && q < c_hi - p) {
                            continue;
                        }
                        const void *src = oah_guest_access(
                            img, g_lo + q, OAH_X86_PAGE_SIZE, PROT_READ);
                        if (src) {
                            memcpy(dst + q, src, OAH_X86_PAGE_SIZE);
                        }
                    }
                    munmap((void *)p, ps);
                    void *rep = mmap((void *)p, ps, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                     -1, 0);
                    if (rep != (void *)p) {
                        ok = false;
                        error = rep == MAP_FAILED ? errno : ENOMEM;
                        break;
                    }
                    memcpy((void *)p, dst, ps);
                }
                free(staged);
                if (!ok) {
                    return linux_error(error);
                }
                oah_jit_cache_flush("map-fixed");
            }
            split_mapping(img, i, address, size, (u32)prot);
            img->segs[i + (left != 0)].file_mapping = file;
            if (file) {
                tag_mapped_module(img, address, size, fd);
            }
            { static int t = -1; if (t < 0) { t = getenv("OAH_MMAP_TRACE") != NULL; }
              if (t) { fprintf(stderr, "mmap fixed addr=%llx sz=%llx prot=%llx -> ok\n",
                               (unsigned long long)address,
                               (unsigned long long)size,
                               (unsigned long long)prot); } }
            return (s64)address;
        }
        { static int t = -1; if (t < 0) { t = getenv("OAH_MMAP_TRACE") != NULL; }
          if (t) { fprintf(stderr, "mmap fixed einval addr=%llx sz=%llx nseg=%u\n",
                           (unsigned long long)address, (unsigned long long)size,
                           img->nseg);
            for (unsigned j = 0; j < img->nseg; j++) {
                fprintf(stderr, "  seg[%u] gva=%llx sz=%llx prot=%x alloc=%p file=%d\n", j,
                        (unsigned long long)img->segs[j].gva,
                        (unsigned long long)img->segs[j].size,
                        img->segs[j].prot, img->segs[j].allocation,
                        img->segs[j].file_mapping);
            } } }
        return -EINVAL;
    }
    if (img->nseg == OAH_MAX_LOAD_SEGS) {
        return -ENOMEM;
    }
    u8 *backing;
    if (file && (flags & 0x01) && fd >= 0 && fd < OAH_FD_PATH_MAX &&
        fd_seals[fd] & (OAH_F_SEAL_WRITE | OAH_F_SEAL_FUTURE_WRITE) &&
        prot & PROT_WRITE) {
        return fd_seals[fd] & OAH_F_SEAL_FUTURE_WRITE ? -EBUSY
                                                      : -EPERM;
    }
    if (file && (flags & 0x01)) {
        /* MAP_SHARED on a file: hand the guest a genuinely shared host
         * mapping so writes reach the file (gdbm database updates). */
        backing = mmap(NULL, size, host_prot_for(prot), MAP_SHARED, fd,
                       (off_t)offset);
    } else {
        backing = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (backing == MAP_FAILED) {
        { static int t = -1; if (t < 0) { t = getenv("OAH_MFD_TRACE") != NULL; }
          if (t && file) { fprintf(stderr, "mmap file fd=%d sz=%llx prot=%llx off=%llx -> fail %d\n",
                                   fd, (unsigned long long)size, (unsigned long long)prot,
                                   (unsigned long long)offset, errno); } }
        return linux_error(errno);
    }
    if (file && !(flags & 0x01) && !load_file(backing, size, fd, offset)) {
        int error = errno;
        munmap(backing, size);
        return linux_error(error);
    }
    img->segs[img->nseg++] = (oah_load_seg){
        .gva = (u64)(uintptr_t)backing, .host = backing, .size = size, .prot = (u32)prot,
        .file_mapping = file, .allocation = backing, .allocation_size = size,
        .module = -1
    };
    if (!(file && (flags & 0x01))) {
        /* Anonymous/private backing starts RW for staging; then mirror
         * the guest protections so JIT'd accesses fault like the interp. */
        host_sync_prot(img, (u64)(uintptr_t)backing, size);
    }
    if (file) {
        tag_mapped_module(img, (u64)(uintptr_t)backing, size, fd);
    }
    if (getenv("OAH_SEG_DEBUG")) {
        fprintf(stderr, "mmap +seg gva=%p size=%llx prot=%llx\n",
                backing, (unsigned long long)size,
                (unsigned long long)prot);
    }
    return (s64)(uintptr_t)backing;
}

/* Only ranges that can contain guest code need a JIT flush: profiling
 * shows mprotect/munmap fires constantly on data mappings (malloc
 * arenas, RELRO, stacks) that hold no translated fragments. Checked
 * before the mapping changes so exec segs about to be unmapped still
 * count. */
static bool range_hits_exec(oah_image *img, u64 addr, u64 len)
{
    for (unsigned i = 0; i < img->nseg; i++) {
        const oah_load_seg *s = &img->segs[i];
        if ((s->prot & PROT_EXEC) &&
            addr < s->gva + s->size && s->gva < addr + len) {
            return true;
        }
    }
    return false;
}

static s64 memory_change(oah_image *img, u64 addr, u64 len, u64 prot, bool unmap)
{
    const u64 mask = OAH_X86_PAGE_SIZE - 1;
    if (!len || len > UINT64_MAX - mask || (prot & ~7ull) || (addr & mask)) {
        return -EINVAL;
    }
    if (range_hits_exec(img, addr, len)) {
        oah_jit_cache_flush("mprotect/munmap");
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
        for (unsigned i = img->load_segments; i < img->nseg; i++) {
            oah_load_seg *seg = &img->segs[i];
            if (!seg->allocation || addr < seg->gva || addr - seg->gva >= seg->size ||
                len > seg->size - (addr - seg->gva)) {
                continue;
            }
            u64 left = addr - seg->gva;
            u64 right = seg->size - left - len;
            if (left && right) {
                if (img->nseg == OAH_MAX_LOAD_SEGS) {
                    return -ENOMEM;
                }
                oah_load_seg tail = *seg;
                tail.gva += left + len;
                tail.host += left + len;
                tail.size = right;
                img->segs[img->nseg++] = tail;
                seg->size = left;
            } else if (left) {
                seg->size = left;
            } else if (right) {
                seg->gva += len;
                seg->host += len;
                seg->size = right;
            } else {
                bool last = true;
                for (unsigned j = img->load_segments; j < img->nseg; j++) {
                    if (j != i && img->segs[j].allocation == seg->allocation) {
                        last = false;
                        break;
                    }
                }
                if (last && munmap(seg->allocation, seg->allocation_size) != 0) {
                    return linux_error(errno);
                }
                *seg = img->segs[--img->nseg];
            }
            /* The guest range is gone but the host allocation usually
             * stays — deny host access over it so JIT'd loads/stores to
             * the unmapped range fault instead of touching stale
             * memory. Whole-allocation unmaps already munmap'd it. */
            host_sync_prot(img, addr, len);
            return 0;
        }
        return -EINVAL;
    }
    /* Linux mprotect may span multiple VMAs (e.g. ld.so applies RELRO
     * across consecutive segments), so walk the range splitting each
     * covered segment rather than requiring one to contain it whole.
     * Any unmapped gap fails like Linux's ENOMEM. */
    u64 cur = addr;
    const u64 end = addr + len;
    while (cur < end) {
        unsigned i;
        oah_load_seg *seg = NULL;
        for (i = 0; i < img->nseg; i++) {
            if (cur >= img->segs[i].gva &&
                cur - img->segs[i].gva < img->segs[i].size) {
                seg = &img->segs[i];
                break;
            }
        }
        if (!seg) {
            if (getenv("OAH_SEG_DEBUG")) {
                fprintf(stderr, "mprotect gap at gva=%llx (range %llx-%llx) segs:",
                        (unsigned long long)cur, (unsigned long long)addr,
                        (unsigned long long)end);
                for (unsigned j = 0; j < img->nseg; j++) {
                    fprintf(stderr, " [%llx+%llx]",
                            (unsigned long long)img->segs[j].gva,
                            (unsigned long long)img->segs[j].size);
                }
                fprintf(stderr, "\n");
            }
            return -ENOMEM;
        }
        u64 left = cur - seg->gva;
        u64 span = seg->size - left;
        if (span > end - cur) {
            span = end - cur;
        }
        unsigned extra = (left != 0) + (span != seg->size - left);
        if ((extra && i >= img->load_segments && !seg->allocation) ||
            extra > OAH_MAX_LOAD_SEGS - img->nseg) {
            if (getenv("OAH_SEG_DEBUG")) {
                fprintf(stderr, "mprotect unsplittable seg i=%u gva=%llx+%llx span=%llx nseg=%u\n",
                        i, (unsigned long long)seg->gva,
                        (unsigned long long)seg->size,
                        (unsigned long long)span, img->nseg);
            }
            return -ENOMEM;
        }
        split_mapping(img, i, cur, span, (u32)prot);
        cur += span;
    }
    return 0;
}

static s64 guest_mremap(oah_image *img, u64 address, u64 prior, u64 requested, u64 flags)
{
    if (range_hits_exec(img, address, prior)) {
        oah_jit_cache_flush("mremap");
    }
    const u64 mask = OAH_X86_PAGE_SIZE - 1;
    if (!prior || !requested || (address & mask) ||
        prior > (1ull << 30) || requested > (1ull << 30) ||
        (flags & ~1ull)) {
        return -EINVAL;
    }
    prior = (prior + mask) & ~mask;
    requested = (requested + mask) & ~mask;
    for (unsigned i = img->load_segments; i < img->nseg; i++) {
        oah_load_seg *seg = &img->segs[i];
        if (seg->gva != address || seg->size != prior || !seg->allocation ||
            seg->file_mapping || seg->host != seg->allocation) {
            continue;
        }
        for (unsigned j = img->load_segments; j < img->nseg; j++) {
            if (i != j && img->segs[j].allocation == seg->allocation) {
                return -LINUX_EOPNOTSUPP;
            }
        }
        if (requested <= prior) {
            /* Shrunk tail stays allocated but is gone for the guest. */
            seg->size = requested;
            host_sync_prot(img, address + requested, prior - requested);
            return (s64)address;
        }
        if (!(flags & 1)) {
            return -ENOMEM;
        }
        u8 *replacement = mmap(NULL, requested, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (replacement == MAP_FAILED) {
            return linux_error(errno);
        }
        memcpy(replacement, seg->host, prior);
        if (munmap(seg->allocation, seg->allocation_size) < 0) {
            int error = errno;
            munmap(replacement, requested);
            return linux_error(error);
        }
        seg->host = seg->allocation = replacement;
        seg->gva = (u64)(uintptr_t)replacement;
        seg->size = seg->allocation_size = requested;
        host_sync_prot(img, seg->gva, requested);
        return (s64)seg->gva;
    }
    return -EFAULT;
}

static bool current_guest_task(const oah_guest *g, u64 target)
{
    return !target || (s32)target == getpid() || (g->tid && (u32)target == g->tid);
}

/* Linux rlimit resource numbers differ from Darwin's for NPROC, NOFILE,
 * MEMLOCK, and AS; resources past RTTIME have no host equivalent. */
static int host_rlimit_resource(int linux_resource)
{
    static const char map[] = {0, 1, 2, 3, 4, RLIMIT_AS, 7, 8, 6, 5};
    if ((unsigned)linux_resource >= sizeof(map)) {
        return -1;
    }
    return map[linux_resource];
}

static s64 guest_prlimit(oah_image *img, pid_t pid, int resource,
                         u64 new_addr, u64 old_addr)
{
    void *output = old_addr ? oah_guest_access(img, old_addr, 16, PROT_WRITE)
                            : NULL;
    if (pid) {
        return -EPERM;
    }
    if (old_addr && !output) {
        return -EFAULT;
    }
    int res = host_rlimit_resource(resource);
    if (res < 0) {
        return -LINUX_ENOSYS;
    }
    struct rlimit limit;
    if (getrlimit(res, &limit) != 0) {
        return linux_error(errno);
    }
    if (output) {
        const u64 values[2] = {
            limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX : limit.rlim_cur,
            limit.rlim_max == RLIM_INFINITY ? UINT64_MAX : limit.rlim_max};
        memcpy(output, values, sizeof(values));
    }
    if (new_addr) {
        const void *input = oah_guest_access(img, new_addr, 16, PROT_READ);
        if (!input) {
            return -EFAULT;
        }
        u64 values[2];
        memcpy(values, input, sizeof(values));
        limit.rlim_cur = values[0] == UINT64_MAX ? RLIM_INFINITY : values[0];
        limit.rlim_max = values[1] == UINT64_MAX ? RLIM_INFINITY : values[1];
        return host_result(setrlimit(res, &limit));
    }
    return 0;
}

static s64 guest_affinity(oah_guest *g, oah_image *img, u64 task, u64 size, u64 address)
{
    if (!current_guest_task(g, task)) {
        return -ESRCH;
    }
    if (size < 8 || (size & 7)) {
        return -EINVAL;
    }
    void *output = oah_guest_access(img, address, 8, PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    const u64 mask = 1; /* Guest instructions share one virtual execution slot. */
    memcpy(output, &mask, sizeof(mask));
    return sizeof(mask);
}

static s64 guest_prctl(oah_image *img, u64 operation, u64 argument)
{
    if (operation == 23) { /* PR_CAPBSET_READ */
        return argument <= 40 ? 0 : -EINVAL;
    }
    if (operation == 7) { /* PR_GET_KEEPCAPS */
        return img->guest_keepcaps;
    }
    if (operation == 8) { /* PR_SET_KEEPCAPS */
        if (argument > 1) {
            return -EINVAL;
        }
        img->guest_keepcaps = (u8)argument;
        return 0;
    }
    if (operation == 15) { /* PR_SET_NAME */
        u64 available = 15;
        const u8 *input = oah_guest_span(img, argument, &available);
        if (!input) {
            return -EFAULT;
        }
        const u8 *end = memchr(input, 0, (size_t)available);
        if (!end && available < 15) {
            return -EFAULT;
        }
        char name[16] = {0};
        memcpy(name, input, end ? (size_t)(end - input) : 15);
        int error = pthread_setname_np(name);
        return error ? linux_error(error) : 0;
    }
    return -LINUX_ENOSYS;
}

/* Linux capability emulation: caps are process state, not a privilege
 * check, so track them and report euid-0 = full set. v3 uses two
 * 32-bit blocks; v1 uses one. */
static u64 guest_capability_mask(const oah_image *img, int which)
{
    if (img->guest_caps_set) {
        return img->guest_caps[which];
    }
    return img->guest_uid[1] == 0 ? (1ull << 40) - 1 : 0;
}

static s64 guest_capability(oah_image *img, u64 header_addr, u64 data_addr,
                            bool setting)
{
    u32 header[2];
    const void *input = oah_guest_access(img, header_addr, sizeof(header), PROT_READ);
    if (!input) {
        return -EFAULT;
    }
    memcpy(header, input, sizeof(header));
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            fprintf(stderr, "cap set=%d version=%x pid=%d data=%llx\n",
                    setting, header[0], (s32)header[1],
                    (unsigned long long)data_addr);
        }
    }
    if ((s32)header[1] < 0) {
        return -EINVAL;
    }
    unsigned blocks;
    switch (header[0]) {
    case 0x20080522: /* _LINUX_CAPABILITY_VERSION_3 */
        blocks = 2;
        break;
    case 0x20071026: /* VERSION_2 is withdrawn; probe still accepts it */
    case 0x19980330: /* VERSION_1 */
        blocks = 1;
        break;
    default:
        /* The kernel answers an unknown version with EINVAL plus the
         * preferred version written back — libcap's probe depends on it. */
        {
            u32 latest = 0x20080522;
            void *back = oah_guest_access(img, header_addr, sizeof(latest), PROT_WRITE);
            if (back) {
                memcpy(back, &latest, sizeof(latest));
            }
        }
        return -EINVAL;
    }
    if (!data_addr) {
        return setting ? -EFAULT : 0; /* version probe */
    }
    u32 data[6] = {0}; /* 2 blocks x {effective, permitted, inheritable} */
    if (setting) {
        const void *raw = oah_guest_access(img, data_addr, blocks * 12, PROT_READ);
        if (!raw) {
            return -EFAULT;
        }
        memcpy(data, raw, blocks * 12);
        for (int i = 0; i < 3; i++) {
            img->guest_caps[i] = (u64)data[i] | ((u64)data[i + 3] << 32);
        }
        img->guest_caps_set = 1;
        return 0;
    }
    for (int i = 0; i < 3; i++) {
        u64 mask = guest_capability_mask(img, i);
        data[i] = (u32)mask;
        data[i + 3] = (u32)(mask >> 32);
    }
    void *output = oah_guest_access(img, data_addr, blocks * 12, PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    memcpy(output, data, blocks * 12);
    return 0;
}

static s64 guest_system_info(oah_image *img, u64 address)
{
    struct {
        s64 uptime;
        u64 loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap;
        u16 procs;
        u64 totalhigh, freehigh;
        u32 mem_unit;
    } info;
    _Static_assert(sizeof(info) == 112, "Linux x86-64 sysinfo layout");
    memset(&info, 0, sizeof(info));
    void *output = oah_guest_access(img, address, sizeof(info), PROT_WRITE);
    if (!output) {
        return -EFAULT;
    }
    struct timespec uptime;
    if (clock_gettime(CLOCK_MONOTONIC, &uptime) < 0) {
        return linux_error(errno);
    }
    info.uptime = uptime.tv_sec;
    size_t memory_size = sizeof(info.totalram);
    if (sysctlbyname("hw.memsize", &info.totalram, &memory_size, NULL, 0) < 0) {
        return linux_error(errno);
    }
    vm_statistics64_data_t memory;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    mach_port_t host = mach_host_self();
    kern_return_t queried = host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&memory, &count);
    mach_port_deallocate(mach_task_self(), host);
    if (queried == KERN_SUCCESS) {
        info.freeram = (u64)memory.free_count * (u64)getpagesize();
    }
    double loads[3];
    int available = getloadavg(loads, 3);
    for (int i = 0; i < available; i++) {
        info.loads[i] = (u64)(loads[i] * (1u << 16));
    }
    info.procs = (u16)(workers < UINT16_MAX ? workers + 1 : UINT16_MAX);
    info.mem_unit = 1;
    memcpy(output, &info, sizeof(info));
    return 0;
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
    struct pollfd *fds = count ? calloc(count, sizeof(*fds) + sizeof(u16)) : NULL;
    if (count && !fds) {
        return -ENOMEM;
    }
    u16 *interests = fds ? (u16 *)(fds + count) : NULL;
    enum { LINUX_POLLWRNORM = 0x100, LINUX_POLLWRBAND = 0x200 };
    const unsigned shared_events = POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLRDBAND;
    const unsigned always_reported = POLLERR | POLLHUP | POLLNVAL;
    for (u64 i = 0; i < count; i++) {
        linux_pollfd entry;
        memcpy(&entry, guest + i * sizeof(entry), sizeof(entry));
        /* Darwin shares the base bits. Its POLLWRNORM aliases POLLOUT. */
        interests[i] = entry.events;
        fds[i].fd = entry.fd;
        fds[i].events = entry.events & shared_events;
        if (entry.events & LINUX_POLLWRNORM) {
            fds[i].events |= POLLOUT;
        }
        if (entry.events & LINUX_POLLWRBAND) {
            fds[i].events |= POLLWRBAND;
        }
    }
    /* Emulated ALSA pcm fds are /dev/null underneath — host poll would
     * report them always-ready and let the guest busy-spin. Compute
     * their readiness from queue state instead, and bound each host
     * poll chunk so re-checks track buffer drain. */
    bool has_alsa = false;
    for (u64 i = 0; i < count; i++) {
        if (oah_alsa_owns(fds[i].fd)) {
            has_alsa = true;
            fds[i].fd = -1; /* poll skips it */
        }
    }
    u16 *alsa_rev = NULL;
    int ready = 0;
    bool released = false;
    if (has_alsa) {
        alsa_rev = calloc(count ? count : 1, sizeof(*alsa_rev));
        if (!alsa_rev) {
            free(fds);
            return -ENOMEM;
        }
        struct timespec deadline, now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        deadline = now;
        if (timeout >= 0) {
            deadline.tv_sec += timeout / 1000;
            deadline.tv_nsec += (long)(timeout % 1000) * 1000000;
            if (deadline.tv_nsec >= 1000000000) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }
        }
        for (;;) {
            for (u64 i = 0; i < count; i++) {
                linux_pollfd entry;
                memcpy(&entry, guest + i * sizeof(entry), sizeof(entry));
                if (entry.fd >= 0 && oah_alsa_owns(entry.fd)) {
                    alsa_rev[i] = (u16)oah_alsa_poll(entry.fd, interests[i]);
                    if (alsa_rev[i]) {
                        ready++;
                    }
                }
            }
            int chunk = 8; /* ms: tracks ~23ms period drain closely */
            if (timeout >= 0) {
                long long rem = (deadline.tv_sec - now.tv_sec) * 1000 +
                                (deadline.tv_nsec - now.tv_nsec) / 1000000;
                if (rem <= 0 && ready == 0) {
                    break;
                }
                if (rem < chunk) {
                    chunk = (int)rem;
                }
            }
            if (ready > 0) {
                break;
            }
            released = begin_blocking_call();
            int r = poll(fds, (nfds_t)count, chunk);
            finish_blocking_call(released);
            if (r < 0) {
                ready = r;
                break;
            }
            ready = r;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (timeout >= 0 && ready == 0 &&
                (now.tv_sec > deadline.tv_sec ||
                 (now.tv_sec == deadline.tv_sec &&
                  now.tv_nsec >= deadline.tv_nsec))) {
                break;
            }
        }
    } else {
        released = begin_blocking_call();
        ready = poll(fds, (nfds_t)count, timeout < 0 ? -1 : timeout);
        finish_blocking_call(released);
    }
    s64 result = host_result(ready);
    if (released && count && result >= 0) {
        guest = oah_guest_access(img, address, count * sizeof(linux_pollfd), PROT_WRITE);
        if (!guest) {
            result = -EFAULT;
        }
    }
    if (result >= 0) {
        result = 0;
        for (u64 i = 0; i < count; i++) {
            u16 events = interests[i];
            u16 revents = fds[i].revents & (always_reported | (events & shared_events));
            if (alsa_rev && alsa_rev[i]) {
                revents |= alsa_rev[i];
            }
            if ((events & LINUX_POLLWRNORM) && (fds[i].revents & POLLOUT)) {
                revents |= LINUX_POLLWRNORM;
            }
            if ((events & LINUX_POLLWRBAND) && (fds[i].revents & POLLWRBAND)) {
                revents |= LINUX_POLLWRBAND;
            }
            result += revents != 0;
            {
                static int st = -1;
                if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
                if (st) {
                    fprintf(stderr, "poll fd=%d events=%x revents=%x\n",
                            fds[i].fd, events, revents);
                }
            }
            memcpy(guest + i * sizeof(linux_pollfd) + offsetof(linux_pollfd, revents),
                   &revents, sizeof(revents));
        }
    }
    free(alsa_rev);
    free(fds);
    return result;
}

typedef struct guest_eventfd {
    unsigned refs;
    int reader, writer;
    u64 value;
    bool semaphore;
    pthread_cond_t changed;
    struct guest_eventfd *next;
} guest_eventfd;

typedef struct eventfd_descriptor {
    int fd;
    guest_eventfd *counter;
    struct eventfd_descriptor *next;
} eventfd_descriptor;

static eventfd_descriptor *eventfds;
static guest_eventfd *eventfd_objects;

typedef struct readiness_wait_fd {
    int fd;
    struct readiness_wait_fd *next;
} readiness_wait_fd;

static readiness_wait_fd *readiness_wait_fds;

static guest_eventfd *eventfd_for_fd(int fd)
{
    for (eventfd_descriptor *entry = eventfds; entry; entry = entry->next) {
        if (entry->fd == fd) {
            return entry->counter;
        }
    }
    return NULL;
}

static void release_eventfd(guest_eventfd *counter)
{
    if (!--counter->refs) {
        guest_eventfd **link = &eventfd_objects;
        while (*link && *link != counter) {
            link = &(*link)->next;
        }
        if (*link) {
            *link = counter->next;
        }
        close(counter->reader);
        close(counter->writer);
        pthread_cond_destroy(&counter->changed);
        free(counter);
    }
}

static void forget_eventfd(int fd)
{
    eventfd_descriptor **link = &eventfds;
    while (*link && (*link)->fd != fd) {
        link = &(*link)->next;
    }
    if (*link) {
        eventfd_descriptor *entry = *link;
        *link = entry->next;
        release_eventfd(entry->counter);
        free(entry);
    }
}

static bool add_eventfd(int fd, guest_eventfd *counter)
{
    eventfd_descriptor *entry = malloc(sizeof(*entry));
    if (!entry) {
        return false;
    }
    *entry = (eventfd_descriptor){fd, counter, eventfds};
    counter->refs++;
    eventfds = entry;
    return true;
}

static bool readiness_internal_fd(int fd)
{
    for (guest_eventfd *entry = eventfd_objects; entry; entry = entry->next) {
        if (entry->reader == fd || entry->writer == fd) {
            return true;
        }
    }
    for (readiness_wait_fd *entry = readiness_wait_fds; entry; entry = entry->next) {
        if (entry->fd == fd) {
            return true;
        }
    }
    return false;
}

static s64 guest_eventfd_create(u32 value, u64 flags)
{
    if (flags & ~0x80801ull) {
        return -EINVAL;
    }
    guest_eventfd *counter = calloc(1, sizeof(*counter));
    if (!counter) {
        return -ENOMEM;
    }
    int error = pthread_cond_init(&counter->changed, NULL);
    if (error) {
        free(counter);
        return linux_error(error);
    }
    counter->refs = 1;
    counter->reader = counter->writer = -1;
    int pair[2];
    int fd = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        error = errno;
        goto fail;
    }
    fd = pair[0];
    counter->writer = pair[1];
    counter->reader = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (counter->reader < 0 ||
        fcntl(counter->writer, F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(fd, F_SETFD, flags & 0x80000 ? FD_CLOEXEC : 0) < 0 ||
        fcntl(fd, F_SETFL, flags & 0x800 ? O_NONBLOCK : 0) < 0 ||
        (value && send(counter->writer, "e", 1, MSG_DONTWAIT) != 1)) {
        error = errno;
        goto fail;
    }
    counter->value = value;
    counter->semaphore = (flags & 1) != 0;
    if (!add_eventfd(fd, counter)) {
        error = ENOMEM;
        goto fail;
    }
    counter->next = eventfd_objects;
    eventfd_objects = counter;
    release_eventfd(counter);
    return fd;

fail:
    if (fd >= 0) {
        close(fd);
    }
    release_eventfd(counter);
    return linux_error(error);
}

/* The socket carries a read token in one direction. Filling the reverse
 * direction makes the guest descriptor non-writable at counter saturation. */
static void eventfd_update_writable(guest_eventfd *counter, bool full)
{
    char bytes[4096] = {0};
    ssize_t size;
    do {
        size = full ? send(counter->reader, bytes, sizeof(bytes), MSG_DONTWAIT) :
                      recv(counter->writer, bytes, sizeof(bytes), MSG_DONTWAIT);
    } while (size > 0 || (size < 0 && errno == EINTR));
}

static s64 guest_eventfd_io(oah_image *img, int fd, guest_eventfd *counter,
                             u64 address, u64 size, bool reading)
{
    if (size < sizeof(u64)) {
        return -EINVAL;
    }
    void *buffer = oah_guest_access(img, address, sizeof(u64), reading ? PROT_WRITE : PROT_READ);
    if (!buffer) {
        return -EFAULT;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return linux_error(errno);
    }
    u64 value = 0;
    if (!reading) {
        memcpy(&value, buffer, sizeof(value));
        if (value == UINT64_MAX) {
            return -EINVAL;
        }
    }
    counter->refs++;
    s64 result = sizeof(value);
    while (reading ? !counter->value : value > UINT64_MAX - 1 - counter->value) {
        if (flags & O_NONBLOCK) {
            result = -LINUX_EAGAIN;
            break;
        }
        int error = pthread_cond_wait(&counter->changed, &guest_lock);
        if (error) {
            result = linux_error(error);
            break;
        }
    }
    bool was_full = counter->value == UINT64_MAX - 1;
    if (result > 0 && reading) {
        buffer = oah_guest_access(img, address, sizeof(value), PROT_WRITE);
        if (!buffer) {
            result = -EFAULT;
        } else {
            value = counter->semaphore ? 1 : counter->value;
            char token;
            if (value == counter->value && recv(counter->reader, &token, 1, MSG_DONTWAIT) != 1) {
                result = -EIO;
            } else {
                counter->value -= value;
                memcpy(buffer, &value, sizeof(value));
            }
        }
    } else if (result > 0 && value) {
        if (!counter->value && send(counter->writer, "e", 1, MSG_DONTWAIT) != 1) {
            result = -EIO;
        } else {
            counter->value += value;
        }
    }
    if (result > 0) {
        bool full = counter->value == UINT64_MAX - 1;
        if (full != was_full) {
            eventfd_update_writable(counter, full);
        }
        pthread_cond_broadcast(&counter->changed);
    }
    release_eventfd(counter);
    return result;
}

enum {
    X86_EPOLLIN = 0x001, X86_EPOLLOUT = 0x004, X86_EPOLLERR = 0x008,
    X86_EPOLLHUP = 0x010, X86_EPOLLRDHUP = 0x2000,
    X86_EPOLLONESHOT = 0x40000000, X86_EPOLLET = 0x80000000u
};

typedef struct epoll_watch {
    int fd;
    u32 events;
    u64 data;
    uintptr_t generation;
    bool armed, pipe;
    struct epoll_watch *next;
} epoll_watch;

typedef struct {
    unsigned references;
    epoll_watch *watches;
} guest_epoll;

typedef struct epoll_descriptor {
    int fd;
    guest_epoll *epoll;
    struct epoll_descriptor *next;
} epoll_descriptor;

static epoll_descriptor *epolls;
static uintptr_t epoll_generation;

static guest_epoll *epoll_for_fd(int fd)
{
    for (epoll_descriptor *entry = epolls; entry; entry = entry->next) {
        if (entry->fd == fd) {
            return entry->epoll;
        }
    }
    return NULL;
}

static void release_epoll(guest_epoll *epoll)
{
    if (--epoll->references) {
        return;
    }
    while (epoll->watches) {
        epoll_watch *watch = epoll->watches;
        epoll->watches = watch->next;
        free(watch);
    }
    free(epoll);
}

static epoll_watch **epoll_watch_link(guest_epoll *epoll, int fd)
{
    epoll_watch **link = &epoll->watches;
    while (*link && (*link)->fd != fd) {
        link = &(*link)->next;
    }
    return link;
}

static void epoll_change(int queue, const epoll_watch *watch, u16 flags)
{
    const short filters[] = {EVFILT_READ, EVFILT_WRITE};
    const u32 bits[] = {X86_EPOLLIN | X86_EPOLLRDHUP, X86_EPOLLOUT};
    for (unsigned i = 0; i < 2; i++) {
        if (watch->events & bits[i]) {
            struct kevent change;
            EV_SET(&change, (uintptr_t)watch->fd, filters[i], flags, 0, 0,
                   (void *)watch->generation);
            kevent(queue, &change, 1, NULL, 0, NULL);
        }
    }
}

static int epoll_add_filters(int queue, const epoll_watch *watch)
{
    const short filters[] = {EVFILT_READ, EVFILT_WRITE};
    const u32 bits[] = {X86_EPOLLIN | X86_EPOLLRDHUP, X86_EPOLLOUT};
    u16 flags = EV_ADD | EV_ENABLE | (watch->events & X86_EPOLLET ? EV_CLEAR : 0);
    for (unsigned i = 0; i < 2; i++) {
        if (watch->events & bits[i]) {
            struct kevent change;
            EV_SET(&change, (uintptr_t)watch->fd, filters[i], flags, 0, 0,
                   (void *)watch->generation);
            if (kevent(queue, &change, 1, NULL, 0, NULL) < 0) {
                int error = errno;
                epoll_change(queue, watch, EV_DELETE);
                return error;
            }
        }
    }
    return 0;
}

static void forget_epoll_fd(int fd)
{
    epoll_descriptor **link = &epolls;
    while (*link) {
        epoll_descriptor *entry = *link;
        if (entry->fd == fd) {
            *link = entry->next;
            release_epoll(entry->epoll);
            free(entry);
            continue;
        }
        epoll_watch **registration = epoll_watch_link(entry->epoll, fd);
        if (*registration) {
            epoll_watch *watch = *registration;
            epoll_change(entry->fd, watch, EV_DELETE);
            *registration = watch->next;
            free(watch);
        }
        link = &entry->next;
    }
}

static bool add_epoll_descriptor(int fd, guest_epoll *epoll)
{
    epoll_descriptor *entry = malloc(sizeof(*entry));
    if (!entry) {
        return false;
    }
    *entry = (epoll_descriptor){fd, epoll, epolls};
    epoll->references++;
    epolls = entry;
    return true;
}

static s64 guest_epoll_create(u64 flags)
{
    if (flags & ~0x80000ull) {
        return -EINVAL;
    }
    guest_epoll *epoll = calloc(1, sizeof(*epoll));
    if (!epoll) {
        return -ENOMEM;
    }
    int fd = kqueue();
    int error = errno;
    if (fd >= 0) {
        if (fcntl(fd, F_SETFD, flags ? FD_CLOEXEC : 0) < 0) {
            error = errno;
        } else if (add_epoll_descriptor(fd, epoll)) {
            return fd;
        } else {
            error = ENOMEM;
        }
        close(fd);
    }
    free(epoll);
    return linux_error(error);
}

static s64 guest_epoll_ctl(oah_image *img, int queue, u64 operation, int fd, u64 address)
{
    guest_epoll *epoll = epoll_for_fd(queue);
    if (!epoll) {
        return fcntl(queue, F_GETFD) < 0 ? -EBADF : -EINVAL;
    }
    if (operation < 1 || operation > 3 || fd == queue) {
        return -EINVAL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        return linux_error(errno);
    }
    if (epoll_for_fd(fd) || S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
        return -EPERM;
    }
    epoll_watch **link = epoll_watch_link(epoll, fd);
    epoll_watch *existing = *link;
    if (operation == 2) {
        if (!existing) {
            return -ENOENT;
        }
        epoll_change(queue, existing, EV_DELETE);
        *link = existing->next;
        free(existing);
        return 0;
    }
    const u8 *event = oah_guest_access(img, address, 12, PROT_READ);
    if (!event) {
        return -EFAULT;
    }
    if ((operation == 1) == (existing != NULL)) {
        return existing ? -EEXIST : -ENOENT;
    }
    epoll_watch value = {.fd = fd, .generation = ++epoll_generation, .armed = true,
                         .pipe = S_ISFIFO(st.st_mode)};
    memcpy(&value.events, event, 4);
    memcpy(&value.data, event + 4, 8);
    const u32 filters = X86_EPOLLIN | X86_EPOLLOUT | X86_EPOLLRDHUP;
    /* A flag-only mask (EPOLLET with no ready bits) is legal — dbus's
     * socket set adds watches disabled this way, then enables via MOD.
     * It registers no kevent filters and stays inert until then. */
    if (value.events & ~(filters | X86_EPOLLERR | X86_EPOLLHUP | X86_EPOLLONESHOT | X86_EPOLLET)) {
        return -LINUX_EOPNOTSUPP;
    }
    epoll_watch *destination = existing ? existing : malloc(sizeof(*destination));
    if (!destination) {
        return -ENOMEM;
    }
    if (existing) {
        epoll_change(queue, existing, EV_DELETE);
    }
    int error = epoll_add_filters(queue, &value);
    if (error) {
        if (existing) {
            if (!epoll_add_filters(queue, existing) && !existing->armed) {
                epoll_change(queue, existing, EV_DISABLE);
            }
        } else {
            free(destination);
        }
        return linux_error(error);
    }
    value.next = existing ? existing->next : NULL;
    *destination = value;
    *link = destination;
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            fprintf(stderr, "epoll_ctl q=%d op=%llu fd=%d events=%x\n",
                    queue, (unsigned long long)operation, fd, value.events);
        }
    }
    return 0;
}

static s64 guest_epoll_wait(oah_image *img, int queue, u64 address, int count, int milliseconds)
{
    guest_epoll *epoll = epoll_for_fd(queue);
    if (!epoll) {
        return fcntl(queue, F_GETFD) < 0 ? -EBADF : -EINVAL;
    }
    if (count <= 0 || count > INT_MAX / 12) {
        return -EINVAL;
    }
    if (!oah_guest_access(img, address, (u64)count * 12, PROT_WRITE)) {
        return -EFAULT;
    }
    struct kevent *events = calloc((size_t)count, sizeof(*events));
    uintptr_t *generations = calloc((size_t)count, sizeof(*generations));
    if (!events || !generations) {
        free(events);
        free(generations);
        return -ENOMEM;
    }
    int live_queue = workers ? fcntl(queue, F_DUPFD_CLOEXEC, 0) : queue;
    if (live_queue < 0) {
        int error = errno;
        free(events);
        free(generations);
        return linux_error(error);
    }
    readiness_wait_fd pinned = {.fd = live_queue, .next = readiness_wait_fds};
    if (live_queue != queue) {
        readiness_wait_fds = &pinned;
    }
    epoll->references++;
    struct timespec duration = {0};
    if (milliseconds >= 0) {
        duration.tv_sec = milliseconds / 1000;
        duration.tv_nsec = (milliseconds % 1000) * 1000000L;
    }
    bool released = begin_blocking_call();
    int available = kevent(live_queue, NULL, 0, events, count,
                           milliseconds >= 0 ? &duration : NULL);
    finish_blocking_call(released);
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            fprintf(stderr, "epoll_wait q=%d -> %d", live_queue, available);
            for (int i = 0; i < available && i < 8; i++) {
                fprintf(stderr, " [fd=%d filt=%d flags=%x data=%lld]",
                        (int)events[i].ident, events[i].filter,
                        events[i].flags, (long long)events[i].data);
            }
            fprintf(stderr, "\n");
        }
    }
    s64 result = host_result(available);
    if (available > 0) {
        u8 *output = oah_guest_access(img, address, (u64)count * 12, PROT_WRITE);
        result = output ? 0 : -EFAULT;
        for (int i = 0; output && i < available; i++) {
            const struct kevent *event = &events[i];
            epoll_watch *watch = *epoll_watch_link(epoll, (int)event->ident);
            if (!watch || (uintptr_t)event->udata != watch->generation) {
                continue;
            }
            u32 bits = event->filter == EVFILT_WRITE ? X86_EPOLLOUT :
                       watch->events & X86_EPOLLIN;
            if (event->flags & EV_EOF) {
                if (event->filter == EVFILT_READ) {
                    bits |= watch->events & X86_EPOLLRDHUP;
                    if (watch->pipe) {
                        bits |= X86_EPOLLHUP;
                        if (!event->data) {
                            bits &= ~X86_EPOLLIN;
                        }
                    }
                } else if (watch->pipe) {
                    bits |= X86_EPOLLERR;
                }
                struct pollfd current = {.fd = watch->fd};
                if (poll(&current, 1, 0) > 0) {
                    if (current.revents & POLLHUP) bits |= X86_EPOLLHUP;
                    if (current.revents & POLLERR) bits |= X86_EPOLLERR;
                }
            }
            if (event->flags & EV_ERROR) {
                bits |= X86_EPOLLERR;
            }
            if (!bits) {
                continue;
            }
            int index = 0;
            while (index < result && generations[index] != watch->generation) {
                index++;
            }
            if (index < result) {
                u32 previous;
                memcpy(&previous, output + index * 12, 4);
                bits |= previous;
            } else {
                if (!watch->armed) {
                    continue;
                }
                generations[result++] = watch->generation;
                memcpy(output + index * 12 + 4, &watch->data, 8);
                if (watch->events & X86_EPOLLONESHOT) {
                    epoll_change(live_queue, watch, EV_DISABLE);
                    watch->armed = false;
                }
            }
            memcpy(output + index * 12, &bits, 4);
        }
    }
    if (live_queue != queue) {
        readiness_wait_fd **link = &readiness_wait_fds;
        while (*link != &pinned) {
            link = &(*link)->next;
        }
        *link = pinned.next;
        close(live_queue);
    }
    release_epoll(epoll);
    free(generations);
    free(events);
    return result;
}

static bool duplicate_readiness_fd(int source, int target)
{
    guest_epoll *epoll = epoll_for_fd(source);
    if (epoll) {
        return add_epoll_descriptor(target, epoll);
    }
    guest_eventfd *counter = eventfd_for_fd(source);
    return !counter || add_eventfd(target, counter);
}

static void forget_readiness_fd(int fd)
{
    forget_epoll_fd(fd);
    forget_eventfd(fd);
}

/* Emulated fds cannot survive execve: the new process builds a fresh guest
 * fd table, and a carried-over kqueue or eventfd pair would just be a stray
 * host fd. Mark them close-on-exec instead of refusing the exec. */
static void readiness_prepare_exec(void)
{
    for (epoll_descriptor *entry = epolls; entry; entry = entry->next) {
        fcntl(entry->fd, F_SETFD, FD_CLOEXEC);
    }
    for (eventfd_descriptor *entry = eventfds; entry; entry = entry->next) {
        fcntl(entry->fd, F_SETFD, FD_CLOEXEC);
    }
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

static s64 guest_close_range(u32 first, u32 last, u32 flags)
{
    if (last < first || (flags & ~6u)) {
        return -EINVAL;
    }
    /* Splitting a live thread's descriptor table needs a separate emulation. */
    if ((flags & 2) && workers) {
        return -LINUX_ENOSYS;
    }
    errno = 0;
    const int needed = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (needed <= 0) {
        return errno ? linux_error(errno) : 0;
    }
    if (needed > INT_MAX - 1024) {
        return -ENOMEM;
    }
    int capacity = needed + 1024;
    struct proc_fdinfo *fds = malloc((size_t)capacity);
    if (!fds) {
        return -ENOMEM;
    }
    errno = 0;
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, capacity);
    if (bytes <= 0) {
        int error = errno;
        free(fds);
        return error ? linux_error(error) : 0;
    }
    for (size_t i = 0; i < (size_t)bytes / sizeof(*fds); i++) {
        int fd = fds[i].proc_fd;
        if ((u32)fd < first || (u32)fd > last || fd == vfork_release_fd || readiness_internal_fd(fd)) {
            continue;
        }
        bool internal = false;
        for (guest_dir *dir = directories; dir; dir = dir->next) {
            if (dirfd(dir->stream) == fd) {
                internal = true;
                break;
            }
        }
        if (internal) {
            continue;
        }
        if (flags & 4) {
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        } else {
            forget_directory(fd);
            forget_readiness_fd(fd);
            untrack_fd_path(fd);
            close(fd);
        }
    }
    free(fds);
    return 0;
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
        { static int st = -1;
          if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
          if (st) { fprintf(stderr, "fd_pair host fail errno=%d\n", errno); } }
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

static int socket_flags(int fd, u64 flags)
{
    int status = fcntl(fd, F_GETFL);
    int enabled = 1;
    if (status < 0 ||
        fcntl(fd, F_SETFL, (status & ~O_NONBLOCK) | (flags & 0x800 ? O_NONBLOCK : 0)) < 0 ||
        fcntl(fd, F_SETFD, flags & 0x80000 ? FD_CLOEXEC : 0) < 0) {
        return -1;
    }
    /* Keep a broken connection from terminating the native launcher. */
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
}

static s64 guest_socket(u64 family, u64 type_flags, u64 protocol)
{
    if (type_flags & ~0x8080full) {
        return -EINVAL;
    }
    if (family != 1 && family != 2 && family != 10) {
        return -LINUX_EAFNOSUPPORT;
    }
    int type = type_flags & 0xf;
    if (type != 1 && type != 2) {
        return -LINUX_ESOCKTNOSUPPORT;
    }
    if (protocol != 0 && (family == 1 || (protocol != 6 && protocol != 17))) {
        return -LINUX_EPROTONOSUPPORT;
    }
    int fd = socket(family == 1 ? AF_UNIX : family == 2 ? AF_INET : AF_INET6,
                    type == 1 ? SOCK_STREAM : SOCK_DGRAM, (int)protocol);
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            fprintf(stderr, "socket fam=%llu type=%llu proto=%llu -> %d\n",
                    (unsigned long long)family, (unsigned long long)type_flags,
                    (unsigned long long)protocol, fd);
        }
    }
    if (fd < 0) {
        return linux_error(errno);
    }
    if (socket_flags(fd, type_flags) < 0) {
        int error = errno;
        close(fd);
        return linux_error(error);
    }
    return fd;
}

static s64 guest_socket_address(oah_image *img, int fd, u64 address, u64 size, bool binding)
{
    if (size < 2 || size > sizeof(struct sockaddr_storage)) {
        return -EINVAL;
    }
    const u8 *input = oah_guest_access(img, address, size, PROT_READ);
    if (!input) {
        return -EFAULT;
    }
    u16 family;
    memcpy(&family, input, sizeof(family));
    if (family == 1) {
        struct sockaddr_un local = {.sun_family = AF_UNIX};
        if (size <= sizeof(family) || size > sizeof(family) + 108) {
            return -EINVAL;
        }
        const char *path = (const char *)input + sizeof(family);
        size_t path_size = (size_t)size - sizeof(family);
        if (!*path) {
            return -111; /* ECONNREFUSED. Darwin has no abstract Unix namespace. */
        }
        size_t length = strnlen(path, path_size);
        if (length >= sizeof(local.sun_path)) {
            return -LINUX_ENAMETOOLONG;
        }
        /* Guest socket paths resolve inside the sysroot so guest peers
         * rendezvous on one filesystem location. Resolved paths that
         * exceed sun_path map to a deterministic /tmp name instead —
         * both sides derive it identically. Connect falls back to the
         * verbatim host path so guest apps can reach real host sockets
         * (e.g. the X server at /tmp/.X11-unix/X0). */
        char guest_path[109];
        memcpy(guest_path, path, length);
        guest_path[length] = 0;
        char resolved[sizeof(local.sun_path)];
        char hashed[sizeof(local.sun_path)];
        const char *use = guest_path;
        bool have_resolved = false;
        if (sysroot_path(img, guest_path)) {
            char full[PATH_MAX];
            int w = snprintf(full, sizeof(full), "%s%s", img->sysroot, guest_path);
            if (w > 0 && w < (int)sizeof(resolved)) {
                strcpy(resolved, full);
                have_resolved = true;
            }
            u64 h = 1469598103934665603ull;
            for (const u8 *p = (const u8 *)full; *p; p++) {
                h = (h ^ *p) * 1099511628211ull;
            }
            snprintf(hashed, sizeof(hashed), "/tmp/.oah-%016llx",
                     (unsigned long long)h);
            if (binding) {
                if (have_resolved) {
                    ensure_parents(resolved);
                    use = resolved;
                } else {
                    use = hashed;
                }
            } else if (have_resolved && access(resolved, F_OK) == 0) {
                use = resolved;
            } else if (access(hashed, F_OK) == 0) {
                use = hashed;
            }
        }
        size_t use_len = strlen(use);
        memcpy(local.sun_path, use, use_len + 1);
        local.sun_len = (u8)(offsetof(struct sockaddr_un, sun_path) + use_len + 1);
        {
            static int st = -1;
            if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
            if (st) {
                fprintf(stderr, "unix %s fd=%d path=%s -> %s\n",
                        binding ? "bind" : "connect", fd, guest_path, use);
            }
        }
        bool released = !binding && begin_blocking_call();
        int result = binding ? bind(fd, (const struct sockaddr *)&local, local.sun_len) :
                               connect(fd, (const struct sockaddr *)&local, local.sun_len);
        finish_blocking_call(released);
        return host_result(result);
    }
    struct sockaddr_storage host = {0};
    socklen_t length = family == 2 ? sizeof(struct sockaddr_in) :
                       family == 10 ? sizeof(struct sockaddr_in6) : 0;
    if (!length) {
        return -LINUX_EAFNOSUPPORT;
    }
    if (size < length) {
        return -EINVAL;
    }
    memcpy(&host, input, length);
    host.ss_len = length;
    host.ss_family = family == 2 ? AF_INET : AF_INET6;
    bool released = !binding && begin_blocking_call();
    int result = binding ? bind(fd, (const struct sockaddr *)&host, length) :
                           connect(fd, (const struct sockaddr *)&host, length);
    finish_blocking_call(released);
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&host;
            fprintf(stderr, "sockaddr bind=%d fd=%d to=%u.%u.%u.%u:%u -> %d\n",
                    binding, fd,
                    (unsigned)((u8*)&sin->sin_addr)[0], (unsigned)((u8*)&sin->sin_addr)[1],
                    (unsigned)((u8*)&sin->sin_addr)[2], (unsigned)((u8*)&sin->sin_addr)[3],
                    (unsigned)ntohs(sin->sin_port), result);
        }
    }
    return host_result(result);
}

static s64 guest_socket_name(oah_image *img, int fd, u64 address, u64 size_address,
                             u64 flags, u64 nr)
{
    bool accepting = nr == 43 || nr == 288;
    if (flags & ~0x80800ull) {
        return -EINVAL;
    }
    u32 size = 0;
    void *length_output = NULL, *output = NULL;
    if (!accepting || address) {
        length_output = oah_guest_access(img, size_address, sizeof(size), PROT_READ | PROT_WRITE);
        if (!length_output) {
            return -EFAULT;
        }
        memcpy(&size, length_output, sizeof(size));
        if ((s32)size < 0) {
            return -EINVAL;
        }
        size = size < sizeof(struct sockaddr_storage) ? size : sizeof(struct sockaddr_storage);
        output = size ? oah_guest_access(img, address, size, PROT_WRITE) : NULL;
        if (size && !output) {
            return -EFAULT;
        }
    }
    struct sockaddr_storage host = {0};
    struct sockaddr *name = (struct sockaddr *)&host;
    socklen_t length = sizeof(host);
    bool released = accepting && begin_blocking_call();
    int result = accepting ? accept(fd, length_output ? name : NULL, length_output ? &length : NULL)
                 : nr == 51 ? getsockname(fd, name, &length) : getpeername(fd, name, &length);
    finish_blocking_call(released);
    if (result < 0) {
        return linux_error(errno);
    }
    if (accepting && socket_flags(result, flags) < 0) {
        int error = errno;
        close(result);
        return linux_error(error);
    }
    if (length_output) {
        if (released) {
            length_output = oah_guest_access(img, size_address, sizeof(size), PROT_WRITE);
            output = size ? oah_guest_access(img, address, size, PROT_WRITE) : NULL;
            if (!length_output || (size && !output)) {
                close(result);
                return -EFAULT;
            }
        }
        u16 family = host.ss_family == AF_UNIX ? 1 :
                     host.ss_family == AF_INET ? 2 : host.ss_family == AF_INET6 ? 10 : 0;
        if (!family) {
            if (accepting) {
                close(result);
            }
            return -LINUX_EAFNOSUPPORT;
        }
        memcpy(&host, &family, sizeof(family));
        if (size) {
            memcpy(output, &host, size < length ? size : length);
        }
        u32 guest_length = length;
        memcpy(length_output, &guest_length, sizeof(guest_length));
    }
    return result;
}

static s64 guest_socket_message(oah_image *img, int fd, u64 address, u64 flags, bool receiving)
{
    struct linux_msghdr {
        u64 name;
        u32 name_length, padding1;
        u64 vectors, vector_count, control, control_length;
        u32 flags, padding2;
    } data;
    _Static_assert(sizeof(data) == 56, "Linux x86-64 msghdr layout");
    void *header = oah_guest_access(img, address, sizeof(data),
                                    receiving ? PROT_READ | PROT_WRITE : PROT_READ);
    if (!header) {
        return -EFAULT;
    }
    memcpy(&data, header, sizeof(data));
    if (flags & ~(receiving ? 0x40000042ull : 0x4040ull)) {
        return -LINUX_EOPNOTSUPP;
    }
    struct sockaddr_storage name = {0};
    u32 guest_name_capacity = 0;
    socklen_t name_needed = 0;
    if (data.name) {
        if (receiving) {
            guest_name_capacity = data.name_length;
            if ((s32)guest_name_capacity < 0) {
                return -EINVAL;
            }
            name_needed = sizeof(name);
        } else {
            const void *input = oah_guest_access(img, data.name, sizeof(name), PROT_READ);
            if (!input) {
                return -EFAULT;
            }
            u16 family;
            memcpy(&family, input, sizeof(family));
            if (family != 1 && family != 2 && family != 10) {
                return -LINUX_EAFNOSUPPORT;
            }
            socklen_t needed = family == 1 ? sizeof(struct sockaddr_un) :
                               family == 2 ? sizeof(struct sockaddr_in)
                                           : sizeof(struct sockaddr_in6);
            if (data.name_length < needed) {
                return -EINVAL;
            }
            memcpy(&name, input, needed);
            name.ss_len = needed;
            name.ss_family = family == 1 ? AF_UNIX :
                             family == 2 ? AF_INET : AF_INET6;
            name_needed = needed;
        }
    }
    struct iovec vectors[1024];
    if (data.vector_count > sizeof(vectors) / sizeof(vectors[0])) {
        return -EINVAL;
    }
    const u8 *input = oah_guest_access(img, data.vectors,
                                        data.vector_count * 16, PROT_READ);
    if (data.vector_count && !input) {
        return -EFAULT;
    }
    for (u64 i = 0; i < data.vector_count; i++) {
        u64 entry[2];
        memcpy(entry, input + i * sizeof(entry), sizeof(entry));
        if (entry[1] > SSIZE_MAX) {
            return -EINVAL;
        }
        vectors[i].iov_len = entry[1];
        vectors[i].iov_base = oah_guest_access(img, entry[0], entry[1],
                                              receiving ? PROT_WRITE : PROT_READ);
        if (entry[1] && !vectors[i].iov_base) {
            return -EFAULT;
        }
    }
    struct msghdr host = {.msg_iov = vectors, .msg_iovlen = (int)data.vector_count};
    if (name_needed) {
        host.msg_name = &name;
        host.msg_namelen = name_needed;
    }
    /* Control messages: the guest cmsghdr is Linux's 16-byte header
     * ({u64 len, u32 level, u32 type}); Darwin's is 12 bytes with a
     * u32 len. Translate each cmsg and lay the host buffer out with the
     * host CMSG_* macros — never copy the guest layout verbatim. Guest
     * fds are host fds, so SCM_RIGHTS is a passthrough. */
    u8 host_control[1024];
    size_t host_control_used = 0;
    if (!receiving && data.control_length) {
        const u8 *gctl = oah_guest_access(img, data.control,
                                          data.control_length, PROT_READ);
        if (!gctl) {
            return -EFAULT;
        }
        u64 off = 0;
        while (off + 16 <= data.control_length) {
            u64 clen;
            u32 level, type;
            memcpy(&clen, gctl + off, 8);
            memcpy(&level, gctl + off + 8, 4);
            memcpy(&type, gctl + off + 12, 4);
            if (clen < 16 || off + clen > data.control_length) {
                return -EINVAL;
            }
            const u8 *cdata = gctl + off + 16;
            size_t dlen = (size_t)clen - 16;
            if (level == 1 && type == 1) { /* SCM_RIGHTS */
                size_t need = CMSG_SPACE(dlen);
                if (host_control_used + need > sizeof(host_control)) {
                    return -EINVAL;
                }
                struct cmsghdr *h = (struct cmsghdr *)(host_control + host_control_used);
                h->cmsg_len = CMSG_LEN(dlen);
                h->cmsg_level = SOL_SOCKET;
                h->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(h), cdata, dlen);
                memset(host_control + host_control_used + CMSG_LEN(dlen), 0,
                       need - CMSG_LEN(dlen));
                host_control_used += need;
            }
            off += (clen + 7) & ~(u64)7;
        }
        if (off != data.control_length) {
            return -EINVAL;
        }
        if (host_control_used) {
            host.msg_control = host_control;
            host.msg_controllen = host_control_used;
        }
    }
    if (receiving && data.control && data.control_length) {
        host.msg_control = host_control;
        host.msg_controllen = sizeof(host_control);
    }
    int host_flags = (flags & 0x40 ? MSG_DONTWAIT : 0) | (flags & 2 ? MSG_PEEK : 0);
    s64 result = host_result(receiving ? recvmsg(fd, &host, host_flags) :
                                       sendmsg(fd, &host, host_flags));
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&name;
            fprintf(stderr, "sockmsg recv=%d fd=%d name=%u.%u.%u.%u:%u -> %lld\n",
                    receiving, fd,
                    data.name ? (unsigned)((u8*)&sin->sin_addr)[0] : 0,
                    data.name ? (unsigned)((u8*)&sin->sin_addr)[1] : 0,
                    data.name ? (unsigned)((u8*)&sin->sin_addr)[2] : 0,
                    data.name ? (unsigned)((u8*)&sin->sin_addr)[3] : 0,
                    data.name ? (unsigned)ntohs(sin->sin_port) : 0,
                    (long long)result);
        }
    }
    if (receiving && result >= 0) {
        data.name_length = 0;
        if (data.name && host.msg_namelen) {
            u16 family = name.ss_family == AF_UNIX ? 1 :
                         name.ss_family == AF_INET ? 2 :
                         name.ss_family == AF_INET6 ? 10 : 0;
            if (family) {
                u32 out = host.msg_namelen < guest_name_capacity ?
                          host.msg_namelen : guest_name_capacity;
                void *name_out = oah_guest_access(img, data.name, out ? out : 1,
                                                  PROT_WRITE);
                if (out && !name_out) {
                    return -EFAULT;
                }
                memcpy(&name, &family, sizeof(family));
                if (out) {
                    memcpy(name_out, &name, out);
                }
                data.name_length = host.msg_namelen;
            }
        }
        u64 guest_control_used = 0;
        if (host.msg_control && host.msg_controllen >= CMSG_LEN(0) &&
            !(flags & 2 /* MSG_PEEK */)) {
            u8 *gctl_out = oah_guest_access(img, data.control,
                                            data.control_length, PROT_WRITE);
            if (!gctl_out) {
                return -EFAULT;
            }
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&host);
                 c && c->cmsg_len >= sizeof(*c) &&
                 c->cmsg_len <= host.msg_controllen;
                 c = CMSG_NXTHDR(&host, c)) {
                u32 level = 0, type = 0;
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                    level = 1; type = 1;
                } else if (c->cmsg_level == SOL_SOCKET &&
                           c->cmsg_type == SCM_TIMESTAMP) {
                    level = 1; type = 29; /* SO_TIMESTAMP */
                } else {
                    continue;
                }
                size_t dlen = (size_t)c->cmsg_len - CMSG_LEN(0);
                size_t need = 16 + ((dlen + 7) & ~(size_t)7);
                if (guest_control_used + need > data.control_length) {
                    data.flags |= 8; /* MSG_CTRUNC */
                    break;
                }
                u8 *g = gctl_out + guest_control_used;
                u64 glen = 16 + dlen;
                memcpy(g, &glen, 8);
                memcpy(g + 8, &level, 4);
                memcpy(g + 12, &type, 4);
                memcpy(g + 16, CMSG_DATA(c), dlen);
                memset(g + 16 + dlen, 0, need - 16 - dlen);
                guest_control_used += need;
            }
        }
        data.control_length = guest_control_used;
        data.flags = (host.msg_flags & MSG_CTRUNC ? 8 : 0) |
                     (host.msg_flags & MSG_TRUNC ? 32 : 0) |
                     (data.flags & 8);
        memcpy(header, &data, sizeof(data));
    }
    return result;
}

/* Linux mmsghdr: msghdr (56 bytes) + u32 msg_len + u32 pad = 64 bytes. */
static s64 guest_socket_mmessage(oah_image *img, int fd, u64 vec, u64 count,
                                 u64 flags, u64 timeout_addr, bool receiving)
{
    if (!count || count > 1024) {
        return -EINVAL;
    }
    if (receiving && timeout_addr) {
        struct timespec ts;
        const void *input = oah_guest_access(img, timeout_addr, sizeof(ts), PROT_READ);
        if (!input) {
            return -EFAULT;
        }
        memcpy(&ts, input, sizeof(ts));
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ms = ts.tv_sec >= 0
            ? (int)(ts.tv_sec > INT32_MAX / 1000 ? INT32_MAX : ts.tv_sec * 1000 +
                    ts.tv_nsec / 1000000)
            : -1;
        bool released = begin_blocking_call();
        int ready = poll(&pfd, 1, ms);
        finish_blocking_call(released);
        if (ready <= 0) {
            return ready < 0 ? linux_error(errno) : 0;
        }
    }
    /* Linux MSG_WAITFORONE (0x10000) turns on MSG_DONTWAIT after the
     * first received datagram; without it every entry uses the caller's
     * flags verbatim. sendmmsg never gains MSG_DONTWAIT. A successful
     * zero-length receive still counts as a message, and a copy-out
     * fault after at least one entry reports the completed count. */
    u64 done = 0;
    for (; done < count; done++) {
        u64 entry = vec + done * 64;
        u64 per_flags = flags;
        if (receiving) {
            per_flags &= ~(u64)0x10000;
            if (done && (flags & 0x10000)) {
                per_flags |= 0x40;
            }
        }
        s64 one = guest_socket_message(img, fd, entry, per_flags, receiving);
        if (one < 0) {
            return done ? (s64)done : one;
        }
        void *len_out = oah_guest_access(img, entry + 56, 4, PROT_WRITE);
        if (!len_out) {
            return done ? (s64)done : -EFAULT;
        }
        u32 sent = (u32)one;
        memcpy(len_out, &sent, sizeof(sent));
    }
    return (s64)done;
}

/* sendto/recvfrom with an explicit peer address (unconnected datagrams). */
static s64 guest_socket_transfer(oah_image *img, int fd, u64 address, u64 size,
                                 u64 flags, u64 addr, u64 addr_len, bool receiving)
{
    struct sockaddr_storage host = {0};
    struct sockaddr *sa = (struct sockaddr *)&host;
    socklen_t salen = sizeof(host);
    u32 guest_capacity = 0;
    u32 *length_output = NULL;

    if (receiving) {
        if (addr) {
            length_output = oah_guest_access(img, addr_len, sizeof(u32),
                                             PROT_READ | PROT_WRITE);
            if (!length_output) {
                return -EFAULT;
            }
            memcpy(&guest_capacity, length_output, sizeof(guest_capacity));
            if ((s32)guest_capacity < 0) {
                return -EINVAL;
            }
        }
    } else if (addr) {
        const void *input = oah_guest_access(img, addr, sizeof(host), PROT_READ);
        if (!input) {
            return -EFAULT;
        }
        u16 family;
        memcpy(&family, input, sizeof(family));
        if (family != 2 && family != 10) {
            return -LINUX_EAFNOSUPPORT;
        }
        socklen_t needed = family == 2 ? sizeof(struct sockaddr_in)
                                       : sizeof(struct sockaddr_in6);
        if (addr_len < needed) {
            return -EINVAL;
        }
        memcpy(&host, input, needed);
        host.ss_len = needed;
        host.ss_family = family == 2 ? AF_INET : AF_INET6;
        salen = needed;
    }

    u32 protection = receiving ? PROT_WRITE : PROT_READ;
    void *guest = oah_guest_access(img, address, size, protection);
    if (size && !guest) {
        return -EFAULT;
    }
    int host_flags = (flags & 0x40 ? MSG_DONTWAIT : 0) | (flags & 0x2 ? MSG_PEEK : 0);
    bool released = begin_blocking_call();
    ssize_t bytes = receiving
        ? recvfrom(fd, guest, size, host_flags, addr ? sa : NULL, addr ? &salen : NULL)
        : sendto(fd, guest, size, host_flags, addr ? sa : NULL, salen);
    finish_blocking_call(released);
    {
        static int st = -1;
        if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
        if (st) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&host;
            fprintf(stderr, "sockto recv=%d fd=%d to=%u.%u.%u.%u:%u -> %zd\n",
                    receiving, fd,
                    (unsigned)((u8*)&sin->sin_addr)[0], (unsigned)((u8*)&sin->sin_addr)[1],
                    (unsigned)((u8*)&sin->sin_addr)[2], (unsigned)((u8*)&sin->sin_addr)[3],
                    (unsigned)ntohs(sin->sin_port), bytes);
        }
    }
    if (bytes < 0) {
        return linux_error(errno);
    }
    if (receiving && addr) {
        u16 family = host.ss_family == AF_UNIX ? 1 :
                     host.ss_family == AF_INET ? 2 :
                     host.ss_family == AF_INET6 ? 10 : 0;
        if (!family) {
            return -LINUX_EAFNOSUPPORT;
        }
        u32 out = salen < guest_capacity ? (u32)salen : guest_capacity;
        if (out) {
            memcpy(&host, &family, sizeof(family));
            void *name_out = oah_guest_access(img, addr, out, PROT_WRITE);
            if (!name_out) {
                return -EFAULT;
            }
            memcpy(name_out, &host, out);
        }
        memcpy(length_output, &salen, sizeof(u32));
    }
    return bytes;
}

static int guest_socket_option(u64 level, u64 option, int *host_level)
{
    if (level == 1) {
        *host_level = SOL_SOCKET;
        switch (option) {
        case 2: return SO_REUSEADDR;
        case 3: return SO_TYPE;
        case 4: return SO_ERROR;
        case 6: return SO_BROADCAST;
        case 9: return SO_KEEPALIVE;
        case 20: return SO_RCVTIMEO;
        case 21: return SO_SNDTIMEO;
        case 16:
            /* SO_PASSCRED: Darwin sends credentials with SCM_CREDS
             * unconditionally; our cmsg translation handles them either
             * way, so accepting the toggle as a no-op is correct. */
            *host_level = -1;
            return 0;
        default: return -1;
        }
    }
    if (level == 6 && option == 1) {
        *host_level = IPPROTO_TCP;
        return TCP_NODELAY;
    }
    if (level == 0 && (option == 11 || option == 8 || option == 12)) {
        /* Linux IP_RECVERR / IP_PKTINFO / IP_RECVTTL: advisory for glibc's
         * resolver error detection — accept as a no-op (host getsockopt
         * reports a harmless zero). */
        *host_level = -1;
        return 0;
    }
    if (level == 41 && option == 26) {
        *host_level = IPPROTO_IPV6;
        return IPV6_V6ONLY;
    }
    return -1;
}

static s64 guest_socket_options(oah_image *img, int fd, u64 level, u64 option,
                                u64 address, u64 length, bool setting)
{
    if (level == 1 && option == 17 && !setting) {
        /* SO_PEERCRED → ucred{pid,uid,gid}. The peer is another guest
         * process, so ids must be in guest terms — guests that see
         * themselves as root present their peer as root too. */
        u8 ucred[12] = {0};
        uid_t uid;
        gid_t gid;
        if (getpeereid(fd, &uid, &gid) < 0) {
            return linux_error(errno);
        }
        if (guest_root(img)) {
            uid = img->guest_uid[0];
            gid = img->guest_gid[0];
        }
        memcpy(ucred + 4, &uid, 4);
        memcpy(ucred + 8, &gid, 4);
#ifdef LOCAL_PEEREPID
        pid_t epid = 0;
        socklen_t elen = sizeof(epid);
        if (getsockopt(fd, 0, LOCAL_PEEREPID, &epid, &elen) == 0) {
            memcpy(ucred, &epid, 4);
        }
#endif
        void *out = oah_guest_access(img, address, 12, PROT_WRITE);
        void *sz = oah_guest_access(img, length, 4, PROT_WRITE);
        if (!out || !sz) {
            return -EFAULT;
        }
        memcpy(out, ucred, 12);
        u32 s = 12;
        memcpy(sz, &s, 4);
        return 0;
    }
    int host_level;
    int host_option = guest_socket_option(level, option, &host_level);
    if (host_option < 0) {
        return -92; /* ENOPROTOOPT */
    }
    int value;
    if (host_level < 0) {
        /* advisory option accepted as a no-op */
        if (!setting) {
            void *out = oah_guest_access(img, address, sizeof(value), PROT_WRITE);
            void *sz = oah_guest_access(img, length, 4, PROT_WRITE);
            if (!out || !sz) {
                return -EFAULT;
            }
            memset(out, 0, sizeof(value));
            u32 s = sizeof(value);
            memcpy(sz, &s, sizeof(s));
        }
        return 0;
    }
    if (setting) {
        if (host_option == SO_RCVTIMEO || host_option == SO_SNDTIMEO) {
            struct timeval tv;
            if (length < (u64)sizeof(tv)) {
                return -EINVAL;
            }
            const void *input = oah_guest_access(img, address, sizeof(tv), PROT_READ);
            if (!input) {
                return -EFAULT;
            }
            memcpy(&tv, input, sizeof(tv));
            return host_result(setsockopt(fd, host_level, host_option, &tv, sizeof(tv)));
        }
        const void *input = oah_guest_access(img, address, sizeof(value), PROT_READ);
        if (length < sizeof(value)) {
            return -EINVAL;
        }
        if (!input) {
            return -EFAULT;
        }
        memcpy(&value, input, sizeof(value));
        return host_result(setsockopt(fd, host_level, host_option, &value, sizeof(value)));
    }
    void *size_address = oah_guest_access(img, length, 4, PROT_READ | PROT_WRITE);
    u32 size;
    if (!size_address) {
        return -EFAULT;
    }
    memcpy(&size, size_address, sizeof(size));
    if ((s32)size < 0) {
        return -EINVAL;
    }
    if (size > sizeof(value)) {
        size = sizeof(value);
    }
    void *output = size ? oah_guest_access(img, address, size, PROT_WRITE) : NULL;
    if (size && !output) {
        return -EFAULT;
    }
    socklen_t actual = sizeof(value);
    if (getsockopt(fd, host_level, host_option, &value, &actual) < 0) {
        return linux_error(errno);
    }
    if (host_level == SOL_SOCKET && host_option == SO_ERROR && value) {
        value = (int)-linux_error(value);
    }
    if (size) {
        memcpy(output, &value, size);
    }
    memcpy(size_address, &size, sizeof(size));
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
    oah_darwin_program program;
    if (!oah_darwin_resolve_program(&program, img->sysroot, path, true)) {
        return linux_error(errno);
    }

    enum { MAX_VECTOR = 4096, LAUNCH_ARGS = 12 + OAH_SCRIPT_PREFIX };
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
    char instruction_limit[24];
    if (img->instruction_limit) {
        snprintf(instruction_limit, sizeof(instruction_limit), "%llu",
                 (unsigned long long)img->instruction_limit);
        args[count++] = "--max-insns";
        args[count++] = instruction_limit;
    }
    args[count++] = "--guest-exec";
    args[count++] = program.executable;
    char env_count_text[16];
    args[count++] = env_count_text;
    args[count++] = "--";

    /* Pass guest variables as payload so the host loader never reads them. */
    s64 result = guest_exec_vector(img, env_arg, args + count, MAX_VECTOR, &bytes, false);
    if (!result) {
        size_t env_count = 0;
        while (args[count + env_count]) {
            env_count++;
        }
        snprintf(env_count_text, sizeof(env_count_text), "%zu", env_count);
        count += env_count;
        args[count++] = "";
        char *prefix[OAH_SCRIPT_PREFIX];
        size_t prefix_count = oah_darwin_program_prefix(&program, prefix);
        size_t start = count + (prefix_count ? prefix_count - 1 : 0);
        result = guest_exec_vector(img, argv_arg, args + start, MAX_VECTOR, &bytes, true);
        if (!result && prefix_count) {
            memcpy(args + count, prefix, prefix_count * sizeof(*args));
        }
    }
    if (!result) {
        if (getenv("OAH_EXEC_TRACE")) {
            for (size_t i = 0; args[i]; i++) {
                fprintf(stderr, "[exec-trace] arg[%zu]=%s\n", i, args[i]);
            }
        }
        /* Translator configuration lives in the host environment; carry the
         * OAH_* variables into the exec'd child so settings like strict
         * sysroot mode, cache selection, and tracing survive guest execve. */
        char *host_env[64];
        size_t host_env_count = 0;
        char *const *envp;
        for (envp = environ; *envp && host_env_count + 1 < sizeof(host_env) / sizeof(*host_env);
             envp++) {
            if (strncmp(*envp, "OAH_", 4) == 0) {
                host_env[host_env_count++] = *envp;
            }
        }
        /* Guest-visible ids/caps are process state the exec'd child must
         * inherit — the new oah image would otherwise come up as root. */
        char ids_buffer[640];
        if (guest_root(img)) {
            size_t n = snprintf(ids_buffer, sizeof(ids_buffer),
                                "OAH_GUEST_IDS=%u,%u,%u,%u,%u,%u",
                                img->guest_uid[0], img->guest_uid[1], img->guest_uid[2],
                                img->guest_gid[0], img->guest_gid[1], img->guest_gid[2]);
            n += snprintf(ids_buffer + n, sizeof(ids_buffer) - n, ",%d",
                          img->guest_ngroups);
            for (int i = 0; i < img->guest_ngroups; i++) {
                n += snprintf(ids_buffer + n, sizeof(ids_buffer) - n, ",%u",
                              img->guest_groups[i]);
            }
            snprintf(ids_buffer + n, sizeof(ids_buffer) - n, ",%u,%u,%llu,%llu,%llu",
                     img->guest_caps_set, img->guest_keepcaps,
                     (unsigned long long)img->guest_caps[0],
                     (unsigned long long)img->guest_caps[1],
                     (unsigned long long)img->guest_caps[2]);
            host_env[host_env_count++] = ids_buffer;
        }
        host_env[host_env_count] = NULL;
        struct itimerval timer;
        const struct itimerval stopped = {0};
        if (posix_timer_created && setitimer(ITIMER_REAL, &stopped, &timer) < 0) {
            result = linux_error(errno);
        } else {
            result = host_result(execve(img->launcher, args, (char *const *)host_env));
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
    bool released = begin_blocking_call();
    int slept = nanosleep(&interval, &remaining);
    finish_blocking_call(released);
    if (slept == 0) {
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
    /* Strict sysroot mode anchors the process cwd inside the sysroot so
     * relative paths and AT_FDCWD stay confined. A cwd the guest itself
     * established (inherited across execve) is inside the sysroot already
     * and must be preserved — anchoring again would reset it to "/". */
    static int strict_chdir = -1;
    if (strict_chdir < 0) {
        strict_chdir = 0;
        if (img->sysroot && getenv("OAH_SYSROOT_STRICT")) {
            char cwd[PATH_MAX];
            strict_chdir = (getcwd(cwd, sizeof(cwd)) &&
                            under_sysroot(img, cwd)) ||
                           chdir(img->sysroot) == 0;
        }
    }
    u64 nr = g->gpr[OAH_X86_RAX];
    u64 a0 = g->gpr[OAH_X86_RDI], a1 = g->gpr[OAH_X86_RSI];
    u64 a2 = g->gpr[OAH_X86_RDX], a3 = g->gpr[OAH_X86_R10];
    u64 a4 = g->gpr[OAH_X86_R8], a5 = g->gpr[OAH_X86_R9];
    s64 result;
    { static int mfd_t = -1;
      if (mfd_t < 0) { mfd_t = getenv("OAH_MFD_TRACE") != NULL; }
      if (mfd_t &&
          ((a0 < OAH_FD_PATH_MAX && fd_is_memfd[(int)a0]) ||
           (nr == 9 && a4 < OAH_FD_PATH_MAX && fd_is_memfd[(int)a4]))) {
          fprintf(stderr, "mfd syscall %llu fd=%llu a1=%llx a2=%llx\n",
                  (unsigned long long)nr,
                  (unsigned long long)(nr == 9 ? a4 : a0),
                  (unsigned long long)a1, (unsigned long long)a2);
      } }
    g->gpr[OAH_X86_RCX] = g->rip;
    g->gpr[OAH_X86_R11] = g->rflags;

    if (((nr >= 42 && nr <= 52) || nr == 54 || nr == 55 || nr == 288) &&
        eventfd_for_fd((int)a0)) {
        g->gpr[OAH_X86_RAX] = (u64)-LINUX_ENOTSOCK;
        return OAH_SYS_CONTINUE;
    }
    {
        static int all_trace = -1;
        if (all_trace < 0) {
            all_trace = getenv("OAH_ALL_TRACE") != NULL;
        }
        if ((all_trace && getenv("OAH_ALL_TRACE_VERBOSE") &&
             nr != 35 && nr != 230 && nr != 202) ||
            (all_trace && ((nr >= 41 && nr <= 55) || nr == 288 || nr == 307 ||
                          nr == 299 || nr == 270 || nr == 271 ||
                          nr == 332 || nr == 437 || nr == 79 || nr == 262 ||
                          nr == 217 || nr == 161 || nr == 257 || nr == 4 ||
                          nr == 5 || nr == 6 || nr == 267 || nr == 89 ||
                          nr == 80))) {
            fprintf(stderr, "syscall %llu a0=%llx a1=%llx a2=%llx a3=%llx",
                    (unsigned long long)nr, (unsigned long long)a0,
                    (unsigned long long)a1, (unsigned long long)a2,
                    (unsigned long long)a3);
            if (nr == 257 || nr == 2 || nr == 262 || nr == 4 || nr == 6 ||
                nr == 267 || nr == 89 || nr == 80) {
                const char *tp = guest_path(img, nr == 2 || nr == 4 || nr == 6 ||
                                            nr == 89 || nr == 80 ? a0 : a1);
                fprintf(stderr, " path=%s", tp ? tp : "?");
            }
            fprintf(stderr, "\n");
        }
    }
    switch (nr) {
    case OAH_X86_NR_EXIT_GROUP:
        if (workers) {
            _exit((int)(a0 & 0xff));
        }
        return OAH_SYS_EXIT;
    case OAH_X86_NR_EXIT:
        g->thread_exit = true;
        if (!g->tid || g->tid == (u32)getpid()) {
            clear_guest_tid(g, img);
            while (workers) {
                pthread_cond_wait(&workers_exited, &guest_lock);
            }
        }
        return OAH_SYS_EXIT;
    case 13: case 14: case 15: case 127: case 130: case 131: case 200: case 234:
        return oah_guest_signal_syscall(g, img);
    case OAH_X86_NR_READ:
    case OAH_X86_NR_WRITE: {
        {
            static int bt = -1;
            if (bt < 0) {
                bt = getenv("OAH_BACKTRACE") != NULL;
            }
            if (bt && nr == OAH_X86_NR_WRITE) {
                const u8 *buf = oah_guest_access(img, a1, a2, PROT_READ);
                if (buf && memmem(buf, a2, "usable", 6)) {
                    u64 w = g->gpr[OAH_X86_RBP];
                    fprintf(stderr, "backtrace from write:\n");
                    for (int i = 0; i < 24 && w > 0x10000; i++) {
                        const u64 *slot = oah_guest_access(img, w, 16, PROT_READ);
                        if (!slot) break;
                        fprintf(stderr, "  rbp=%llx ret=%llx\n",
                                (unsigned long long)w,
                                (unsigned long long)slot[1]);
                        w = slot[0];
                    }
                }
            }
        }
        {
            static int stdin_trace = -1;
            if (stdin_trace < 0) {
                stdin_trace = getenv("OAH_STDIN_TRACE") != NULL;
            }
            if (stdin_trace && nr == OAH_X86_NR_READ && a0 < 8) {
                fprintf(stderr, "sys_read fd=%llu buf=%llx size=%llu\n",
                        (unsigned long long)a0,
                        (unsigned long long)a1, (unsigned long long)a2);
            }
        }
        guest_eventfd *counter = eventfd_for_fd((int)a0);
        result = counter ? guest_eventfd_io(img, (int)a0, counter, a1, a2, nr == OAH_X86_NR_READ) :
                 oah_dsp_owns((int)a0) ? (nr == OAH_X86_NR_READ ? -EINVAL
                                       : oah_dsp_write(img, (int)a0, a1, a2)) :
                 oah_alsa_owns((int)a0) ? (nr == OAH_X86_NR_READ ? -EINVAL
                                        : oah_alsa_write(img, (int)a0, a1, a2)) :
                           guest_blocking_io(img, (int)a0, a1, a2, nr == OAH_X86_NR_READ, false, 0);
        break;
    }
    case 284: case 290: /* eventfd, eventfd2 */
        result = guest_eventfd_create((u32)a0, nr == 290 ? a1 : 0);
        break;
    case 2: /* open */
        result = guest_open(img, AT_FDCWD, a0, a1, a2);
        break;
    case OAH_X86_NR_OPENAT:
        result = guest_open(img, (int)a0, a1, a2, a3);
        break;
    case 436: result = guest_close_range((u32)a0, (u32)a1, (u32)a2); break;
    case OAH_X86_NR_CLOSE:
        forget_directory((int)a0);
        forget_readiness_fd((int)a0);
        untrack_fd_path((int)a0);
        result = oah_dsp_owns((int)a0) ? host_result(oah_dsp_close((int)a0))
                 : oah_alsa_owns((int)a0) ? host_result(oah_alsa_close((int)a0))
                                      : host_result(close((int)a0));
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
    case 137: case 138: { /* statvfs, fstatvfs */
        u64 *out = oah_guest_access(img, a1, 88, PROT_WRITE);
        if (!out) {
            result = -EFAULT;
            break;
        }
        struct statvfs sv;
        if (nr == 138) {
            result = host_result(fstatvfs((int)a0, &sv));
        } else {
            const char *path = guest_path(img, a0);
            if (!path) {
                result = -EFAULT;
                break;
            }
            char rp[PATH_MAX];
            int rr = resolve_read_path(img, path, rp, sizeof(rp), true);
            result = rr < 0 ? rr : host_result(statvfs(rr ? rp : path, &sv));
            if (result < 0 && rr > 0 && !sysroot_strict(img) &&
                (errno == ENOENT || errno == ENOTDIR)) {
                result = host_result(statvfs(path, &sv));
            }
        }
        if (result >= 0) {
            u64 lv[11] = {
                sv.f_bsize, sv.f_frsize, sv.f_blocks, sv.f_bfree, sv.f_bavail,
                sv.f_files, sv.f_ffree, sv.f_ffree, 0, 0, sv.f_namemax
            };
            memcpy(&lv[8], &sv.f_fsid, sizeof(sv.f_fsid) < 8 ? sizeof(sv.f_fsid) : 8);
            memcpy(out, lv, sizeof(lv));
        }
        break;
    }
    case 9: /* mmap */
        result = guest_mmap(img, a0, a1, a2, a3, (int)a4, a5);
        break;
    case 10: /* mprotect */
    case 11: /* munmap */
        result = memory_change(img, a0, a1, nr == 11 ? 0 : a2, nr == 11);
        { static int t = -1; if (t < 0) { t = getenv("OAH_MMAP_TRACE") != NULL; }
          if (t) { fprintf(stderr, "%s addr=%llx len=%llx prot=%llx -> %lld\n",
                           nr == 11 ? "munmap" : "mprotect",
                           (unsigned long long)a0, (unsigned long long)a1,
                           (unsigned long long)a2, (long long)result); } }
        break;
    case OAH_X86_NR_BRK:
        result = (s64)guest_brk(img, a0);
        break;
    case 213: /* epoll_create */
        result = (s32)a0 > 0 ? guest_epoll_create(0) : -EINVAL;
        break;
    case 291: /* epoll_create1 */
        result = guest_epoll_create(a0);
        break;
    case 233: /* epoll_ctl */
        result = guest_epoll_ctl(img, (int)a0, a1, (int)a2, a3);
        break;
    case 232: case 281: /* epoll_wait, epoll_pwait */
        result = nr == 281 && a4 ? -LINUX_ENOSYS :
                 guest_epoll_wait(img, (int)a0, a1, (s32)a2, (s32)a3);
        break;
    case 25: /* mremap */
        result = guest_mremap(img, a0, a1, a2, a3);
        break;
    case 99: /* sysinfo */
        result = guest_system_info(img, a0);
        break;
    case 118: case 120: { /* getresuid, getresgid */
        const u32 *ids = nr == 118 ? img->guest_uid : img->guest_gid;
        void *outputs[] = {oah_guest_access(img, a0, 4, PROT_WRITE),
                           oah_guest_access(img, a1, 4, PROT_WRITE),
                           oah_guest_access(img, a2, 4, PROT_WRITE)};
        if (!outputs[0] || !outputs[1] || !outputs[2]) {
            result = -EFAULT;
        } else if (!guest_root(img)) {
            u32 v = nr == 118 ? getuid() : getgid();
            for (unsigned i = 0; i < 3; i++) {
                memcpy(outputs[i], &v, sizeof(v));
            }
            result = 0;
        } else {
            for (unsigned i = 0; i < 3; i++) {
                memcpy(outputs[i], &ids[i], sizeof(u32));
            }
            result = 0;
        }
        break;
    }
    case 143: case 145: /* sched_getparam, sched_getscheduler */
        result = current_guest_task(g, a0) ? 0 : -ESRCH;
        if (!result && nr == 143) {
            void *output = oah_guest_access(img, a1, 4, PROT_WRITE);
            const s32 priority = 0;
            if (output) {
                memcpy(output, &priority, sizeof(priority));
            } else {
                result = -EFAULT;
            }
        }
        break;
    case 157: /* prctl */
        result = guest_prctl(img, a0, a1);
        break;
    case 204: /* sched_getaffinity */
        result = guest_affinity(g, img, a0, a1, a2);
        break;
    case 7: /* poll */
        result = guest_poll(img, a0, a1, (s32)a2);
        break;
    case 16: { /* ioctl */
        {   static int pty_trace = -1;
            if (pty_trace < 0) { pty_trace = getenv("OAH_PTY_TRACE") != NULL; }
            if (pty_trace) { fprintf(stderr, "ioctl fd=%lld req=%llx\n",
                                     (long long)a0, (unsigned long long)a1); }
        }
        if (eventfd_for_fd((int)a0)) {
            result = -ENOTTY;
            break;
        }
        if (oah_dsp_owns((int)a0)) {
            result = oah_dsp_ioctl(img, (int)a0, a1, a2);
            break;
        }
        if (oah_alsa_owns((int)a0)) {
            result = oah_alsa_ioctl(img, (int)a0, a1, a2);
            break;
        }
        if (a1 == 0x541b) { /* FIONREAD */
            int count;
            void *output = oah_guest_access(img, a2, sizeof(count), PROT_WRITE);
            result = output ? host_result(ioctl((int)a0, FIONREAD, &count)) : -EFAULT;
            if (!result) {
                memcpy(output, &count, sizeof(count));
            }
            break;
        }
        if (a1 == 0x5421) { /* FIONBIO */
            int enabled;
            const void *input = oah_guest_access(img, a2, sizeof(enabled), PROT_READ);
            if (!input) {
                result = -EFAULT;
                break;
            }
            memcpy(&enabled, input, sizeof(enabled));
            result = host_result(ioctl((int)a0, FIONBIO, &enabled));
            break;
        }
        if (a1 == 0x80045430) { /* TIOCGPTN: pts unit number */
            u32 *output = oah_guest_access(img, a2, 4, PROT_WRITE);
            if (!output) {
                result = -EFAULT;
                break;
            }
            const char *name = ptsname((int)a0);
            int unit = -1;
            if (name) {
                sscanf(name, "/dev/ttys%d", &unit);
            }
            {   static int pty_trace = -1;
                if (pty_trace < 0) { pty_trace = getenv("OAH_PTY_TRACE") != NULL; }
                if (pty_trace) { fprintf(stderr, "TIOCGPTN fd=%lld name=%s unit=%d\n",
                                         (long long)a0, name ? name : "?", unit); }
            }
            result = unit < 0 ? host_result(-1) : 0;
            if (!result) {
                memcpy(output, &unit, 4);
            }
            if (unit < 0) {
                errno = ENOTTY;
                result = -ENOTTY;
            }
            break;
        }
        if (a1 == 0x40045431 || a1 == 0x80045432) { /* TIOCSPTLCK, TIOCGPTLCK */
            static int pty_trace = -1;
            if (pty_trace < 0) { pty_trace = getenv("OAH_PTY_TRACE") != NULL; }
            if (pty_trace) { fprintf(stderr, "pty-ioctl %llx fd=%lld\n",
                                     (unsigned long long)a1, (long long)a0); }
            /* Darwin unlocks pts at grantpt; lock state is a no-op. */
            void *output = a1 == 0x80045432 ?
                oah_guest_access(img, a2, 4, PROT_WRITE) : NULL;
            if (a1 == 0x80045432 && !output) {
                result = -EFAULT;
                break;
            }
            /* Darwin grantpt chowns the slave to the caller; on Linux it's
             * a no-op so guests (xterm) skip it and would hit EACCES on
             * the slave open. Run it before unlockpt. */
            if (a1 == 0x40045431) {
                grantpt((int)a0);
            }
            result = a1 == 0x80045432 ? 0 : host_result(unlockpt((int)a0));
            if (a1 == 0x80045432) {
                memset(output, 0, 4);
            }
            break;
        }
        if (a1 == 0x5441) { /* TIOCGPTPEER: slave fd for this master */
            const char *name = ptsname((int)a0);
            if (!name) {
                result = -ENOTTY;
                break;
            }
            int sflags = (int)(a2 & 3);
            u64 rest = a2 & ~3ull;
            for (unsigned i = 0; i < sizeof(open_flags) / sizeof(open_flags[0]); i++) {
                if (rest & open_flags[i].guest) {
                    sflags |= open_flags[i].host;
                    rest &= ~open_flags[i].guest;
                }
            }
            if (rest) {
                result = -EINVAL;
                break;
            }
            result = host_result(guest_lockable_fd(open(name, sflags, 0),
                                                 sflags));
            break;
        }
        if (a1 == 0x5451 || a1 == 0x5450) { /* FIOCLEX, FIONCLEX */
            result = host_result(ioctl((int)a0,
                                       a1 == 0x5451 ? FIOCLEX : FIONCLEX));
            break;
        }
        if (a1 >= 0x5401 && a1 <= 0x5404) {
            /* TCGETS, TCSETS, TCSETSW, TCSETSF over translated termios. */
            static const unsigned long host_req[] = {
                TIOCGETA, TIOCSETA, TIOCSETAW, TIOCSETAF,
            };
            bool get = a1 == 0x5401;
            linux_termios *lt = oah_guest_access(img, a2, sizeof(*lt),
                                                 get ? PROT_WRITE : PROT_READ);
            if (!lt) {
                result = -EFAULT;
                break;
            }
            struct termios ht;
            if (get) {
                result = host_result(ioctl((int)a0, TIOCGETA, &ht));
                if (result >= 0) {
                    termios_to_guest(&ht, lt);
                }
            } else {
                termios_to_host(lt, &ht);
                result = host_result(ioctl((int)a0, host_req[a1 - 0x5401], &ht));
            }
            break;
        }
        struct winsize *size = oah_guest_access(img, a2, sizeof(*size), PROT_WRITE);
        if (a1 == 0x540e) { /* TIOCSCTTY */
            result = host_result(ioctl((int)a0, TIOCSCTTY, 0));
            if (result >= 0 &&
                fcntl((int)a0, F_GETPATH, guest_ctty_path) < 0) {
                guest_ctty_path[0] = 0;
            }
            break;
        }
        if (a1 == 0x5422) { /* TIOCNOTTY */
            result = host_result(ioctl((int)a0, TIOCNOTTY));
            if (result >= 0) {
                guest_ctty_path[0] = 0;
            }
            break;
        }
        if (a1 == 0x5414) { /* TIOCSWINSZ — same 4x u16 layout on both. */
            result = !size ? -EFAULT
                           : host_result(ioctl((int)a0, TIOCSWINSZ, size));
            break;
        }
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
    case 21: case 269: case 439: { /* access, faccessat, faccessat2 */
        const char *path = guest_path(img, nr == 21 ? a0 : a1);
        u64 mode = nr == 21 ? a1 : a2;
        u64 faccess_flags = nr == 21 ? 0 : a3;
        int dirfd = nr == 21 ? AT_FDCWD : darwin_dirfd(a0);
        int host_flags = faccess_flags & 0x200 ? AT_EACCESS : 0;
        const char *prel;
        char canon[256];
        char pts[64];
        int unit = -1;
        if (path && !strncmp(path, "/dev/pts/", 9) &&
            sscanf(path + 9, "%d", &unit) == 1) {
            snprintf(pts, sizeof(pts), "/dev/ttys%03d", unit);
            path = pts;
        }
        if (!path) {
            result = -EFAULT;
        } else if (mode & ~7ull || faccess_flags & ~0x700ull) {
            result = -EINVAL;
        } else if (path[0] == '/' && proc_path_rel(path, &prel)) {
            prel = proc_rel_canon(prel, canon, sizeof(canon));
            bool exists = proc_is_dir(prel) || proc_is_link(prel) ||
                procfs_synth(img, prel, (u8[1]){0}, 1) != -ENOENT;
            if (!exists) {
                result = -ENOENT;
            } else if (mode & 4) { /* R_OK: all proc nodes are readable */
                result = 0;
            } else if (mode & 2) { /* W_OK */
                result = proc_writable(prel) ? 0 : -EACCES;
            } else { /* X_OK */
                result = proc_is_dir(prel) ? 0 : -EACCES;
            }
        } else {
            char rp[PATH_MAX];
            int rr = resolve_read_path(img, path, rp, sizeof(rp), !(faccess_flags & 0x100));
            result = rr < 0 ? rr :
                     rr ? host_result(faccessat(AT_FDCWD, rp, (int)mode, host_flags))
                        : host_result(faccessat(dirfd, path, (int)mode, host_flags));
            /* Reads fall back to the host when the sysroot lacks the file
             * (non-strict mode only; strict keeps the sysroot verdict). */
            if (result < 0 && rr > 0 && !sysroot_strict(img) &&
                (errno == ENOENT || errno == ENOTDIR)) {
                result = host_result(faccessat(dirfd, path, (int)mode, host_flags));
            }
        }
        {
            static int open_trace = -1;
            if (open_trace < 0) {
                open_trace = getenv("OAH_OPEN_TRACE") != NULL;
            }
            if (open_trace) {
                fprintf(stderr, "access(%s) = %lld\n", path ? path : "?",
                        (long long)result);
            }
        }
        break;
    }
    case 19: case 20: /* readv, writev */
        result = eventfd_for_fd((int)a0) ? -LINUX_ENOSYS :
                 guest_vector_io(img, (int)a0, a1, a2, nr == 19);
        break;
    case 22: case 293: /* pipe, pipe2 */
        result = guest_fd_pair(img, a0, nr == 293 ? a1 : 0, 0);
        break;
    case 32: /* dup */
        result = host_result(dup((int)a0));
        if (result >= 0 && (int)a0 < OAH_FD_PATH_MAX &&
            result < OAH_FD_PATH_MAX) {
            if (fd_path[(int)a0][0]) {
                memcpy(fd_path[(int)result], fd_path[(int)a0], PATH_MAX);
            }
            fd_seals[(int)result] = fd_seals[(int)a0];
            fd_is_memfd[(int)result] = fd_is_memfd[(int)a0];
        }
        if (result >= 0) {
            if (!duplicate_readiness_fd((int)a0, (int)result)) {
                close((int)result);
                result = -ENOMEM;
            }
        }
        break;
    case 33: case 292: { /* dup2, dup3 */
        int source = (int)a0, target = (int)a1;
        if (nr == 292 && (source == target || (a2 & ~0x80000ull))) {
            result = -EINVAL;
            break;
        }
        result = host_result(dup2(source, target));
        if (result >= 0 && source != target) {
            forget_directory(target);
            forget_readiness_fd(target);
            untrack_fd_path(target);
            if (source < OAH_FD_PATH_MAX && target < OAH_FD_PATH_MAX) {
                if (fd_path[source][0]) {
                    memcpy(fd_path[target], fd_path[source], PATH_MAX);
                }
                fd_seals[target] = fd_seals[source];
                fd_is_memfd[target] = fd_is_memfd[source];
            }
            if (!duplicate_readiness_fd(source, target)) {
                close(target);
                result = -ENOMEM;
                break;
            }
            if (nr == 292 && a2 && fcntl(target, F_SETFD, FD_CLOEXEC) < 0) {
                result = linux_error(errno);
                forget_readiness_fd(target);
                close(target);
            }
        }
        break;
    }
    case 41: result = guest_socket(a0, a1, a2); break;
    case 42: case 49: /* connect, bind */
        result = guest_socket_address(img, (int)a0, a1, a2, nr == 49);
        break;
    case 43: case 51: case 52: case 288: /* accept, getsockname, getpeername, accept4 */
        result = guest_socket_name(img, (int)a0, a1, a2, nr == 288 ? a3 : 0, nr);
        break;
    case 44: case 45: { /* sendto, recvfrom */
        bool receiving = nr == 45;
        u64 allowed = 0x40 | 0x2 | (receiving ? 0 : 0x4000);
        if (a3 & ~allowed) {
            result = -LINUX_EOPNOTSUPP;
        } else if (a4 || a5) {
            result = guest_socket_transfer(img, (int)a0, a1, a2, a3, a4, a5, receiving);
        } else {
            int flags = (a3 & 0x40 ? MSG_DONTWAIT : 0) | (a3 & 0x2 ? MSG_PEEK : 0);
            result = guest_blocking_io(img, (int)a0, a1, a2, receiving, true, flags);
        }
        break;
    }
    case 50: result = host_result(listen((int)a0, (int)a1)); break;
    case 54: case 55: /* setsockopt, getsockopt */
        result = guest_socket_options(img, (int)a0, a1, a2, a3, a4, nr == 54);
        break;
    case 46: case 47: /* sendmsg, recvmsg */
        result = guest_socket_message(img, (int)a0, a1, a2, nr == 47);
        break;
    case 299: case 307: /* recvmmsg, sendmmsg */
        result = guest_socket_mmessage(img, (int)a0, a1, a2, a3, a4, nr == 299);
        break;
    case 48: /* shutdown */
        result = a1 > 2 ? -EINVAL : host_result(shutdown((int)a0, (int)a1));
        break;
    case 53: { /* socketpair */
        u64 type = a1 & 0xf;
        { static int st = -1;
          if (st < 0) st = getenv("OAH_SOCK_TRACE") != NULL;
          if (st) { fprintf(stderr, "socketpair fam=%llu type=%llx proto=%llu\n",
                            (unsigned long long)a0, (unsigned long long)a1,
                            (unsigned long long)a2); } }
        if (a0 != 1) {
            result = -LINUX_EAFNOSUPPORT;
        } else if (a2) {
            result = -LINUX_EPROTONOSUPPORT;
        } else if (type != 1 && type != 2 && type != 5) {
            result = -LINUX_ESOCKTNOSUPPORT;
        } else {
            /* Darwin has no SOCK_SEQPACKET for AF_UNIX; datagram sockets
             * keep the same ordered, record-preserving channel semantics
             * a connected seqpacket pair provides. */
            result = guest_fd_pair(img, a3, a1 & ~0xfull,
                                   type == 1 ? SOCK_STREAM : SOCK_DGRAM);
        }
        break;
    }
    case 435: /* clone3 */
        result = guest_clone3(g, img, a0, a1);
        break;
    case 56: /* clone */
        if (a0 & X86_CLONE_THREAD) {
            result = guest_clone_thread(g, img, a0, a1, a2, a3, a4);
            break;
        }
        /* epoll/eventfd descriptors copy into the child harmlessly, and
         * guest threads are cleaned up in guest_fork's child path; fork from
         * a threaded process is required for spawn-style execvp.
         * CLONE_VM (0x100) is safe to ignore when the child execs or exits
         * quickly; CLONE_VFORK (0x4000) gets the release-fd treatment like a
         * real vfork. glibc posix_spawn uses VM|VFORK|SIGCHLD and may pass a
         * stack pointer — the forked child keeps its existing stack, which
         * is fine because the child only prepares and calls execve. */
        if ((a0 & ~0x1204100ull) != 17 || a2 || a4 ||
            (a1 && (a0 & 0x4100) != 0x4100)) {
            if (getenv("OAH_EXEC_TRACE")) {
                fprintf(stderr, "[exec-trace] clone rejected flags=%llx a1=%llx a2=%llx a4=%llx\n",
                        (unsigned long long)a0, (unsigned long long)a1,
                        (unsigned long long)a2, (unsigned long long)a4);
            }
            result = -LINUX_ENOSYS;
            break;
        }
        if ((a0 & 0x1000000) && !oah_guest_access(img, a3, 4, PROT_WRITE)) {
            result = -EFAULT;
            break;
        }
        result = (a0 & 0x4000) ? guest_vfork() : guest_fork();
        if (result == 0 && a1) {
            /* Real clone starts the child on the supplied stack — its return
             * address there selects the entry point (glibc posix_spawn
             * parks __spawni_child's frame on it). fork() keeps RSP, so
             * move the child onto the requested stack explicitly. */
            g->gpr[OAH_X86_RSP] = a1;
        }
        if (!result && (a0 & 0x1000000)) {
            u32 tid = getpid();
            memcpy(oah_guest_access(img, a3, 4, PROT_WRITE), &tid, sizeof(tid));
        }
        break;
    case 57: case 58: /* fork, vfork */
        result = nr == 58 ? guest_vfork() : guest_fork();
        if (getenv("OAH_EXEC_TRACE")) {
            fprintf(stderr, "[exec-trace] nr=%llu result=%lld workers=%u epolls=%p eventfds=%p\n",
                    (unsigned long long)nr, (long long)result, workers,
                    (void *)epolls, (void *)eventfds);
        }
        break;
    case 59:
        /* execve ends every guest thread but the caller; the host execve
         * does the same to their pthreads, so a live workers count is fine. */
        readiness_prepare_exec();
        result = guest_exec(img, a0, a1, a2);
        if (getenv("OAH_EXEC_TRACE")) {
            const char *exec_path = guest_path(img, a0);
            fprintf(stderr, "[exec-trace] execve path=%s result=%lld workers=%u\n",
                    exec_path ? exec_path : "?", (long long)result, workers);
        }
        break;
    case 61: { /* wait4 */
        void *output = a1 ? oah_guest_access(img, a1, 4, PROT_WRITE) : NULL;
        void *rusage = a3 ? oah_guest_access(img, a3, 144, PROT_WRITE) : NULL;
        int status;
        if ((a1 && !output) || (a3 && !rusage) || (a2 & ~3ull)) {
            result = (a1 && !output) || (a3 && !rusage) ? -EFAULT : -EINVAL;
            break;
        }
        int options = (a2 & 1 ? WNOHANG : 0) | (a2 & 2 ? WUNTRACED : 0);
        struct rusage usage;
        const u64 sigchld = 1ull << 16;
        do {
            result = host_result(wait4((pid_t)a0, &status, options,
                                       rusage ? &usage : NULL));
            /* Darwin catches SIGCHLD to wake guest sigsuspend. A default or
             * ignored guest SIGCHLD must not interrupt this blocking wait. */
            if (result != -EINTR || !host_child_pending || host_alarm_pending ||
                (oah_guest_actions(g)[16].handler > 1 && !(g->signal_mask & sigchld))) {
                break;
            }
        } while (true);
        if (result > 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                forget_child((pid_t)result);
            }
            if (output) {
                if (WIFSIGNALED(status)) {
                    status = (status & ~0x7f) | guest_wait_sig(WTERMSIG(status));
                } else if (WIFSTOPPED(status)) {
                    status = (status & ~0x7f00) |
                             (guest_wait_sig(WSTOPSIG(status)) << 8);
                }
                memcpy(output, &status, sizeof(status));
            }
            if (rusage) {
                memcpy(rusage, &usage, sizeof(usage));
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
    case 112: /* setsid */
        result = host_result(setsid());
        if (result >= 0) {
            /* Fresh session: no controlling tty until the next slave open
             * or TIOCSCTTY (Linux drops the inherited ctty here). */
            guest_session_leader = true;
            guest_ctty_path[0] = 0;
        }
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
    case 38: /* setitimer */
        result = guest_interval_timer(img, a0, a1, a2);
        break;
    case 270: { /* pselect6 */
        const u64 addresses[] = {a1, a2, a3};
        struct timespec timeout;
        const struct timespec *tsp = NULL;
        if (a4) {
            const void *input = oah_guest_access(img, a4, sizeof(timeout), PROT_READ);
            if (!input) {
                result = -EFAULT;
                break;
            }
            memcpy(&timeout, input, sizeof(timeout));
            tsp = &timeout;
        }
        result = guest_pselect(g, img, a0, addresses, tsp, a5);
        break;
    }
    case 23: { /* select */
        const u64 addresses[] = {a1, a2, a3};
        struct timespec timeout;
        const struct timespec *tsp = NULL;
        if (a4) {
            const s64 *tv = oah_guest_access(img, a4, 16, PROT_READ);
            if (!tv) {
                result = -EFAULT;
                break;
            }
            timeout.tv_sec = tv[0];
            timeout.tv_nsec = tv[1] * 1000;
            tsp = &timeout;
        }
        result = guest_pselect(g, img, a0, addresses, tsp, 0);
        break;
    }
    case 35: /* nanosleep */
        result = guest_sleep(img, 1, 0, a0, a1);
        break;
    case 37: { /* alarm -> setitimer(ITIMER_REAL) delivering SIGALRM */
        struct itimerval timer = {0}, old;
        timer.it_value.tv_sec = (time_t)a0;
        result = host_result(setitimer(ITIMER_REAL, &timer, &old));
        if (result == 0) {
            result = (s64)old.it_value.tv_sec;
        }
        break;
    }
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
    case 277: /* sync_file_range: approximate with an fd data flush */
        result = a3 & ~7ull ? -EINVAL : host_result(fdatasync((int)a0));
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
        if (result > 0 && img->sysroot) {
            size_t rl = strlen(img->sysroot);
            if (strncmp(buffer, img->sysroot, rl) == 0 &&
                (buffer[rl] == '/' || buffer[rl] == 0)) {
                memmove(buffer, buffer + rl, strlen(buffer) - rl + 1);
                if (!*buffer) {
                    buffer[0] = '/'; buffer[1] = 0;
                }
                result = (s64)strlen(buffer) + 1;
            }
        }
        break;
    }
    case 80: { /* chdir */
        const char *path = guest_path(img, a0);
        char rp[PATH_MAX];
        int rr = resolve_read_path(img, path, rp, sizeof(rp), true);
        result = !path ? -EFAULT : rr < 0 ? rr : host_result(chdir(rr ? rp : path));
        break;
    }
    case 81: result = host_result(fchdir((int)a0)); break;
    case 76: { /* truncate */
        const char *path = guest_path(img, a0);
        char mut[PATH_MAX];
        int mr = resolve_mut_path(img, path, mut, sizeof(mut));
        result = !path ? -EFAULT : mr < 0 ? mr :
                 host_result(truncate(mr ? mut : path, (off_t)a1));
        break;
    }
    case 77: /* ftruncate */
        if ((int)a0 >= 0 && (int)a0 < OAH_FD_PATH_MAX &&
            fd_seals[(int)a0] & (OAH_F_SEAL_GROW | OAH_F_SEAL_SHRINK)) {
            struct stat st;
            if (fstat((int)a0, &st) == 0 &&
                ((a1 > (u64)st.st_size && fd_seals[(int)a0] & OAH_F_SEAL_GROW) ||
                 (a1 < (u64)st.st_size &&
                  fd_seals[(int)a0] & OAH_F_SEAL_SHRINK))) {
                result = -EPERM;
                break;
            }
        }
        result = host_result(ftruncate((int)a0, (off_t)a1));
        break;
    case 82: case 264: case 316: { /* rename, renameat, renameat2 */
        const char *source = guest_path(img, nr == 82 ? a0 : a1);
        const char *target = guest_path(img, nr == 82 ? a1 : a3);
        int from = nr == 82 ? AT_FDCWD : darwin_dirfd(a0);
        int to = nr == 82 ? AT_FDCWD : darwin_dirfd(a2);
        char mut_s[PATH_MAX], mut_t[PATH_MAX];
        int mr_s = resolve_mut_path(img, source, mut_s, sizeof(mut_s));
        int mr_t = resolve_mut_path(img, target, mut_t, sizeof(mut_t));
        if (!source || !target) {
            result = -EFAULT;
        } else if (mr_s < 0 || mr_t < 0) {
            result = mr_s < 0 ? mr_s : mr_t;
        } else if (nr != 316 || !a4) {
            result = host_result(renameat(from, mr_s ? mut_s : source,
                                          to, mr_t ? mut_t : target));
        } else if (a4 == 1 || a4 == 2) {
            result = host_result(renameatx_np(from, mr_s ? mut_s : source,
                                              to, mr_t ? mut_t : target,
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
        char mut[PATH_MAX];
        int mr = resolve_mut_path(img, path, mut, sizeof(mut));
        result = !path ? -EFAULT : mr < 0 ? mr : flags & ~0x200ull ? -EINVAL :
                 host_result(unlinkat(fd, mr ? mut : path, flags ? AT_REMOVEDIR : 0));
        break;
    }
    case 86: case 265: { /* link, linkat */
        const char *source = guest_path(img, nr == 86 ? a0 : a1);
        const char *target = guest_path(img, nr == 86 ? a1 : a3);
        int from = nr == 86 ? AT_FDCWD : darwin_dirfd(a0);
        int to = nr == 86 ? AT_FDCWD : darwin_dirfd(a2);
        u64 flags = nr == 86 ? 0 : a4;
        char mut_s[PATH_MAX], mut_t[PATH_MAX];
        int mr_s = resolve_mut_path(img, source, mut_s, sizeof(mut_s));
        int mr_t = resolve_mut_path(img, target, mut_t, sizeof(mut_t));
        /* Source resolved into the sysroot but lives only on the host:
         * copy it up so the link doesn't dangle (dpkg backup links). */
        if (mr_s > 0 && source && source[0] == '/') {
            struct stat st;
            if (lstat(mut_s, &st) < 0 && lstat(source, &st) == 0) {
                copy_up(source, mut_s);
            }
        }
        result = !source || !target ? -EFAULT : mr_s < 0 || mr_t < 0 ?
                 (mr_s < 0 ? mr_s : mr_t) : flags & ~0x400ull ? -EINVAL :
                 host_result(linkat(from, mr_s ? mut_s : source,
                                    to, mr_t ? mut_t : target,
                                    flags ? AT_SYMLINK_FOLLOW : 0));
        break;
    }
    case 88: case 266: { /* symlink, symlinkat */
        const char *source = guest_path(img, a0);
        const char *target = guest_path(img, nr == 88 ? a1 : a2);
        int fd = nr == 88 ? AT_FDCWD : darwin_dirfd(a1);
        char mut[PATH_MAX];
        int mr = resolve_mut_path(img, target, mut, sizeof(mut));
        /* Store the target verbatim like Linux does. Absolute targets
         * re-anchor inside the sysroot when resolve_in_root follows them;
         * baking host paths in would leak them into guest-visible state
         * and re-anchor under the sysroot as nonexistent paths. */
        result = !source || !target ? -EFAULT : mr < 0 ? mr :
                 host_result(symlinkat(source, fd, mr ? mut : target));
        break;
    }
    case 90: case 268: case 452: { /* chmod, fchmodat, fchmodat2 */
        const char *path = guest_path(img, nr == 90 ? a0 : a1);
        u64 flags = nr == 452 ? a3 : 0;
        int fd = nr == 90 ? AT_FDCWD : darwin_dirfd(a0);
        char mut[PATH_MAX];
        int unit = -1;
        if (path && !strncmp(path, "/dev/pts/", 9) &&
            sscanf(path + 9, "%d", &unit) == 1) {
            snprintf(mut, sizeof(mut), "/dev/ttys%03d", unit);
            path = mut;
        }
        int mr = resolve_mut_path(img, path, mut, sizeof(mut));
        result = !path ? -EFAULT : mr < 0 ? mr : flags & ~0x100ull ? -EINVAL :
                 host_result(fchmodat(fd, mr ? mut : path, (mode_t)(nr == 90 ? a1 : a2),
                                      flags ? AT_SYMLINK_NOFOLLOW : 0));
        break;
    }
    case 91: result = host_result(fchmod((int)a0, (mode_t)a1)); break;
    case 93: { /* fchown */
        char fp[PATH_MAX];
        int orp = guest_root(img)
                  ? owner_record_path(img, (int)a0, "", true, fp, sizeof(fp))
                  : 0;
        result = orp < 0 ? orp : orp ? record_guest_owner(fp, a1, a2, false)
               : a0 < OAH_FD_PATH_MAX &&
                 !strncmp(fd_path[a0], "/dev/ttys", 9) ? 0
                                     : host_result(fchown((int)a0, (uid_t)a1,
                                                          (gid_t)a2));
        break;
    }
    case 95: result = umask((mode_t)a0); break;
    case 188: case 189: { /* setxattr, lsetxattr */
        const char *path = guest_path(img, a0);
        const char *name = a1 ? guest_path(img, a1) : NULL;
        const void *value = a2 ? oah_guest_access(img, a2, a3, PROT_READ) : NULL;
        char rp[PATH_MAX];
        int rr = resolve_read_path(img, path, rp, sizeof(rp), nr != 189);
        result = !path || (a2 && !value) || (a1 && !name) ? -EFAULT :
                 a4 & ~3ull ? -EINVAL :
                 rr < 0 ? rr :
                 host_result(setxattr(rr ? rp : path, name ? name : "",
                                      value, (size_t)a3, 0,
                                      (nr == 189 ? XATTR_NOFOLLOW : 0) |
                                      (a4 == 1 ? XATTR_CREATE :
                                       a4 == 2 ? XATTR_REPLACE : 0)));
        break;
    }
    case 190: /* fsetxattr */
        result = host_result(fsetxattr((int)a0,
                                       (const char *)guest_path(img, a1),
                                       a2 ? oah_guest_access(img, a2, a3,
                                                             PROT_READ) : NULL,
                                       (size_t)a3, 0,
                                       a4 == 1 ? XATTR_CREATE :
                                       a4 == 2 ? XATTR_REPLACE : 0));
        break;
    case 197: case 198: { /* removexattr, lremovexattr */
        const char *path = guest_path(img, a0);
        const char *name = a1 ? guest_path(img, a1) : NULL;
        char rp[PATH_MAX];
        int rr = resolve_read_path(img, path, rp, sizeof(rp), nr != 198);
        result = !path || (a1 && !name) ? -EFAULT :
                 rr < 0 ? rr :
                 host_result(removexattr(rr ? rp : path, name ? name : "",
                                         nr == 198 ? XATTR_NOFOLLOW : 0));
        break;
    }
    case 199: /* fremovexattr */
        result = host_result(fremovexattr((int)a0,
                                          (const char *)guest_path(img, a1),
                                          0));
        break;
    case 191: case 192: case 194: case 195: { /* getxattr, lgetxattr,
                                               listxattr, llistxattr */
        const char *path = guest_path(img, a0);
        char rp[PATH_MAX];
        int rr = resolve_read_path(img, path, rp, sizeof(rp), nr != 192 && nr != 195);
        if (!path || rr < 0) {
            result = !path ? -EFAULT : rr;
            break;
        }
        const char *sp = rr ? rp : path;
        bool list = nr == 194 || nr == 195;
        u64 cap = list ? a1 : a2;
        /* Host buffer: names for listxattr, value for getxattr. */
        size_t capn = cap > 4096 ? 4096 : (size_t)cap;
        u8 *tmp = malloc(capn ? capn : 1);
        ssize_t n;
        u32 opts = (nr == 192 || nr == 195) ? XATTR_NOFOLLOW : 0;
        if (list) {
            n = listxattr(sp, (char *)tmp, capn, opts);
        } else {
            const char *name = guest_path(img, a1);
            if (!name) {
                free(tmp);
                result = -EFAULT;
                break;
            }
            n = getxattr(sp, name, tmp, capn, 0, opts);
        }
        if (n < 0) {
            int e = errno == ENOATTR || errno == ENODATA ? -61 /* ENODATA */
                    : linux_error(errno);
            free(tmp);
            result = e;
            break;
        }
        result = n;
        if (cap) {
            if (n > (ssize_t)cap) {
                result = -34; /* ERANGE */
            } else {
                void *dst = oah_guest_access(img, list ? a1 : a2, (u64)n,
                                             PROT_WRITE);
                if (!dst) {
                    result = -EFAULT;
                } else {
                    memcpy(dst, tmp, (size_t)n);
                }
            }
        }
        free(tmp);
        break;
    }
    case 193: case 196: { /* fgetxattr, flistxattr */
        bool list = nr == 196;
        u64 cap = list ? a1 : a2;
        size_t capn = cap > 4096 ? 4096 : (size_t)cap;
        u8 *tmp = malloc(capn ? capn : 1);
        ssize_t n;
        if (list) {
            n = flistxattr((int)a0, (char *)tmp, capn, 0);
        } else {
            const char *name = guest_path(img, a1);
            if (!name) {
                free(tmp);
                result = -EFAULT;
                break;
            }
            n = fgetxattr((int)a0, name, tmp, capn, 0, 0);
        }
        if (n < 0) {
            int e = errno == ENOATTR || errno == ENODATA ? -61 : linux_error(errno);
            free(tmp);
            result = e;
            break;
        }
        result = n;
        if (cap) {
            if (n > (ssize_t)cap) {
                result = -34;
            } else {
                void *dst = oah_guest_access(img, list ? a1 : a2, (u64)n,
                                             PROT_WRITE);
                if (!dst) {
                    result = -EFAULT;
                } else {
                    memcpy(dst, tmp, (size_t)n);
                }
            }
        }
        free(tmp);
        break;
    }
    case 133: case 259: { /* mknod, mknodat, FIFO only */
        const char *path = guest_path(img, nr == 133 ? a0 : a1);
        mode_t mode = (mode_t)(nr == 133 ? a1 : a2);
        int fd = nr == 133 ? AT_FDCWD : darwin_dirfd(a0);
        char mut[PATH_MAX];
        int mr = resolve_mut_path(img, path, mut, sizeof(mut));
        result = !path ? -EFAULT : mr < 0 ? mr : !S_ISFIFO(mode) ? -LINUX_ENOSYS :
                 host_result(mkfifoat(fd, mr ? mut : path, mode & 07777));
        break;
    }
    case 202: /* futex */
        result = guest_futex(img, a0, a1, (u32)a2, a3, (u32)a5);
        break;
    case 83: case 258: { /* mkdir, mkdirat */
        const char *path = guest_path(img, nr == 83 ? a0 : a1);
        int fd = nr == 83 ? -100 : (int)a0;
        char mut[PATH_MAX];
        int mr = resolve_mut_path(img, path, mut, sizeof(mut));
        result = !path ? -EFAULT : mr < 0 ? mr :
                 host_result(mkdirat(fd == -100 ? AT_FDCWD : fd,
                     mr ? mut : path, (mode_t)(nr == 83 ? a1 : a2)));
        if (getenv("OAH_MKDIR_TRACE")) {
            fprintf(stderr, "mkdir path=%s resolved=%s result=%lld\n",
                    path ? path : "?", mr ? mut : path, (long long)result);
        }
        break;
    }
    case 89: case 267: { /* readlink, readlinkat */
        const char *path = guest_path(img, nr == 89 ? a0 : a1);
        u64 size = nr == 89 ? a2 : a3;
        char *buffer = oah_guest_access(img, nr == 89 ? a1 : a2, size, PROT_WRITE);
        int fd = nr == 89 ? -100 : (int)a0;
        /* Virtual symlink: reports the guest path of the running exe —
         * glibc expands $ORIGIN in RPATHs through it. */
        const char *self_exe = oah_proc_self_exe();
        if (path && self_exe[0] && img->sysroot &&
            (!strcmp(path, "/proc/self/exe") ||
             !strcmp(path, "/proc/thread-self/exe"))) {
            size_t n = strlen(self_exe);
            if (!size || !buffer) {
                result = !size ? -EINVAL : -EFAULT;
            } else {
                if (n > size) { n = size; }
                memcpy(buffer, self_exe, n);
                result = (s64)n;
            }
            break;
        }
        /* Other virtual /proc links: self, thread-self, self/fd/N. */
        if (path) {
            const char *prel;
            char linkbuf[PATH_MAX];
            const char *target = NULL;
            if (!strcmp(path, "/proc/self")) {
                snprintf(linkbuf, sizeof(linkbuf), "%d", (int)getpid());
                target = linkbuf;
            } else if (!strcmp(path, "/proc/thread-self")) {
                snprintf(linkbuf, sizeof(linkbuf), "%d/task/%d",
                         (int)getpid(), (int)getpid());
                target = linkbuf;
            } else if (proc_path_rel(path, &prel) &&
                       !strncmp(prel, "self/fd/", 8)) {
                char *end;
                long fdn = strtol(prel + 8, &end, 10);
                if (end != prel + 8 && !*end && fdn >= 0 &&
                    fdn < OAH_FD_PATH_MAX && fd_path[fdn][0]) {
                    const char *hp = fd_path[fdn];
                    /* Report the guest path: strip the sysroot prefix. */
                    if (img->sysroot) {
                        size_t rl = strlen(img->sysroot);
                        if (!strncmp(hp, img->sysroot, rl) && hp[rl] == '/') {
                            hp += rl;
                        }
                    }
                    int unit = -1;
                    if (!strncmp(hp, "/dev/ttys", 9) &&
                        sscanf(hp + 9, "%d", &unit) == 1) {
                        /* Report pty slaves by their guest /dev/pts name so
                         * ttyname() and chown paths stay in guest terms. */
                        snprintf(linkbuf, sizeof(linkbuf), "/dev/pts/%d", unit);
                    } else {
                        snprintf(linkbuf, sizeof(linkbuf), "%s", hp);
                    }
                    target = linkbuf;
                } else if (end != prel + 8 && !*end && fdn >= 0) {
                    result = -ENOENT;
                    break;
                }
            }
            if (target) {
                size_t n = strlen(target);
                if (!size || !buffer) {
                    result = !size ? -EINVAL : -EFAULT;
                } else {
                    if (n > size) { n = size; }
                    memcpy(buffer, target, n);
                    result = (s64)n;
                }
                break;
            }
        }
        char rp[PATH_MAX];
        int rr = resolve_read_path(img, path, rp, sizeof(rp), false);
        result = rr < 0 ? rr : !size ? -EINVAL : !path || !buffer ? -EFAULT :
                 host_result(readlinkat(fd == -100 ? AT_FDCWD : fd,
                                        rr ? rp : path, buffer, size));
        if (result > 0 && img->sysroot &&
            (size_t)result <= size && (size_t)result < PATH_MAX) {
            size_t rl = strlen(img->sysroot);
            if ((size_t)result > rl &&
                strncmp(buffer, img->sysroot, rl) == 0 && buffer[rl] == '/') {
                memmove(buffer, buffer + rl, (size_t)result - rl);
                result -= (s64)rl;
            }
        }
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
            char mut[PATH_MAX];
            int mr = resolve_mut_path(img, path, mut, sizeof(mut));
            result = mr < 0 ? mr :
                 host_result(path ? utimensat(fd, mr ? mut : path,
                                              input ? times : NULL,
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
        result = getpid();
        break;
    case 186: /* gettid */
        result = g->tid ? g->tid : (u32)getpid();
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
            if (result >= 0) {
                if (!duplicate_readiness_fd((int)a0, (int)result)) {
                    close((int)result);
                    result = -ENOMEM;
                }
            }
            if (result >= 0 && (int)a0 < OAH_FD_PATH_MAX &&
                result < OAH_FD_PATH_MAX) {
                fd_seals[(int)result] = fd_seals[(int)a0];
                fd_is_memfd[(int)result] = fd_is_memfd[(int)a0];
            }
        } else if (a1 == 1033 || a1 == 1034) { /* F_ADD_SEALS, F_GET_SEALS */
            int fdn = (int)a0;
            if (fdn >= 0 && fdn < OAH_FD_PATH_MAX && !fd_is_memfd[fdn]) {
                /* A memfd arriving via SCM_RIGHTS or inherited through
                 * execve is unknown to the table. Darwin shm objects
                 * report S_IFMT == 0 in st_mode — probe for that. */
                struct stat st;
                if (fstat(fdn, &st) == 0 && !(st.st_mode & S_IFMT)) {
                    fd_is_memfd[fdn] = true;
                }
            }
            if (fdn < 0 || fdn >= OAH_FD_PATH_MAX || !fd_is_memfd[fdn]) {
                result = -EINVAL;
            } else if (a1 == 1034) {
                result = fd_seals[fdn];
            } else if (a2 & ~0x1full) {
                result = -EINVAL;
            } else if (fd_seals[fdn] & OAH_F_SEAL_SEAL) {
                result = -EPERM;
            } else {
                fd_seals[fdn] |= (u8)a2;
                result = 0;
            }
            { static int t = -1;
              if (t < 0) { t = getenv("OAH_MFD_TRACE") != NULL; }
              if (t) { fprintf(stderr, "fcntl seal fd=%d cmd=%llu arg=%llx -> %lld\n",
                               fdn, (unsigned long long)a1,
                               (unsigned long long)a2, (long long)result); } }
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
            if (result >= 0 && oah_alsa_owns((int)a0)) {
                oah_alsa_note_flags((int)a0, fcntl((int)a0, F_GETFL));
            }
        } else if (a1 >= 5 && a1 <= 7) { /* F_GETLK, F_SETLK, F_SETLKW */
            struct { int16_t type, whence; int64_t start, len; int32_t pid; } guest_fl;
            const void *input = oah_guest_access(img, a2, sizeof(guest_fl), PROT_READ);
            if (!input) {
                result = -EFAULT;
                break;
            }
            memcpy(&guest_fl, input, sizeof(guest_fl));
            struct flock host_fl = {.l_start = guest_fl.start, .l_len = guest_fl.len,
                                    .l_pid = guest_fl.pid, .l_type = guest_fl.type,
                                    .l_whence = guest_fl.whence};
            int cmd = a1 == 5 ? F_GETLK : a1 == 6 ? F_SETLK : F_SETLKW;
            bool released = a1 == 7 && begin_blocking_call();
            int rc = fcntl((int)a0, cmd, &host_fl);
            if (rc < 0 && getenv("OAH_ALL_TRACE")) {
                int fl = fcntl((int)a0, F_GETFL);
                fprintf(stderr, "fcntl lk dbg: fd=%d cmd=%d rc=%d errno=%d "
                                "getfl=%d type=%d\n",
                        (int)a0, cmd, rc, errno, fl, host_fl.l_type);
            }
            result = host_result(rc);
            finish_blocking_call(released);
            if (result >= 0 && a1 == 5) {
                void *output = oah_guest_access(img, a2, sizeof(guest_fl), PROT_WRITE);
                if (!output) {
                    result = -EFAULT;
                    break;
                }
                guest_fl.type = host_fl.l_type;
                guest_fl.whence = host_fl.l_whence;
                guest_fl.start = host_fl.l_start;
                guest_fl.len = host_fl.l_len;
                guest_fl.pid = host_fl.l_pid;
                memcpy(output, &guest_fl, sizeof(guest_fl));
            }
        } else {
            result = -EINVAL;
        }
        break;
    case 102: result = guest_root(img) ? img->guest_uid[0] : getuid(); break;
    case 104: result = guest_root(img) ? img->guest_gid[0] : getgid(); break;
    case 125: case 126: /* capget, capset */
        result = guest_capability(img, a0, a1, nr == 126);
        break;
    case 107: result = guest_root(img) ? img->guest_uid[1] : geteuid(); break;
    case 108: result = guest_root(img) ? img->guest_gid[1] : getegid(); break;
    case 105: case 106: /* setuid, setgid: root sets all three ids */
        if (!guest_root(img)) {
            result = -LINUX_EOPNOTSUPP;
            break;
        }
        if (nr == 105) {
            img->guest_uid[0] = img->guest_uid[1] = img->guest_uid[2] = (u32)a0;
        } else {
            img->guest_gid[0] = img->guest_gid[1] = img->guest_gid[2] = (u32)a0;
        }
        result = 0;
        break;
    case 113: case 114: /* setreuid, setregid */
        if (!guest_root(img)) {
            result = -LINUX_EOPNOTSUPP;
            break;
        }
        if (nr == 113) {
            if ((u32)a0 != ~0u) img->guest_uid[0] = (u32)a0;
            if ((u32)a1 != ~0u) img->guest_uid[1] = img->guest_uid[2] = (u32)a1;
        } else {
            if ((u32)a0 != ~0u) img->guest_gid[0] = (u32)a0;
            if ((u32)a1 != ~0u) img->guest_gid[1] = img->guest_gid[2] = (u32)a1;
        }
        result = 0;
        break;
    case 117: case 119: /* setresuid, setresgid */
        if (!guest_root(img)) {
            result = -LINUX_EOPNOTSUPP;
            break;
        }
        {
            u32 *ids = nr == 117 ? img->guest_uid : img->guest_gid;
            if ((u32)a0 != ~0u) ids[0] = (u32)a0;
            if ((u32)a1 != ~0u) ids[1] = (u32)a1;
            if ((u32)a2 != ~0u) ids[2] = (u32)a2;
        }
        result = 0;
        break;
    case 116: { /* setgroups */
        if (!guest_root(img)) {
            result = -LINUX_EOPNOTSUPP;
            break;
        }
        int n = (int)a0;
        if (n < 0 || n > 64) {
            result = -EINVAL;
            break;
        }
        if (n) {
            u32 *groups = oah_guest_access(img, a1, (u64)n * 4, PROT_READ);
            if (!groups) {
                result = -EFAULT;
                break;
            }
            memcpy(img->guest_groups, groups, (size_t)n * 4);
        }
        img->guest_ngroups = n;
        result = 0;
        break;
    }
    case 122: case 123: /* setfsuid, setfsgid: report the prior id */
        result = guest_root(img) ?
                 (nr == 122 ? img->guest_uid[1] : img->guest_gid[1]) :
                 -LINUX_EOPNOTSUPP;
        break;
    case 92: case 94: { /* chown, lchown */
        const char *path = guest_path(img, a0);
        char rp[PATH_MAX];
        int orp = !path ? 0 :
                  owner_record_path(img, AT_FDCWD, path, false, rp, sizeof(rp));
        if (!path) {
            result = -EFAULT;
        } else if (!strncmp(path, "/dev/pts/", 9)) {
            result = 0; /* pty slaves belong to the opener; no host node */
        } else if (orp < 0) {
            result = orp;
        } else if (orp > 0 && guest_root(img)) {
            /* Sysroot file: record the requested owner in xattrs so
             * stat reports it and package metadata stays verifiable.
             * lchown records on the link itself. */
            result = record_guest_owner(rp, a1, a2, nr == 94);
        } else {
            result = host_result(nr == 92
                                 ? chown(orp ? rp : path, (uid_t)a1, (gid_t)a2)
                                 : lchown(orp ? rp : path,
                                          (uid_t)a1, (gid_t)a2));
        }
        break;
    }
    case 260: { /* fchownat */
        const char *path = guest_path(img, a1);
        char rp[PATH_MAX];
        int orp = !path ? 0 :
                  owner_record_path(img, darwin_dirfd(a0), path, a4 & 0x1000,
                                    rp, sizeof(rp));
        if (!path) {
            result = -EFAULT;
        } else if (!strncmp(path, "/dev/pts/", 9)) {
            result = 0; /* pty slaves belong to the opener; no host node */
        } else if (a4 & ~0x1100ull) {
            result = -EINVAL;
        } else if (orp < 0) {
            result = orp;
        } else if (orp > 0 && guest_root(img)) {
            result = record_guest_owner(rp, a2, a3, a4 & 0x100);
        } else {
            result = host_result(fchownat(darwin_dirfd(a0),
                                          orp ? rp : path, (uid_t)a2,
                                          (gid_t)a3,
                                          a4 & 0x100 ? AT_SYMLINK_NOFOLLOW : 0));
        }
        break;
    }
    case 115: { /* getgroups */
        int want = (int)a0;
        if (guest_root(img)) {
            result = img->guest_ngroups;
            if (want > 0) {
                gid_t *groups = oah_guest_access(img, a1, (u64)want * 4,
                                                 PROT_WRITE);
                if (!groups) {
                    result = -EFAULT;
                    break;
                }
                int n = want < img->guest_ngroups ? want : img->guest_ngroups;
                memcpy(groups, img->guest_groups, (size_t)n * 4);
            }
            break;
        }
        result = want ? host_result(getgroups(want, oah_guest_access(img, a1, want * 4, PROT_WRITE)))
                      : host_result(getgroups(0, NULL));
        break;
    }
    case OAH_X86_NR_ARCH_PRCTL:
        if (a0 == OAH_ARCH_SET_FS) {
            g->fs_base = a1;
            oah_jit_cache_flush("set-fs");
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
        g->clear_tid = a0;
        result = g->tid ? g->tid : (u32)getpid();
        break;
    case 302: { /* prlimit64 */
        result = guest_prlimit(img, (pid_t)a0, (int)a1, a2, a3);
        break;
    }
    case 97: /* getrlimit */
    case 160: /* setrlimit */ {
        int res = host_rlimit_resource((int)a0);
        void *buf = a1 ? oah_guest_access(img, a1, 16,
                                          nr == 97 ? PROT_WRITE : PROT_READ)
                       : NULL;
        if (a1 && !buf) {
            result = -EFAULT;
        } else if (res < 0) {
            result = -LINUX_ENOSYS;
        } else {
            struct rlimit limit;
            if (nr == 160) {
                u64 values[2];
                memcpy(values, buf, sizeof(values));
                limit.rlim_cur = values[0] == UINT64_MAX ? RLIM_INFINITY : values[0];
                limit.rlim_max = values[1] == UINT64_MAX ? RLIM_INFINITY : values[1];
                result = host_result(setrlimit(res, &limit));
            } else if (getrlimit(res, &limit) != 0) {
                result = linux_error(errno);
            } else {
                const u64 values[2] = {
                    limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX : limit.rlim_cur,
                    limit.rlim_max == RLIM_INFINITY ? UINT64_MAX : limit.rlim_max};
                memcpy(buf, values, sizeof(values));
                result = 0;
            }
        }
        break;
    }
    case 319: { /* memfd_create: anonymous file-backed fd, mmap-able */
        static _Atomic int mfd_seq;
        char shm_name[64];
        snprintf(shm_name, sizeof(shm_name), "/attesor-mfd-%d-%d",
                 getpid(), mfd_seq++);
        int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
        { static int t = -1; if (t < 0) { t = getenv("OAH_MFD_TRACE") != NULL; }
          if (t) { fprintf(stderr, "memfd_create flags=%llx -> fd=%d errno=%d\n",
                           (unsigned long long)a1, fd, fd < 0 ? errno : 0); } }
        if (fd < 0) {
            result = linux_error(errno);
        } else {
            shm_unlink(shm_name);
            if (a1 & 1) { /* MFD_CLOEXEC */
                fcntl(fd, F_SETFD, FD_CLOEXEC);
            }
            if (fd < OAH_FD_PATH_MAX) {
                fd_is_memfd[fd] = true;
                fd_seals[fd] = 0;
            }
            result = fd;
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
    {
        static int all_trace = -1;
        if (all_trace < 0) {
            all_trace = getenv("OAH_ALL_TRACE") != NULL;
        }
        if (all_trace && getenv("OAH_ALL_TRACE_VERBOSE") &&
            nr != 35 && nr != 230 && nr != 202) {
            fprintf(stderr, "  -> %lld\n", (long long)result);
        }
    }
    g->gpr[OAH_X86_RAX] = (u64)result;
    return OAH_SYS_CONTINUE;
}
