/* dsp_darwin.c — Linux OSS /dev/dsp emulation over CoreAudio.
 *
 * Guest programs (SDL 1.2's dsp audio driver, OSS-era games, aplay)
 * open /dev/dsp, negotiate format with SNDCTL_DSP_* ioctls, then
 * write() PCM frames. Each open fd is backed by an AudioQueue: writes
 * stage into a fragment buffer, full buffers are enqueued, and writes
 * throttle while every buffer is in flight so pacing matches a real
 * sound card. */

#if defined(__APPLE__)

#include <AudioToolbox/AudioToolbox.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oah/elf_map.h"
#include "oah/syscall_bridge.h"
#include "oah/types.h"

/* Linux errno values differ from Darwin's above ~32 (e.g. EAGAIN is
 * 35 on macOS but 11 on Linux). Return Linux values to the guest. */
#define LX_EAGAIN 11

/* OSS soundcard.h constants (x86-64 ioctl numbers).
 * SETFMT/SPEED/CHANNELS/STEREO are _SIOWR (0xC004); accept the _SIOR
 * encoding too since some programs use it. */
#define OSS_SPEED       0xC0045002
#define OSS_SPEED_R     0x80045002
#define OSS_STEREO      0xC0045003
#define OSS_STEREO_R    0x80045003
#define OSS_GETBLKSIZE  0x80045004
#define OSS_SETFMT      0xC0045005
#define OSS_SETFMT_R    0x80045005
#define OSS_CHANNELS    0xC0045006
#define OSS_CHANNELS_R  0x80045006
#define OSS_RESET       0x5000
#define OSS_SYNC        0x5001
#define OSS_POST        0x5008
#define OSS_SETFRAGMENT 0xC004500A
#define OSS_GETFMTS     0x8004500B
#define OSS_GETOSPACE   0x800E500C
#define OSS_NONBLOCK    0x500E
#define OSS_GETCAPS     0x8004500F
#define OSS_GETOPTR     0x800E5012
#define OSS_SETDUPLEX   0x5016
#define OSS_GETODELAY   0x80045017

#define AFMT_MU_LAW 0x01
#define AFMT_U8     0x08
#define AFMT_S16_LE 0x10
#define AFMT_S16_BE 0x20
#define AFMT_SUPPORTED (AFMT_MU_LAW | AFMT_U8 | AFMT_S16_LE | AFMT_S16_BE)

#define MAX_DSP 16
#define NBUF 4

typedef struct {
    int fd;
    int fmt, rate, channels;
    unsigned frame;          /* bytes per frame */
    size_t frag;             /* staging target before enqueue */
    u8 *stage;
    size_t stage_len;
    AudioQueueRef queue;
    AudioQueueBufferRef bufs[NBUF];
    int in_flight[NBUF];     /* per-buffer busy flags */
    int n_in_flight;
    int started;
    int nonblock;
    u64 written, played;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} oah_dsp;

static oah_dsp dsp_table[MAX_DSP];
static pthread_mutex_t table_mu = PTHREAD_MUTEX_INITIALIZER;
static bool table_ready;

/* fd < 0 marks a free slot; fd 0 is a valid guest fd (stdin), so the
 * table must be initialized to -1 before first use. */
static void table_init(void)
{
    if (!table_ready) {
        for (int i = 0; i < MAX_DSP; i++) {
            dsp_table[i].fd = -1;
        }
        table_ready = true;
    }
}

static oah_dsp *dsp_for(int fd)
{
    table_init();
    for (int i = 0; i < MAX_DSP; i++) {
        if (dsp_table[i].fd >= 0 && dsp_table[i].fd == fd) {
            return &dsp_table[i];
        }
    }
    return NULL;
}

bool oah_dsp_owns(int fd)
{
    pthread_mutex_lock(&table_mu);
    bool yes = dsp_for(fd) != NULL;
    pthread_mutex_unlock(&table_mu);
    return yes;
}

static void dsp_callback(void *ctx, AudioQueueRef queue, AudioQueueBufferRef buf)
{
    oah_dsp *d = ctx;
    if (pthread_mutex_lock(&d->mu) != 0) {
        return; /* would corrupt state; drop the completion */
    }
    for (int i = 0; i < NBUF; i++) {
        if (d->bufs[i] == buf) {
            d->in_flight[i] = 0;
            break;
        }
    }
    d->n_in_flight--;
    d->played += buf->mAudioDataByteSize;
    if (getenv("OAH_DSP_DEBUG")) {
        fprintf(stderr, "dsp played=%llu inflight=%d\n",
                (unsigned long long)d->played, d->n_in_flight);
    }
    pthread_cond_broadcast(&d->cv);
    pthread_mutex_unlock(&d->mu);
}

static int dsp_start(oah_dsp *d)
{
    if (d->started) {
        return 0;
    }
    AudioStreamBasicDescription fmt = {0};
    unsigned bits = d->fmt == AFMT_U8 || d->fmt == AFMT_MU_LAW ? 8 : 16;
    fmt.mSampleRate = d->rate;
    fmt.mFormatID = d->fmt == AFMT_MU_LAW ? kAudioFormatULaw : kAudioFormatLinearPCM;
    fmt.mFormatFlags =
        (d->fmt == AFMT_S16_BE ? kAudioFormatFlagIsBigEndian : 0) |
        (bits == 16 ? kAudioFormatFlagIsSignedInteger : 0) |
        kAudioFormatFlagIsPacked;
    fmt.mFramesPerPacket = 1;
    fmt.mChannelsPerFrame = (UInt32)d->channels;
    fmt.mBytesPerFrame = fmt.mBytesPerPacket = d->frame;
    fmt.mBitsPerChannel = bits;
    if (AudioQueueNewOutput(&fmt, dsp_callback, d, NULL,
                            NULL, 0, &d->queue) != noErr) {
        return -EIO;
    }
    for (int i = 0; i < NBUF; i++) {
        if (AudioQueueAllocateBuffer(d->queue, (UInt32)d->frag, &d->bufs[i]) != noErr) {
            AudioQueueDispose(d->queue, true);
            d->queue = NULL;
            return -EIO;
        }
    }
    if (AudioQueueStart(d->queue, NULL) != noErr) {
        AudioQueueDispose(d->queue, true);
        d->queue = NULL;
        return -EIO;
    }
    d->started = 1;
    return 0;
}

/* Push staged bytes into queue buffers until stage is drained.
 * Blocks while all buffers are in flight unless nonblock. */
static int dsp_flush(oah_dsp *d)
{
    int rc;
    if ((rc = dsp_start(d)) != 0) {
        return rc;
    }
    while (d->stage_len >= d->frag) {
        int idx = -1;
        pthread_mutex_lock(&d->mu);
        if (d->stage_len < d->frag) {
            pthread_mutex_unlock(&d->mu);
            break;
        }
        for (int i = 0; i < NBUF; i++) {
            if (!d->in_flight[i]) { idx = i; break; }
        }
        if (idx < 0) {
            if (d->nonblock) {
                pthread_mutex_unlock(&d->mu);
                return -LX_EAGAIN;
            }
            /* See alsa_darwin.c: a blocked audio wait must not hold the
             * guest lock while other guest threads are live. */
            bool released = oah_darwin_has_workers();
            if (released) {
                oah_darwin_guest_leave();
            }
            pthread_cond_wait(&d->cv, &d->mu);
            if (released) {
                oah_darwin_guest_enter();
            }
            pthread_mutex_unlock(&d->mu);
            continue;
        }
        memcpy(d->bufs[idx]->mAudioData, d->stage, d->frag);
        d->bufs[idx]->mAudioDataByteSize = (UInt32)d->frag;
        memmove(d->stage, d->stage + d->frag, d->stage_len - d->frag);
        d->stage_len -= d->frag;
        pthread_mutex_unlock(&d->mu);
        /* enqueue with no locks held: AudioQueue may invoke the
         * completion callback on this thread */
        OSStatus st = AudioQueueEnqueueBuffer(d->queue, d->bufs[idx], 0, NULL);
        pthread_mutex_lock(&d->mu);
        if (st == noErr) {
            d->in_flight[idx] = 1;
            d->n_in_flight++;
            pthread_mutex_unlock(&d->mu);
        } else {
            pthread_mutex_unlock(&d->mu);
            return -EIO;
        }
    }
    return 0;
}

int oah_dsp_open(int flags)
{
    /* playback only; capture-open gets ENODEV like a missing card */
    if ((flags & O_ACCMODE) == O_RDONLY) {
        return -ENODEV;
    }
    int fd = open("/dev/null", O_WRONLY | (flags & O_CLOEXEC));
    if (fd < 0) {
        return -errno;
    }
    pthread_mutex_lock(&table_mu);
    table_init();
    int slot = -1;
    for (int i = 0; i < MAX_DSP; i++) {
        if (dsp_table[i].fd < 0) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&table_mu);
        close(fd);
        return -ENOSPC;
    }
    oah_dsp *d = &dsp_table[slot];
    memset(d, 0, sizeof(*d));
    d->fd = fd;
    d->fmt = AFMT_S16_LE;
    d->rate = 22050;
    d->channels = 2;
    d->frame = 4;
    d->frag = 4096;
    d->stage = malloc(d->frag);
    d->nonblock = (flags & O_NONBLOCK) != 0;
    pthread_mutex_init(&d->mu, NULL);
    pthread_cond_init(&d->cv, NULL);
    pthread_mutex_unlock(&table_mu);
    return fd;
}

s64 oah_dsp_write(oah_image *img, int fd, u64 gva, u64 len)
{
    pthread_mutex_lock(&table_mu);
    oah_dsp *d = dsp_for(fd);
    if (!d) {
        pthread_mutex_unlock(&table_mu);
        return -EBADF;
    }
    if (!d->stage) {
        pthread_mutex_unlock(&table_mu);
        return -ENOMEM;
    }
    /* append guest bytes to the staging buffer in chunks */
    u64 done = 0;
    while (done < len) {
        size_t want = d->frag - d->stage_len;
        if (want == 0) {
            int rc = dsp_flush(d);
            if (rc) {
                pthread_mutex_unlock(&table_mu);
                return done ? (s64)done : rc;
            }
            continue;
        }
        if (want > len - done) {
            want = (size_t)(len - done);
        }
        const void *src = oah_guest_access(img, gva + done, want, PROT_READ);
        if (!src) {
            if (getenv("OAH_DSP_DEBUG")) {
                fprintf(stderr, "dsp EFAULT gva=%llx len=%llu want=%zu done=%llu\n",
                        (unsigned long long)gva, (unsigned long long)len,
                        want, (unsigned long long)done);
            }
            pthread_mutex_unlock(&table_mu);
            return done ? (s64)done : -EFAULT;
        }
        memcpy(d->stage + d->stage_len, src, want);
        d->stage_len += want;
        d->written += want;
        done += want;
        int rc = dsp_flush(d);
        if (rc == -LX_EAGAIN) {
            pthread_mutex_unlock(&table_mu);
            return done ? (s64)done : -EAGAIN;
        }
        if (rc) {
            pthread_mutex_unlock(&table_mu);
            return done ? (s64)done : rc;
        }
    }
    pthread_mutex_unlock(&table_mu);
    return (s64)done;
}

int oah_dsp_close(int fd)
{
    pthread_mutex_lock(&table_mu);
    oah_dsp *d = dsp_for(fd);
    if (!d) {
        pthread_mutex_unlock(&table_mu);
        return -1;
    }
    if (d->queue) {
        AudioQueueStop(d->queue, false); /* drain */
        AudioQueueDispose(d->queue, true);
        d->queue = NULL;
    }
    free(d->stage);
    pthread_mutex_destroy(&d->mu);
    pthread_cond_destroy(&d->cv);
    memset(d, 0, sizeof(*d));
    d->fd = -1;
    pthread_mutex_unlock(&table_mu);
    return close(fd);
}

s64 oah_dsp_ioctl(oah_image *img, int fd, u64 req, u64 arg)
{
    pthread_mutex_lock(&table_mu);
    oah_dsp *d = dsp_for(fd);
    if (!d) {
        pthread_mutex_unlock(&table_mu);
        return -ENOTTY;
    }
    int *out = arg ? oah_guest_access(img, arg, 4, PROT_WRITE) : NULL;
    const int *in = arg ? oah_guest_access(img, arg, 4, PROT_READ) : NULL;
    s64 result = 0;
    switch (req) {
    case OSS_GETFMTS:
        if (!out) { result = -EFAULT; break; }
        *out = AFMT_SUPPORTED;
        break;
    case OSS_SETFMT:
    case OSS_SETFMT_R:
        if (!in || !out) { result = -EFAULT; break; }
        d->fmt = (*in & AFMT_SUPPORTED) ? *in : AFMT_S16_LE;
        d->frame = (d->fmt == AFMT_U8 || d->fmt == AFMT_MU_LAW ? 1 : 2)
                   * (unsigned)d->channels;
        *out = d->fmt;
        break;
    case OSS_SPEED:
    case OSS_SPEED_R:
        if (!in || !out) { result = -EFAULT; break; }
        if (*in > 0) { d->rate = *in; }
        *out = d->rate;
        break;
    case OSS_CHANNELS:
    case OSS_CHANNELS_R:
        if (!in || !out) { result = -EFAULT; break; }
        if (*in >= 1 && *in <= 8) { d->channels = *in; }
        d->frame = (d->fmt == AFMT_U8 || d->fmt == AFMT_MU_LAW ? 1 : 2)
                   * (unsigned)d->channels;
        *out = d->channels;
        break;
    case OSS_STEREO:
    case OSS_STEREO_R:
        if (!in || !out) { result = -EFAULT; break; }
        d->channels = *in ? 2 : 1;
        d->frame = (d->fmt == AFMT_U8 || d->fmt == AFMT_MU_LAW ? 1 : 2)
                   * (unsigned)d->channels;
        *out = d->channels - 1;
        break;
    case OSS_SETFRAGMENT:
        if (!in) { result = -EFAULT; break; }
        {
            unsigned shift = *in & 0xffff;
            if (shift < 9) shift = 9;
            if (shift > 16) shift = 16;
            u8 *next = realloc(d->stage, 1u << shift);
            if (!next) { result = -ENOMEM; break; }
            d->stage = next;
            d->frag = 1u << shift;
            d->stage_len = 0;
        }
        break;
    case OSS_GETBLKSIZE:
        if (!out) { result = -EFAULT; break; }
        *out = (int)d->frag;
        break;
    case OSS_GETCAPS:
        if (!out) { result = -EFAULT; break; }
        *out = 0x0001 | 0x0010; /* DSP_CAP_OUTPUT | DSP_CAP_TRIGGER */
        break;
    case OSS_NONBLOCK:
        d->nonblock = 1;
        break;
    case OSS_GETOSPACE: {
        void *info = oah_guest_access(img, arg, 16, PROT_WRITE);
        if (!info) { result = -EFAULT; break; }
        pthread_mutex_lock(&d->mu);
        int free_bufs = NBUF - d->n_in_flight;
        int room = (int)(d->frag - d->stage_len);
        int frags = free_bufs + (room >= (int)d->frag ? 1 : 0);
        int bytes = free_bufs * (int)d->frag + room;
        int total = NBUF + 1;
        memset(info, 0, 16);
        memcpy(info, &frags, 4);
        memcpy((u8 *)info + 4, &total, 4);
        memcpy((u8 *)info + 8, &(int){(int)d->frag}, 4);
        memcpy((u8 *)info + 12, &bytes, 4);
        pthread_mutex_unlock(&d->mu);
        break;
    }
    case OSS_GETODELAY:
        if (!out) { result = -EFAULT; break; }
        pthread_mutex_lock(&d->mu);
        *out = (int)(d->written - d->played);
        pthread_mutex_unlock(&d->mu);
        break;
    case OSS_GETOPTR: {
        void *info = oah_guest_access(img, arg, 16, PROT_WRITE);
        if (!info) { result = -EFAULT; break; }
        pthread_mutex_lock(&d->mu);
        memset(info, 0, 16);
        u64 v = d->written;
        memcpy((u8 *)info + 4, &v, 8); /* count_info.bytes at offset 4 */
        pthread_mutex_unlock(&d->mu);
        break;
    }
    case OSS_RESET:
        pthread_mutex_lock(&d->mu);
        if (d->queue) {
            AudioQueueStop(d->queue, true);
            for (int i = 0; i < NBUF; i++) { d->in_flight[i] = 0; }
            d->n_in_flight = 0;
            d->stage_len = 0;
            AudioQueueStart(d->queue, NULL);
        }
        pthread_mutex_unlock(&d->mu);
        break;
    case OSS_SYNC:
    case OSS_POST:
    case OSS_SETDUPLEX:
        break;
    default:
        result = -ENOTTY;
        break;
    }
    pthread_mutex_unlock(&table_mu);
    return result;
}

#endif /* __APPLE__ */
