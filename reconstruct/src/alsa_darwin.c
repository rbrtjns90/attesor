/* alsa_darwin.c — Linux ALSA dev-snd emulation over CoreAudio.
 *
 * SDL 2.x dropped the OSS driver, so its only usable Linux audio path
 * is libasound: open /dev/snd/pcmC0D0p, negotiate format through the
 * SNDRV_PCM ioctl surface (HW_REFINE/HW_PARAMS/SW_PARAMS), then stream
 * frames via SNDRV_PCM_IOCTL_WRITEI_FRAMES. Control-device ioctls on
 * /dev/snd/controlC0 answer the card/pcm enumeration libasound does
 * while resolving device names.
 *
 * Each playback fd is backed by an AudioQueue like the OSS layer:
 * writei frames stage into a period-sized buffer, full buffers are
 * enqueued, and writes throttle while every buffer is in flight.
 * Only interleaved read/write access is offered (no mmap) so the
 * guest never attempts SYNC_PTR or direct-buffer ioctls. */

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
#include "oah/types.h"

/* Linux errno values that differ from or don't exist on Darwin. */
#define LX_EAGAIN 11
#define LX_EBADFD 77

/* --- ioctl numbers (x86-64: dir<<30 | type<<8 | nr | size<<16) --- */
/* PCM device, type 'A' */
#define ALSA_PCM_PVERSION     0x80044100
#define ALSA_PCM_INFO         0x81204101
#define ALSA_PCM_TSTAMP       0x40044102
#define ALSA_PCM_TTSTAMP      0x40044103
#define ALSA_PCM_USER_PVER    0x40044104
#define ALSA_PCM_HW_REFINE    0xc2604110
#define ALSA_PCM_HW_PARAMS    0xc2604111
#define ALSA_PCM_HW_FREE      0x00004112
#define ALSA_PCM_SW_PARAMS    0xc0884113
#define ALSA_PCM_STATUS       0x80984120
#define ALSA_PCM_DELAY        0x80084121
#define ALSA_PCM_HWSYNC       0x00004122
#define ALSA_PCM_SYNC_PTR     0xc0884123
#define ALSA_PCM_STATUS_EXT   0xc0984124
#define ALSA_PCM_CHANNEL_INFO 0x80184132
#define ALSA_PCM_PREPARE      0x00004140
#define ALSA_PCM_RESET        0x00004141
#define ALSA_PCM_START        0x00004142
#define ALSA_PCM_DROP         0x00004143
#define ALSA_PCM_DRAIN        0x00004144
#define ALSA_PCM_PAUSE        0x40044145
#define ALSA_PCM_REWIND       0x40084146
#define ALSA_PCM_RESUME       0x00004147
#define ALSA_PCM_XRUN         0x00004148
#define ALSA_PCM_FORWARD      0x40084149
#define ALSA_PCM_WRITEI       0x40184150
#define ALSA_PCM_READI        0x80184151
#define ALSA_PCM_WRITEN       0x40184152
#define ALSA_PCM_READN        0x80184153
#define ALSA_PCM_LINK         0x40044160
#define ALSA_PCM_UNLINK       0x00004161
/* Control device, type 'U' */
#define ALSA_CTL_PVERSION     0x80045500
#define ALSA_CTL_CARD_INFO    0x81785501
#define ALSA_CTL_ELEM_LIST    0xc0285510
#define ALSA_CTL_ELEM_INFO    0xc1105511
#define ALSA_CTL_SUBSCRIBE    0x80045516
#define ALSA_CTL_TLV_READ     0xc008551a
#define ALSA_CTL_HWDEP_NEXT   0xc0045520
#define ALSA_CTL_PCM_NEXT     0x80045530
#define ALSA_CTL_PCM_INFO     0xc1205531
#define ALSA_CTL_PCM_PREFER   0x40045532
#define ALSA_CTL_RAWMIDI_NEXT 0xc0045540
#define ALSA_CTL_UMP_NEXT     0xc0045543
#define ALSA_CTL_POWER        0xc00455d0

#define SNDRV_PROTOCOL_VERSION_2_0_15 0x0002000f

/* SNDRV_PCM_ACCESS_* (mask bits) */
#define ALSA_ACC_RW_INTERLEAVED 3
/* SNDRV_PCM_FORMAT_* (mask bits) */
#define ALSA_FMT_S8      0
#define ALSA_FMT_U8      1
#define ALSA_FMT_S16_LE  2
#define ALSA_FMT_S16_BE  3
#define ALSA_FMT_S32_LE  10
#define ALSA_FMT_S32_BE  11
#define ALSA_FMT_FLOAT_LE 14
#define ALSA_FMT_MU_LAW  20
/* SNDRV_PCM_SUBFORMAT_STD */
#define ALSA_SUBFMT_STD  0
/* SNDRV_PCM_STATE_* */
#define ALSA_ST_OPEN     0
#define ALSA_ST_SETUP    1
#define ALSA_ST_PREPARED 2
#define ALSA_ST_RUNNING  3
#define ALSA_ST_XRUN     4
#define ALSA_ST_DRAINING 5
#define ALSA_ST_PAUSED   6
/* SNDRV_PCM_INFO_* capabilities reported to the guest */
#define ALSA_INFO_INTERLEAVED      0x00000100
#define ALSA_INFO_BLOCK_TRANSFER   0x00010000
#define ALSA_INFO_NO_PERIOD_WAKEUP 0x00800000

/* hw_params param indices (offsets into masks[]/intervals[]) */
#define HP_ACCESS        0
#define HP_FORMAT        1
#define HP_SUBFORMAT     2
#define HP_SAMPLE_BITS   0   /* interval idx = param - 8 */
#define HP_FRAME_BITS    1
#define HP_CHANNELS      2
#define HP_RATE          3
#define HP_PERIOD_TIME   4
#define HP_PERIOD_SIZE   5
#define HP_PERIOD_BYTES  6
#define HP_PERIODS       7
#define HP_BUFFER_TIME   8
#define HP_BUFFER_SIZE   9
#define HP_BUFFER_BYTES  10
#define HP_TICK_TIME     11
/* param numbers for rmask/cmask */
#define PARAM_ACCESS       0
#define PARAM_FORMAT       1
#define PARAM_SUBFORMAT    2
#define PARAM_SAMPLE_BITS  8
#define PARAM_FRAME_BITS   9
#define PARAM_CHANNELS     10
#define PARAM_RATE         11
#define PARAM_PERIOD_SIZE  13
#define PARAM_PERIODS      15
#define PARAM_BUFFER_SIZE  17

/* snd_pcm_hw_params byte offsets (608 bytes total) */
#define HPO_MASKS    4     /* 3 x snd_mask(32) */
#define HPO_INTERVALS 260  /* 12 x snd_interval(12): min,max,flags */
#define HPO_RMASK    512
#define HPO_CMASK    516
#define HPO_INFO     520
#define HPO_MSBITS   524
#define HPO_RATE_NUM 528
#define HPO_RATE_DEN 532
#define HPO_FIFO     536
#define HW_PARAMS_SIZE 608

/* snd_interval flag bits (u32 at offset 8) */
#define IV_OPENMIN 1
#define IV_OPENMAX 2
#define IV_INTEGER 4
#define IV_EMPTY   8

#define MAX_ALSA 16
#define NBUF 4

typedef struct {
    int fd;
    int is_ctl;
    /* negotiated setup */
    int fmt;
    unsigned rate, channels, frame;
    u64 period_frames, buffer_frames;
    u64 start_threshold, avail_min;
    int state;
    int nonblock;
    /* AudioQueue output */
    AudioQueueRef queue;
    AudioQueueBufferRef bufs[NBUF];
    int in_flight[NBUF];
    int n_in_flight;
    int started;
    u64 written, played;      /* frames */
    u8 *stage;
    size_t stage_len, frag;   /* frag = period bytes */
    pthread_mutex_t mu;
    pthread_cond_t cv;
} oah_alsa;

static oah_alsa alsa_table[MAX_ALSA];
static pthread_mutex_t table_mu = PTHREAD_MUTEX_INITIALIZER;
static int table_ready;

static void table_init(void)
{
    if (!table_ready) {
        for (int i = 0; i < MAX_ALSA; i++) {
            alsa_table[i].fd = -1;
        }
        table_ready = 1;
    }
}

static oah_alsa *alsa_for(int fd)
{
    for (int i = 0; i < MAX_ALSA; i++) {
        if (alsa_table[i].fd >= 0 && alsa_table[i].fd == fd) {
            return &alsa_table[i];
        }
    }
    return NULL;
}

bool oah_alsa_owns(int fd)
{
    pthread_mutex_lock(&table_mu);
    table_init();
    bool yes = alsa_for(fd) != NULL;
    pthread_mutex_unlock(&table_mu);
    return yes;
}

/* Reflect host-side O_NONBLOCK changes (guest fcntl F_SETFL). */
void oah_alsa_note_flags(int fd, int host_flags)
{
    pthread_mutex_lock(&table_mu);
    oah_alsa *d = alsa_for(fd);
    if (d) {
        d->nonblock = (host_flags & O_NONBLOCK) != 0;
    }
    pthread_mutex_unlock(&table_mu);
}

static int alsa_dbg(void)
{
    static int v = -1;
    if (v < 0) {
        v = getenv("OAH_ALSA_DEBUG") != NULL;
    }
    return v;
}

/* --- AudioQueue plumbing (same model as dsp_darwin) ------------------ */

static void alsa_callback(void *ctx, AudioQueueRef queue, AudioQueueBufferRef buf)
{
    oah_alsa *d = ctx;
    (void)queue;
    pthread_mutex_lock(&d->mu);
    for (int i = 0; i < NBUF; i++) {
        if (d->bufs[i] == buf) {
            d->in_flight[i] = 0;
            d->n_in_flight--;
            d->played += d->frag / d->frame;
            break;
        }
    }
    pthread_cond_signal(&d->cv);
    pthread_mutex_unlock(&d->mu);
    if (alsa_dbg()) {
        fprintf(stderr, "alsa played=%llu inflight=%d\n",
                (unsigned long long)d->played, d->n_in_flight);
    }
}

static int alsa_queue_create(oah_alsa *d)
{
    if (d->queue) {
        return 0;
    }
    AudioStreamBasicDescription fmt = {0};
    unsigned bits;
    fmt.mSampleRate = d->rate;
    fmt.mFramesPerPacket = 1;
    fmt.mChannelsPerFrame = d->channels;
    switch (d->fmt) {
    case ALSA_FMT_MU_LAW:
        bits = 8;
        fmt.mFormatID = kAudioFormatULaw;
        break;
    case ALSA_FMT_FLOAT_LE:
        bits = 32;
        fmt.mFormatID = kAudioFormatLinearPCM;
        fmt.mFormatFlags = kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked;
        break;
    case ALSA_FMT_U8:
        bits = 8;
        fmt.mFormatID = kAudioFormatLinearPCM;
        fmt.mFormatFlags = kAudioFormatFlagIsPacked;
        break;
    case ALSA_FMT_S8:
        bits = 8;
        fmt.mFormatID = kAudioFormatLinearPCM;
        fmt.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
        break;
    case ALSA_FMT_S32_BE:
    case ALSA_FMT_S32_LE:
        bits = 32;
        fmt.mFormatID = kAudioFormatLinearPCM;
        fmt.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked |
            (d->fmt == ALSA_FMT_S32_BE ? kAudioFormatFlagIsBigEndian : 0);
        break;
    case ALSA_FMT_S16_BE:
        bits = 16;
        fmt.mFormatID = kAudioFormatLinearPCM;
        fmt.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsBigEndian |
            kAudioFormatFlagIsPacked;
        break;
    default:
        bits = 16;
        fmt.mFormatID = kAudioFormatLinearPCM;
        fmt.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
        break;
    }
    fmt.mBitsPerChannel = bits;
    fmt.mBytesPerFrame = fmt.mBytesPerPacket = bits / 8 * d->channels;
    if (AudioQueueNewOutput(&fmt, alsa_callback, d, NULL, NULL, 0,
                          &d->queue) != noErr) {
        return -EIO;
    }
    for (int i = 0; i < NBUF; i++) {
        if (AudioQueueAllocateBuffer(d->queue, (UInt32)d->frag,
                                     &d->bufs[i]) != noErr) {
            AudioQueueDispose(d->queue, true);
            d->queue = NULL;
            return -EIO;
        }
    }
    return 0;
}

/* Push staged bytes into queue buffers. Starts the queue once the
 * negotiated start_threshold of queued frames is reached. Blocks
 * while all buffers are in flight unless nonblock. */
static int alsa_flush(oah_alsa *d)
{
    int rc;
    if ((rc = alsa_queue_create(d)) != 0) {
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
            pthread_cond_wait(&d->cv, &d->mu);
            pthread_mutex_unlock(&d->mu);
            continue;
        }
        memcpy(d->bufs[idx]->mAudioData, d->stage, d->frag);
        d->bufs[idx]->mAudioDataByteSize = (UInt32)d->frag;
        memmove(d->stage, d->stage + d->frag, d->stage_len - d->frag);
        d->stage_len -= d->frag;
        pthread_mutex_unlock(&d->mu);
        OSStatus st = AudioQueueEnqueueBuffer(d->queue, d->bufs[idx], 0, NULL);
        pthread_mutex_lock(&d->mu);
        if (st != noErr) {
            pthread_mutex_unlock(&d->mu);
            return -EIO;
        }
        d->in_flight[idx] = 1;
        d->n_in_flight++;
        if (!d->started &&
            (u64)d->n_in_flight * (d->frag / d->frame) >= d->start_threshold) {
            d->started = 1;
            d->state = ALSA_ST_RUNNING;
            OSStatus sst = AudioQueueStart(d->queue, NULL);
            if (alsa_dbg()) {
                fprintf(stderr, "alsa start queued=%llu st=%d\n",
                        (unsigned long long)d->n_in_flight * (d->frag / d->frame),
                        (int)sst);
            }
        }
        pthread_mutex_unlock(&d->mu);
    }
    return 0;
}

static void alsa_reset_counters(oah_alsa *d)
{
    pthread_mutex_lock(&d->mu);
    d->written = d->played = 0;
    d->stage_len = 0;
    d->n_in_flight = 0;
    d->started = 0;
    for (int i = 0; i < NBUF; i++) {
        d->in_flight[i] = 0;
    }
    pthread_mutex_unlock(&d->mu);
}

static int alsa_prepare(oah_alsa *d)
{
    if (d->queue) {
        AudioQueueStop(d->queue, true);
        AudioQueueReset(d->queue);
    }
    alsa_reset_counters(d);
    d->state = ALSA_ST_PREPARED;
    return 0;
}

static int alsa_start(oah_alsa *d)
{
    int rc;
    if ((rc = alsa_queue_create(d)) != 0) {
        return rc;
    }
    pthread_mutex_lock(&d->mu);
    if (!d->started) {
        d->started = 1;
        AudioQueueStart(d->queue, NULL);
    }
    d->state = ALSA_ST_RUNNING;
    pthread_mutex_unlock(&d->mu);
    return 0;
}

static int alsa_drop(oah_alsa *d)
{
    if (d->queue) {
        AudioQueueStop(d->queue, true);
    }
    alsa_reset_counters(d);
    d->state = ALSA_ST_SETUP;
    return 0;
}

static int alsa_drain(oah_alsa *d)
{
    d->state = ALSA_ST_DRAINING;
    pthread_mutex_lock(&d->mu);
    while (d->n_in_flight > 0) {
        pthread_cond_wait(&d->cv, &d->mu);
    }
    pthread_mutex_unlock(&d->mu);
    if (d->queue) {
        AudioQueueStop(d->queue, false);
    }
    d->state = ALSA_ST_SETUP;
    return 0;
}

/* --- open/close ------------------------------------------------------ */

/* Classify /dev/snd names. Returns 1 = playback pcm, 2 = control. */
static int alsa_classify(const char *path)
{
    unsigned card, dev;
    char kind;
    if (sscanf(path, "/dev/snd/pcmC%uD%u%c", &card, &dev, &kind) == 3) {
        if (card != 0 || dev != 0 || kind != 'p') {
            return -1; /* capture and other cards/devices: absent */
        }
        return 1;
    }
    if (strncmp(path, "/dev/snd/controlC", 17) == 0) {
        /* One virtual card: controlC0 only, like a single-card system.
         * libasound probes controlC0..31 during device enumeration;
         * succeeding on all of them makes it scan every phantom card. */
        return path[17] == '0' && path[18] == '\0' ? 2 : -1;
    }
    return -1;
}

int oah_alsa_open(const char *path, int flags)
{
    int kind = alsa_classify(path);
    if (kind < 0) {
        return -ENODEV;
    }
    /* playback only; a capture-open gets ENODEV like a missing card */
    if (kind == 1 && (flags & O_ACCMODE) == O_RDONLY) {
        return -ENODEV;
    }
    int fd = open("/dev/null", O_WRONLY | (flags & O_CLOEXEC));
    if (fd < 0) {
        return -errno;
    }
    pthread_mutex_lock(&table_mu);
    table_init();
    int slot = -1;
    for (int i = 0; i < MAX_ALSA; i++) {
        if (alsa_table[i].fd < 0) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&table_mu);
        close(fd);
        return -ENOSPC;
    }
    oah_alsa *d = &alsa_table[slot];
    memset(d, 0, sizeof(*d));
    d->fd = fd;
    d->is_ctl = (kind == 2);
    d->fmt = ALSA_FMT_S16_LE;
    d->rate = 44100;
    d->channels = 2;
    d->frame = 4;
    d->period_frames = 1024;
    d->buffer_frames = 4096;
    d->start_threshold = 1;
    d->avail_min = 1024;
    d->state = ALSA_ST_OPEN;
    d->frag = 4096;
    d->stage = malloc(d->frag);
    d->nonblock = (flags & O_NONBLOCK) != 0;
    pthread_mutex_init(&d->mu, NULL);
    pthread_cond_init(&d->cv, NULL);
    pthread_mutex_unlock(&table_mu);
    if (alsa_dbg()) {
        fprintf(stderr, "alsa open %s -> fd %d (%s)\n", path, fd,
                kind == 2 ? "ctl" : "pcm");
    }
    return fd;
}

int oah_alsa_close(int fd)
{
    pthread_mutex_lock(&table_mu);
    oah_alsa *d = alsa_for(fd);
    if (!d) {
        pthread_mutex_unlock(&table_mu);
        return -1;
    }
    if (d->queue) {
        AudioQueueStop(d->queue, false);
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

/* --- snd_pcm_hw_params field access (guest memory) -------------------- */

static u32 hp_u32(u8 *p, u32 off)
{
    u32 v;
    memcpy(&v, p + off, 4);
    return v;
}

static void hp_set_u32(u8 *p, u32 off, u32 v)
{
    memcpy(p + off, &v, 4);
}

static void hp_set_u64(u8 *p, u32 off, u64 v)
{
    memcpy(p + off, &v, 8);
}

/* Intersect interval at interval index i with [lo,hi]. Returns -EINVAL
 * if empty. Sets *changed when the constraint was tightened. */
static int hp_refine_interval(u8 *p, int idx, u32 lo, u32 hi, int *changed)
{
    u32 off = HPO_INTERVALS + (u32)idx * 12;
    u32 min = hp_u32(p, off), max = hp_u32(p, off + 4);
    u32 fl = hp_u32(p, off + 8);
    if (fl & IV_EMPTY) {
        return -EINVAL;
    }
    u32 nmin = min > lo ? min : lo;
    u32 nmax = max < hi ? max : hi;
    if (nmin > nmax) {
        hp_set_u32(p, off + 8, fl | IV_EMPTY);
        return -EINVAL;
    }
    if (nmin != min || nmax != max) {
        *changed = 1;
        hp_set_u32(p, off, nmin);
        hp_set_u32(p, off + 4, nmax);
    }
    return 0;
}

/* Intersect mask at mask index i with allowed low-256 bits. */
static int hp_refine_mask(u8 *p, int idx, u32 allow0, int *changed)
{
    u32 off = HPO_MASKS + (u32)idx * 32;
    int empty = 1;
    u32 first = hp_u32(p, off);
    for (int w = 0; w < 8; w++) {
        u32 bits = hp_u32(p, off + (u32)w * 4);
        u32 keep = (w == 0) ? (bits & allow0) : 0;
        if (keep != bits) {
            hp_set_u32(p, off + (u32)w * 4, keep);
            *changed = 1;
        }
        if (keep) {
            empty = 0;
        }
    }
    if (empty) {
        /* kernel leaves the mask all-zero */
        (void)first;
        return -EINVAL;
    }
    return 0;
}

/* Format capabilities: single-word mask of offered formats. */
#define ALSA_FMT_MASK ((1u << ALSA_FMT_S8) | (1u << ALSA_FMT_U8) |      \
                       (1u << ALSA_FMT_S16_LE) | (1u << ALSA_FMT_S16_BE) | \
                       (1u << ALSA_FMT_S32_LE) | (1u << ALSA_FMT_S32_BE) | \
                       (1u << ALSA_FMT_FLOAT_LE) | (1u << ALSA_FMT_MU_LAW))

static unsigned alsa_fmt_bits(int fmt)
{
    switch (fmt) {
    case ALSA_FMT_S8:
    case ALSA_FMT_U8:
    case ALSA_FMT_MU_LAW: return 8;
    case ALSA_FMT_S32_LE:
    case ALSA_FMT_S32_BE:
    case ALSA_FMT_FLOAT_LE: return 32;
    default: return 16;
    }
}

static int alsa_hw_refine(u8 *p)
{
    u32 rmask = hp_u32(p, HPO_RMASK);
    int changed = 0;

    struct {
        int param, idx;
        int is_mask;
        u32 allow, lo, hi;
    } rules[] = {
        {PARAM_ACCESS, HP_ACCESS, 1, 1u << ALSA_ACC_RW_INTERLEAVED, 0, 0},
        {PARAM_FORMAT, HP_FORMAT, 1, ALSA_FMT_MASK, 0, 0},
        {PARAM_SUBFORMAT, HP_SUBFORMAT, 1, 1u << ALSA_SUBFMT_STD, 0, 0},
        {PARAM_SAMPLE_BITS, HP_SAMPLE_BITS, 0, 0, 8, 32},
        {PARAM_FRAME_BITS, HP_FRAME_BITS, 0, 0, 8, 256},
        {PARAM_CHANNELS, HP_CHANNELS, 0, 0, 1, 8},
        {PARAM_RATE, HP_RATE, 0, 0, 4000, 192000},
        {PARAM_PERIOD_SIZE, HP_PERIOD_SIZE, 0, 0, 32, 65536},
        {PARAM_PERIODS, HP_PERIODS, 0, 0, 2, 1024},
        {PARAM_BUFFER_SIZE, HP_BUFFER_SIZE, 0, 0, 64, 262144},
    };
    for (unsigned i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        if (!(rmask & (1u << rules[i].param))) {
            continue;
        }
        int rc = rules[i].is_mask
            ? hp_refine_mask(p, rules[i].idx, rules[i].allow, &changed)
            : hp_refine_interval(p, rules[i].idx, rules[i].lo, rules[i].hi,
                                 &changed);
        if (rc) {
            return rc;
        }
        if (changed) {
            hp_set_u32(p, HPO_CMASK,
                       hp_u32(p, HPO_CMASK) | (1u << rules[i].param));
        }
    }
    hp_set_u32(p, HPO_INFO,
               ALSA_INFO_INTERLEAVED | ALSA_INFO_BLOCK_TRANSFER |
               ALSA_INFO_NO_PERIOD_WAKEUP);
    hp_set_u32(p, HPO_MSBITS, 32);
    hp_set_u32(p, HPO_RATE_NUM, 0);
    hp_set_u32(p, HPO_RATE_DEN, 0);
    hp_set_u64(p, HPO_FIFO, 4096);
    return 0;
}

static int hp_single_mask(u8 *p, int idx)
{
    u32 off = HPO_MASKS + (u32)idx * 32;
    u32 b0 = hp_u32(p, off);
    if (!b0 || (b0 & (b0 - 1))) {
        return -1;
    }
    for (int w = 1; w < 8; w++) {
        if (hp_u32(p, off + (u32)w * 4)) {
            return -1;
        }
    }
    return __builtin_ctz(b0);
}

static int hp_single_interval(u8 *p, int idx, u32 *out)
{
    u32 off = HPO_INTERVALS + (u32)idx * 12;
    u32 min = hp_u32(p, off), max = hp_u32(p, off + 4);
    u32 fl = hp_u32(p, off + 8);
    if ((fl & IV_EMPTY) || min != max) {
        return -1;
    }
    *out = min;
    return 0;
}

static int alsa_hw_params_commit(oah_alsa *d, u8 *p)
{
    int access = hp_single_mask(p, HP_ACCESS);
    int fmt = hp_single_mask(p, HP_FORMAT);
    int sub = hp_single_mask(p, HP_SUBFORMAT);
    u32 channels, rate, period, periods, buf_size;
    if (access != ALSA_ACC_RW_INTERLEAVED || fmt < 0 ||
        !(ALSA_FMT_MASK & (1u << fmt)) || sub != ALSA_SUBFMT_STD ||
        hp_single_interval(p, HP_CHANNELS, &channels) ||
        hp_single_interval(p, HP_RATE, &rate) ||
        hp_single_interval(p, HP_PERIOD_SIZE, &period) ||
        hp_single_interval(p, HP_PERIODS, &periods) ||
        hp_single_interval(p, HP_BUFFER_SIZE, &buf_size) ||
        channels < 1 || channels > 8 || rate < 4000 || rate > 192000 ||
        period < 32 || buf_size < period) {
        return -EINVAL;
    }
    if (buf_size < period * periods) {
        /* ALSA allows buffer_size >= period_size*periods is the common
         * negotiation; accept caller-provided smaller ratios anyway */
    }
    d->fmt = fmt;
    d->rate = rate;
    d->channels = channels;
    d->frame = alsa_fmt_bits(fmt) / 8 * channels;
    d->period_frames = period;
    d->buffer_frames = buf_size;
    d->state = ALSA_ST_SETUP;
    /* AudioQueue buffers sized to one period */
    size_t frag = (size_t)period * d->frame;
    if (frag < 512) {
        frag = 512;
    }
    free(d->stage);
    d->frag = frag;
    d->stage = malloc(d->frag);
    if (!d->stage) {
        return -ENOMEM;
    }
    if (d->queue) {
        AudioQueueDispose(d->queue, true);
        d->queue = NULL;
        alsa_reset_counters(d);
    }
    hp_set_u32(p, HPO_INFO,
               ALSA_INFO_INTERLEAVED | ALSA_INFO_BLOCK_TRANSFER |
               ALSA_INFO_NO_PERIOD_WAKEUP);
    hp_set_u32(p, HPO_MSBITS, alsa_fmt_bits(fmt));
    hp_set_u32(p, HPO_RATE_NUM, rate);
    hp_set_u32(p, HPO_RATE_DEN, 1);
    hp_set_u64(p, HPO_FIFO, buf_size);
    if (alsa_dbg()) {
        fprintf(stderr, "alsa hw_params fmt=%d rate=%u ch=%u period=%u buf=%u\n",
                fmt, rate, channels, period, buf_size);
    }
    return 0;
}

/* --- ioctls ------------------------------------------------------------ */

static int alsa_fill_pcm_info(u8 *out)
{
    memset(out, 0, 288);
    /* device=0, subdevice=0, stream=0(playback), card=0 */
    memcpy(out + 16, "Attesor PCM", 12);
    memcpy(out + 80, "Attesor virtual audio", 22);
    memcpy(out + 160, "subdevice #0", 13);
    hp_set_u32(out, 200, 1); /* subdevices_count */
    hp_set_u32(out, 204, 1); /* subdevices_avail */
    return 0;
}

static s64 alsa_status(oah_image *img, oah_alsa *d, u64 arg)
{
    u8 *out = oah_guest_access(img, arg, 152, PROT_WRITE);
    if (!out) {
        return -EFAULT;
    }
    memset(out, 0, 152);
    pthread_mutex_lock(&d->mu);
    u64 delay = d->written - d->played;
    u64 avail = delay < d->buffer_frames ? d->buffer_frames - delay : 0;
    hp_set_u32(out, 0, (u32)d->state);           /* state */
    hp_set_u64(out, 40, d->written);             /* appl_ptr */
    hp_set_u64(out, 48, d->played);              /* hw_ptr */
    u64 s = delay;
    hp_set_u64(out, 56, s);                      /* delay */
    hp_set_u64(out, 64, avail);                  /* avail */
    hp_set_u64(out, 72, d->buffer_frames);       /* avail_max */
    hp_set_u32(out, 80, (u32)d->state);          /* suspended_state */
    pthread_mutex_unlock(&d->mu);
    return 0;
}

static s64 alsa_writei(oah_image *img, oah_alsa *d, u64 arg)
{
    struct {
        s64 result;
        u64 buf;
        u64 frames;
    } x;
    const void *xp = oah_guest_access(img, arg, sizeof(x), PROT_READ);
    if (!xp) {
        return -EFAULT;
    }
    memcpy(&x, xp, sizeof(x));
    if (!x.frames) {
        goto done0;
    }
    if (alsa_dbg()) {
        static int wr;
        if (++wr < 6 || wr % 100 == 0) {
            fprintf(stderr, "alsa writei #%d frames=%llu state=%d\n",
                    wr, (unsigned long long)x.frames, d->state);
        }
    }
    if (d->state < ALSA_ST_SETUP) {
        return -EIO;
    }
    {
        pthread_mutex_lock(&d->mu);
        u64 delay = d->written - d->played;
        u64 avail = delay < d->buffer_frames ? d->buffer_frames - delay : 0;
        pthread_mutex_unlock(&d->mu);
        if (!avail) {
            if (d->nonblock) {
                x.result = -LX_EAGAIN;
                goto put;
            }
            /* fall through: flush below will block on a free buffer */
            avail = 1;
        }
        u64 frames = x.frames < avail ? x.frames : avail;
        u64 room = (d->frag - d->stage_len) / d->frame;
        if (frames > room) {
            frames = room;
            if (!frames) {
                int rc = alsa_flush(d);
                if (rc) {
                    x.result = rc;
                    goto put;
                }
                room = (d->frag - d->stage_len) / d->frame;
                frames = x.frames < avail ? x.frames : avail;
                if (frames > room) frames = room;
            }
        }
        u64 want = frames * d->frame;
        const void *src = oah_guest_access(img, x.buf, want, PROT_READ);
        if (!src) {
            return -EFAULT;
        }
        memcpy(d->stage + d->stage_len, src, want);
        d->stage_len += want;
        d->written += frames;
        int rc = alsa_flush(d);
        if (rc == -LX_EAGAIN) {
            x.result = frames ? (s64)frames : -LX_EAGAIN;
        } else if (rc) {
            return frames ? 0 : rc;
        } else {
            x.result = (s64)frames;
        }
        goto put;
    }
done0:
    x.result = 0;
put: {
        void *out = oah_guest_access(img, arg, sizeof(x), PROT_WRITE);
        if (!out) {
            return -EFAULT;
        }
        memcpy(out, &x, sizeof(x));
        return x.result < 0 ? x.result : 0;
    }
}

static s64 alsa_ctl_ioctl(oah_image *img, oah_alsa *d, u64 req, u64 arg)
{
    u8 *out = arg ? oah_guest_access(img, arg, 512, PROT_WRITE) : NULL;
    const int *in = arg ? oah_guest_access(img, arg, 4, PROT_READ) : NULL;
    switch (req) {
    case ALSA_CTL_PVERSION:
        if (!out) return -EFAULT;
        hp_set_u32(out, 0, SNDRV_PROTOCOL_VERSION_2_0_15);
        return 0;
    case ALSA_CTL_CARD_INFO: {
        u8 *ci = oah_guest_access(img, arg, 376, PROT_WRITE);
        if (!ci) return -EFAULT;
        memset(ci, 0, 376);
        memcpy(ci + 8, "Attesor", 8);           /* id[16] at off 8 */
        memcpy(ci + 24, "attesor-alsa", 13);    /* driver[16] at 24 */
        memcpy(ci + 40, "Attesor Audio", 14);   /* name[32] at 40 */
        memcpy(ci + 72, "Attesor virtual sound card", 27); /* longname[80] at 72 */
        memcpy(ci + 168, "Attesor Mixer", 14);  /* mixername[80] at 168 */
        return 0;
    }
    case ALSA_CTL_PCM_NEXT: {
        if (!in || !out) return -EFAULT;
        int dev = *in;
        hp_set_u32(out, 0, dev < 0 ? 0u : 0xffffffffu); /* -1 -> 0, else none */
        return 0;
    }
    case ALSA_CTL_PCM_INFO: {
        u8 *pi = oah_guest_access(img, arg, 288, PROT_WRITE);
        if (!pi) return -EFAULT;
        return alsa_fill_pcm_info(pi);
    }
    case ALSA_CTL_PCM_PREFER:
        return 0;
    case ALSA_CTL_ELEM_LIST:
        /* empty mixer: snd_ctl_elem_list {offset,space,used,count,pids} */
        if (!out) return -EFAULT;
        hp_set_u32(out, 8, 0);  /* used */
        hp_set_u32(out, 12, 0); /* count */
        return 0;
    case ALSA_CTL_SUBSCRIBE:
        if (!out) return -EFAULT;
        hp_set_u32(out, 0, 0);
        return 0;
    case ALSA_CTL_HWDEP_NEXT:
    case ALSA_CTL_RAWMIDI_NEXT:
    case ALSA_CTL_UMP_NEXT:
        if (!out) return -EFAULT;
        hp_set_u32(out, 0, 0xffffffffu);
        return 0;
    case ALSA_CTL_POWER:
        return 0;
    default:
        if (alsa_dbg()) {
            fprintf(stderr, "alsa ctl ioctl %#x unhandled\n", (unsigned)req);
        }
        return -ENOTTY;
    }
}

s64 oah_alsa_ioctl(oah_image *img, int fd, u64 req, u64 arg)
{
    pthread_mutex_lock(&table_mu);
    oah_alsa *d = alsa_for(fd);
    if (!d) {
        pthread_mutex_unlock(&table_mu);
        return -ENOTTY;
    }
    if (d->is_ctl) {
        pthread_mutex_unlock(&table_mu);
        return alsa_ctl_ioctl(img, d, req, arg);
    }
    pthread_mutex_unlock(&table_mu);

    u8 *out = arg ? oah_guest_access(img, arg, 640, PROT_WRITE) : NULL;

    if (alsa_dbg()) {
        struct seen { u32 req; unsigned n; };
        static struct seen seen[48];
        static unsigned nseen;
        for (unsigned i = 0; i <= nseen; i++) {
            if (i == nseen) {
                if (nseen < 48) {
                    seen[nseen++] = (struct seen){(u32)req, 1};
                    fprintf(stderr, "alsa ioctl %#x (new)\n", (unsigned)req);
                }
                break;
            }
            if (seen[i].req == (u32)req) {
                if (++seen[i].n < 4) {
                    fprintf(stderr, "alsa ioctl %#x\n", (unsigned)req);
                }
                break;
            }
        }
    }

    switch (req) {
    case ALSA_PCM_PVERSION:
        if (!out) return -EFAULT;
        hp_set_u32(out, 0, SNDRV_PROTOCOL_VERSION_2_0_15);
        return 0;
    case ALSA_PCM_INFO: {
        u8 *pi = oah_guest_access(img, arg, 288, PROT_WRITE);
        if (!pi) return -EFAULT;
        return alsa_fill_pcm_info(pi);
    }
    case ALSA_PCM_TSTAMP:
    case ALSA_PCM_TTSTAMP:
    case ALSA_PCM_USER_PVER:
    case ALSA_PCM_HWSYNC:
        return 0;
    case ALSA_PCM_HW_REFINE:
    case ALSA_PCM_HW_PARAMS: {
        u8 *p = oah_guest_access(img, arg, HW_PARAMS_SIZE, PROT_READ | PROT_WRITE);
        if (!p) return -EFAULT;
        return req == ALSA_PCM_HW_REFINE ? alsa_hw_refine(p)
                                         : alsa_hw_params_commit(d, p);
    }
    case ALSA_PCM_HW_FREE:
        d->state = ALSA_ST_OPEN;
        return 0;
    case ALSA_PCM_SW_PARAMS: {
        const u8 *sp = oah_guest_access(img, arg, 136, PROT_READ);
        if (!sp) return -EFAULT;
        u64 v;
        memcpy(&v, sp + 16, 8);
        d->avail_min = v;
        memcpy(&v, sp + 32, 8);
        d->start_threshold = v;
        /* The queue can only ever hold NBUF*period frames; a threshold
         * beyond that can never fire and would deadlock playback. */
        u64 cap = (u64)NBUF * d->period_frames;
        if (d->start_threshold > cap) {
            d->start_threshold = cap;
        }
        if (alsa_dbg()) {
            fprintf(stderr, "alsa sw_params avail_min=%llu start_thr=%llu\n",
                    (unsigned long long)d->avail_min,
                    (unsigned long long)d->start_threshold);
        }
        u8 *w = oah_guest_access(img, arg, 136, PROT_WRITE);
        if (w) {
            memset(w + 96, 0, 40); /* proto/reserved tail is output */
        }
        return 0;
    }
    case ALSA_PCM_STATUS:
    case ALSA_PCM_STATUS_EXT:
        return alsa_status(img, d, arg);
    case ALSA_PCM_DELAY: {
        if (!out) return -EFAULT;
        pthread_mutex_lock(&d->mu);
        hp_set_u64(out, 0, d->written - d->played);
        pthread_mutex_unlock(&d->mu);
        return 0;
    }
    case ALSA_PCM_CHANNEL_INFO: {
        u8 *ci = oah_guest_access(img, arg, 24, PROT_WRITE);
        if (!ci) return -EFAULT;
        memset(ci, 0, 24);
        hp_set_u32(ci, 16, 32);   /* first bit */
        hp_set_u32(ci, 20, d->frame * 8); /* step bits */
        return 0;
    }
    case ALSA_PCM_PREPARE:
        return alsa_prepare(d);
    case ALSA_PCM_RESET:
        alsa_reset_counters(d);
        return 0;
    case ALSA_PCM_START:
        return alsa_start(d);
    case ALSA_PCM_DROP:
        return alsa_drop(d);
    case ALSA_PCM_DRAIN:
        return alsa_drain(d);
    case ALSA_PCM_XRUN:
        d->state = ALSA_ST_XRUN;
        return 0;
    case ALSA_PCM_WRITEI:
        return alsa_writei(img, d, arg);
    case ALSA_PCM_READI:
    case ALSA_PCM_WRITEN:
    case ALSA_PCM_READN:
        return -LX_EBADFD;
    case ALSA_PCM_PAUSE:
    case ALSA_PCM_RESUME:
    case ALSA_PCM_REWIND:
    case ALSA_PCM_FORWARD:
    case ALSA_PCM_LINK:
    case ALSA_PCM_UNLINK:
        return -EINVAL;
    case ALSA_PCM_SYNC_PTR: {
        /* struct snd_pcm_sync_ptr (136B): flags@0, s(status 64B)@8,
         * c(control 64B)@72 — mmap_status: state@0, hw_ptr@8,
         * tstamp@16, suspended@32, audio_tstamp@40, delay@56;
         * mmap_control: appl_ptr@0, avail_min@8. Software plugins
         * (plug/dmix) read these to compute avail even without mmap. */
        u8 *sp = oah_guest_access(img, arg, 136, PROT_READ | PROT_WRITE);
        if (!sp) return -EFAULT;
        u32 flags;
        memcpy(&flags, sp, 4);
        if (flags & 0x6) { /* APPL|AVAIL_MIN pushed by the guest */
            u64 v;
            if (flags & 0x2) { /* APPL */
                memcpy(&v, sp + 72, 8);
                d->written = v;
            }
            if (flags & 0x4) { /* AVAIL_MIN */
                memcpy(&v, sp + 80, 8);
                d->avail_min = v;
            }
        }
        pthread_mutex_lock(&d->mu);
        hp_set_u32(sp, 8, (u32)d->state);
        hp_set_u64(sp, 16, d->played);
        hp_set_u64(sp, 64, d->written - d->played);
        hp_set_u64(sp, 72, d->written);
        hp_set_u64(sp, 80, d->avail_min);
        pthread_mutex_unlock(&d->mu);
        return 0;
    }
    default:
        if (alsa_dbg()) {
            fprintf(stderr, "alsa pcm ioctl %#x unhandled\n", (unsigned)req);
        }
        return -ENOTTY;
    }
}

/* poll() readiness for an emulated fd. Real kernel PCM fds block until
 * avail >= avail_min; reporting POLLOUT unconditionally would let the
 * guest busy-spin on the SDL audio thread. events is the requested
 * Linux poll mask; returns the revents mask (same bit values). */
int oah_alsa_poll(int fd, int events)
{
    enum { P_POLLOUT = 0x4, P_POLLWRNORM = 0x100,
           P_POLLERR = 0x8, P_POLLNVAL = 0x20 };
    pthread_mutex_lock(&table_mu);
    oah_alsa *d = alsa_for(fd);
    if (!d) {
        pthread_mutex_unlock(&table_mu);
        return P_POLLNVAL;
    }
    if (d->is_ctl) {
        pthread_mutex_unlock(&table_mu);
        return events & P_POLLOUT ? P_POLLOUT : 0;
    }
    pthread_mutex_unlock(&table_mu);
    if (d->state == ALSA_ST_XRUN) {
        return P_POLLERR;
    }
    pthread_mutex_lock(&d->mu);
    u64 delay = d->written - d->played;
    u64 avail = delay < d->buffer_frames ? d->buffer_frames - delay : 0;
    u64 need = d->avail_min;
    pthread_mutex_unlock(&d->mu);
    if (avail < need) {
        return 0;
    }
    return (events & P_POLLOUT) ? (P_POLLOUT | P_POLLWRNORM)
                              : (P_POLLOUT | P_POLLWRNORM);
}

/* fd write() on a pcm fd takes interleaved frames like writei. */
s64 oah_alsa_write(oah_image *img, int fd, u64 gva, u64 len)
{
    pthread_mutex_lock(&table_mu);
    oah_alsa *d = alsa_for(fd);
    if (!d || d->is_ctl) {
        pthread_mutex_unlock(&table_mu);
        return -EINVAL;
    }
    pthread_mutex_unlock(&table_mu);
    if (d->state < ALSA_ST_SETUP) {
        return -EIO;
    }
    u64 frames = len / d->frame;
    const void *src = oah_guest_access(img, gva, frames * d->frame, PROT_READ);
    if (!src) {
        return -EFAULT;
    }
    u64 done = 0;
    while (done < frames) {
        pthread_mutex_lock(&d->mu);
        u64 delay = d->written - d->played;
        u64 avail = delay < d->buffer_frames ? d->buffer_frames - delay : 0;
        pthread_mutex_unlock(&d->mu);
        if (!avail) {
            if (d->nonblock) {
                return done ? (s64)(done * d->frame) : -LX_EAGAIN;
            }
            int rc = alsa_flush(d);
            if (rc) {
                return done ? (s64)(done * d->frame) : rc;
            }
            continue;
        }
        u64 want = frames - done < avail ? frames - done : avail;
        u64 room = (d->frag - d->stage_len) / d->frame;
        if (want > room) {
            want = room;
            if (!want) {
                int rc = alsa_flush(d);
                if (rc) {
                    return done ? (s64)(done * d->frame) : rc;
                }
                continue;
            }
        }
        memcpy(d->stage + d->stage_len,
               (const u8 *)src + done * d->frame, want * d->frame);
        d->stage_len += want * d->frame;
        d->written += want;
        done += want;
        int rc = alsa_flush(d);
        if (rc && rc != -LX_EAGAIN) {
            return done ? (s64)(done * d->frame) : rc;
        }
    }
    return (s64)(done * d->frame);
}

#endif /* __APPLE__ */
