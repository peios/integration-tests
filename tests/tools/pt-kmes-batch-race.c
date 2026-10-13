/* PEI-485: a real batch producer and a deliberately lagging mmap reader.
 * The reader follows PSPK's saved-tail/re-read protocol. Loss is expected;
 * accepting a torn record after that check is not. No kernel test hooks.
 * x86-64 KMES ABI constants match helpers/kmes.lua and uapi/pkm/kmes.h.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { ATTACH = 1091, EMIT_BATCH = 1092, COUNT = 64, BATCHES = 512,
       META = 8192, HEADER = 77, LIMIT = 65536 };
static const char event_type[] = "PIT_BATCH_RACE";
struct entry {
    uint64_t type;
    uint16_t type_len;
    uint8_t pad0[6];
    uint64_t payload;
    uint32_t payload_len;
    uint8_t pad1[4];
};
_Static_assert(sizeof(struct entry) == 32, "KMES descriptor ABI");
struct shared { atomic_uint ready, done, failed, batches; };

static void fail(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set)) fail("pin CPU");
}

static uint64_t load_pos(const uint8_t *map, unsigned offset)
{
    return __atomic_load_n((const uint64_t *)(map + offset), __ATOMIC_ACQUIRE);
}

static uint32_t u32(const void *p)
{
    uint32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static uint64_t u64(const void *p)
{
    uint64_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static void produce(struct shared *s)
{
    struct entry entries[COUNT] = {0};
    uint8_t payload[COUNT][24581];
    pin(0);
    for (unsigned i = 0; i < COUNT; ++i) {
        /* Different, non-power-of-two strides cross record boundaries
         * on successive wraps; plausible size fields alone cannot pass. */
        unsigned bytes = 16384 + (i % 9) * 1024;
        payload[i][0] = 0xc6; /* MessagePack bin32. */
        payload[i][1] = bytes >> 24;
        payload[i][2] = bytes >> 16;
        payload[i][3] = bytes >> 8;
        payload[i][4] = bytes;
        entries[i].type = (uintptr_t)event_type;
        entries[i].type_len = sizeof(event_type) - 1;
        entries[i].payload = (uintptr_t)payload[i];
        entries[i].payload_len = bytes + 5;
    }
    while (!atomic_load_explicit(&s->ready, memory_order_acquire)) sched_yield();
    for (unsigned batch = 0; batch < BATCHES; ++batch) {
        for (unsigned i = 0; i < COUNT; ++i) {
            uint64_t id = 1 + batch * COUNT + i, inverse = ~id;
            for (unsigned n = 5; n < entries[i].payload_len; n += 16) {
                memcpy(payload[i] + n, &id, 8);
                memcpy(payload[i] + n + 8, &inverse, 8);
            }
        }
        uint32_t emitted = 0;
        if (syscall(EMIT_BATCH, entries, COUNT, &emitted) || emitted != COUNT) {
            fprintf(stderr, "batch %u: errno=%d emitted=%u\n", batch, errno, emitted);
            atomic_store(&s->failed, 1);
            break;
        }
        atomic_fetch_add(&s->batches, 1);
    }
    atomic_store_explicit(&s->done, 1, memory_order_release);
    _exit(0);
}

int main(void)
{
    uint64_t capacity = 0;
    uint8_t copy[LIMIT];
    unsigned long accepted = 0, discarded = 0;
    int status, bad = 0;
    alarm(30);
    pin(1); /* Producer and reader must genuinely execute concurrently. */
    int fd = syscall(ATTACH, 0, &capacity);
    if (fd < 0) fail("attach CPU 0");
    if (capacity < LIMIT || (capacity & (capacity - 1))) return 2;
    uint8_t *map = mmap(NULL, META + capacity * 2, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) fail("map ring");
    struct shared *s = mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) fail("shared state");
    atomic_init(&s->ready, 0);
    atomic_init(&s->done, 0);
    atomic_init(&s->failed, 0);
    atomic_init(&s->batches, 0);
    uint64_t initial_tail = load_pos(map, 72), final_tail;
    pid_t producer = fork();
    if (producer < 0) fail("fork");
    if (!producer) produce(s);
    atomic_store_explicit(&s->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&s->done, memory_order_acquire)) {
        uint64_t write_pos = load_pos(map, 64);
        uint64_t saved_tail = load_pos(map, 72), pos = saved_tail;
        if (pos >= write_pos) continue;
        const uint8_t *record = map + META + (pos & (capacity - 1));
        uint32_t size = u32(record);
        if (size >= HEADER && size <= LIMIT && size <= write_pos - pos)
            memcpy(copy, record, size);
        /* Keep the entire copy before the second tail observation. */
        atomic_thread_fence(memory_order_seq_cst);
        uint64_t tail_after = load_pos(map, 72);
        if (tail_after > saved_tail && pos < tail_after) {
            ++discarded;
            continue;
        }
        if (size < HEADER || size > LIMIT || size > write_pos - pos ||
            u32(copy) != size || u32(copy + 4) > size) {
            fprintf(stderr, "stable-tail invalid header at %llu: size=%u\n",
                    (unsigned long long)pos, size);
            bad = 1;
            break;
        }
        /* Other kernel events may share CPU 0; they are not our payload. */
        if (u32(copy + 4) != HEADER + sizeof(event_type) - 1 ||
            memcmp(copy + HEADER, event_type, sizeof(event_type) - 1)) continue;
        const uint8_t *p = copy + u32(copy + 4);
        unsigned len = size - u32(copy + 4);
        uint32_t bin_len = len >= 5 ? ((uint32_t)p[1] << 24) |
            ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4] : 0;
        if (len < 21 || p[0] != 0xc6 || bin_len != len - 5 || bin_len % 16) {
            fprintf(stderr, "stable-tail invalid payload framing\n");
            bad = 1;
            break;
        }
        uint64_t id = u64(p + 5);
        for (unsigned n = 5; n < len; n += 16) {
            if (!id || id > COUNT * BATCHES || u64(p + n) != id || u64(p + n + 8) != ~id) {
                fprintf(stderr, "stable-tail torn payload id=%llu offset=%u\n",
                        (unsigned long long)id, n);
                bad = 1;
                break;
            }
        }
        if (bad) break;
        ++accepted;
        /* Stay near the oldest surviving record rather than keeping up.
         * Re-attaching consumers may legitimately start at this tail. */
    }
    if (bad) kill(producer, SIGKILL);
    if (waitpid(producer, &status, 0) != producer) fail("wait producer");
    final_tail = load_pos(map, 72);
    unsigned batches = atomic_load(&s->batches);
    printf("batches=%u accepted=%lu discarded=%lu wraps=%llu\n", batches,
           accepted, discarded, (unsigned long long)((final_tail - initial_tail) / capacity));
    return bad || !WIFEXITED(status) || WEXITSTATUS(status) || atomic_load(&s->failed) ||
           batches != BATCHES || accepted < 256 || !discarded ||
           final_tail - initial_tail < capacity * 32;
}
