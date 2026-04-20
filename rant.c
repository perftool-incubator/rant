#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif

#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif

#define DEFAULT_BUCKET_OVERFLOW_NS 100000ULL
#define DEFAULT_BUCKET_SIZE_NS     1000ULL
#define DEFAULT_BUCKET_MAX         ((uint64_t)(DEFAULT_BUCKET_OVERFLOW_NS / DEFAULT_BUCKET_SIZE_NS) + 1)

typedef struct {
    const char *iface;
    const char *ip;
    uint64_t threshold;
    uint64_t log_threshold;
    int threshold_continue;
    int show_histogram;
    const char *log_file;
    uint64_t bucket_overflow;
    uint32_t bucket_size;
    uint64_t duration;
    uint64_t warmup;
    int busy_poll_us;
    int busy_poll_budget;
    int prefer_busy_poll;
    int use_hugepages;
    int enable_trace_marker;
    int enable_snapshot;
    int verbose;
    int enable_pmc;
    int no_tx_ts;
    int no_hw_ts;
} config_t;

uint64_t *histogram = NULL;
uint64_t bucket_max;

size_t overflow_capacity = 500000000;
uint64_t *overflow_samples = NULL;
size_t overflow_samples_bytes = 0;  // Track allocation size for munmap
int using_hugepages_overflow = 0;  // Track if overflow used hugepages

struct record {
    struct timespec hw_tx, hw_rx;
    uint64_t sw_tx, sw_rx;  /* RDTSC cycles — converted to ns at output */
    uint64_t delta;
};

struct Stats {
    uint64_t min;
    uint64_t max;
    uint64_t sum;
    uint64_t count;
    uint64_t min_idx;
    uint64_t max_idx;
};

struct Stats stats = { 0x7FFFFFFFFFFFFFFFLL, 0, 0, 0, 0, 0 };

struct record *log_book = NULL;
size_t log_size = 0;
size_t log_capacity = 0;  // Calculated based on test duration
size_t log_book_bytes = 0;  // Track allocation size for munmap
int using_hugepages = 0;  // Track if hugepages were successfully allocated
int circular_log = 0;  // Circular buffer mode (when --snapshot + --log)
#define SNAPSHOT_LOG_CAPACITY 500000  // ~10 seconds at 50K packets/sec
int verbose = 0;  // Verbose output mode
volatile sig_atomic_t keep_running = 1;

/* Trace marker file descriptor for kernel tracing integration */
int trace_marker_fd = -1;
int tracing_on_fd = -1;
int snapshot_fd = -1;
uint64_t negative_delta_count = 0;

void handle_sig(int sig) {
    keep_running = 0;
}

void get_ts(struct msghdr *msg, struct timespec *hw_ts) {
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
            struct timespec *stamps = (struct timespec *)CMSG_DATA(cmsg);
            if (hw_ts) *hw_ts = stamps[2];  /* RAW_HARDWARE (PHC clock) */
        }
    }
}

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    // __builtin_ia32_rdtsc() is a compiler intrinsic for 'rdtsc'
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

/* RDTSC calibration globals — used to convert cycles to TAI nanoseconds */
uint64_t cycles_per_sec = 0;
uint64_t rdtsc_ref = 0;        /* RDTSC value at anchor point */
uint64_t tai_ref_ns = 0;       /* CLOCK_TAI nanoseconds at anchor point */

void calibrate_rdtsc() {
    struct timespec sleep_time = {1, 0};
    uint64_t start = rdtsc();
    nanosleep(&sleep_time, NULL);
    uint64_t end = rdtsc();
    cycles_per_sec = end - start;

    /* Anchor RDTSC to CLOCK_TAI for log correlation with ftrace (tai clock) and PHC */
    struct timespec tai;
    rdtsc_ref = rdtsc();
    clock_gettime(CLOCK_TAI, &tai);
    tai_ref_ns = (uint64_t)tai.tv_sec * 1000000000ULL + (uint64_t)tai.tv_nsec;
}

/* Convert RDTSC cycles to CLOCK_TAI nanoseconds */
static inline uint64_t rdtsc_to_tai_ns(uint64_t tsc) {
    int64_t delta_cycles = (int64_t)(tsc - rdtsc_ref);
    int64_t delta_ns = delta_cycles * (int64_t)1000000000LL / (int64_t)cycles_per_sec;
    return tai_ref_ns + delta_ns;
}

/* --- Hardware Performance Counter (PMC) support via rdpmc --- */

#define PMC_MAX 3

struct pmc_counter {
    const char *name;
    uint64_t raw_config;
    int fd;
    uint32_t index;  /* rdpmc counter index */
    struct perf_event_mmap_page *page;
};

static int pmc_count = 0;
static struct pmc_counter pmc_counters[PMC_MAX];

/* Default PMC events for Sapphire Rapids */
static struct {
    const char *name;
    uint64_t config;
} pmc_default_events[PMC_MAX] = {
    { "L1d_miss",        0x000008d1 },  /* MEM_LOAD_RETIRED.L1_MISS */
    { "icache_stl",      0x00000480 },  /* ICACHE_DATA.STALLS */
    { "cycles",          0x0000003c },  /* CPU_CLK_UNHALTED.THREAD */
};

static long sys_perf_event_open(struct perf_event_attr *attr, pid_t pid,
                                int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Set up PMC counters for the calling thread. Returns number of active counters. */
static int pmc_setup(void) {
    pmc_count = 0;

    for (int i = 0; i < PMC_MAX; i++) {
        struct perf_event_attr attr = {0};
        attr.type = PERF_TYPE_RAW;
        attr.size = sizeof(attr);
        attr.config = pmc_default_events[i].config;
        attr.disabled = 0;
        attr.exclude_kernel = 0;
        attr.exclude_user = 0;
        attr.pinned = 1;

        int fd = sys_perf_event_open(&attr, 0, -1, -1, 0);
        if (fd < 0) {
            fprintf(stderr, "Warning: Cannot open PMC '%s' (config=0x%"PRIx64"): %s\n",
                    pmc_default_events[i].name, pmc_default_events[i].config,
                    strerror(errno));
            continue;
        }

        struct perf_event_mmap_page *page = mmap(NULL, 4096,
            PROT_READ, MAP_SHARED, fd, 0);
        if (page == MAP_FAILED) {
            fprintf(stderr, "Warning: Cannot mmap PMC '%s': %s\n",
                    pmc_default_events[i].name, strerror(errno));
            close(fd);
            continue;
        }

        if (page->index == 0) {
            fprintf(stderr, "Warning: PMC '%s' has no counter index (rdpmc not available)\n",
                    pmc_default_events[i].name);
            munmap(page, 4096);
            close(fd);
            continue;
        }

        pmc_counters[pmc_count].name = pmc_default_events[i].name;
        pmc_counters[pmc_count].raw_config = pmc_default_events[i].config;
        pmc_counters[pmc_count].fd = fd;
        pmc_counters[pmc_count].index = page->index - 1;
        pmc_counters[pmc_count].page = page;
        pmc_count++;
    }

    return pmc_count;
}

static void pmc_cleanup(void) {
    for (int i = 0; i < pmc_count; i++) {
        if (pmc_counters[i].page)
            munmap(pmc_counters[i].page, 4096);
        if (pmc_counters[i].fd >= 0)
            close(pmc_counters[i].fd);
    }
    pmc_count = 0;
}

/* Read a single PMC — one rdpmc instruction, ~20ns */
static inline uint64_t read_pmc(int idx) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdpmc" : "=a"(lo), "=d"(hi) : "c"(pmc_counters[idx].index));
    return ((uint64_t)hi << 32) | lo;
}

/* Snapshot all active PMC counters into an array */
static inline void pmc_snapshot(uint64_t *vals) {
    for (int i = 0; i < pmc_count; i++)
        vals[i] = read_pmc(i);
}

/* Try to open a tracefs file, checking multiple paths */
static int open_tracefs(const char *filename, int flags) {
    char path[256];
    int fd;

    /* Try instance path first (works even if global buffer is corrupted) */
    snprintf(path, sizeof(path), "/sys/kernel/tracing/instances/rant/%s", filename);
    fd = open(path, flags);
    if (fd >= 0) return fd;

    /* Try global tracefs */
    snprintf(path, sizeof(path), "/sys/kernel/tracing/%s", filename);
    fd = open(path, flags);
    if (fd >= 0) return fd;

    /* Try debugfs */
    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/%s", filename);
    fd = open(path, flags);
    return fd;
}

/* Open trace_marker and tracing_on for kernel tracing integration */
void open_trace_marker() {
    /* Create rant trace instance if it doesn't exist */
    mkdir("/sys/kernel/tracing/instances/rant", 0755);

    trace_marker_fd = open_tracefs("trace_marker", O_WRONLY);
    if (trace_marker_fd < 0) {
        fprintf(stderr, "Warning: Cannot open trace_marker: %s\n", strerror(errno));
        fprintf(stderr, "  Kernel tracing integration disabled.\n");
        fprintf(stderr, "  Try: sudo mount -t tracefs nodev /sys/kernel/tracing\n\n");
    } else if (verbose) {
        fprintf(stderr, "✅ Trace marker enabled\n");
    }

    tracing_on_fd = open_tracefs("tracing_on", O_WRONLY);
    if (tracing_on_fd < 0)
        fprintf(stderr, "Warning: Cannot open tracing_on: %s\n", strerror(errno));
    else
        write(tracing_on_fd, "1", 1);  /* Ensure tracing is on at start */
}

/* Open snapshot file descriptor for ftrace snapshot trigger */
void open_snapshot() {
    snapshot_fd = open_tracefs("snapshot", O_WRONLY);
    if (snapshot_fd < 0) {
        fprintf(stderr, "Warning: Cannot open snapshot: %s\n", strerror(errno));
        fprintf(stderr, "  Allocate snapshot buffer first: echo 1 > /sys/kernel/tracing/instances/rant/snapshot\n");
    } else if (verbose) {
        fprintf(stderr, "✅ Trace snapshot enabled\n");
    }

}

/* Close trace_marker and tracing_on file descriptors */
void close_trace_marker() {
    if (trace_marker_fd >= 0) {
        close(trace_marker_fd);
        trace_marker_fd = -1;
    }
    if (tracing_on_fd >= 0) {
        close(tracing_on_fd);
        tracing_on_fd = -1;
    }
    if (snapshot_fd >= 0) {
        close(snapshot_fd);
        snapshot_fd = -1;
    }
}

/* Write to trace_marker when threshold exceeded */
void write_trace_marker(const char *msg) {
    if (trace_marker_fd >= 0) {
        write(trace_marker_fd, msg, strlen(msg));
    }
}

/* Record sample in the histogram */
void histogram_record(long long delta, config_t cfg) {
    if (delta < 0) delta = 0;
    stats.sum += delta;
    if (delta < stats.min) {
        stats.min_idx = stats.count;
	stats.min = delta;
    }
    if (delta > stats.max) {
	stats.max_idx = stats.count;
	stats.max = delta;
    }
    stats.count++;
    uint32_t bucket_index = (uint32_t) delta / cfg.bucket_size;
    if (bucket_index >= bucket_max) {
        overflow_samples[histogram[bucket_max]]=delta;
	bucket_index = bucket_max;
    }
    histogram[bucket_index]++;
}

int compare_samples(const void *a, const void *b) {
    uint64_t arg1 = *(const uint64_t *)a;
    uint64_t arg2 = *(const uint64_t *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

/* Get Percentile */
uint64_t get_percentile(double percentile, config_t cfg) {
    if (stats.count == 0) return 0;

    /* Calculate the rank we are looking for */
    double target = stats.count * percentile;
    if (target == 0) return stats.min;

    uint64_t running_sum = 0;
    /* Find the bucket that crosses the target */
    for (int i = 0; i < bucket_max; ++i) {
        running_sum += histogram[i];
        if (running_sum >= target) {
            /* Return the avg latency in the *middle* of this bucket */
            return (uint64_t) ((i + 0.5) * cfg.bucket_size / 1e3);
        }
    }

    /* overflow bucket logic (target sample is in the overflow bucket) */
    uint64_t index = target - running_sum - 1;
    if (index < 0) index = 0;
    if (index >= histogram[bucket_max]) index = histogram[bucket_max] - 1;
    qsort(overflow_samples, histogram[bucket_max], sizeof(uint64_t), compare_samples);
    /* Return the exact value recorded from the overflow bucket */
    return (uint64_t) overflow_samples[index] / 1e3;
}

void histogram_summary(config_t cfg)
{
        int last_empty = 0;
        if (stats.count == 0) {
                return;
        }

        printf("Histogram Summary:\n");
        printf("  Samples   :  %lu\n", stats.count);
        printf("  Minimum   :  %.2f us (#%lu)\n",
			(double) (stats.min / 1e3), stats.min_idx);
        printf("  Maximum   :  %.2f us (#%lu)\n",
			(double) (stats.max / 1e3), stats.max_idx);
        printf("  Average   :  %.2f us\n",
			(double) (stats.sum / stats.count) / 1e3);
        printf("  Percentiles (us):\n");
        printf("    50th    :  %lu (Median)\n", get_percentile(0.50, cfg));
        printf("    90th    :  %lu\n", get_percentile(0.90, cfg));
        printf("    95th    :  %lu\n", get_percentile(0.95, cfg));
        printf("    99th    :  %lu\n", get_percentile(0.99, cfg));
        printf("    99.9th  :  %lu\n", get_percentile(0.999, cfg));
        printf("    99.99th :  %lu\n", get_percentile(0.9999, cfg));

        printf("  Buckets (us):\n");
        printf("    %lu-♾️ : %lu (overflows)\n",
               (long long) (cfg.bucket_overflow / 1e3), histogram[bucket_max]);
        printf("    ...\n");
        for (int i = bucket_max-1; i >= 0; i--) {
                if (histogram[i] > 0) {
                        uint32_t bucket_start = (uint32_t) i * cfg.bucket_size / 1e3;
                        uint32_t bucket_end = (uint32_t) (i + 1) * cfg.bucket_size / 1e3;
                        printf("    %lu-%lu: %lu\n",
                                bucket_start, bucket_end, histogram[i]);
                        last_empty = 0;
                }
                else {
                        if (last_empty == 0) {
                                printf("    ...\n");
                        }
                        last_empty = 1;
                }
        }
}

/* Emit: dispatch round trip pkt (client) */
void emit(config_t cfg) {

    /* Socket options including Hardware Timestamping */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (!cfg.no_hw_ts) {
        struct ifreq ifr; strncpy(ifr.ifr_name, cfg.iface, IFNAMSIZ);
        struct hwtstamp_config hw_cfg = { .tx_type = HWTSTAMP_TX_ON, .rx_filter = HWTSTAMP_FILTER_ALL };
        ifr.ifr_data = (char *)&hw_cfg; ioctl(s, SIOCSHWTSTAMP, &ifr);

        int flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
        setsockopt(s, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));
    }

    /* Set busy poll socket options if configured */
    if (cfg.busy_poll_us > 0) {
        if (setsockopt(s, SOL_SOCKET, SO_BUSY_POLL, &cfg.busy_poll_us, sizeof(cfg.busy_poll_us)) < 0) {
            perror("setsockopt SO_BUSY_POLL");
        }
    }
    if (cfg.busy_poll_budget > 0) {
        if (setsockopt(s, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &cfg.busy_poll_budget, sizeof(cfg.busy_poll_budget)) < 0) {
            perror("setsockopt SO_BUSY_POLL_BUDGET");
        }
    }
    if (cfg.prefer_busy_poll) {
        int prefer = 1;
        if (setsockopt(s, SOL_SOCKET, SO_PREFER_BUSY_POLL, &prefer, sizeof(prefer)) < 0) {
            perror("setsockopt SO_PREFER_BUSY_POLL");
        }
    }

    /* Socket addr & port */
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(12345) };
    inet_pton(AF_INET, cfg.ip, &addr.sin_addr);

    /* RX */
    char buf_rx[1];
    char cbuf_rx[256];
    struct pollfd pfd_rx = { .fd = s, .events = POLLIN };
    struct iovec iov_rx;
    iov_rx.iov_base = buf_rx; iov_rx.iov_len = sizeof(buf_rx);
    struct msghdr msg_rx = {0};
    msg_rx.msg_iov = &iov_rx; msg_rx.msg_iovlen = 1;
    msg_rx.msg_control = cbuf_rx;

    /* TX */
    char buf_tx[1];
    char cbuf_tx[256];
    struct pollfd pfd_tx = { .fd = s, .events = POLLPRI };
    struct iovec iov_tx;
    iov_tx.iov_base = buf_tx; iov_tx.iov_len = sizeof(buf_tx);
    struct msghdr msg_tx = {0};
    msg_tx.msg_iov = &iov_tx; msg_tx.msg_iovlen = 1;
    msg_tx.msg_control = cbuf_tx;


    if (verbose)
        fprintf(stderr, "\n⏱️  Calibrating RDTSC...\n");
    calibrate_rdtsc();
    if (verbose)
        fprintf(stderr, "✅ RDTSC: %"PRIu64" cycles/sec, anchored to TAI\n", cycles_per_sec);
    uint64_t start_tsc = rdtsc();
    uint64_t test_start_tsc = start_tsc;
    uint64_t deadline = cfg.duration > 0 ? start_tsc + (cfg.duration * cycles_per_sec): 0;
    uint64_t packet_count = 0;
    struct record warmup_record;  /* Temporary storage for warmup packets */
    struct record *rtt;

    if (verbose && cfg.warmup > 0)
        fprintf(stderr, "\n🔄 Warmup: sending %"PRIu64" packets...\n", cfg.warmup);
    else if (verbose)
        fprintf(stderr, "\n🚀 Test started\n");

    /* RDTSC breakdown checkpoints for client */
    uint64_t tsc_pre_sendto, tsc_sendto, tsc_poll_tx, tsc_errqueue, tsc_pre_poll_rx, tsc_poll_rx, tsc_pre_recvmsg, tsc_recvmsg;

    while (keep_running) {

        /* Start timing when warmup completes, before first test packet */
        if (packet_count == cfg.warmup) {
            test_start_tsc = rdtsc();
            if (trace_marker_fd >= 0) {
                char marker[128];
                struct timespec now;
                clock_gettime(CLOCK_TAI, &now);
                snprintf(marker, sizeof(marker),
                    "RANT_TEST_START emit sys=%ld.%09ld\n",
                    now.tv_sec, now.tv_nsec);
                write_trace_marker(marker);
            }
            if (verbose && cfg.warmup > 0)
                fprintf(stderr, "✅ Warmup complete, test started\n");
        }

        /* Use warmup_record as scratch; log_book write is deferred until after delta is known */
        rtt = &warmup_record;

        /* T1_SW: RDTSC before sendto */
        rtt->sw_tx = rdtsc();
        tsc_pre_sendto = rtt->sw_tx;

        /* Send Ping */
        sendto(s, buf_tx, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
        tsc_sendto = rdtsc();

        if (!cfg.no_hw_ts) {
            /* Wait for TX timestamp (blocks until POLLPRI or signal) */
            msg_tx.msg_controllen = sizeof(cbuf_tx);
            msg_tx.msg_flags = 0;
            poll(&pfd_tx, 1, -1);
            if (!keep_running) break;
            tsc_poll_tx = rdtsc();

            /* Retrieve T1_HW from error queue */
            rtt->hw_tx.tv_sec = 0;
            rtt->hw_tx.tv_nsec = 0;
            recvmsg(s, &msg_tx, MSG_ERRQUEUE);
            tsc_errqueue = rdtsc();
            get_ts(&msg_tx, &rtt->hw_tx);
        } else {
            tsc_poll_tx = tsc_sendto;
            tsc_errqueue = tsc_sendto;
        }

        /* Wait for pong (blocks until POLLIN or signal) */
        msg_rx.msg_controllen = sizeof(cbuf_rx);
        msg_rx.msg_flags = 0;
        tsc_pre_poll_rx = rdtsc();
        poll(&pfd_rx, 1, -1);
        if (!keep_running) break;
        tsc_poll_rx = rdtsc();

        /* Receive Pong — T4_HW from cmsg, T4_SW from RDTSC */
        tsc_pre_recvmsg = rdtsc();
        recvmsg(s, &msg_rx, 0);
        tsc_recvmsg = rdtsc();
        rtt->sw_rx = tsc_recvmsg;
        if (!cfg.no_hw_ts) {
            get_ts(&msg_rx, &rtt->hw_rx);
        }

        if (!cfg.no_hw_ts) {
            /* Calculate Round Trip Time latency: T4_HW - T1_HW */
            int64_t signed_rtt =
                (rtt->hw_rx.tv_sec - rtt->hw_tx.tv_sec) * 1000000000LL +
                (rtt->hw_rx.tv_nsec - rtt->hw_tx.tv_nsec);
            if (signed_rtt < 0) { negative_delta_count++; signed_rtt = 0; }
            rtt->delta = (uint64_t)signed_rtt;
        } else {
            /* RDTSC-only: RTT = T4_SW - T1_SW */
            rtt->delta = (uint64_t)((tsc_recvmsg - tsc_pre_sendto) * 1000000000ULL / cycles_per_sec);
        }

        packet_count++;
        if (packet_count > cfg.warmup) {
            histogram_record(rtt->delta, cfg);

            /* Save to log_book if logging enabled and delta exceeds log_threshold (or no log_threshold set) */
            if (log_book != NULL && (cfg.log_threshold == 0 || rtt->delta > cfg.log_threshold)) {
                if (circular_log) {
                    log_book[log_size % log_capacity] = *rtt;
                } else if (log_size < log_capacity) {
                    log_book[log_size] = *rtt;
                } else if (log_size == log_capacity) {
                    fprintf(stderr, "\nWARNING: Log capacity exceeded (%zu records), further spikes not logged\n", log_capacity);
                }
                log_size++;
            }

            if (cfg.threshold > 0 && rtt->delta > cfg.threshold) {
                printf("Round-Trip latency (%"PRIu64" ns) exceeds threshold (%"PRIu64" ns).\n",
                       rtt->delta, cfg.threshold);
                printf("  T1_HW (NIC tx):  %ld.%09ld\n", rtt->hw_tx.tv_sec, rtt->hw_tx.tv_nsec);
                printf("  T4_HW (NIC rx):  %ld.%09ld\n", rtt->hw_rx.tv_sec, rtt->hw_rx.tv_nsec);
                printf("  T1_SW (RDTSC):   %"PRIu64"\n", rtt->sw_tx);
                printf("  T4_SW (RDTSC):   %"PRIu64"\n", rtt->sw_rx);
                printf("  --- RDTSC breakdown ---\n");
                printf("    sendto syscall:     %"PRIu64" ns\n",
                       (uint64_t)((tsc_sendto - tsc_pre_sendto) * 1000000000ULL / cycles_per_sec));
                printf("    sendto→poll_tx:     %"PRIu64" ns\n",
                       (uint64_t)((tsc_poll_tx - tsc_sendto) * 1000000000ULL / cycles_per_sec));
                printf("    poll_tx→errqueue:   %"PRIu64" ns\n",
                       (uint64_t)((tsc_errqueue - tsc_poll_tx) * 1000000000ULL / cycles_per_sec));
                printf("    errqueue→poll_rx:   %"PRIu64" ns\n",
                       (uint64_t)((tsc_poll_rx - tsc_errqueue) * 1000000000ULL / cycles_per_sec));
                printf("    poll_rx→recvmsg:    %"PRIu64" ns\n",
                       (uint64_t)((tsc_pre_recvmsg - tsc_poll_rx) * 1000000000ULL / cycles_per_sec));
                printf("    recvmsg syscall:    %"PRIu64" ns\n",
                       (uint64_t)((tsc_recvmsg - tsc_pre_recvmsg) * 1000000000ULL / cycles_per_sec));
                printf("    total:              %"PRIu64" ns\n",
                       (uint64_t)((tsc_recvmsg - tsc_pre_sendto) * 1000000000ULL / cycles_per_sec));

                /* Write to trace_marker for kernel tracing correlation */
                if (trace_marker_fd >= 0) {
                    char trace_msg[256];
                    snprintf(trace_msg, sizeof(trace_msg),
                             "rant: RTT threshold exceeded: seq=%"PRIu64" latency=%"PRIu64"ns threshold=%"PRIu64"ns\n",
                             packet_count, rtt->delta, cfg.threshold);
                    write_trace_marker(trace_msg);
                }
                if (snapshot_fd >= 0)
                    write(snapshot_fd, "1", 1);
                if (tracing_on_fd >= 0)
                    write(tracing_on_fd, "0", 1);

                if (!cfg.threshold_continue) {
                    keep_running = 0;
                    break;
                }
            }
        }

        /* check if duration timed out */
        if (cfg.duration > 0 && rdtsc() > deadline)
            break;
    }

    uint64_t duration_cycles = rdtsc() - test_start_tsc;
    printf("Test is complete. Duration: %.2f s\n", (double)duration_cycles / cycles_per_sec);
}

/* Reflect: send back round trip pkt (server) */
void reflect(config_t cfg) {

    /* Socket options including Hardware Timestamping */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (!cfg.no_hw_ts) {
        struct ifreq ifr; strncpy(ifr.ifr_name, cfg.iface, IFNAMSIZ);
        struct hwtstamp_config hw_cfg = {
            .tx_type = cfg.no_tx_ts ? HWTSTAMP_TX_OFF : HWTSTAMP_TX_ON,
            .rx_filter = HWTSTAMP_FILTER_ALL
        };
        ifr.ifr_data = (char *)&hw_cfg; ioctl(s, SIOCSHWTSTAMP, &ifr);

        int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
        if (!cfg.no_tx_ts)
            flags |= SOF_TIMESTAMPING_TX_HARDWARE;
        setsockopt(s, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));
    }

    /* Set busy poll socket options if configured */
    if (cfg.busy_poll_us > 0) {
        if (setsockopt(s, SOL_SOCKET, SO_BUSY_POLL, &cfg.busy_poll_us, sizeof(cfg.busy_poll_us)) < 0) {
            perror("setsockopt SO_BUSY_POLL");
        }
    }
    if (cfg.busy_poll_budget > 0) {
        if (setsockopt(s, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &cfg.busy_poll_budget, sizeof(cfg.busy_poll_budget)) < 0) {
            perror("setsockopt SO_BUSY_POLL_BUDGET");
        }
    }
    if (cfg.prefer_busy_poll) {
        int prefer = 1;
        if (setsockopt(s, SOL_SOCKET, SO_PREFER_BUSY_POLL, &prefer, sizeof(prefer)) < 0) {
            perror("setsockopt SO_PREFER_BUSY_POLL");
        }
    }

    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(12345), .sin_addr.s_addr = INADDR_ANY };
    bind(s, (struct sockaddr *)&addr, sizeof(addr));

    /* RX */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buf_rx[1];
    char cbuf_rx[256];
    struct pollfd pfd_rx = { .fd = s, .events = POLLIN };
    struct iovec iov_rx;
    iov_rx.iov_base = buf_rx; iov_rx.iov_len = sizeof(buf_rx);
    struct msghdr msg_rx = {0};
    msg_rx.msg_name = &client_addr;
    msg_rx.msg_namelen = client_len;
    msg_rx.msg_iov = &iov_rx; msg_rx.msg_iovlen = 1;
    msg_rx.msg_control = cbuf_rx;

    /* TX */
    char buf_tx[1];
    char cbuf_tx[256];
    struct pollfd pfd_tx = { .fd = s, .events = POLLPRI };
    struct iovec iov_tx;
    iov_tx.iov_base = buf_tx; iov_tx.iov_len = sizeof(buf_tx);
    struct msghdr msg_tx = {0};
    msg_tx.msg_iov = &iov_tx; msg_tx.msg_iovlen = 1;
    msg_tx.msg_control = cbuf_tx;

    if (verbose)
        fprintf(stderr, "\n⏱️  Calibrating RDTSC...\n");
    calibrate_rdtsc();
    if (verbose)
        fprintf(stderr, "✅ RDTSC: %"PRIu64" cycles/sec, anchored to TAI\n", cycles_per_sec);

    /* Set up PMC counters if enabled */
    if (cfg.enable_pmc) {
        int n = pmc_setup();
        if (n > 0)
            fprintf(stderr, "✅ PMC: %d counters active (rdpmc)\n", n);
        else
            fprintf(stderr, "Warning: No PMC counters available. Continuing without PMC.\n");
    }

    uint64_t start_tsc = rdtsc();
    uint64_t test_start_tsc = start_tsc;
    uint64_t deadline = cfg.duration > 0 ? start_tsc + (cfg.duration * cycles_per_sec): 0;
    uint64_t packet_count = 0;
    struct record warmup_record;
    struct record *resp;

    if (verbose)
        fprintf(stderr, "\n⏳ Waiting for first packet...\n");

    /* RDTSC checkpoints for spike instrumentation */
    uint64_t tsc_before_poll, tsc_poll, tsc_pre_recvmsg, tsc_recvmsg, tsc_get_ts, tsc_pre_sendto, tsc_sendto, tsc_poll_tx, tsc_errqueue;
    uint64_t tsc_prev_loop_end = 0;  /* When previous iteration finished */

    /* PMC checkpoints for per-syscall counter deltas */
    uint64_t pmc_pre_poll[PMC_MAX], pmc_post_poll[PMC_MAX];
    uint64_t pmc_pre_recvmsg[PMC_MAX], pmc_post_recvmsg[PMC_MAX];
    uint64_t pmc_pre_sendto[PMC_MAX], pmc_post_sendto[PMC_MAX];

    /* Fast-path PMC accumulators for comparison (<20us = fast) */
    uint64_t pmc_fast_poll_sum[PMC_MAX] = {0}, pmc_fast_recvmsg_sum[PMC_MAX] = {0}, pmc_fast_sendto_sum[PMC_MAX] = {0};
    uint64_t pmc_fast_count = 0;

    while (keep_running) {

        /* Use warmup_record as scratch; log_book write is deferred until after delta is known */
        resp = &warmup_record;

        /* Wait for ping (busy-polls via SO_BUSY_POLL, then dequeue) */
        msg_rx.msg_controllen = sizeof(cbuf_rx);
        msg_rx.msg_flags = 0;
        pmc_snapshot(pmc_pre_poll);
        tsc_before_poll = rdtsc();
        poll(&pfd_rx, 1, -1);
        if (!keep_running) break;
        tsc_poll = rdtsc();
        pmc_snapshot(pmc_post_poll);

        /* Receive ping — T2_HW from cmsg, T2_SW from RDTSC */
        pmc_snapshot(pmc_pre_recvmsg);
        tsc_pre_recvmsg = rdtsc();
        recvmsg(s, &msg_rx, 0);
        tsc_recvmsg = rdtsc();
        pmc_snapshot(pmc_post_recvmsg);
        resp->sw_rx = tsc_recvmsg;
        if (!cfg.no_hw_ts)
            get_ts(&msg_rx, &resp->hw_rx);
        tsc_get_ts = rdtsc();

        /* Send pong — T3_SW from RDTSC */
        resp->sw_tx = rdtsc();
        pmc_snapshot(pmc_pre_sendto);
        tsc_pre_sendto = rdtsc();
        sendto(s, buf_tx, 1, 0, (struct sockaddr *)&client_addr, client_len);
        tsc_sendto = rdtsc();
        pmc_snapshot(pmc_post_sendto);

        if (!cfg.no_tx_ts) {
            /* Wait for TX timestamp (blocks until POLLPRI or signal) */
            msg_tx.msg_controllen = sizeof(cbuf_tx);
            msg_tx.msg_flags = 0;
            poll(&pfd_tx, 1, -1);
            if (!keep_running) break;
            tsc_poll_tx = rdtsc();

            /* Retrieve T3_HW from error queue */
            recvmsg(s, &msg_tx, MSG_ERRQUEUE);
            tsc_errqueue = rdtsc();
            get_ts(&msg_tx, &resp->hw_tx);

            /* Calculate response latency: T3_HW - T2_HW */
            int64_t signed_delta =
                (resp->hw_tx.tv_sec - resp->hw_rx.tv_sec) * 1000000000LL +
                (resp->hw_tx.tv_nsec - resp->hw_rx.tv_nsec);
            if (signed_delta < 0) { negative_delta_count++; signed_delta = 0; }
            resp->delta = (uint64_t)signed_delta;
        } else {
            /* No TX timestamp — use RDTSC delta as approximate response time */
            tsc_poll_tx = tsc_sendto;
            tsc_errqueue = tsc_sendto;
            resp->delta = (uint64_t)((tsc_sendto - tsc_pre_recvmsg) * 1000000000ULL / cycles_per_sec);
        }

        packet_count++;

        /* Start timing when warmup completes */
        if (packet_count == cfg.warmup) {
            test_start_tsc = rdtsc();
            if (trace_marker_fd >= 0) {
                char marker[128];
                struct timespec now;
                clock_gettime(CLOCK_TAI, &now);
                snprintf(marker, sizeof(marker),
                    "RANT_TEST_START reflect phc=%ld.%09ld sys=%ld.%09ld\n",
                    resp->hw_rx.tv_sec, resp->hw_rx.tv_nsec,
                    now.tv_sec, now.tv_nsec);
                write_trace_marker(marker);
            }
            if (verbose && cfg.warmup > 0)
                fprintf(stderr, "✅ Warmup complete (%"PRIu64" packets), test started\n", cfg.warmup);
            else if (verbose)
                fprintf(stderr, "🚀 Test started\n");
        }

        if (packet_count <= cfg.warmup)
            continue;

        histogram_record(resp->delta, cfg);

        /* Save to log_book if logging enabled and delta exceeds log_threshold (or no log_threshold set) */
        if (log_book != NULL && (cfg.log_threshold == 0 || resp->delta > cfg.log_threshold)) {
            if (circular_log) {
                log_book[log_size % log_capacity] = *resp;
            } else if (log_size < log_capacity) {
                log_book[log_size] = *resp;
            } else if (log_size == log_capacity) {
                fprintf(stderr, "\nWARNING: Log capacity exceeded (%zu records), further spikes not logged\n", log_capacity);
            }
            log_size++;
        }

        /* Accumulate fast-path PMC stats (delta < 20us) for comparison */
        if (pmc_count > 0 && resp->delta < 20000) {
            for (int i = 0; i < pmc_count; i++) {
                pmc_fast_poll_sum[i] += pmc_post_poll[i] - pmc_pre_poll[i];
                pmc_fast_recvmsg_sum[i] += pmc_post_recvmsg[i] - pmc_pre_recvmsg[i];
                pmc_fast_sendto_sum[i] += pmc_post_sendto[i] - pmc_pre_sendto[i];
            }
            pmc_fast_count++;
        }

        if (cfg.threshold > 0 && resp->delta > cfg.threshold) {
            printf("Response latency (%"PRIu64" ns) exceeds threshold (%"PRIu64" ns).\n",
                   resp->delta, cfg.threshold);
            printf("  T2_HW (NIC rx):  %ld.%09ld\n", resp->hw_rx.tv_sec, resp->hw_rx.tv_nsec);
            if (!cfg.no_tx_ts)
                printf("  T3_HW (NIC tx):  %ld.%09ld\n", resp->hw_tx.tv_sec, resp->hw_tx.tv_nsec);
            printf("  App processing (T3_SW - T2_SW): %"PRIu64" ns\n",
                   (uint64_t)((resp->sw_tx - resp->sw_rx) * 1000000000ULL / cycles_per_sec));
            printf("  --- RDTSC breakdown ---\n");
            if (tsc_prev_loop_end > 0)
                printf("    prev_end→poll_start: %"PRIu64" ns\n",
                       (uint64_t)((tsc_before_poll - tsc_prev_loop_end) * 1000000000ULL / cycles_per_sec));
            printf("    before→poll:        %"PRIu64" ns\n",
                   (uint64_t)((tsc_poll - tsc_before_poll) * 1000000000ULL / cycles_per_sec));
            printf("    poll→pre_recvmsg:   %"PRIu64" ns\n",
                   (uint64_t)((tsc_pre_recvmsg - tsc_poll) * 1000000000ULL / cycles_per_sec));
            printf("    recvmsg syscall:    %"PRIu64" ns\n",
                   (uint64_t)((tsc_recvmsg - tsc_pre_recvmsg) * 1000000000ULL / cycles_per_sec));
            printf("    recvmsg→get_ts:     %"PRIu64" ns\n",
                   (uint64_t)((tsc_get_ts - tsc_recvmsg) * 1000000000ULL / cycles_per_sec));
            printf("    get_ts→pre_sendto:  %"PRIu64" ns\n",
                   (uint64_t)((tsc_pre_sendto - tsc_get_ts) * 1000000000ULL / cycles_per_sec));
            printf("    sendto syscall:     %"PRIu64" ns\n",
                   (uint64_t)((tsc_sendto - tsc_pre_sendto) * 1000000000ULL / cycles_per_sec));
            if (!cfg.no_tx_ts) {
                printf("    sendto→poll_tx:     %"PRIu64" ns\n",
                       (uint64_t)((tsc_poll_tx - tsc_sendto) * 1000000000ULL / cycles_per_sec));
                printf("    poll_tx→errqueue:   %"PRIu64" ns\n",
                       (uint64_t)((tsc_errqueue - tsc_poll_tx) * 1000000000ULL / cycles_per_sec));
            }
            printf("    total:              %"PRIu64" ns\n",
                   (uint64_t)((tsc_errqueue - tsc_before_poll) * 1000000000ULL / cycles_per_sec));

            if (pmc_count > 0) {
                printf("  --- PMC: this spike ---\n");
                printf("    poll() syscall:\n");
                for (int i = 0; i < pmc_count; i++)
                    printf("      %-20s: %"PRIu64"\n", pmc_counters[i].name,
                           pmc_post_poll[i] - pmc_pre_poll[i]);
                printf("    recvmsg() syscall:\n");
                for (int i = 0; i < pmc_count; i++)
                    printf("      %-20s: %"PRIu64"\n", pmc_counters[i].name,
                           pmc_post_recvmsg[i] - pmc_pre_recvmsg[i]);
                printf("    sendto() syscall:\n");
                for (int i = 0; i < pmc_count; i++)
                    printf("      %-20s: %"PRIu64"\n", pmc_counters[i].name,
                           pmc_post_sendto[i] - pmc_pre_sendto[i]);
                if (pmc_fast_count > 0) {
                    printf("  --- PMC: fast-path avg (<20us, %"PRIu64" samples) ---\n", pmc_fast_count);
                    printf("    poll() syscall:\n");
                    for (int i = 0; i < pmc_count; i++)
                        printf("      %-20s: %.1f\n", pmc_counters[i].name,
                               (double)pmc_fast_poll_sum[i] / pmc_fast_count);
                    printf("    recvmsg() syscall:\n");
                    for (int i = 0; i < pmc_count; i++)
                        printf("      %-20s: %.1f\n", pmc_counters[i].name,
                               (double)pmc_fast_recvmsg_sum[i] / pmc_fast_count);
                    printf("    sendto() syscall:\n");
                    for (int i = 0; i < pmc_count; i++)
                        printf("      %-20s: %.1f\n", pmc_counters[i].name,
                               (double)pmc_fast_sendto_sum[i] / pmc_fast_count);
                }
            }

            if (trace_marker_fd >= 0) {
                char trace_msg[256];
                struct timespec now;
                clock_gettime(CLOCK_TAI, &now);
                snprintf(trace_msg, sizeof(trace_msg),
                         "rant: Response threshold exceeded: seq=%"PRIu64" latency=%"PRIu64"ns"
                         " phc=%ld.%09ld sys=%ld.%09ld\n",
                         packet_count, resp->delta,
                         resp->hw_rx.tv_sec, resp->hw_rx.tv_nsec,
                         now.tv_sec, now.tv_nsec);
                write_trace_marker(trace_msg);
            }
            if (snapshot_fd >= 0)
                write(snapshot_fd, "1", 1);
            if (tracing_on_fd >= 0)
                write(tracing_on_fd, "0", 1);

            if (!cfg.threshold_continue) {
                keep_running = 0;
                break;
            }
        }

        tsc_prev_loop_end = rdtsc();

        if (cfg.duration > 0 && tsc_prev_loop_end > deadline)
            break;
    }

    uint64_t duration_cycles = rdtsc() - test_start_tsc;
    printf("Test is complete. Duration: %.2f s\n", (double)duration_cycles / cycles_per_sec);
}


void roundtrip_log(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        int len = fprintf(fp, "%10s %30s %30s %30s %30s %15s\n", "SEQ", "T1_SW", "T1_HW", "T4_HW", "T4_SW", "RTT");
	for (int i = 0; i < len - 1; i++) {
            fputc('-', fp);
        }
        fputc('\n', fp);

        size_t count = (circular_log && log_size > log_capacity) ? log_capacity : log_size;
        size_t start = (circular_log && log_size > log_capacity) ? (log_size % log_capacity) : 0;
        size_t seq_base = (log_size > count) ? (log_size - count) : 0;

        for (size_t n = 0; n < count; n++) {
            size_t i = (start + n) % log_capacity;
            uint64_t sw_tx_ns = rdtsc_to_tai_ns(log_book[i].sw_tx);
            uint64_t sw_rx_ns = rdtsc_to_tai_ns(log_book[i].sw_rx);
            fprintf(fp, "%10zu %20ld.%09ld %20ld.%09ld %20ld.%09ld %20ld.%09ld %15"PRIu64"\n",
                seq_base + n,
                (long)(sw_tx_ns / 1000000000ULL), (long)(sw_tx_ns % 1000000000ULL),
                log_book[i].hw_tx.tv_sec, log_book[i].hw_tx.tv_nsec,
                log_book[i].hw_rx.tv_sec, log_book[i].hw_rx.tv_nsec,
                (long)(sw_rx_ns / 1000000000ULL), (long)(sw_rx_ns % 1000000000ULL),
                log_book[i].delta);
        }
    }
    fclose(fp);
}

void show_stats() {
    printf("\n--- Latency Statistics ---\n");
    printf("MIN: %"PRIu64" ns | MAX: %"PRIu64" ns | AVG: %"PRIu64" ns | Total Samples: %"PRIu64" \n\n",
            stats.count ? stats.min : 0, stats.count ? stats.max : 0, stats.count ? (uint64_t) stats.sum / stats.count : 0, stats.count);
    if (negative_delta_count > 0)
        printf("WARNING: %"PRIu64" negative deltas detected (set to 0). Check PTP clock sync.\n\n", negative_delta_count);
}

void response_log(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        int len = fprintf(fp, "%10s %30s %30s %30s %30s %15s\n", "SEQ", "T2_HW", "T2_SW", "T3_SW", "T3_HW", "RESPONSE");
	for (int i = 0; i < len - 1; i++) {
            fputc('-', fp);
        }
        fputc('\n', fp);

        size_t count = (circular_log && log_size > log_capacity) ? log_capacity : log_size;
        size_t start = (circular_log && log_size > log_capacity) ? (log_size % log_capacity) : 0;
        size_t seq_base = (log_size > count) ? (log_size - count) : 0;

        for (size_t n = 0; n < count; n++) {
            size_t i = (start + n) % log_capacity;
            uint64_t sw_rx_ns = rdtsc_to_tai_ns(log_book[i].sw_rx);
            uint64_t sw_tx_ns = rdtsc_to_tai_ns(log_book[i].sw_tx);
            fprintf(fp, "%10zu %20ld.%09ld %20ld.%09ld %20ld.%09ld %20ld.%09ld %15"PRIu64"\n",
                seq_base + n,
                log_book[i].hw_rx.tv_sec, log_book[i].hw_rx.tv_nsec,
                (long)(sw_rx_ns / 1000000000ULL), (long)(sw_rx_ns % 1000000000ULL),
                (long)(sw_tx_ns / 1000000000ULL), (long)(sw_tx_ns % 1000000000ULL),
                log_book[i].hw_tx.tv_sec, log_book[i].hw_tx.tv_nsec,
                log_book[i].delta);
        }
    }
    fclose(fp);
}

void print_usage(const char *progname) {
    printf("Usage: %s --interface <iface> [OPTIONS]\n\n", progname);
    printf("Required:\n");
    printf("  -i, --interface <iface>       Network interface to use\n\n");
    printf("Optional:\n");
    printf("  -a, --address <ip>            Server IP address (client mode)\n");
    printf("  -t, --threshold <us>          Stop when latency exceeds threshold (microseconds, after warmup)\n");
    printf("  -C, --continue                Continue running after threshold breach (don't stop)\n");
    printf("  -L, --log-threshold <us>      Only log packets exceeding this latency (microseconds)\n");
    printf("  -T, --trace-marker            Enable kernel trace_marker integration (stops tracing on threshold)\n");
    printf("  -S, --snapshot                Take ftrace snapshot on threshold breach.\n");
    printf("                                  With --log: uses circular buffer (~10s, 36MB)\n");
    printf("                                  Trace setup: echo 16384 > /sys/.../instances/rant/buffer_size_kb\n");
    printf("  -d, --duration <sec>          Test duration in seconds\n");
    printf("  -w, --warmup <pkts>           Number of warmup packets to discard\n");
    printf("  -H, --histogram               Show histogram summary\n");
    printf("  -l, --log <file>              Write transaction log to file\n");
    printf("  -o, --overflow <us>           Histogram overflow bucket threshold (default: 100us)\n");
    printf("  -b, --bucket-size <us>        Histogram bucket size (default: 1us)\n");
    printf("  -G, --hugepages               Use hugepages for memory allocation (requires system config)\n");
    printf("  -p, --busy-poll-us <us>       Set SO_BUSY_POLL per-socket timeout (microseconds)\n");
    printf("  -B, --budget <budget>         Set SO_BUSY_POLL_BUDGET (NAPI poll budget)\n");
    printf("  -P, --prefer-busypoll         Set SO_PREFER_BUSY_POLL (prefer busy poll over interrupt)\n");
    printf("  -v, --verbose                 Verbose output (show config, allocation, progress)\n");
    printf("  -M, --pmc                     Enable hardware performance counter (rdpmc) instrumentation\n");
    printf("  -N, --no-tx-ts                Skip TX timestamp retrieval (server only, reduces latency)\n");
    printf("  -R, --no-hw-ts                Disable all HW timestamps, use RDTSC only for T1/T2/T3/T4\n");
    printf("  -h, --help                    Show this help message\n");
}

int main(int argc, char **argv) {
    int opt;
    config_t config = {
        .iface = NULL,
        .ip = NULL,
        .threshold = 0,
        .log_threshold = 0,
        .threshold_continue = 0,
	.show_histogram = 0,
	.log_file = NULL,
	.bucket_overflow = DEFAULT_BUCKET_OVERFLOW_NS,
        .bucket_size = DEFAULT_BUCKET_SIZE_NS,
	.duration =0,
	.warmup = 0,
	.busy_poll_budget = 0,
	.prefer_busy_poll = 0,
	.use_hugepages = 0,
	.enable_trace_marker = 0,
	.enable_snapshot = 0,
	.verbose = 0,
	.enable_pmc = 0
    };
    
    bucket_max = DEFAULT_BUCKET_MAX;

    signal(SIGINT, handle_sig);

    static struct option long_options[] = {
        {"duration",         required_argument, 0, 'd'},
        {"warmup",           required_argument, 0, 'w'},
        {"overflow",         required_argument, 0, 'o'},
        {"bucket-size",      required_argument, 0, 'b'},
        {"interface",        required_argument, 0, 'i'},
        {"address",          required_argument, 0, 'a'},
        {"threshold",        required_argument, 0, 't'},
        {"trace-marker",     no_argument,       0, 'T'},
        {"snapshot",         no_argument,       0, 'S'},
        {"histogram",        no_argument,       0, 'H'},
        {"log",              required_argument, 0, 'l'},
        {"hugepages",        no_argument,       0, 'G'},
        {"budget",           required_argument, 0, 'B'},
        {"prefer-busypoll",  no_argument,       0, 'P'},
        {"verbose",          no_argument,       0, 'v'},
        {"pmc",              no_argument,       0, 'M'},
        {"log-threshold",    required_argument, 0, 'L'},
        {"continue",         no_argument,       0, 'C'},
        {"no-tx-ts",         no_argument,       0, 'N'},
        {"no-hw-ts",         no_argument,       0, 'R'},
        {"busy-poll-us",     required_argument, 0, 'p'},
        {"help",             no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "d:w:o:b:i:a:t:TSHl:GB:PvML:CNp:Rh", long_options, &option_index)) != -1) {
        switch (opt) {
	    case 'd':
		uint64_t duration_sec = atoll(optarg);
		if (duration_sec <= 0) {
                    fprintf(stdout, "Warning: Duration (%"PRIu64" sec) <= 0: "
		                    "fallback to default.\n", duration_sec);
		}
		else {
		    config.duration = duration_sec;
		}
		break;
	    case 'w':
		uint64_t warmup_pkts = atoll(optarg);
		if (warmup_pkts <= 0) {
                    fprintf(stdout, "Warning: Warmup (%"PRIu64" pkts) <= 0: "
		                    "fallback to default.\n", warmup_pkts);
		}
		else {
		    config.warmup = warmup_pkts;
		}
		break;
	    case 'o':
		uint64_t overflow_us = atoll(optarg);
		if (overflow_us <= 0) {
                    fprintf(stdout, "Warning: Bucket overflow (us) <= 0: "
		                    "fallback to default.\n");
		}
		else {
		    config.bucket_overflow = overflow_us * 1000;
                    bucket_max = (uint64_t) config.bucket_overflow / config.bucket_size;
		}
		break;
	    case 'b':
		uint64_t size_us = atoll(optarg);
		if (size_us <= 0) {
                    fprintf(stdout, "Warning: Bucket size (us) <= 0: "
		                    "fallback to default.\n");
		}
		else {
		    config.bucket_size = size_us * 1000;
                    bucket_max = (uint64_t) config.bucket_overflow / config.bucket_size;
		}
		break;
            case 'i':
                config.iface = optarg;
                break;
            case 'a':
                config.ip = optarg;
                break;
            case 't':
                uint64_t threshold = atoll(optarg);
                if (threshold <= 0) {
                    fprintf(stdout, "Warning: Threshold (us) <= 0: "
				    "fallback to default.\n");
                }
		/* Converto us to ns */
		config.threshold = threshold * 1000;
                break;
            case 'T':  // --trace-marker
                config.enable_trace_marker = 1;
                break;
	    case 'S':  // --snapshot
		config.enable_snapshot = 1;
		break;
	    case 'H':
		config.show_histogram = 1;
		break;
	    case 'l':
		config.log_file = optarg;
		break;
	    case 'G':  // --hugepages
		config.use_hugepages = 1;
		break;
	    case 'B':  // --budget
		config.busy_poll_budget = atoi(optarg);
		if (config.busy_poll_budget <= 0) {
		    fprintf(stdout, "Warning: Budget must be > 0, ignoring.\n");
		    config.busy_poll_budget = 0;
		}
		break;
	    case 'P':  // --prefer-busypoll
		config.prefer_busy_poll = 1;
		break;
	    case 'v':  // --verbose
		config.verbose = 1;
		break;
	    case 'M':  // --pmc
		config.enable_pmc = 1;
		break;
	    case 'L':  // --log-threshold
		;
		uint64_t log_thresh_us = atoll(optarg);
		if (log_thresh_us <= 0) {
		    fprintf(stdout, "Warning: Log threshold (us) <= 0: fallback to default.\n");
		} else {
		    config.log_threshold = log_thresh_us * 1000;
		}
		break;
	    case 'C':  // --continue
		config.threshold_continue = 1;
		break;
	    case 'N':  // --no-tx-ts
		config.no_tx_ts = 1;
		break;
	    case 'R':  // --no-hw-ts
		config.no_hw_ts = 1;
		config.no_tx_ts = 1;  /* implies no TX timestamps too */
		break;
	    case 'p':  // --busy-poll-us
		config.busy_poll_us = atoi(optarg);
		break;
	    case 'h':
		print_usage(argv[0]);
		return 0;
            default:
		print_usage(argv[0]);
                return 1;
        }
    }

    if (config.iface == NULL) {
	print_usage(argv[0]);
	return 1;
    }

    /* Set global verbose flag for functions that don't take config */
    verbose = config.verbose;

    /* Snapshot implies trace-marker (needs trace_marker + tracing_on) */
    if (config.enable_snapshot)
        config.enable_trace_marker = 1;

    /* Print test configuration summary */
    if (verbose) {
        fprintf(stderr, "\n📋 Test Configuration\n");
        fprintf(stderr, "  Mode:           %s\n", config.ip ? "Emit (client)" : "Reflect (server)");
        fprintf(stderr, "  Interface:      %s\n", config.iface);
        if (config.ip)
            fprintf(stderr, "  Server address: %s\n", config.ip);
        fprintf(stderr, "  Duration:       %s", config.duration > 0 ? "" : "unlimited (until Ctrl-C");
        if (config.duration > 0)
            fprintf(stderr, "%"PRIu64" seconds", config.duration);
        else
            fprintf(stderr, ")");
        fprintf(stderr, "\n");
        fprintf(stderr, "  Warmup:         %"PRIu64" packets\n", config.warmup);
        if (config.threshold > 0)
            fprintf(stderr, "  Threshold:      %"PRIu64" us (%s)\n", config.threshold / 1000,
                config.threshold_continue ? "continue" : "stop on breach");
        if (config.log_threshold > 0)
            fprintf(stderr, "  Log threshold:  %"PRIu64" us (only log spikes)\n", config.log_threshold / 1000);
        fprintf(stderr, "  Histogram:      %s (overflow: %"PRIu64" us, bucket: %"PRIu32" us)\n",
            config.show_histogram ? "yes" : "no",
            config.bucket_overflow / 1000, config.bucket_size / 1000);
        if (config.log_file)
            fprintf(stderr, "  Log file:       %s\n", config.log_file);
        fprintf(stderr, "  Trace marker:   %s\n", config.enable_trace_marker ? "yes" : "no");
        fprintf(stderr, "  Snapshot:       %s\n", config.enable_snapshot ? "yes" : "no");
        fprintf(stderr, "  Hugepages:      %s\n", config.use_hugepages ? "yes" : "no");
        if (config.busy_poll_budget > 0)
            fprintf(stderr, "  Busy poll:      budget=%d, prefer=%s\n",
                config.busy_poll_budget, config.prefer_busy_poll ? "yes" : "no");
        fprintf(stderr, "  PMC (rdpmc):    %s\n", config.enable_pmc ? "yes" : "no");
        fprintf(stderr, "\n");
    }

    /* Open trace_marker if trace-marker flag is specified */
    if (config.enable_trace_marker) {
        open_trace_marker();
    }

    /* Open snapshot fd if snapshot flag is specified */
    if (config.enable_snapshot) {
        open_snapshot();
    }

    /* Only allocate log_book if --log is specified */
    if (config.log_file == NULL) {
        log_book = NULL;
        log_capacity = 0;
        log_book_bytes = 0;
    } else if (config.enable_snapshot) {
        /* Snapshot mode: circular buffer with ~10 seconds of packets */
        circular_log = 1;
        log_capacity = SNAPSHOT_LOG_CAPACITY;
        log_book_bytes = log_capacity * sizeof(struct record);

        if (verbose)
            fprintf(stderr, "📦 Log: circular buffer %zu records (~10s, %.1f MB)\n",
                log_capacity, log_book_bytes / (1024.0 * 1024.0));

        log_book = calloc(log_capacity, sizeof(struct record));
        if (log_book == NULL) {
            perror("calloc failed");
            return 1;
        }
        using_hugepages = 0;
    } else if (config.log_threshold > 0) {
        /* Log-threshold mode: only spikes are recorded, use small fixed buffer */
        log_capacity = 1000000;  /* 1M spike records — enough for days of testing */
        log_book_bytes = log_capacity * sizeof(struct record);

        if (verbose)
            fprintf(stderr, "📦 Log: spike-only buffer %zu records (%.1f MB, threshold > %"PRIu64" us)\n",
                log_capacity, log_book_bytes / (1024.0 * 1024.0), config.log_threshold / 1000);

        log_book = calloc(log_capacity, sizeof(struct record));
        if (log_book == NULL) {
            perror("calloc failed");
            return 1;
        }
        using_hugepages = 0;
    } else {
        /* Calculate log_capacity based on test duration or default to 1 hour equivalent */
        uint64_t duration_for_capacity;

        if (config.duration > 0) {
            duration_for_capacity = config.duration;
        } else {
            /* Default: 1 hour worth of samples (~25GB with cache alignment) */
            duration_for_capacity = 3600;
        }

        uint64_t expected_samples = duration_for_capacity * 50000;  /* Assume 50k samples/sec */
        log_capacity = (size_t)(expected_samples * 1.15);  /* Add 15% buffer */
        log_book_bytes = log_capacity * sizeof(struct record);

        size_t required_gb = log_book_bytes / (1024ULL * 1024 * 1024);

        if (verbose)
            fprintf(stderr, "📦 Log: allocating for ~%lu seconds: %zu records (%.2f GB)\n",
                duration_for_capacity, log_capacity,
                log_book_bytes / (1024.0 * 1024.0 * 1024.0));

        /* Sanity check: warn if allocation is very large (>256 GB) */
        if (required_gb > 256) {
            fprintf(stderr, "\nWARNING: Allocation size (%zu GB) exceeds 256 GB!\n", required_gb);
            fprintf(stderr, "  This may cause the system to hang or run out of memory.\n");
            fprintf(stderr, "  Consider using -d <seconds> to specify a shorter test duration.\n");
            fprintf(stderr, "  Press Ctrl-C now to abort, or wait 5 seconds to continue...\n\n");
            sleep(5);
        }

        if (config.use_hugepages) {
            /* Try to allocate with hugepages */

            /* Try 2MB hugepages first (21 = log2(2MB)) */
            log_book = mmap(NULL, log_book_bytes,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (21 << MAP_HUGE_SHIFT),
                            -1, 0);

            if (log_book == MAP_FAILED) {
                if (verbose)
                    fprintf(stderr, "  2MB hugepages not available, trying default...\n");

                /* Try default hugepages without size specification */
                log_book = mmap(NULL, log_book_bytes,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                -1, 0);

                if (log_book == MAP_FAILED) {
                    fprintf(stderr, "Warning: Hugepages not available, falling back to calloc\n");

                    /* Fallback to calloc */
                    log_book = calloc(log_capacity, sizeof(struct record));
                    if (log_book == NULL) {
                        perror("calloc failed");
                        return 1;
                    }
                    using_hugepages = 0;
                } else {
                    using_hugepages = 1;
                }
            } else {
                using_hugepages = 1;
            }
            if (verbose && using_hugepages)
                fprintf(stderr, "✅ Log memory: %.2f GB (hugepages)\n",
                        log_book_bytes / (1024.0 * 1024.0 * 1024.0));
        } else {
            /* Default: use regular calloc allocation */
            log_book = calloc(log_capacity, sizeof(struct record));
            if (log_book == NULL) {
                perror("calloc failed");
                return 1;
            }
            using_hugepages = 0;
        }
        if (verbose && !using_hugepages) {
            fprintf(stderr, "✅ Log memory: %.2f GB (calloc)\n",
                    log_book_bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }

    /* [0-bucket_max-1]: buckets, [bucket_max]: overflows */
    histogram = calloc(bucket_max+1, sizeof(uint64_t));
    if (histogram == NULL) return 1;

    /* Allocate overflow_samples (4GB array) */
    overflow_samples_bytes = overflow_capacity * sizeof(uint64_t);

    if (config.use_hugepages) {
        overflow_samples = mmap(NULL, overflow_samples_bytes,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (21 << MAP_HUGE_SHIFT),
                                -1, 0);

        if (overflow_samples == MAP_FAILED) {
            overflow_samples = calloc(overflow_capacity, sizeof(uint64_t));
            if (overflow_samples == NULL) {
                perror("calloc overflow_samples failed");
                return 1;
            }
            using_hugepages_overflow = 0;
        } else {
            using_hugepages_overflow = 1;
        }
    } else {
        overflow_samples = calloc(overflow_capacity, sizeof(uint64_t));
        if (overflow_samples == NULL) {
            perror("calloc overflow_samples failed");
            return 1;
        }
        using_hugepages_overflow = 0;
    }
    if (verbose)
        fprintf(stderr, "✅ Overflow buffer: %.2f GB (%s)\n",
                overflow_samples_bytes / (1024.0 * 1024.0 * 1024.0),
                using_hugepages_overflow ? "hugepages" : "calloc");

    /* Lock all memory pages in RAM to prevent page faults during test */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("mlockall");
        fprintf(stderr, "Warning: Cannot lock memory. May experience page fault delays.\n");
        fprintf(stderr, "Try: ulimit -l unlimited or sudo setcap cap_ipc_lock=+ep %s\n", argv[0]);
    } else if (verbose) {
        fprintf(stderr, "✅ Memory locked (mlockall)\n");
    }

    if (verbose)
        fprintf(stderr, "\n🔧 Setting up %s socket on %s...\n",
            config.ip ? "client" : "server", config.iface);

    /* Reflect (server) */
    if (config.ip == NULL) {
        reflect(config);
	if (config.log_file) {
	    if (verbose)
	        fprintf(stderr, "\n💾 Writing log to %s (%zu records)...\n", config.log_file, log_size);
	    response_log(config.log_file);
	    if (verbose)
	        fprintf(stderr, "✅ Log written\n");
	}
    }
    /* Emit (client) */
    else {
        emit(config);
	if (config.log_file) {
	    if (verbose)
	        fprintf(stderr, "\n💾 Writing log to %s (%zu records)...\n", config.log_file, log_size);
	    roundtrip_log(config.log_file);
	    if (verbose)
	        fprintf(stderr, "✅ Log written\n");
	}
    }
    show_stats();
    if (config.show_histogram)
	histogram_summary(config);

    /* Cleanup PMC counters */
    if (config.enable_pmc)
        pmc_cleanup();

    /* Cleanup: munmap for hugepage allocations, free for regular allocations */
    if (log_book != NULL) {
        if (using_hugepages) {
            munmap(log_book, log_book_bytes);
        } else {
            free(log_book);
        }
    }
    if (overflow_samples != NULL) {
        if (using_hugepages_overflow) {
            munmap(overflow_samples, overflow_samples_bytes);
        } else {
            free(overflow_samples);
        }
    }
    free(histogram);

    /* Close trace_marker file descriptor */
    close_trace_marker();

    return 0;
}


