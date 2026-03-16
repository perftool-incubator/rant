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
    int use_sw_timestamps;
    int show_histogram;
    const char *log_file;
    uint64_t bucket_overflow;
    uint32_t bucket_size;
    uint64_t duration;
    uint64_t warmup;
    int busy_poll_budget;
    int prefer_busy_poll;
    int use_hugepages;
    int enable_trace_marker;
} config_t;

uint64_t *histogram = NULL;
uint64_t bucket_max;

size_t overflow_capacity = 500000000;
uint64_t *overflow_samples = NULL;
size_t overflow_samples_bytes = 0;  // Track allocation size for munmap
int using_hugepages_overflow = 0;  // Track if overflow used hugepages

struct record {
    struct timespec hw_tx, hw_rx, sw_tx, sw_rx;
    uint64_t delta;
};  /* 72 bytes natural packing - cache alignment removed due to memory cost */

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
volatile sig_atomic_t keep_running = 1;

/* Trace marker file descriptor for kernel tracing integration */
int trace_marker_fd = -1;

void handle_sig(int sig) {
    keep_running = 0;
}

void get_ts(struct msghdr *msg, struct timespec *ts) {
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
            *ts = ((struct timespec *)CMSG_DATA(cmsg))[2];
}

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    // __builtin_ia32_rdtsc() is a compiler intrinsic for 'rdtsc'
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

uint64_t calibrate_rdtsc() {
    /* one sec */
    struct timespec sleep_time = {1, 0};
    uint64_t start = rdtsc();
    nanosleep(&sleep_time, NULL);
    uint64_t end = rdtsc();
    /* Cycles Per Second */
    return end - start;
}

/* Open trace_marker for kernel tracing integration */
void open_trace_marker() {
    /* Try debugfs location first */
    trace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
    if (trace_marker_fd < 0) {
        /* Try tracefs location */
        trace_marker_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
        if (trace_marker_fd < 0) {
            fprintf(stderr, "Warning: Cannot open trace_marker: %s\n", strerror(errno));
            fprintf(stderr, "  Kernel tracing integration disabled.\n");
            fprintf(stderr, "  Try: sudo mount -t tracefs nodev /sys/kernel/tracing\n");
            fprintf(stderr, "  Or: sudo mount -t debugfs nodev /sys/kernel/debug\n\n");
            trace_marker_fd = -1;
        }
    }
    if (trace_marker_fd >= 0) {
        fprintf(stderr, "Trace marker enabled for kernel tracing integration\n\n");
    }
}

/* Close trace_marker file descriptor */
void close_trace_marker() {
    if (trace_marker_fd >= 0) {
        close(trace_marker_fd);
        trace_marker_fd = -1;
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
    struct ifreq ifr; strncpy(ifr.ifr_name, cfg.iface, IFNAMSIZ);
    struct hwtstamp_config hw_cfg = { .tx_type = HWTSTAMP_TX_ON, .rx_filter = HWTSTAMP_FILTER_ALL };
    ifr.ifr_data = (char *)&hw_cfg; ioctl(s, SIOCSHWTSTAMP, &ifr);

    int flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    setsockopt(s, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

    /* Set busy poll socket options if configured */
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
    struct pollfd pfd_tx = { .fd = s, .events = POLLERR };
    struct iovec iov_tx;
    iov_tx.iov_base = buf_tx; iov_tx.iov_len = sizeof(buf_tx);
    struct msghdr msg_tx = {0};
    msg_tx.msg_iov = &iov_tx; msg_tx.msg_iovlen = 1;
    msg_tx.msg_control = cbuf_tx;


    uint64_t cycles_per_sec = calibrate_rdtsc();
    uint64_t start_tsc = rdtsc();
    uint64_t test_start_tsc = start_tsc;
    uint64_t deadline = cfg.duration > 0 ? start_tsc + (cfg.duration * cycles_per_sec): 0;
    uint64_t packet_count = 0;
    struct record warmup_record;  /* Temporary storage for warmup packets */
    struct record *rtt;

    while (keep_running) {

        /* Start timing when warmup completes, before first test packet */
        if (packet_count == cfg.warmup) {
            test_start_tsc = rdtsc();
        }

        /* Only save to log_book after warmup and if logging enabled */
        if (packet_count >= cfg.warmup && log_book != NULL) {
            /* Check if log capacity exceeded */
            if (log_size >= log_capacity) {
                fprintf(stderr, "\nWARNING: Log capacity exceeded (%zu records)\n", log_capacity);
                fprintf(stderr, "  Stopping test to prevent buffer overflow.\n");
                fprintf(stderr, "  Consider using -d <seconds> for shorter tests or increase capacity.\n");
                keep_running = 0;
                break;
            }
            rtt = &log_book[log_size++];
        } else {
            rtt = &warmup_record;
        }

        /* Reset length before fetching from Error Queue */
    	msg_tx.msg_controllen = sizeof(cbuf_tx); 
        msg_tx.msg_flags = 0;

	/* Reset hw_tx to ensure we are not seeing stale data */
	rtt->hw_tx.tv_sec = 0;
        rtt->hw_tx.tv_nsec = 0;

	/* T1_SW: Software timestamp when ping is sent */
	if (cfg.use_sw_timestamps)
	    clock_gettime(CLOCK_TAI, &rtt->sw_tx);

	/* Send Ping */
	sendto(s, buf_tx, 1, 0, (struct sockaddr*)&addr, sizeof(addr));

        /* T1_HW: Hardware timestamp when ping in sent */
        while (poll(&pfd_tx, 1, 0) <= 0 && keep_running) {
            if (cfg.duration > 0 && rdtsc() > deadline)
                break;
        }
	if (recvmsg(s, &msg_tx, MSG_ERRQUEUE | MSG_DONTWAIT) > 0) {
            get_ts(&msg_tx, &rtt->hw_tx);
        }

        /* Reset length before fetching the response */
	msg_rx.msg_controllen = sizeof(cbuf_rx);
        msg_rx.msg_flags = 0;

	/* wait for pong */
        while (poll(&pfd_rx, 1, 0) <= 0 && keep_running) {
            if (cfg.duration > 0 && rdtsc() > deadline)
                break;
        }

        /* Packet arrived: Receive Pong & Get RX Timestamp */
        if (recvmsg(s, &msg_rx, MSG_DONTWAIT) > 0) {

            /* T4_SW: Software timestamp IMMEDIATELY after recvmsg (before ANY other code) */
            if (cfg.use_sw_timestamps)
		clock_gettime(CLOCK_TAI, &rtt->sw_rx);

            /* T4_HW: Hardware timestamp when pong is received  */
            get_ts(&msg_rx, &rtt->hw_rx);

            /* Calculate Round Trip Time latency: T4_HW - T1_HW */
            rtt->delta =
		    (rtt->hw_rx.tv_sec - rtt->hw_tx.tv_sec) * 1000000000LL +
                    (rtt->hw_rx.tv_nsec - rtt->hw_tx.tv_nsec);

            packet_count++;
            if (packet_count > cfg.warmup) {
	        histogram_record(rtt->delta, cfg);

		if (cfg.threshold > 0 && rtt->delta > cfg.threshold) {
		    printf("Round-Trip latency (%"PRIu64" ns) exceeds threshold (%"PRIu64" ns).\n",
			   rtt->delta, cfg.threshold);

		    /* Write to trace_marker for kernel tracing correlation */
		    if (trace_marker_fd >= 0) {
			char trace_msg[256];
			snprintf(trace_msg, sizeof(trace_msg),
				 "rant: RTT threshold exceeded: seq=%"PRIu64" latency=%"PRIu64"ns threshold=%"PRIu64"ns\n",
				 packet_count, rtt->delta, cfg.threshold);
			write_trace_marker(trace_msg);
		    }

		    /* exit early: threshold exceeded */
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
    struct ifreq ifr; strncpy(ifr.ifr_name, cfg.iface, IFNAMSIZ);
    struct hwtstamp_config hw_cfg = { .tx_type = HWTSTAMP_TX_ON, .rx_filter = HWTSTAMP_FILTER_ALL };
    ifr.ifr_data = (char *)&hw_cfg; ioctl(s, SIOCSHWTSTAMP, &ifr);

    int flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    setsockopt(s, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

    /* Set busy poll socket options if configured */
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
    struct pollfd pfd_tx = { .fd = s, .events = POLLERR };
    struct iovec iov_tx;
    iov_tx.iov_base = buf_tx; iov_tx.iov_len = sizeof(buf_tx);
    struct msghdr msg_tx = {0};
    msg_tx.msg_iov = &iov_tx; msg_tx.msg_iovlen = 1;
    msg_tx.msg_control = cbuf_tx;

    uint64_t cycles_per_sec = calibrate_rdtsc();
    uint64_t start_tsc = rdtsc();
    uint64_t test_start_tsc = start_tsc;
    uint64_t deadline = cfg.duration > 0 ? start_tsc + (cfg.duration * cycles_per_sec): 0;
    uint64_t packet_count = 0;
    struct record warmup_record;  /* Temporary storage for warmup packets */
    struct record *resp;

    while (keep_running) {

        /* Start timing when warmup completes, before first test packet */
        if (packet_count == cfg.warmup) {
            test_start_tsc = rdtsc();
        }

        /* Reset length before fetching Ping pkt */
    	msg_rx.msg_controllen = sizeof(cbuf_rx);
        msg_rx.msg_flags = 0;

	/* Wait for Ping */
        while (poll(&pfd_rx, 1, 0) <= 0 && keep_running) {
            if (cfg.duration > 0 && rdtsc() > deadline)
                break;
	}

        /* Packet arrived: Receive Ping & Get RX Timestamp */
        if (recvmsg(s, &msg_rx, MSG_DONTWAIT) > 0) {

            /* T2_SW: Software timestamp IMMEDIATELY after recvmsg (before ANY other code) */
            struct timespec t2_sw_immediate;
            if (cfg.use_sw_timestamps) {
	        clock_gettime(CLOCK_TAI, &t2_sw_immediate);
            }

            /* T2_HW: Hardware timestamp when ping is received (extract from cmsg) */
            struct timespec t2_hw;
            get_ts(&msg_rx, &t2_hw);

	    /* NOW do application logic (pointer assignment, warmup check, etc.) */
	    if (packet_count >= cfg.warmup && log_book != NULL) {
	        /* Check if log capacity exceeded */
	        if (log_size >= log_capacity) {
	            fprintf(stderr, "\nWARNING: Log capacity exceeded (%zu records)\n", log_capacity);
	            fprintf(stderr, "  Stopping test to prevent buffer overflow.\n");
	            fprintf(stderr, "  Consider using -d <seconds> for shorter tests or increase capacity.\n");
	            keep_running = 0;
	            break;
	        }
	        resp = &log_book[log_size++];
	    } else {
	        resp = &warmup_record;
	    }

            /* Store the immediately-captured timestamps */
            resp->sw_rx = t2_sw_immediate;
            resp->hw_rx = t2_hw;

	    /* Reset length before fetching from Error Queue */
    	    msg_tx.msg_controllen = sizeof(cbuf_tx); 
            msg_tx.msg_flags = 0;

	    /* Reset hw_tx to ensure we are not seeing stale data */
	    resp->hw_tx.tv_sec = 0;
            resp->hw_tx.tv_nsec = 0;

            /* T3_SW: Software timestamp when pong is sent */
            if (cfg.use_sw_timestamps) {
                clock_gettime(CLOCK_TAI, &resp->sw_tx);
            }

	    /* Send Pong */
            sendto(s, buf_tx, 1, 0, (struct sockaddr *)&client_addr, client_len);

            /* T3_HW: Hardware timestamp when pong is sent */
            while (poll(&pfd_tx, 1, 0) <= 0 && keep_running) {
                if (cfg.duration > 0 && rdtsc() > deadline)
                    break;
            }
            if (recvmsg(s, &msg_tx, MSG_ERRQUEUE | MSG_DONTWAIT) > 0) {
                get_ts(&msg_tx, &resp->hw_tx);
            }

	    /* Calculate Response latency (T3_HW - T2_HW) */
            resp->delta =
		    (resp->hw_tx.tv_sec - resp->hw_rx.tv_sec) * 1000000000LL +
                    (resp->hw_tx.tv_nsec - resp->hw_rx.tv_nsec);

            packet_count++;
            if (packet_count > cfg.warmup) {
	        histogram_record(resp->delta, cfg);

		if (cfg.threshold > 0 && resp->delta > cfg.threshold) {
		    printf("Response latency (%"PRIu64" ns) exceeds threshold (%"PRIu64" ns).\n",
			   resp->delta, cfg.threshold);

		    /* Write to trace_marker for kernel tracing correlation */
		    if (trace_marker_fd >= 0) {
			char trace_msg[256];
			snprintf(trace_msg, sizeof(trace_msg),
				 "rant: Response threshold exceeded: seq=%"PRIu64" latency=%"PRIu64"ns threshold=%"PRIu64"ns\n",
				 packet_count, resp->delta, cfg.threshold);
			write_trace_marker(trace_msg);
		    }

		    /* exit early: threshold exceeded */
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


void roundtrip_log(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        int len = fprintf(fp, "%10s %30s %30s %30s %30s %15s\n", "SEQ", "T1_SW", "T1_HW", "T4_HW", "T4_SW", "RTT");
	for (int i = 0; i < len - 1; i++) {
            fputc('-', fp);
        }
        fputc('\n', fp);

        for (long i = 0; i < log_size; i++) {
            fprintf(fp, "%10ld %20ld.%09ld %20ld.%09ld %20ld.%09ld %20ld.%09ld %15lld\n",
                i,
                log_book[i].sw_tx.tv_sec, log_book[i].sw_tx.tv_nsec,
                log_book[i].hw_tx.tv_sec, log_book[i].hw_tx.tv_nsec,
                log_book[i].hw_rx.tv_sec, log_book[i].hw_rx.tv_nsec,
                log_book[i].sw_rx.tv_sec, log_book[i].sw_rx.tv_nsec,
                log_book[i].delta);
        }
    }
    fclose(fp);
    return; 
}

void show_stats() {
    printf("\n--- Latency Statistics ---\n");
    printf("MIN: %"PRIu64" ns | MAX: %"PRIu64" ns | AVG: %"PRIu64" ns | Total Samples: %"PRIu64" \n\n",
            stats.count ? stats.min : 0, stats.count ? stats.max : 0, stats.count ? (uint64_t) stats.sum / stats.count : 0, stats.count);
}

void response_log(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        int len = fprintf(fp, "%10s %30s %30s %30s %30s %15s\n", "SEQ", "T2_HW", "T2_SW", "T3_SW", "T3_HW", "RESPONSE");
	for (int i = 0; i < len - 1; i++) {
            fputc('-', fp);
        }
        fputc('\n', fp);

        for (long i = 0; i < log_size; i++) {
            fprintf(fp, "%10ld %20ld.%09ld %20ld.%09ld %20ld.%09ld %20ld.%09ld %15lld\n",
                i,
                log_book[i].hw_rx.tv_sec, log_book[i].hw_rx.tv_nsec,
                log_book[i].sw_rx.tv_sec, log_book[i].sw_rx.tv_nsec,
                log_book[i].sw_tx.tv_sec, log_book[i].sw_tx.tv_nsec,
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
    printf("  -T, --trace-marker            Enable kernel trace_marker integration (requires -t)\n");
    printf("  -d, --duration <sec>          Test duration in seconds\n");
    printf("  -w, --warmup <pkts>           Number of warmup packets to discard\n");
    printf("  -s, --sw-timestamps           Collect software timestamps\n");
    printf("  -H, --histogram               Show histogram summary\n");
    printf("  -l, --log <file>              Write transaction log to file\n");
    printf("  -o, --overflow <us>           Histogram overflow bucket threshold (default: 100us)\n");
    printf("  -b, --bucket-size <us>        Histogram bucket size (default: 1us)\n");
    printf("  -G, --hugepages               Use hugepages for memory allocation (requires system config)\n");
    printf("  -B, --budget <budget>         Set SO_BUSY_POLL_BUDGET (NAPI poll budget)\n");
    printf("  -P, --prefer-busypoll         Set SO_PREFER_BUSY_POLL (prefer busy poll over interrupt)\n");
    printf("  -h, --help                    Show this help message\n");
}

int main(int argc, char **argv) {
    int opt;
    config_t config = {
        .iface = NULL,
        .ip = NULL,
        .threshold = 0,
        .use_sw_timestamps = 0,
	.show_histogram = 0,
	.log_file = NULL,
	.bucket_overflow = DEFAULT_BUCKET_OVERFLOW_NS,
        .bucket_size = DEFAULT_BUCKET_SIZE_NS,
	.duration =0,
	.warmup = 0,
	.busy_poll_budget = 0,
	.prefer_busy_poll = 0,
	.use_hugepages = 0,
	.enable_trace_marker = 0
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
        {"sw-timestamps",    no_argument,       0, 's'},
        {"histogram",        no_argument,       0, 'H'},
        {"log",              required_argument, 0, 'l'},
        {"hugepages",        no_argument,       0, 'G'},
        {"budget",           required_argument, 0, 'B'},
        {"prefer-busypoll",  no_argument,       0, 'P'},
        {"help",             no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "d:w:o:b:i:a:t:TsHl:GB:Ph", long_options, &option_index)) != -1) {
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
            case 's':
                config.use_sw_timestamps = 1;
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

    /* Open trace_marker if both threshold and trace-marker flag are specified */
    if (config.threshold > 0 && config.enable_trace_marker) {
        open_trace_marker();
    }

    /* Only allocate log_book if --log is specified */
    if (config.log_file == NULL) {
        fprintf(stderr, "No --log file specified, logging disabled\n\n");
        log_book = NULL;
        log_capacity = 0;
        log_book_bytes = 0;
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

        fprintf(stderr, "Allocating log memory for ~%lu seconds (%.1f hours): %zu records (%.2f GB)\n",
            duration_for_capacity, duration_for_capacity / 3600.0, log_capacity,
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
            fprintf(stderr, "Attempting hugepage allocation (use -G flag)...\n");

            /* Try 2MB hugepages first (21 = log2(2MB)) */
            log_book = mmap(NULL, log_book_bytes,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (21 << MAP_HUGE_SHIFT),
                            -1, 0);

            if (log_book == MAP_FAILED) {
                fprintf(stderr, "Warning: 2MB hugepages not available, trying default hugepages...\n");

                /* Try default hugepages without size specification */
                log_book = mmap(NULL, log_book_bytes,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                -1, 0);

                if (log_book == MAP_FAILED) {
                    fprintf(stderr, "Warning: Hugepages not available, falling back to regular allocation\n");
                    fprintf(stderr, "  To configure hugepages, run:\n");
                    fprintf(stderr, "    sudo sh -c 'echo %zu > /proc/sys/vm/nr_hugepages'\n",
                            (log_book_bytes / (2 * 1024 * 1024)) + 1);

                    /* Fallback to calloc */
                    log_book = calloc(log_capacity, sizeof(struct record));
                    if (log_book == NULL) {
                        perror("calloc failed");
                        return 1;
                    }
                    using_hugepages = 0;
                    fprintf(stderr, "Allocated %.2f GB using regular memory (calloc)\n\n",
                            log_book_bytes / (1024.0 * 1024.0 * 1024.0));
                } else {
                    using_hugepages = 1;
                    fprintf(stderr, "Allocated %.2f GB using default hugepages\n\n",
                            log_book_bytes / (1024.0 * 1024.0 * 1024.0));
                }
            } else {
                using_hugepages = 1;
                fprintf(stderr, "Allocated %.2f GB using 2MB hugepages\n\n",
                        log_book_bytes / (1024.0 * 1024.0 * 1024.0));
            }
        } else {
            /* Default: use regular calloc allocation */
            log_book = calloc(log_capacity, sizeof(struct record));
            if (log_book == NULL) {
                perror("calloc failed");
                return 1;
            }
            using_hugepages = 0;
            fprintf(stderr, "Allocated %.2f GB using regular memory (calloc)\n",
                    log_book_bytes / (1024.0 * 1024.0 * 1024.0));
            fprintf(stderr, "  Tip: Use -G flag for hugepage optimization\n\n");
        }
    }

    /* [0-bucket_max-1]: buckets, [bucket_max]: overflows */
    histogram = calloc(bucket_max+1, sizeof(uint64_t));
    if (histogram == NULL) return 1;

    /* Allocate overflow_samples (4GB array) */
    overflow_samples_bytes = overflow_capacity * sizeof(uint64_t);

    if (config.use_hugepages) {
        fprintf(stderr, "Allocating overflow buffer: %.2f GB (with hugepages)\n",
                overflow_samples_bytes / (1024.0 * 1024.0 * 1024.0));

        overflow_samples = mmap(NULL, overflow_samples_bytes,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (21 << MAP_HUGE_SHIFT),
                                -1, 0);

        if (overflow_samples == MAP_FAILED) {
            /* Fallback to calloc */
            overflow_samples = calloc(overflow_capacity, sizeof(uint64_t));
            if (overflow_samples == NULL) {
                perror("calloc overflow_samples failed");
                return 1;
            }
            using_hugepages_overflow = 0;
            fprintf(stderr, "Overflow buffer using regular memory (calloc)\n\n");
        } else {
            using_hugepages_overflow = 1;
            fprintf(stderr, "Overflow buffer using 2MB hugepages\n\n");
        }
    } else {
        /* Default: use calloc */
        overflow_samples = calloc(overflow_capacity, sizeof(uint64_t));
        if (overflow_samples == NULL) {
            perror("calloc overflow_samples failed");
            return 1;
        }
        using_hugepages_overflow = 0;
    }

    /* Lock all memory pages in RAM to prevent page faults during test */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("mlockall");
        fprintf(stderr, "Warning: Cannot lock memory in RAM. May experience page fault delays.\n");
        fprintf(stderr, "Try: sudo setcap cap_ipc_lock=+ep %s\n", argv[0]);
        fprintf(stderr, "Or run with: ulimit -l unlimited\n");
        fprintf(stderr, "Continuing without memory lock...\n\n");
    } else {
        fprintf(stderr, "Memory locked in RAM (mlockall successful)\n\n");
    }

    /* Reflect (server) */
    if (config.ip == NULL) {
        reflect(config);
	if (config.log_file)
	    response_log(config.log_file);
    }
    /* Emit (client) */
    else {
        emit(config);
	if (config.log_file)
	    roundtrip_log(config.log_file);
    }
    show_stats();
    if (config.show_histogram)
	histogram_summary(config);

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


