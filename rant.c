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

#define DEFAULT_BUCKET_OVERFLOW_NS 100000ULL
#define DEFAULT_BUCKET_SIZE_NS     1000ULL
#define DEFAULT_BUCKET_MAX         ((uint64_t)(DEFAULT_BUCKET_OVERFLOW_NS / DEFAULT_BUCKET_SIZE_NS) + 1)

typedef struct {
    const char *iface;
    const char *ip;
    uint64_t threshold;
    int use_sw_timestamps;
    int show_histogram;
    int write_log;
    uint64_t bucket_overflow;
    uint32_t bucket_size;
    uint64_t duration;
    uint64_t warmup;
} config_t;

uint64_t *histogram = NULL;
uint64_t bucket_max;

size_t overflow_capacity = 500000000;
uint64_t *overflow_samples = NULL;

struct record {
    struct timespec hw_tx, hw_rx, sw_tx, sw_rx;
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
size_t log_capacity = 10000000000;
volatile sig_atomic_t keep_running = 1;

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

/* Record sample in the histogram */
void histogram_record(long long delta, config_t cfg) {
    stats.count++;
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
    uint32_t bucket_index = (uint32_t) delta / cfg.bucket_size;
    if (bucket_index >= cfg.bucket_overflow) {
	bucket_index = bucket_max;
        overflow_samples[histogram[bucket_index]]=delta;
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
    for (int i = 0; i <= cfg.bucket_overflow; ++i) {
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

    while (keep_running) {

	uint64_t now = rdtsc();

	if (cfg.duration > 0 && now >= deadline)
	    break;

        struct record *rtt = &log_book[log_size++];

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
        if (poll(&pfd_tx, 1, 2) > 0) {
            recvmsg(s, &msg_tx, MSG_ERRQUEUE);
            get_ts(&msg_tx, &rtt->hw_tx);
        }

        /* Reset length before fetching the response */
	msg_rx.msg_controllen = sizeof(cbuf_rx);
        msg_rx.msg_flags = 0;

	/* wait for pong */
        while ((poll(&pfd_rx, 1, 100) <= 0) && (keep_running ))
            continue;		
	
        /* Packet arrived: Receive Pong & Get RX Timestamp */
        if (recvmsg(s, &msg_rx, 0) > 0) {

            /* T4_SW: Software timestamp when pong is received */
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
		if (packet_count == cfg.warmup + 1)
		    test_start_tsc = rdtsc();
	    }

            if (cfg.threshold > 0 && rtt->delta > cfg.threshold) {
                printf("Round-Trip latency (%"PRIu64" ns) exceeds threshold (%"PRIu64" ns).\n",
			rtt->delta, cfg.threshold);
                break;
            }
        }
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

    while (keep_running) {

        uint64_t now = rdtsc();

        if (cfg.duration > 0 && now >= deadline)
            break;

        /* Reset length before fetching Ping pkt */
    	msg_rx.msg_controllen = sizeof(cbuf_rx);
        msg_rx.msg_flags = 0;

	/* Wait for Ping */
        if (poll(&pfd_rx, 1, 100) <= 0)
	    continue;

        /* Packet arrived: Receive Ping & Get RX Timestamp */
        if (recvmsg(s, &msg_rx, 0) > 0) {

	    struct record *resp = &log_book[log_size++];

            if (cfg.use_sw_timestamps) {
	        /* T2_SW: Software timestamp when ping is received */
	        clock_gettime(CLOCK_TAI, &resp->sw_rx);
            }
            /* T2_HW: Hardware timestamp when ping is received */
            get_ts(&msg_rx, &resp->hw_rx);

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
            if (poll(&pfd_tx, 1, 2) > 0) {
                recvmsg(s, &msg_tx, MSG_ERRQUEUE);
                get_ts(&msg_tx, &resp->hw_tx);
            }

	    /* Calculate Response latency (T3_HW - T2_HW) */
            resp->delta =
		    (resp->hw_tx.tv_sec - resp->hw_rx.tv_sec) * 1000000000LL +
                    (resp->hw_tx.tv_nsec - resp->hw_rx.tv_nsec);

            packet_count++;
            if (packet_count > cfg.warmup) {
	        histogram_record(resp->delta, cfg);
		if (packet_count == cfg.warmup + 1)
		    test_start_tsc = rdtsc();
	    }

            if (cfg.threshold > 0 && resp->delta > cfg.threshold) {
                printf("Response latency (%"PRIu64" ns) exceeds threshold (%"PRIu64" ns).\n",
			resp->delta, cfg.threshold);
		keep_running = 0;
                break;
            }
        }
    }

    uint64_t duration_cycles = rdtsc() - test_start_tsc;
    printf("Test is complete. Duration: %.2f s\n", (double)duration_cycles / cycles_per_sec);
}


void roundtrip_log() {    
    FILE *fp = fopen("roundtrip.txt", "w");
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
            stats.min, stats.max, stats.count ? (uint64_t) stats.sum / stats.count : 0, stats.count);
}

void response_log() {
    FILE *fp = fopen("response.txt", "w");
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
    printf("  -t, --threshold <us>          Stop when latency exceeds threshold (microseconds)\n");
    printf("  -d, --duration <sec>          Test duration in seconds\n");
    printf("  -w, --warmup <pkts>           Number of warmup packets to discard\n");
    printf("  -s, --sw-timestamps           Collect software timestamps\n");
    printf("  -H, --histogram               Show histogram summary\n");
    printf("  -l, --log                     Write transaction log to file\n");
    printf("  -o, --overflow <us>           Histogram overflow bucket threshold (default: 100us)\n");
    printf("  -b, --bucket-size <us>        Histogram bucket size (default: 1us)\n");
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
	.write_log = 0,
	.bucket_overflow = DEFAULT_BUCKET_OVERFLOW_NS,
        .bucket_size = DEFAULT_BUCKET_SIZE_NS,
	.duration =0,
	.warmup = 0
    };
    
    bucket_max = DEFAULT_BUCKET_MAX;

    signal(SIGINT, handle_sig);

    static struct option long_options[] = {
        {"duration",      required_argument, 0, 'd'},
        {"warmup",        required_argument, 0, 'w'},
        {"overflow",      required_argument, 0, 'o'},
        {"bucket-size",   required_argument, 0, 'b'},
        {"interface",     required_argument, 0, 'i'},
        {"address",       required_argument, 0, 'a'},
        {"threshold",     required_argument, 0, 't'},
        {"sw-timestamps", no_argument,       0, 's'},
        {"histogram",     no_argument,       0, 'H'},
        {"log",           no_argument,       0, 'l'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "d:w:o:b:i:a:t:sHlh", long_options, &option_index)) != -1) {
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
            case 's':
                config.use_sw_timestamps = 1;
                break;
	    case 'H':
		config.show_histogram = 1;
		break;
	    case 'l':
		config.write_log = 1;
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

    log_book = calloc(log_capacity, sizeof(struct record));
    if (log_book == NULL) return 1;

    /* [0-bucket_max-1]: buckets, [bucket_max]: overflows */
    histogram = calloc(bucket_max+1, sizeof(uint64_t));
    if (histogram == NULL) return 1;

    overflow_samples = calloc(overflow_capacity, sizeof(uint64_t));
    if (overflow_samples == NULL) return 1;

    /* Reflect (server) */
    if (config.ip == NULL) {
        reflect(config);
	if (config.write_log)
	    response_log();
    }
    /* Emit (client) */
    else {
        emit(config);
	if (config.write_log)
	    roundtrip_log();
    }
    show_stats();
    if (config.show_histogram)
	histogram_summary(config);

    free(log_book);
    free(histogram);
    free(overflow_samples);

    return 0;
}


