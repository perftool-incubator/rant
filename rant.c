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

struct record {
    struct timespec hw_tx, hw_rx, sw_tx, sw_rx;
    long long delta;
};

struct record *log_book = NULL;
size_t log_size = 0;
size_t log_capacity = 10000000000;
volatile int keep_running = 1;

void handle_sig(int sig) {
    keep_running = 0;
}

void get_ts(struct msghdr *msg, struct timespec *ts) {
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
            *ts = ((struct timespec *)CMSG_DATA(cmsg))[2];
}

/* Emit: dispatch round trip pkt (client) */
void emit(char* iface, char* ip, long long threshold, int use_sw_timestamps) {

    /* Socket options including Hardware Timestamping */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr; strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    struct hwtstamp_config cfg = { .tx_type = HWTSTAMP_TX_ON, .rx_filter = HWTSTAMP_FILTER_ALL };
    ifr.ifr_data = (char *)&cfg; ioctl(s, SIOCSHWTSTAMP, &ifr);

    int flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    setsockopt(s, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

    /* Socket addr & port */
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(12345) };
    inet_pton(AF_INET, ip, &addr.sin_addr);

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

    while (keep_running) {
	
        struct record *rtt = &log_book[log_size++];

        /* Reset length before fetching from Error Queue */
    	msg_tx.msg_controllen = sizeof(cbuf_tx); 
        msg_tx.msg_flags = 0;

	/* Reset hw_tx to ensure we are not seeing stale data */
	rtt->hw_tx.tv_sec = 0;
        rtt->hw_tx.tv_nsec = 0;

	/* T1_SW: Software timestamp when ping is sent */
	if (use_sw_timestamps)
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
            if (use_sw_timestamps)
		clock_gettime(CLOCK_TAI, &rtt->sw_rx);

            /* T4_HW: Hardware timestamp when pong is received  */
            get_ts(&msg_rx, &rtt->hw_rx);

            /* Calculate Round Trip Time latency: T4_HW - T1_HW */
            rtt->delta = 
		    (rtt->hw_rx.tv_sec - rtt->hw_tx.tv_sec) * 1000000000LL +
                    (rtt->hw_rx.tv_nsec - rtt->hw_tx.tv_nsec);

            if (threshold > 0 && rtt->delta > threshold) {
                printf("Round-Trip latency (%lld ns) exceeds threshold (%lld ns).\n",
			rtt->delta, threshold);
                break;
            }
        }
    }

    printf("Test is complete.\n");
}

/* Reflect: send back round trip pkt (server) */
void reflect(char* iface, long long threshold, int use_sw_timestamps) {

    /* Socket options including Hardware Timestamping */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr; strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    struct hwtstamp_config cfg = { .tx_type = HWTSTAMP_TX_ON, .rx_filter = HWTSTAMP_FILTER_ALL };
    ifr.ifr_data = (char *)&cfg; ioctl(s, SIOCSHWTSTAMP, &ifr);

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

    while (keep_running) {
	
        /* Reset length before fetching Ping pkt */
    	msg_rx.msg_controllen = sizeof(cbuf_rx); 
        msg_rx.msg_flags = 0;

	/* Wait for Ping */
        if (poll(&pfd_rx, 1, 100) <= 0)
	    continue;

        /* Packet arrived: Receive Ping & Get RX Timestamp */
        if (recvmsg(s, &msg_rx, 0) > 0) {
        
	    struct record *resp = &log_book[log_size++];

            if (use_sw_timestamps) {
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
            if (use_sw_timestamps) {
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

            if (threshold > 0 && resp->delta > threshold) {
                printf("Response latency (%lld ns) exceeds threshold (%lld ns).\n",
			resp->delta, threshold);
		keep_running = 0;
                break;
            }
        }
    }

    printf("Test is complete.\n");
}


void roundtrip_log() {    
    /* Print Final Stats */
    long long min = 1e18, max = 0, sum = 0;
    for(int i=0; i<log_size; i++) {
        if(log_book[i].delta < min) min = log_book[i].delta;
        if(log_book[i].delta > max) max = log_book[i].delta;
        sum += log_book[i].delta;
    }
    if (log_size == 0) min=0;

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

    printf("\n--- Round-Trip Latency Statistics ---\n");
    printf("MIN: %lld ns | MAX: %lld ns | AVG: %lld ns | Total Samples: %lld \n\n", 
            min, max, log_size ? sum/log_size : 0, log_size);

    return; 
}

void response_log() {    
    /* Print Final Stats */
    long long min = 1e18, max = 0, sum = 0;
    for(int i=0; i<log_size; i++) {
        if(log_book[i].delta < min) min = log_book[i].delta;
        if(log_book[i].delta > max) max = log_book[i].delta;
        sum += log_book[i].delta;
    }
    if (log_size == 0) min=0;

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

    printf("\n--- Response Latency Statistics ---\n");
    printf("MIN: %lld ns | MAX: %lld ns | AVG: %lld ns | Total Samples: %lld \n\n", 
            min, max, log_size ? sum/log_size : 0, log_size);

    return; 
}

int main(int argc, char **argv) {
    long long threshold = 0;
    int use_sw_timestamps = 0;
    int opt;

    char *iface = NULL;
    char *ip = NULL;

    signal(SIGINT, handle_sig);

    while ((opt = getopt(argc, argv, "i:a:t:s")) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 'a':
                ip = optarg;
                break;
            case 't':
                threshold = atoll(optarg);
                if (threshold <= 0) {
                    fprintf(stderr, "Error: Threshold must be > 0\n");
                    return 1;
                }
                break;
            case 's':
                use_sw_timestamps = 1;
                break;
            default:
                goto usage;
        }
    }

    if (iface == NULL) {
    usage:
        printf("Usage: %s -i <iface> [-a <ip>] [-t <threshold_ns>] [-s]\n", argv[0]);
        return 1;
    }

    size_t total_bytes = sizeof(struct record) * log_capacity;
    log_book = malloc(total_bytes);

    /* Reflect (server) */
    if (ip == NULL) {
        reflect(iface, threshold, use_sw_timestamps);
	response_log();
    }
    /* Emit (client) */
    else {
        emit(iface, ip, threshold, use_sw_timestamps);
	roundtrip_log();
    }

    free(log_book);

    return 0;
}


