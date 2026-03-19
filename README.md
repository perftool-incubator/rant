# rant
Round-trip And Network Timing

`rant` is an Emit/Reflect test (Request/Response), a "ping-pong" test to measure
network latency with nanosecond precision using hardware timestamps.

## Topology
```
Emit (client)              |                       |      Reflect (server)
---------------------------|-----------------------|----------------------
  T1_SW                    |                       |
    |                      |                       |
 sendto()                  |                       |
     \_________ >> T1_HW  *|========== >> =========|* T2_HW >>  recvmsg()
                           |                       |                |
                           |                       |              T2_SW
                           |                       |                |
                           |                       |              T3_SW
                           |                       |                |
                           |                       |             sendto()
     recvmsg()  << T4_HW  *|========== << =========|* T3_HW << ____/
         |                 |                       |
       T4_SW               |                       |
```

## Timestamps
### T1: Client sends ping packet
* `T1_SW`: SW timestamp when userspace sends the packet
* `T1_HW`: HW timestamp when packet is actually sent into the wire
### T2: Server receives ping packet
* `T2_HW`: HW timestamp when packet is actually received off the wire
* `T2_SW`: SW timestamp when packet is delivered to userspace
### T3: Server sends pong packet
* `T3_SW`: SW timestamp when userspace sends the packet
* `T3_HW`: HW timestamp when packet is actually sent into the wire
### T4: Client receives pong packet
* `T4_HW`: HW timestamp when packet is actually received off the wire
* `T4_SW`: SW timestamp when packet is delivered to userspace

## Metrics
* `T4_HW - T1_HW`: Hardware Round-Trip Time (client measures)
* `T3_HW - T2_HW`: Hardware Response Time (server measures)

Software timestamps (`--sw-timestamps`) enable additional decomposition:
* `T1_HW - T1_SW`: App-to-NIC TX delay (client)
* `T2_SW - T2_HW`: NIC-to-App RX delay (server)
* `T3_SW - T2_SW`: App processing time (server)
* `T3_HW - T3_SW`: App-to-NIC TX delay (server)
* `T4_SW - T4_HW`: NIC-to-App RX delay (client)

## Compile
```
gcc -o rant rant.c
```

## Usage

```
./rant --interface <iface> [OPTIONS]

Required:
  -i, --interface <iface>       Network interface to use

Optional:
  -a, --address <ip>            Server IP address (client mode, omit for server)
  -t, --threshold <us>          Stop when latency exceeds threshold (microseconds)
  -T, --trace-marker            Enable kernel trace_marker integration
  -S, --snapshot                Take ftrace snapshot on threshold breach
  -d, --duration <sec>          Test duration in seconds
  -w, --warmup <pkts>           Number of warmup packets to discard from statistics
  -s, --sw-timestamps           Collect software timestamps (T*_SW)
  -H, --histogram               Show histogram summary at end of test
  -l, --log <file>              Write transaction log to file
  -o, --overflow <us>           Histogram overflow bucket threshold (default: 100us)
  -b, --bucket-size <us>        Histogram bucket size (default: 1us)
  -G, --hugepages               Use hugepages for memory allocation
  -B, --budget <n>              Set SO_BUSY_POLL_BUDGET (NAPI poll budget)
  -P, --prefer-busypoll         Set SO_PREFER_BUSY_POLL
  -v, --verbose                 Verbose output (config, allocation, progress)
  -h, --help                    Show help message
```

## Running Tests

### Quick test (60 seconds, client only shown)
```bash
sudo nsenter --net=/var/run/netns/ns_ens7f0np0 \
  taskset -c 51 chrt -f 22 \
  ./rant -i ens7f0np0 -a 192.168.1.11 --warmup 100000 --duration 60 --threshold 30
```

### Full test with all features

**Server (Reflect)**:
```bash
sudo nsenter --net=/var/run/netns/ns_ens7f1np1 \
  taskset --cpu-list 61 chrt -f 22 \
  ./rant -i ens7f1np1 \
    --warmup 100000 \
    --duration 600 \
    --threshold 100 \
    --sw-timestamps \
    --histogram \
    --log response.txt \
    --trace-marker \
    --snapshot
```

**Client (Emit)**:
```bash
sudo nsenter --net=/var/run/netns/ns_ens7f0np0 \
  taskset -c 51 chrt -f 22 \
  ./rant -i ens7f0np0 -a 192.168.1.11 \
    --warmup 100000 \
    --duration 600 \
    --threshold 100 \
    --sw-timestamps \
    --histogram \
    --log roundtrip.txt \
    --trace-marker \
    --snapshot
```

Notes:
* `nsenter --net=` is used instead of `ip netns exec` to preserve access to tracefs
* `taskset` pins the process to an isolated CPU
* `chrt -f 22` sets SCHED_FIFO priority 22 (below IRQ thread priority)
* `--warmup 100000` discards the first 100K packets from statistics

### Example output

**Server**:
```
Trace marker enabled for kernel tracing integration
Trace snapshot enabled
Snapshot mode: circular log buffer of 500000 records (~10s, 34.3 MB)

Memory locked in RAM (mlockall successful)

Test is complete. Duration: 600.12 s

--- Latency Statistics ---
MIN: 6875 ns | MAX: 32989 ns | AVG: 9911 ns | Total Samples: 28546206

Histogram Summary:
  Samples   :  28546206
  Minimum   :  6.88 us (#15209052)
  Maximum   :  32.99 us (#27246923)
  Average   :  9.91 us
  Percentiles (us):
    50th    :  9 (Median)
    90th    :  10
    95th    :  10
    99th    :  11
    99.9th  :  14
    99.99th :  18
```

**Client**:
```
--- Latency Statistics ---
MIN: 8327 ns | MAX: 34439 ns | AVG: 11363 ns | Total Samples: 28546206

Histogram Summary:
  Percentiles (us):
    50th    :  11 (Median)
    90th    :  11
    99th    :  12
    99.9th  :  16
    99.99th :  20
```

## Transaction Log (`--log`)

When `--log <file>` is specified, all transactions are written to a file at
test completion.

**Server log** (columns: SEQ, T2_HW, T2_SW, T3_SW, T3_HW, RESPONSE):
```
       SEQ                          T2_HW                          T2_SW                          T3_SW                          T3_HW        RESPONSE
------------------------------------------------------------------------------------------------------------------------------------------------------
         0           1771555281.293211904           1771555281.293247670           1771555281.293248149           1771555281.293264861           52957
```

**Client log** (columns: SEQ, T1_SW, T1_HW, T4_HW, T4_SW, RTT):
```
       SEQ                          T1_SW                          T1_HW                          T4_HW                          T4_SW             RTT
------------------------------------------------------------------------------------------------------------------------------------------------------
         0           1771555281.293181657           1771555281.293210998           1771555281.293265767           1771555281.293287981           54769
```

Software timestamp columns (T*_SW) are only present when `--sw-timestamps` is used.
Without it, only HW timestamps and the latency delta are logged.

### Circular buffer mode

When `--snapshot` and `--log` are both active, the log uses a circular buffer
of 500,000 records (~10 seconds at 50K packets/sec, ~34 MB). This allows
long-duration tests without excessive memory usage. Only the last ~10 seconds
of transactions are preserved in the log file, which is typically sufficient
for post-mortem analysis around a threshold breach.

Without `--snapshot`, the full log is allocated based on test duration.

## Trace Marker Integration (`--trace-marker`)

The `--trace-marker` flag integrates rant with the kernel's ftrace subsystem.
When enabled:

1. rant opens `/sys/kernel/tracing/instances/rant/trace_marker`
2. Writes `RANT_TEST_START` when the test begins (after warmup)
3. On threshold breach: writes the latency spike details to trace_marker,
   then stops tracing (`tracing_on = 0`)

This allows correlating application-level latency spikes with kernel events
(IRQ delivery, scheduling, softirq processing, etc.) captured in the same
trace buffer.

### Setup

Create a dedicated ftrace instance and configure tracing before running rant:

```bash
# Create rant trace instance
mkdir -p /sys/kernel/tracing/instances/rant

# Set buffer size (16 MB per CPU is good for ~10s of trace data)
echo 16384 > /sys/kernel/tracing/instances/rant/buffer_size_kb

# Limit tracing to relevant CPUs (e.g., app CPU 61 and IRQ CPU 62)
echo 60000000,00000000 > /sys/kernel/tracing/instances/rant/tracing_cpumask

# Enable useful tracers/events
echo 1 > /sys/kernel/tracing/instances/rant/events/irq/irq_handler_entry/enable
echo 1 > /sys/kernel/tracing/instances/rant/events/irq/irq_handler_exit/enable
echo 1 > /sys/kernel/tracing/instances/rant/events/net/napi_gro_receive_entry/enable
echo 1 > /sys/kernel/tracing/instances/rant/events/sched/sched_switch/enable
```

## Ftrace Snapshot (`--snapshot`)

The `--snapshot` flag triggers an ftrace snapshot when a threshold breach
occurs. Combined with `--trace-marker`, this captures a frozen copy of the
trace buffer at the exact moment of a latency spike.

### Setup

Allocate the snapshot buffer before running rant:
```bash
echo 1 > /sys/kernel/tracing/instances/rant/snapshot
```

### Retrieving snapshot data

After a threshold breach, rant stops tracing and takes a snapshot. Read the
data from:

```bash
# Snapshot buffer (CPU that triggered the snapshot)
cat /sys/kernel/tracing/instances/rant/snapshot

# Live trace buffer (frozen by tracing_on=0, useful for other CPUs)
cat /sys/kernel/tracing/instances/rant/per_cpu/cpu62/trace
```

Note: The snapshot mechanism is per-CPU — it captures the trace buffer of the
CPU that writes to the snapshot file. For data from other CPUs, read from the
live trace buffer (which is frozen since tracing was stopped).

## Threshold Diagnostics

When `--threshold` is set and a latency spike exceeds the threshold, rant
prints a detailed breakdown:

**Server (Reflect)**:
```
Response latency (330151 ns) exceeds threshold (100000 ns).
  T2_HW (NIC rx):  1773883524.780127138
  T3_HW (NIC tx):  1773883524.780457289
  T2_SW (app rx):  1773883524.780430176
  T3_SW (app tx):  1773883524.780430768
  NIC-to-app (T2_SW - T2_HW): 303038 ns    <-- where the spike is
  App-to-NIC (T3_HW - T3_SW): 26521 ns
  App processing (T3_SW - T2_SW): 592 ns
```

This decomposition (requires `--sw-timestamps`) pinpoints whether the spike
is in the NIC/driver RX path, the application, or the TX path.

## Memory

* `mlockall()` is called at startup to prevent page faults during the test
* Log allocation is based on test duration (estimated at 50K packets/sec)
* `--hugepages` uses `mmap` with `MAP_HUGETLB` for log and overflow arrays
* The histogram uses 1-byte-per-microsecond buckets (100 buckets + 1 overflow by default)
* Overflow samples (>100us) are stored separately for exact percentile calculation

## Interface Configuration (`config.sh`)

`config.sh` sets up a network interface for low-latency testing: namespace
isolation, ethtool tuning, IRQ affinity, CPU isolation, and PTP clock sync.

It auto-discovers hardware properties (MAC, PCI address, driver, IRQ, PTP
clock) from the interface name.

### Usage

```
config.sh <interface> --ip <local_ip> --remote-ip <remote_ip> \
          --cpu <app_cpu> --irq-cpu <irq_cpu> [options]

Required:
  <interface>              Network interface name
  --ip <addr>              Local IP address to assign (with /24)
  --remote-ip <addr>       Remote peer IP address
  --cpu <n>                CPU core for the application
  --irq-cpu <n>            CPU core for IRQ handling

Optional:
  --remote-mac <mac>       Remote MAC address for static ARP
  --busy-poll <val>        Busy poll value (default: 0)
  --ptp-source <dev>       PTP source device (auto-detected from sysfs)
  --ptp-sync-to <dev>      PTP device to sync to (for second port)
  --no-namespace           Skip namespace setup
  --no-ptp                 Skip PTP sync setup
  --irq-prio <n>           IRQ thread FIFO priority (default: 55)
  --ksoftirqd-prio <n>     ksoftirqd FIFO priority (default: 11)
```

### Example

```bash
# Configure client interface (port 0)
sudo ./config.sh ens7f0np0 \
  --ip 192.168.1.10 --remote-ip 192.168.1.11 \
  --remote-mac 58:a2:e1:0b:21:df \
  --cpu 51 --irq-cpu 52

# Configure server interface (port 1), sync PTP clocks
sudo ./config.sh ens7f1np1 \
  --ip 192.168.1.11 --remote-ip 192.168.1.10 \
  --remote-mac 58:a2:e1:0b:21:de \
  --cpu 61 --irq-cpu 62 \
  --ptp-sync-to /dev/ptp7
```

### What it configures

* **Namespace**: Creates `ns_<ifname>`, moves interface into it
* **Ethtool**: Single queue, checksums off, GRO/LRO/TSO off, coalescing
  minimized (rx-usecs=0, rx-frames=1), small ring buffers (512), pause frames off
* **Driver-specific**: Detects `mlx5` or `ice` and applies appropriate private
  flags (CQE mode off, rx_cqe_moder off, tx_port_ts off for mlx5)
* **NAPI**: `napi_defer_hard_irqs=0`, `gro_flush_timeout=0`
* **Network**: Static ARP, IPv6 disabled, multicast off, ARP off, noqueue qdisc
* **CPU**: Isolates app and IRQ CPUs via `tuna`, sets IRQ thread to FIFO priority
* **PCIe**: Disables PCIe power management via `setpci`
* **PTP**: Starts `phc2sys` for clock synchronization

## Limitations
Features not yet implemented:
* Clock drift detection and warnings
* Hardware timestamp support verification
