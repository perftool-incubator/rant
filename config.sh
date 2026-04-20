#!/bin/bash
#
# config.sh - Configure a network interface for low-latency rant testing
#
# Auto-discovers MAC, PCI address, IRQ, and PTP clock from the interface.
# Sets up namespace, ethtool tuning, IRQ affinity, and PTP sync.
#
# Usage:
#   config.sh <interface> --ip <local_ip> --remote-ip <remote_ip> \
#             --cpu <app_cpu> --irq-cpu <irq_cpu> [options]
#
# Required:
#   <interface>              Network interface name
#   --ip <addr>              Local IP address to assign (with /24)
#   --remote-ip <addr>       Remote peer IP address
#   --cpu <n>                CPU core for the application
#   --irq-cpu <n>            CPU core for IRQ handling
#
# Optional:
#   --remote-mac <mac>       Remote MAC address (skip if not needed)
#   --busy-poll <val>        Busy poll value (default: 0)
#   --ptp-source <dev>       PTP source device, e.g. /dev/ptp6 (auto-detected)
#   --ptp-sync-to <dev>      PTP device to sync to (for second port)
#   --no-namespace           Skip namespace setup (interface already configured)
#   --no-ptp                 Skip PTP sync setup
#   --irq-prio <n>           IRQ thread FIFO priority (default: 50)
#   --ksoftirqd-prio <n>     ksoftirqd FIFO priority (default: 11)
#   -h, --help               Show this help
#
# Dual-port cards: configure BOTH ports before testing. The script saves IRQ
# thread state and automatically re-pins sibling port threads if ethtool -L
# resets them. For best results, configure the client port first, then server.

set -e

usage() {
    sed -n '2,/^$/s/^# \?//p' "$0"
    exit 1
}

die() { echo "ERROR: $*" >&2; exit 1; }

# --- Parse arguments ---
ifname=""
ip_addr=""
remote_ip=""
remote_mac=""
cpu=""
irq_cpu=""
busy_poll=60
ptp_source=""
ptp_sync_to=""
skip_namespace=0
skip_ptp=0
irq_prio=50
ksoftirqd_prio=11

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)        usage ;;
        --ip)             ip_addr="$2"; shift 2 ;;
        --remote-ip)      remote_ip="$2"; shift 2 ;;
        --remote-mac)     remote_mac="$2"; shift 2 ;;
        --cpu)            cpu="$2"; shift 2 ;;
        --irq-cpu)        irq_cpu="$2"; shift 2 ;;
        --busy-poll)      busy_poll="$2"; shift 2 ;;
        --ptp-source)     ptp_source="$2"; shift 2 ;;
        --ptp-sync-to)    ptp_sync_to="$2"; shift 2 ;;
        --no-namespace)   skip_namespace=1; shift ;;
        --no-ptp)         skip_ptp=1; shift ;;
        --irq-prio)       irq_prio="$2"; shift 2 ;;
        --ksoftirqd-prio) ksoftirqd_prio="$2"; shift 2 ;;
        -*)               die "Unknown option: $1" ;;
        *)
            if [[ -z "$ifname" ]]; then
                ifname="$1"; shift
            else
                die "Unexpected argument: $1"
            fi
            ;;
    esac
done

# --- Validate required arguments ---
[[ -n "$ifname" ]]    || die "Interface name required"
[[ -n "$ip_addr" ]]   || die "--ip required"
[[ -n "$remote_ip" ]] || die "--remote-ip required"
[[ -n "$cpu" ]]        || die "--cpu required"
[[ -n "$irq_cpu" ]]   || die "--irq-cpu required"

# Verify interface exists (before namespace move)
ip link show "$ifname" &>/dev/null || \
    ip netns exec "ns_${ifname}" ip link show "$ifname" &>/dev/null || \
    die "Interface $ifname not found"

set -x

# --- Auto-discover hardware properties ---

# PCI address
pci=$(ethtool -i "$ifname" 2>/dev/null | awk '/bus-info:/{print $2}' | sed 's/^0000://')
[[ -n "$pci" ]] || pci=$(ip netns exec "ns_${ifname}" ethtool -i "$ifname" 2>/dev/null | awk '/bus-info:/{print $2}' | sed 's/^0000://')
[[ -n "$pci" ]] || die "Could not detect PCI address for $ifname"

# Driver name (for driver-specific settings)
driver=$(ethtool -i "$ifname" 2>/dev/null | awk '/driver:/{print $2}')
[[ -n "$driver" ]] || driver=$(ip netns exec "ns_${ifname}" ethtool -i "$ifname" 2>/dev/null | awk '/driver:/{print $2}')

# IRQ name pattern (e.g. mlx5_comp0@pci:0000:ae:00.0)
irq_pattern="@pci:0000:${pci}"

# PTP clock (auto-detect from PCI address — works even after namespace move)
if [[ -z "$ptp_source" ]]; then
    ptp_dev=$(ls -d /sys/bus/pci/devices/0000:${pci}/ptp/ptp* 2>/dev/null | head -1)
    if [[ -n "$ptp_dev" ]]; then
        ptp_source="/dev/$(basename "$ptp_dev")"
    fi
fi

# MAC address
mac=$(ip link show "$ifname" 2>/dev/null | awk '/link\/ether/{print $2}')
[[ -n "$mac" ]] || mac=$(ip netns exec "ns_${ifname}" ip link show "$ifname" 2>/dev/null | awk '/link\/ether/{print $2}')

{ set +x; } 2>/dev/null
echo ""
echo "=== Detected hardware ==="
echo "  Interface:  $ifname"
echo "  MAC:        $mac"
echo "  PCI:        0000:$pci"
echo "  Driver:     $driver"
echo "  PTP:        ${ptp_source:-not found}"
echo "  IRQ match:  *${irq_pattern}*"
echo "  App CPU:    $cpu"
echo "  IRQ CPU:    $irq_cpu"
echo ""
set -x

# --- SELinux AVC cache fix ---
# Default AVC cache (512 entries) causes ~200-300us spikes when full.
# 8192 entries eliminates eviction-driven policy recomputation.
# See docs/selinux.md for details.
if [[ -f /sys/fs/selinux/avc/cache_threshold ]]; then
    current_avc=$(cat /sys/fs/selinux/avc/cache_threshold)
    if [[ "$current_avc" -lt 8192 ]]; then
        echo 8192 > /sys/fs/selinux/avc/cache_threshold
        { set +x; } 2>/dev/null
        echo "=== SELinux AVC cache fix ==="
        echo "  cache_threshold: $current_avc -> 8192"
        set -x
    fi
fi

# --- Sysctl tuning ---
sysctl -w net.core.busy_poll=$busy_poll
sysctl -w net.core.busy_read=$busy_poll
sysctl -w net.core.gro_normal_batch=1
sysctl -w net.core.netdev_budget=300
sysctl -w net.core.netdev_budget_usecs=2000
sysctl -w net.ipv4.tcp_low_latency=1
sysctl -w net.ipv4.tcp_autocorking=0
sysctl -w net.core.default_qdisc=noqueue

# --- Namespace setup ---
ns_cmd="ip netns exec ns_${ifname}"

if [[ "$skip_namespace" -eq 0 ]]; then
    $ns_cmd ip link set "$ifname" netns 1 2>/dev/null || true
    ip netns del "ns_${ifname}" 2>/dev/null || true
    ip netns add "ns_${ifname}"
    ip link set "$ifname" netns "ns_${ifname}"
else
    # If no namespace, commands run directly
    if ! ip netns list | grep -q "^ns_${ifname}"; then
        ns_cmd=""
    fi
fi

# --- Ethtool tuning ---

# Queue and offload settings (driver-independent)
# Skip ethtool -L if already combined 1 — on dual-port cards, ethtool -L on one
# port resets IRQ thread affinities for BOTH ports, undoing previous pinning.
current_combined=$($ns_cmd ethtool -l "$ifname" 2>/dev/null | awk '/^Combined:/{val=$2} END{print val}')
if [[ "$current_combined" != "1" ]]; then
    $ns_cmd ethtool -L "$ifname" combined 1
else
    { set +x; } 2>/dev/null
    echo "  ethtool -L: already combined 1, skipping (avoids dual-port affinity reset)"
    set -x
fi
$ns_cmd ethtool -K "$ifname" rx-checksumming off tx-checksumming off
$ns_cmd ethtool -K "$ifname" lro off gro off
$ns_cmd ethtool -K "$ifname" tso off gso off
$ns_cmd ethtool -C "$ifname" rx-frames 1 tx-frames 1
$ns_cmd ethtool -C "$ifname" adaptive-tx off adaptive-rx off rx-usecs 0 tx-usecs 0
$ns_cmd ethtool -G "$ifname" rx 128 tx 128
$ns_cmd ethtool -g "$ifname"
$ns_cmd ethtool -A "$ifname" rx off tx off

# Driver-specific private flags
case "$driver" in
    mlx5_core|mlx5e)
        $ns_cmd ethtool -C "$ifname" cqe-mode-rx off
        $ns_cmd ethtool -K "$ifname" ntuple off
        $ns_cmd ethtool -K "$ifname" rxhash off
        $ns_cmd ethtool --set-priv-flags "$ifname" rx_cqe_moder off
        $ns_cmd ethtool --set-priv-flags "$ifname" tx_port_ts off
        $ns_cmd ethtool --set-priv-flags "$ifname" skb_tx_mpwqe off
        ;;
    ice)
        $ns_cmd ethtool --set-priv-flags "$ifname" LinkPolling off 2>/dev/null || true
        $ns_cmd ethtool --set-priv-flags "$ifname" flow-director-atr off 2>/dev/null || true
        $ns_cmd ethtool --set-priv-flags "$ifname" disable-fw-lldp on 2>/dev/null || true
        ;;
esac

# NAPI defer and GRO flush
$ns_cmd bash -c "echo 0 > /sys/class/net/$ifname/napi_defer_hard_irqs"
$ns_cmd bash -c "echo 0 > /sys/class/net/$ifname/gro_flush_timeout"

# --- Interface and IP setup ---
$ns_cmd ip link set lo up
$ns_cmd ip link set "$ifname" up
$ns_cmd ip addr add "${ip_addr}/24" dev "$ifname" 2>/dev/null || true

# Qdisc
$ns_cmd tc qdisc replace dev "$ifname" root noqueue

# Traffic reduction
$ns_cmd ip link set "$ifname" promisc on
$ns_cmd sysctl -w "net.ipv6.conf.$ifname.disable_ipv6=1"
$ns_cmd ip link set "$ifname" multicast off
$ns_cmd sysctl -w net.ipv4.conf.all.arp_ignore=1
$ns_cmd sysctl -w net.ipv4.conf.all.arp_announce=2

# Static ARP — do NOT use "ip link set arp off", it flushes all neighbour entries
# including permanent ones. arp_ignore=1 + arp_announce=2 above suppress ARP traffic.
$ns_cmd ip neigh flush all
if [[ -n "$remote_mac" ]]; then
    $ns_cmd ip neigh replace "$remote_ip" lladdr "$remote_mac" nud permanent dev "$ifname"
fi
$ns_cmd ip neigh show all

# --- CPU isolation and IRQ affinity ---
tuna isolate -c "$cpu,$irq_cpu"

# Find the mlx5_comp0 data path IRQ thread (NOT mlx5_async0)
comp_thread=$(pgrep -f "mlx5_comp0${irq_pattern}" | head -1)
async_thread=$(pgrep -f "mlx5_async0${irq_pattern}" | head -1)

if [[ -n "$comp_thread" ]]; then
    # Set comp0 (data path) to high priority and pin to IRQ CPU
    taskset -p -c "$irq_cpu" "$comp_thread"
    chrt -f -p "$irq_prio" "$comp_thread"
    { set +x; } 2>/dev/null
    echo ""
    echo "=== mlx5_comp0 (data path) ==="
    echo "  PID:      $comp_thread"
    echo "  CPU:      $(cat /proc/$comp_thread/status 2>/dev/null | grep Cpus_allowed_list)"
    echo "  Priority: $(chrt -p $comp_thread)"
    set -x
else
    echo "WARNING: mlx5_comp0 thread matching *mlx5_comp0${irq_pattern}* not found"
fi

if [[ -n "$async_thread" ]]; then
    # Set async0 (firmware events) priority
    taskset -p -c "$irq_cpu" "$async_thread"
    chrt -f -p "$ksoftirqd_prio" "$async_thread"
    { set +x; } 2>/dev/null
    echo "=== mlx5_async0 (firmware events) ==="
    echo "  PID:      $async_thread"
    echo "  Priority: $(chrt -p $async_thread)"
    set -x
fi

# Evict or demote other IRQ threads on app and IRQ CPUs.
# Managed IRQs (NVMe, mpi3mr, etc.) cannot be moved via taskset or smp_affinity —
# the kernel enforces their CPU affinity. Instead, we lower them to SCHED_OTHER
# so they cannot preempt the latency-sensitive workload.
{ set +x; } 2>/dev/null
echo ""
echo "=== Evicting/demoting IRQ threads on CPUs $cpu and $irq_cpu ==="
for target_cpu in $cpu $irq_cpu; do
    for pid in $(ps -eLo pid,psr,comm | awk -v cpu="$target_cpu" '$2==cpu && $3~/^irq\// {print $1}'); do
        comm=$(cat /proc/$pid/comm 2>/dev/null)
        # Skip our mlx5 comp0 and async0 threads
        if [[ "$pid" != "$comp_thread" && "$pid" != "$async_thread" ]]; then
            # Try to move off the CPU first
            if taskset -p -c 0 "$pid" 2>/dev/null; then
                # Verify it actually moved (managed IRQs report success but stay put)
                new_cpu=$(ps -o psr= -p "$pid" 2>/dev/null | tr -d ' ')
                if [[ "$new_cpu" == "$target_cpu" ]]; then
                    # Managed IRQ: can't move, demote to SCHED_OTHER instead
                    chrt -o -p 0 "$pid" 2>/dev/null && \
                        echo "  Demoted $comm (PID $pid) to SCHED_OTHER on CPU $target_cpu (managed IRQ)"
                else
                    echo "  Moved $comm (PID $pid) from CPU $target_cpu to CPU $new_cpu"
                fi
            fi
        fi
    done
done
set -x

# Dual-port fix: if ethtool -L ran and reset the sibling port's affinity, re-pin it.
# On dual-port cards, ethtool -L on one port resets IRQ thread affinities for both ports.
# We save/restore sibling state using a temp file keyed by PCI bus address.
pci_bus="${pci%.*}"  # e.g. ae:00 (strip .0 or .1)
state_dir="/tmp/config_sh_irq_state"
mkdir -p "$state_dir"

# Save our comp0/async0 state so the sibling config.sh run can restore us
{ set +x; } 2>/dev/null
echo "$irq_cpu $irq_prio $comp_thread" > "$state_dir/${pci}_comp0"
if [[ -n "$async_thread" ]]; then
    echo "$irq_cpu $ksoftirqd_prio $async_thread" > "$state_dir/${pci}_async0"
fi

# Check if sibling port was already configured — if so, restore its affinity
for state_file in "$state_dir/${pci_bus}."*_comp0; do
    [[ -f "$state_file" ]] || continue
    # Skip our own state file
    [[ "$state_file" == "$state_dir/${pci}_comp0" ]] && continue
    read -r sib_cpu sib_prio sib_pid < "$state_file"
    if [[ -n "$sib_pid" ]] && kill -0 "$sib_pid" 2>/dev/null; then
        sib_comm=$(cat /proc/$sib_pid/comm 2>/dev/null)
        current_cpu=$(ps -o psr= -p "$sib_pid" 2>/dev/null | tr -d ' ')
        if [[ "$current_cpu" != "$sib_cpu" ]]; then
            echo "  Dual-port fix: $sib_comm (PID $sib_pid) drifted to CPU $current_cpu, re-pinning to CPU $sib_cpu"
            taskset -p -c "$sib_cpu" "$sib_pid" 2>/dev/null
        fi
        chrt -f -p "$sib_prio" "$sib_pid" 2>/dev/null
    fi
done
for state_file in "$state_dir/${pci_bus}."*_async0; do
    [[ -f "$state_file" ]] || continue
    [[ "$state_file" == "$state_dir/${pci}_async0" ]] && continue
    read -r sib_cpu sib_prio sib_pid < "$state_file"
    if [[ -n "$sib_pid" ]] && kill -0 "$sib_pid" 2>/dev/null; then
        sib_comm=$(cat /proc/$sib_pid/comm 2>/dev/null)
        current_cpu=$(ps -o psr= -p "$sib_pid" 2>/dev/null | tr -d ' ')
        if [[ "$current_cpu" != "$sib_cpu" ]]; then
            echo "  Dual-port fix: $sib_comm (PID $sib_pid) drifted to CPU $current_cpu, re-pinning to CPU $sib_cpu"
            taskset -p -c "$sib_cpu" "$sib_pid" 2>/dev/null
        fi
        chrt -f -p "$sib_prio" "$sib_pid" 2>/dev/null
    fi
done
set -x

# ksoftirqd priority
ksoftirqd_pid=$(pgrep -x "ksoftirqd/$irq_cpu")
if [[ -n "$ksoftirqd_pid" ]]; then
    chrt -f -p "$ksoftirqd_prio" "$ksoftirqd_pid"
    { set +x; } 2>/dev/null
    echo ""
    echo "=== ksoftirqd/$irq_cpu ==="
    echo "  Priority: $(chrt -p $ksoftirqd_pid)"
    echo ""
    set -x
fi

# --- PCIe power management disable ---
setpci -s "$pci" 0xd0.b=0x00

# --- PTP clock setup ---
if [[ "$skip_ptp" -eq 0 && -n "$ptp_source" ]]; then
    # Kill ALL phc2sys instances — continuous PHC adjustment during the test
    # causes backward clock jumps (negative deltas). Each side of rant only
    # compares timestamps from its OWN PHC, so drift from wall clock is irrelevant.
    pkill -f "phc2sys" 2>/dev/null || true
    sleep 0.5

    # Step-correct PHC to system time (for human-readable log timestamps only)
    phc_ctl "$ptp_source" set $(date +%s.%N) 2>/dev/null || true

    { set +x; } 2>/dev/null
    echo ""
    echo "=== PTP clock ==="
    echo "  PHC device: $ptp_source"
    echo "  Mode:       step-corrected to system time, then free-running"
    echo "  Note:       phc2sys killed — PHC will drift ~1ppm from wall clock"
    echo "              This does NOT affect latency measurements (same-clock deltas)"
    echo ""
    set -x
fi

{ set +x; } 2>/dev/null
echo ""
echo "=== SUCCESS ==="
echo "  Interface $ifname configured in namespace ns_${ifname}"
echo "  IP: ${ip_addr}/24, Remote: ${remote_ip}"
echo "  App CPU: $cpu, IRQ CPU: $irq_cpu"
echo ""
