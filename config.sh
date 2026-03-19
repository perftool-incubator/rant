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
#   --irq-prio <n>           IRQ thread FIFO priority (default: 55)
#   --ksoftirqd-prio <n>     ksoftirqd FIFO priority (default: 11)
#   -h, --help               Show this help

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
busy_poll=0
ptp_source=""
ptp_sync_to=""
skip_namespace=0
skip_ptp=0
irq_prio=55
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

# PTP clock (auto-detect from sysfs)
if [[ -z "$ptp_source" ]]; then
    ptp_dev=$(ls -d /sys/class/net/"$ifname"/device/ptp/ptp* 2>/dev/null | head -1)
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
$ns_cmd ethtool -L "$ifname" combined 1
$ns_cmd ethtool -K "$ifname" rx-checksumming off tx-checksumming off
$ns_cmd ethtool -K "$ifname" lro off gro off
$ns_cmd ethtool -K "$ifname" tso off gso off
$ns_cmd ethtool -C "$ifname" rx-frames 1 tx-frames 1
$ns_cmd ethtool -C "$ifname" adaptive-tx off adaptive-rx off rx-usecs 0 tx-usecs 0
$ns_cmd ethtool -G "$ifname" rx 512 tx 512
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
$ns_cmd ip addr add "${ip_addr}/24" dev "$ifname"

# Qdisc
$ns_cmd tc qdisc replace dev "$ifname" root noqueue

# Static ARP and traffic reduction
$ns_cmd ip neigh flush all
if [[ -n "$remote_mac" ]]; then
    $ns_cmd ip neigh replace "$remote_ip" lladdr "$remote_mac" dev "$ifname"
fi
$ns_cmd ip neigh show all
$ns_cmd ip link set "$ifname" promisc on
$ns_cmd sysctl -w "net.ipv6.conf.$ifname.disable_ipv6=1"
$ns_cmd ip link set "$ifname" multicast off
$ns_cmd ip link set "$ifname" arp off
$ns_cmd sysctl -w net.ipv4.conf.all.arp_ignore=1
$ns_cmd sysctl -w net.ipv4.conf.all.arp_announce=2

# --- CPU isolation and IRQ affinity ---
tuna isolate -c "$cpu,$irq_cpu"

irq_thread=$(pgrep -f "$irq_pattern" | head -1)
if [[ -n "$irq_thread" ]]; then
    tuna move -q "*${irq_pattern}*" -c "$irq_cpu"
    chrt -f -p "$irq_prio" "$irq_thread"
    { set +x; } 2>/dev/null
    echo ""
    echo "=== IRQ thread ==="
    echo "  PID:      $irq_thread"
    echo "  CPU:      $(cat /proc/$irq_thread/status 2>/dev/null | grep Cpus_allowed_list)"
    echo "  Priority: $(chrt -p $irq_thread)"
    echo ""
    set -x
else
    echo "WARNING: IRQ thread matching *${irq_pattern}* not found"
fi

# ksoftirqd priority
ksoftirqd_pid=$(pgrep -x "ksoftirqd/$irq_cpu")
if [[ -n "$ksoftirqd_pid" ]]; then
    chrt -f -p "$ksoftirqd_prio" "$ksoftirqd_pid"
    { set +x; } 2>/dev/null
    echo "=== ksoftirqd/$irq_cpu ==="
    echo "  Priority: $(chrt -p $ksoftirqd_pid)"
    echo ""
    set -x
fi

# --- PCIe power management disable ---
setpci -s "$pci" 0xd0.b=0x00

# --- PTP sync ---
if [[ "$skip_ptp" -eq 0 && -n "$ptp_source" ]]; then
    if [[ -n "$ptp_sync_to" ]]; then
        # Sync source PTP clock to another PTP device (e.g. port0 -> port1)
        phc2sys -s "$ptp_source" -c "$ptp_sync_to" -O 0 -S 0.0 -q &
    else
        # Sync PTP clock to system clock
        phc2sys -s "$ptp_source" -O 0 -S 0.0 -P 1.0 -I 0.1 -R 16 -q &
    fi
fi

{ set +x; } 2>/dev/null
echo ""
echo "=== SUCCESS ==="
echo "  Interface $ifname configured in namespace ns_${ifname}"
echo "  IP: ${ip_addr}/24, Remote: ${remote_ip}"
echo "  App CPU: $cpu, IRQ CPU: $irq_cpu"
echo ""
