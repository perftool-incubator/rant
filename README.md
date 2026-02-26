# rant
Round-trip And Network Timing

`rant` is Emit/Reflect test (Request/Response), a typical "ping-pong" test
to measure latency.

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
### T4: Client receives ping packet
* `T4_HW`: HW timestamp when packet is actually received off the wire
* `T4_SW`: SW timestamp when packet is delivered to userspace 

## Metrics
`T4_HW` - `T1_HW`: Hardware Round Trip Time latency
`T3_HW` - `T2_HW`: Hardware Response Time latency

## Run

```
./rant --interface <iface> [OPTIONS]

Required:
    --interface <iface>       Network interface to use

Optional:
    --address <ip>            Server IP address (client mode, omit for server mode)
    --threshold <us>          Stop when latency exceeds threshold (microseconds)
    --duration <sec>          Test duration in seconds
    --warmup <pkts>           Number of warmup packets to discard from statistics
    --sw-timestamps           Collect software timestamps
    --histogram               Show histogram summary
    --log <file>              Write transaction log to file
    --overflow <us>           Histogram overflow bucket threshold (default: 100us)
    --bucket-size <us>        Histogram bucket size (default: 1us)
    --help                    Show help message
```

### Reflect (Server)
```
#  ip netns exec ns_ens7f1np1 taskset --cpu-list 61 chrt -f 2 ./rant --interface ens7f1np1 --threshold 100000 --sw-timestamps
Test is complete.

--- Response Latency Statistics ---
MIN: 10081 ns | MAX: 52957 ns | AVG: 10867 ns | Total Samples: 442191
```

A log file `response.txt` is created with all the transactions:
```
# less response.txt
       SEQ                          T2_HW                          T2_SW                          T3_SW                          T3_HW        RESPONSE
------------------------------------------------------------------------------------------------------------------------------------------------------
         0           1771555281.293211904           1771555281.293247670           1771555281.293248149           1771555281.293264861           52957
...
```

### Emit (Client)
```
# ip netns exec ns_ens7f0np0 timeout -k 3s --signal=SIGINT 10s taskset -c 51 chrt -f 2  ./rant --interface ens7f0np0 --address 192.168.1.11 --threshold 100000 --sw-timestamps
Test is complete.

--- Round-Trip Latency Statistics ---
MIN: 11513 ns | MAX: 54769 ns | AVG: 12301 ns | Total Samples: 442191
```

A log file `response.txt` is created with all the transactions:
```
# less roundtrip.txt
       SEQ                          T1_SW                          T1_HW                          T4_HW                          T4_SW             RTT
------------------------------------------------------------------------------------------------------------------------------------------------------
         0           1771555281.293181657           1771555281.293210998           1771555281.293265767           1771555281.293287981           54769
...
```

## Compile
```
gcc -o rant rant.c
```

## Limitations
Features not implemented:
* Check
  * Clock drift warning: check clock drift
  * Check hw timestamp support
  * Support nic
* Log level
  * Debug mode (verbose mode to debug)
  * -q quiet (no stdout at all)
* Memory allocation: use hugepages as option
