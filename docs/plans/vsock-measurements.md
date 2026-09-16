# Vsock Stage 15 measurements

These are single functional-test observations on 2026-09-16, not acceptance
thresholds, percentiles, peak-throughput claims, or a controlled comparison
against the pre-vsock revision. Production code is at `bf4539d8`; the
measurement-only patch and source hashes are preserved in
`/tmp/vsock-stage15-gate.b3pd2N/`.

## Configuration and validation

Host: Intel Core i7-11800H, 16 logical CPUs. Each VM uses four vCPUs and 1 GiB
RAM. Installed VMMs are QEMU 10.2.1, Cloud Hypervisor 52.0, and Firecracker
1.15.1. QEMU uses vhost-device-vsock 0.3.0, queue size 256, and shared memfd
RAM; the other VMMs use their built-in UDS proxies. Guest CID is 3, host CID
is 2, and the host service port is 70000. The implementation retains the D7
bounds: 64 streams, 32 listeners, eight children and eight pending accepts per
listener, and 128 KiB RX storage per stream.

Both profiles passed image builds, component/native-network tests, all twenty
peer actions, discovery, formatting, source-hash checks, and Clippy without
new warnings. Every measurement below accompanies a functional PASS; byte,
credit, EOF, and cleanup assertions remain active. The full M2 repeated gate
is separate.

## Boot, activation, and transfer observations

Boot is the guest's “most services up” timestamp before the discovery command.
The two columns within each boot cell are System-console/IP-disabled boots
with vsock absent and attached-but-unused. Image, VMM, profile, vCPUs, RAM,
and backing match within each pair; QEMU's disabled measurement also used
`MOTO_SHARED_MEM=1`. Single samples still include scheduling/startup noise
and do not establish an attributable overhead or regression.

The unchanged standard QEMU no-device topology, with its ordinary NIC and
default non-shared RAM, booted at 489 ms debug and 107 ms release. Do not
subtract these from the System/IP-disabled observations. The earlier release
baseline was 108 ms, also an observation rather than a controlled benchmark.

| VMM/profile | Boot absent / attached (ms) | First CID (ms) | Warm CID (µs) | Mean framed 1-byte RTT (µs) | Duplex payload (MiB/s) | Coexistence payload (MiB/s) |
| --- | --- | --- | --- | --- | --- | --- |
| QEMU debug | 501 / 516 | 10.257 | 538.1 | 285.8 | 64.6 | 33.3 |
| CHV debug | 317 / 313 | 7.844 | 1312.9 | 295.4 | 59.8 | 13.3 |
| FC debug | 259 / 273 | 8.018 | 536.2 | 376.9 | 67.0 | 39.1 |
| QEMU release | 121 / 132 | 6.186 | 33.9 | 110.9 | 207.0 | 82.5 |
| CHV release | 39 / 29 | 4.426 | 25.4 | 105.6 | 219.3 | 32.7 |
| FC release | 16 / 15 | 5.123 | 34.1 | 63.6 | 178.0 | 144.4 |

CID timing measures the native query round trip, including lazy activation
on its first use. The RTT is the mean of 128 sequential framed one-byte
request/echo exchanges on one already-connected stream. It excludes connect
and final EOF but includes native framing, copies, and scheduling.

Duplex times 3 MiB aggregate application payload across concurrent send/read
work. Coexistence times 1 MiB aggregate payload while filesystem and TCP/UDP
work overlaps, including synchronization and worker completion. Both exclude
framing bytes from the numerator. Their volumes, barriers, and workloads
differ: do not divide these rates to claim a controlled slowdown or peak
throughput. Exact byte patterns, work completion, and EOF are checked.

## Memory observations

All values below are whole-process sys-io page usage, not attributed vsock
allocator residency. Activation is sampled after availability and after the
first/warm CID queries. Capacity includes one control stream, 63 newly admitted
streams, eight listeners and their channels. Thus the quotient per 63 streams
also contains listener/channel cost and allocator growth. Cleanup may retain
allocator capacity; its nonzero delta is not a count of unreclaimed streams.

| VMM/profile | Before / after activation (KiB) | Activation delta (KiB) | Control / full / cleanup (KiB) | Full delta / 63 (KiB) |
| --- | --- | --- | --- | --- |
| QEMU debug | 39904 / 40520 | 616 | 50936 / 63388 / 51132 | 197.7 |
| CHV debug | 41884 / 42564 | 680 | 52980 / 65400 / 53144 | 197.1 |
| FC debug | 41384 / 42064 | 680 | 52848 / 65200 / 52944 | 196.1 |
| QEMU release | 25720 / 26336 | 616 | 34000 / 46448 / 34192 | 197.6 |
| CHV release | 27700 / 28380 | 680 | 36440 / 48888 / 36632 | 197.6 |
| FC release | 27200 / 27880 | 680 | 35940 / 48388 / 36132 | 197.6 |

These measurements do not justify changing the approved resource limits.
Exact fixed-pool sizes and ownership remain defined and tested in
virtio-async; these process-level deltas are an empirical footprint estimate.

## Idle CPU and waits

Each sample requests 100 ms; actual intervals were 100.221–100.948 ms.
Four kernel metric queries per snapshot are disclosed in the logs. CPU is
the delta in cumulative process TSC ticks divided by the actual elapsed TSC
interval, expressed below as a percentage of one core. The interval includes
observer queries. These early post-boot/query/activation windows can include
settling work, so they are not steady-state averages.

Each cell is **CPU % / wait-count delta / wake-count delta**:

| VMM/profile | Endpoint disabled | Attached unused | After availability | After activation |
| --- | --- | --- | --- | --- |
| QEMU debug | 0.0000 / 0 / 0 | 0.0000 / 0 / 0 | 0.1879 / 1 / 0 | 0.7258 / 4 / 0 |
| CHV debug | 2.9411 / 4 / 0 | 0.2031 / 1 / 0 | 0.4397 / 2 / 0 | 0.6873 / 1 / 0 |
| FC debug | 2.5776 / 4 / 0 | 2.4351 / 4 / 0 | 0.4635 / 3 / 0 | 0.1697 / 1 / 0 |
| QEMU release | 0.0000 / 0 / 0 | 0.0000 / 0 / 0 | 0.6940 / 7 / 0 | 0.0083 / 1 / 0 |
| CHV release | 0.0224 / 2 / 0 | 0.0136 / 2 / 0 | 0.0070 / 1 / 0 | 0.0077 / 1 / 0 |
| FC release | 0.0281 / 2 / 0 | 0.0124 / 2 / 0 | 0.0314 / 1 / 0 | 0.0121 / 1 / 0 |

The standard QEMU NIC-present/no-vsock sample was 16.8693% / 195 / 28 in
debug and 0.0527% / 4 / 0 in release. It includes ordinary IP/service activity
and is not a vsock idle baseline for the IP-disabled topology. The temporary
collector also ran a redundant discovery call labeled `nonstandard`; that
label is excluded from the standard-topology comparison.

No queues or device pumps are created until activation in the reviewed code.
The zero attached-unused QEMU sample is consistent with that design, but a
100 ms whole-process sample alone cannot prove the absence of all background
work on every VMM.

## Raw evidence

The parent directory contains builds, Clippy, focused no-device logs, the
tested patch/hashes, and per-VMM results. Discovery directories contain
`present-console.log` and `disabled-console.log`; peer directories contain
the guest action logs and `console.log`.

| VMM/profile | Discovery directory | Peer directory |
| --- | --- | --- |
| QEMU debug | `/tmp/test-vsock.latSlN` | `/tmp/test-vsock.iilVoW` |
| CHV debug | `/tmp/test-vsock.oVpVmk` | `/tmp/test-vsock.reAaqN` |
| FC debug | `/tmp/test-vsock.98z28A` | `/tmp/test-vsock.ZiuKmV` |
| QEMU release | `/tmp/test-vsock.VVfCet` | `/tmp/test-vsock.xdbmd3` |
| CHV release | `/tmp/test-vsock.PuReb2` | `/tmp/test-vsock.7f07FW` |
| FC release | `/tmp/test-vsock.SCTlM7` | `/tmp/test-vsock.F7KvZB` |

See [the implementation plan](vsock.md) for milestone status and
[the native API guide](../vsock.md) for application usage.
