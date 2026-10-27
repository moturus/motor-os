# WireGuard measurements

Initial release measurements captured on 2026-10-25. These are short local
screening runs, not a throughput guarantee or a statistical comparison.

The host was an Intel Core i7-11800H (8 cores, 16 threads). Each mode used a
fresh QEMU/KVM VM over moto-tap, with either 4 vCPUs and 1024 MiB or 1 vCPU
and 256 MiB. CPU affinity and frequency were not fixed.

The guest ran rnetbench against a host server in every mode. Physical used
the host's ordinary rnetbench and Linux TCP stack. Plain and WireGuard used
the same host moto-netstack service, inner addresses, MTU 1420 and physical
UDP path; only WireGuard encrypted the packets. The plain guest provider
and `wg` have different bounded forwarding loops, so their difference
includes scheduling as well as cryptography. The physical reference also
has a different host TCP stack.

Each row covers three two-second phases: 64-byte TCP request/reply, upload
and download. The buffer column applies to throughput; request/reply always
uses 64 bytes. Both host implementations honor the requested throughput
buffer size. TX and RX are from the guest's perspective. RTT is the mean
request/reply iteration time, not a tail-latency percentile.

| vCPU/MiB | Mode      | Buffer | RR/s  | RTT us | TX MiB/s | RX MiB/s |
|----------|-----------|--------|-------|--------|----------|----------|
| 4 / 1024 | physical  | 64 B   | 30851 | 32.41  | 29.77    | 14.80    |
| 4 / 1024 | physical  | 64 KiB | 30517 | 32.77  | 2249.03  | 1000.54  |
| 4 / 1024 | plain     | 64 B   | 9414  | 106.22 | 30.37    | 26.70    |
| 4 / 1024 | plain     | 64 KiB | 9454  | 105.77 | 257.54   | 168.37   |
| 4 / 1024 | wireguard | 64 B   | 11832 | 84.51  | 27.99    | 26.94    |
| 4 / 1024 | wireguard | 64 KiB | 11872 | 84.23  | 286.88   | 266.16   |
| 1 / 256  | physical  | 64 B   | 12054 | 82.96  | 42.95    | 15.21    |
| 1 / 256  | physical  | 64 KiB | 12054 | 82.96  | 1223.33  | 650.94   |
| 1 / 256  | plain     | 64 B   | 4682  | 213.58 | 13.49    | 15.29    |
| 1 / 256  | plain     | 64 KiB | 4739  | 210.97 | 140.92   | 142.96   |
| 1 / 256  | wireguard | 64 B   | 4597  | 217.49 | 9.66     | 10.74    |
| 1 / 256  | wireguard | 64 KiB | 4592  | 217.75 | 159.95   | 37.01    |

CPU percentages are fractions of one core, so multithreaded processes can
exceed 100%. Sys-io and client cells list request/reply, upload and download
in that order. Provider CPU covers the entire approximately 6.2-second
row, including the brief gaps between phases; physical has no provider.

| vCPU/MiB | Mode      | Buffer | Sys-io CPU %       | Client CPU %         | Provider % |
|----------|-----------|--------|--------------------|----------------------|------------|
| 4 / 1024 | physical  | 64 B   | 99.2 / 99.5 / 95.2 | 77.5 / 192.6 / 113.3 | -          |
| 4 / 1024 | physical  | 64 KiB | 99.3 / 98.4 / 83.7 | 77.5 / 124.3 / 105.3 | -          |
| 4 / 1024 | plain     | 64 B   | 98.1 / 64.4 / 98.5 | 25.5 / 136.0 / 35.3  | 45.2       |
| 4 / 1024 | plain     | 64 KiB | 99.0 / 95.5 / 77.2 | 25.6 / 85.6 / 77.9   | 68.1       |
| 4 / 1024 | wireguard | 64 B   | 98.9 / 83.5 / 97.0 | 30.4 / 137.2 / 34.2  | 76.0       |
| 4 / 1024 | wireguard | 64 KiB | 99.1 / 94.7 / 96.9 | 30.4 / 67.7 / 37.6   | 86.8       |
| 1 / 256  | physical  | 64 B   | 63.3 / 5.9 / 43.0  | 30.2 / 93.1 / 48.2   | -          |
| 1 / 256  | physical  | 64 KiB | 63.4 / 60.2 / 42.2 | 30.2 / 30.1 / 50.2   | -          |
| 1 / 256  | plain     | 64 B   | 59.7 / 46.6 / 57.2 | 11.9 / 35.9 / 11.8   | 19.2       |
| 1 / 256  | plain     | 64 KiB | 59.9 / 71.4 / 60.8 | 12.0 / 8.9 / 19.8    | 15.4       |
| 1 / 256  | wireguard | 64 B   | 53.5 / 40.8 / 44.1 | 11.6 / 25.3 / 13.5   | 31.7       |
| 1 / 256  | wireguard | 64 KiB | 53.5 / 64.5 / 12.9 | 11.6 / 7.9 / 3.9     | 20.1       |

The following are kernel wait/wake call counts, summed across the three
measured phases for sys-io and rnetbench, and across the entire row for the
provider. These are scheduling/IPC proxies, not counts of packet messages:
the processes also wait and wake for timers and other work.

| vCPU/MiB | Mode      | Buffer | Sys-io wait/wake | Client wait/wake | Provider wait/wake |
|----------|-----------|--------|------------------|------------------|--------------------|
| 4 / 1024 | physical  | 64 B   | 398174/303773    | 440420/2846988   | -                  |
| 4 / 1024 | physical  | 64 KiB | 267970/470681    | 1247688/873372   | -                  |
| 4 / 1024 | plain     | 64 B   | 202857/432373    | 196905/1227670   | 311396/416646      |
| 4 / 1024 | plain     | 64 KiB | 115006/1273445   | 1095135/225187   | 605985/851120      |
| 4 / 1024 | wireguard | 64 B   | 205924/379575    | 355656/1289318   | 183182/287279      |
| 4 / 1024 | wireguard | 64 KiB | 144432/1397933   | 1230538/216088   | 144621/806414      |
| 1 / 256  | physical  | 64 B   | 131794/96736     | 164673/146198    | -                  |
| 1 / 256  | physical  | 64 KiB | 163031/930127    | 168254/609463    | -                  |
| 1 / 256  | plain     | 64 B   | 151573/155938    | 121412/73349     | 145979/180502      |
| 1 / 256  | plain     | 64 KiB | 122610/967328    | 91867/91785      | 102108/777929      |
| 1 / 256  | wireguard | 64 B   | 117331/155164    | 83800/62872      | 85707/119728       |
| 1 / 256  | wireguard | 64 KiB | 81429/764700     | 65904/81176      | 47723/316311       |

Each registered packet device reserved 188,928 bytes of private packet
storage. RX/TX queue capacity was 64 packets each. The final high-water
marks below cover both buffer-size runs. Sys-io reported zero malformed
packets and zero full-RX-queue drops in every run. Host fixture rejection
and application-queue drop counters were also zero; those counters do not
include UDP drops in the host kernel.

| vCPU/MiB | Mode      | RX high-water | TX high-water |
|----------|-----------|---------------|---------------|
| 4 / 1024 | plain     | 29            | 64            |
| 4 / 1024 | wireguard | 31            | 64            |
| 1 / 256  | plain     | 31            | 56            |
| 1 / 256  | wireguard | 32            | 56            |

The four-vCPU WireGuard sample reached 287 MiB/s upload and 266 MiB/s
download, with sys-io near one fully occupied core. Its better results than
the plain sample do not imply that encryption is free: the forwarding
loops differ, and these runs are short. The single-vCPU WireGuard download
sample was much lower, at 37 MiB/s; do not extrapolate the four-vCPU result
to a small VM.

A second single-vCPU WireGuard run collected the existing drop counters to
investigate that result. Its 64 KiB upload was 159.83 MiB/s and download
11.34 MiB/s. All reported WireGuard rejection/drop/failure counters,
sys-io UDP transmit-drop counters, packet-device RX drops and host fixture
drops were zero. These counters do not cover every networking layer, so
they do not explain the low receive utilization. Preserve this variability
as a limitation of the initial measurements; further profiling is needed.

Keep one packet per IPC message for v1. Batching is worth a follow-up
profiling experiment because sys-io CPU, wait/wake activity and the TX
queue reach high levels. These measurements do not establish that IPC is
the bottleneck or that larger batches would preserve latency and fairness.
Measure those effects before changing the protocol or queue limits.

Reproduce the three modes with:

```sh
src/tests/bench-wireguard.sh physical
src/tests/bench-wireguard.sh plain
src/tests/bench-wireguard.sh wireguard
MOTO_SMP=1 MOTO_MEMORY_MIB=256 src/tests/bench-wireguard.sh physical
MOTO_SMP=1 MOTO_MEMORY_MIB=256 src/tests/bench-wireguard.sh plain
MOTO_SMP=1 MOTO_MEMORY_MIB=256 src/tests/bench-wireguard.sh wireguard
```

Run these serially with other CPU-intensive jobs stopped. The script
generates temporary keys, runs local endpoints and removes them afterward.
The integration suite separately exercises bounded-queue saturation,
timer progress, physical ping and filesystem progress under tunnel load.
