# Gears P0 performance baseline

Recorded 2026-08-13 from release build `f894fed14c20` on Linux
7.0.0-29-generic, using an Intel Core i9-10885H host (8 cores, 16 threads).
The Motor samples used KVM with `-cpu host`, 4 vCPUs, and 1024 MiB RAM.

Reproduce the measurements and write the machine-readable result with:

```sh
GEARS_BASELINE_REPORT=/tmp/gears-p0-baseline.txt \
  src/tests/gears-test.sh --release --baseline
```

The command takes exactly three samples. `spread` is
`(maximum - minimum) / median`; a spread above the approved 10% threshold is
reported as noisy rather than retried or replaced. These observations describe
the POC and are not performance budgets. Step 15 establishes the P0 gates.

| Platform | Metric | Samples | Median | Spread | State |
|---|---|---:|---:|---:|---|
| Linux | startup (µs) | 579, 557, 1008 | 579 | 77% | noisy |
| Linux | peak RSS (bytes) | 3837952, 3866624, 3850240 | 3850240 | 0% | stable |
| Linux | foreground tool turnaround (µs) | 7554, 8811, 18288 | 8811 | 121% | noisy |
| Motor | startup (µs) | 2898, 2606, 8829 | 2898 | 214% | noisy |
| Motor | sampled process memory (bytes) | 4505600, 4505600, 4505600 | 4505600 | 0% | stable |
| Motor | foreground tool turnaround (µs) | 20919, 21066, 23960 | 21066 | 14% | noisy |

Startup wraps `gears --version`. Memory is sampled during a complete scripted
agent tool round: Linux reads the process's `VmHWM`; Motor polls the existing
`pstat` `memory_usage` metric every 2 ms. The Motor metric is process virtual
memory and is therefore not directly comparable to Linux RSS. Foreground tool
turnaround is the interval between the mock receiving the initial request and
receiving the follow-up after Gears executes its scripted `write_file` call.
It deliberately includes response handling and construction of the next
provider request because that is the user-visible foreground path.

The provider is the test-only loopback TLS mock. No external network service or
real provider participates in any sample.
