# Gears performance and quality baselines

## Release quality gate

The checked-in machine-readable record beside this document is
`performance-quality-baseline.txt`. Reproduce and compare it with:

```sh
src/tests/gears-test.sh --release --baseline
```

To record candidate numbers without comparing them, use the explicit recording
mode and retain the report for review:

```sh
GEARS_QUALITY_BASELINE=record \
GEARS_BASELINE_REPORT=/tmp/gears-quality-candidate.txt \
  src/tests/gears-test.sh --release --baseline
```

The `[quality]` configuration selects the sample count (at least three) and
maximum regression percentage; the defaults are three and 10%. Set
`GEARS_QUALITY_CONFIG` to measure another reviewed policy. Samples are never
retried or replaced. A spread above the configured percentage marks a metric
noisy. Only a stable current metric with a stable baseline is gated, and its
median may not grow by more than the configured percentage. Missing or invalid
baseline entries fail the gate. Noisy metrics retain all observations and are
reported without blocking.

The release scenario records the following on both Linux and Motor OS:

- startup time for `gears --version`;
- process memory during a complete scripted tool round (Linux peak RSS; Motor
  sampled process virtual memory, which is not directly comparable);
- the largest complete provider request and its compact serialized `messages`
  context;
- durable bytes retained under the session and artifact trees, including
  metadata;
- the fixed event-channel capacity exercised by the render backpressure test;
- foreground tool turnaround from the mock receiving the first request until
  it receives the post-tool follow-up.

The measured quality round writes a 70,000-byte file so that the bounded tool
preview necessarily creates a durable artifact. Its TLS SSE responses carry an
exact HTTP length; the separate fragmented-stream scenario retains EOF framing
coverage. The provider is the test-only loopback TLS mock. No external network
service or real provider participates.

## Historical POC baseline

Recorded 2026-08-13 from release build `f894fed14c20` on Linux
7.0.0-29-generic, using an Intel Core i9-10885H host (8 cores, 16 threads).
The Motor samples used KVM with `-cpu host`, 4 vCPUs, and 1024 MiB RAM.

The command took exactly three samples. `spread` is
`(maximum - minimum) / median`; a spread above the approved 10% threshold is
reported as noisy rather than retried or replaced. These observations describe
the POC and are not performance budgets. They are retained only for historical
comparison; the checked-in release record above is the active gate.

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
