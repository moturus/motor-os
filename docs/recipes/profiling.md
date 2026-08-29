# Performance Profiling Motor OS Applications

While most standard debugging and profiling tools do not work
with Motor OS yet, it is possible to instrument and profile
a Motor OS binary in order to e.g. figure out the causes of
high CPU contention.

Briefly, here are the steps:

## Code instrumentation

* add `tracing` crate to your crates' Cargo.toml: `tracing = { version = "0.1", default-features = false, features = ["attributes"] }`
* add `use tracing::instrument;` to the module(s) you want to instrument
* add `#[instrument(skip_all)]` annotations to the functions you want
to instrument ([docs](https://docs.rs/tracing/0.1.43/tracing/attr.instrument.html))
* wrap code blocks you want to instrument inside functions with
`tracing::trace_span!("nonlocal").in_scope(|| { /* */ });` ([docs](https://docs.rs/tracing/0.1.43/tracing/struct.Span.html#method.in_scope))
* add the following to your binary's Cargo.toml:

```toml
tracing = "0.1"
tracing-subscriber = "0.3"
tracing-flame = "0.2"
```

* in the binary, wrap the region you want to profile with:

```Rust
use tracing_flame::FlameLayer;
use tracing_subscriber::prelude::*;

const FNAME: &str = "/profile.folded";
let file = std::fs::File::create(FNAME).unwrap();
let (flame_layer, guard) = FlameLayer::with_file(FNAME).unwrap();
tracing_subscriber::registry().with(flame_layer).init();

tracing::info_span!("profiling_root").in_scope(|| {
     /* place the code you want to profile here */
});
core::mem::drop(guard); // This will write the trace into the file.
```

## Profile traces collection and visualization

* run your binary in Motor OS
* scp the profile out to your Linux host: `scp -P 2222 motor@192.168.4.2:/profile.folded .`
* run `cargo install inferno`
* run cat `profile.folded | inferno-flamegraph > profile.svg`

Now you have your binary's CPU profile flame graph in `profile.svg`.

Note: you may need to manually edit profile.folded (it is a text file) or fiddle with options to make the flame graph more readable.

## Built-in microbenchmarks

`systest` carries three measurement tools next to its test suite (on the
development image it is `/devtools/tests/systest`; on the standard image,
copy `build/bin/release/systest` into the VM first). A bare `systest` runs
the suite only; each tool has its own subcommand and prints to stdout.

* `systest wake-bench` measures a cross-thread wake/wait hop: ns per
  roundtrip and per hop for the kernel's three wake shapes (`wake()` then
  `wait()`, `wait(wake_target)`, `wait(swap_target)`), with the two threads
  unaffined, on the same CPU, and on different CPUs (the last needs at
  least three CPUs). It is the first number to look at on a new host or
  hypervisor: a synchronous file operation costs several such hops, and on
  KVM a cross-CPU hop is about 1 us with the kernel's idle polling and
  about 25 us without it (an IPI exit plus a halted vCPU wake-up).
* `systest fs-bench [prefix]` measures file I/O per phase: cache-hot
  sequential reads of 4 KB to 1 MB (`hot_seq_4k` .. `hot_seq_1m`), hot
  random 4 KB reads, writes with 1 MB, 64 KB and 4 KB chunks, cold reads
  that go to the device (`cold_seq_4k`, `cold_seq_1m`, `cold_fs_read`,
  `cold_rand_4k`), `stat` and `open_close`. Each phase prints us/op and
  MB/s with the counters that explain them: wait/wake syscalls and page
  maps of sys-io and of the benchmark process, kernel IRQs and wake-up
  IPIs, block cache hits/misses and device reads/writes, and CPU time per
  CPU. A prefix runs only the phases whose name starts with it, for
  example `systest fs-bench hot_seq` (the large writes always run: the
  cold phases read the files they leave). The files go under `TMPDIR`,
  which must be writable: `TMPDIR=/user/tmp systest fs-bench`. Wait a few
  seconds after boot; the tool reads sys-io's statistics provider, which
  registers shortly after start.
* `systest close-race [iters]` and `systest close-race-child [iters]`
  reproduce loopback TCP close ordering: a server accepts, reads `ping`,
  writes `pong` and drops the stream; the client must read `pong`, never
  a connection reset. The first keeps everything in one process (default
  2000 iterations; accepting from one's own listener slows to about one
  per second after a dozen connections, so a small count is enough), the
  second uses a fresh listener per iteration and a child process for the
  client (default 200; it needs the spawn capability a shell child has).
  Both print the ok / ConnectionReset / other counts.

For your own experiments, `stats get` (the `stats` command) reads the same
counters: the kernel's include `sched.poll_hit`, `sched.ipi_elided`,
`sys_cpu_waits` and `sys_cpu_wakes`; read them before and after a run and
take the difference.
