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
