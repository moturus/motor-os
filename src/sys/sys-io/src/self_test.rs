//! sys-io's own unit tests, run inside a live sys-io.
//!
//! sys-io cannot be tested on the host: `moto-async` refuses to build off a
//! Motor target, and nothing runs a Motor-target `cargo test`. Tests written
//! next to the code they cover run inside a debug sys-io. The isolated cases
//! run here at boot. The two cases that write to live mounts run through
//! `systest live-filesystem-tests` on a disposable debug image.
//!
//! A test returns its failure rather than asserting, so that one failure does
//! not hide the rest: all of them are logged, and then sys-io stops.
//!
//! The tests run on the main thread while the runtime thread serves the
//! system. A test that builds its own runtime must leave alone what the
//! process has only one of, such as the kernel's pager queue.

/// A named test. Returning `Err` fails it; the string is what the caller sees.
pub(crate) type SelfTest = (&'static str, fn() -> Result<(), String>);

/// `assert_eq!` that reports instead of aborting sys-io.
macro_rules! st_assert_eq {
    ($left:expr, $right:expr) => {{
        let (left, right) = ($left, $right);
        if left != right {
            return Err(format!("{}:{}: {left:?} != {right:?}", file!(), line!()));
        }
    }};
}

/// `assert!` that reports instead of aborting sys-io.
macro_rules! st_assert {
    ($cond:expr) => {{
        if !$cond {
            return Err(format!(
                "{}:{}: `{}` is false",
                file!(),
                line!(),
                stringify!($cond)
            ));
        }
    }};
}

pub(crate) use {st_assert, st_assert_eq};

/// Run the isolated boot self-tests. A failure stops sys-io, and with it the VM:
/// a debug boot with a failing test must not look like a working one.
pub(crate) fn run_at_boot() {
    let (mut tests_run, mut failures) = (0_u32, 0_u32);
    // The panic repeats what failed: the console can drop the lines above it.
    let mut failed = String::new();
    // Some tests drive error paths, whose WARN and ERROR lines land in the
    // kernel log between this line and the summary.
    log::info!("sys-io self-test: start; warnings and errors up to the summary are expected");

    for (name, test) in crate::runtime::net::SELF_TESTS
        .iter()
        .chain(crate::runtime::fs::SELF_TESTS)
        .chain(crate::runtime::channel_budget::SELF_TESTS)
        .copied()
        .flatten()
    {
        tests_run += 1;
        if let Err(err) = test() {
            failures += 1;
            log::error!("sys-io self-test '{name}' FAILED: {err}");
            failed.push_str(&format!(" [{name}: {err}]"));
        }
    }

    log::info!("sys-io self-test: {tests_run} run, {failures} failed");
    assert!(
        failures == 0,
        "sys-io self-test: {failures} of {tests_run} failed:{failed}"
    );
}
