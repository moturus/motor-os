//! sys-io's own unit tests, run inside a live sys-io.
//!
//! sys-io cannot be tested on the host: `moto-async` refuses to build off a
//! Motor target, and nothing runs a Motor-target `cargo test`. Tests written
//! next to the code they cover were therefore never executed by any harness.
//! They run here instead -- compiled into debug builds only, triggered over the
//! socket-stats service, and reported back to the caller, which is systest.
//!
//! Failures are returned rather than asserted. sys-io is `panic = "abort"`, so
//! an assertion that fired here would take the whole network stack down with
//! it, and a test failure would present as a dead VM instead of a message.

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

/// What a run of the suite produced.
#[derive(Default)]
pub(crate) struct Outcome {
    pub(crate) tests_run: u32,
    pub(crate) failures: u32,
    /// The first failure, as "name: message". Empty when nothing failed.
    pub(crate) first_failure: String,
}

/// Run every registered self-test. Never panics, whatever the tests do with
/// their own data.
pub(crate) fn run_all() -> Outcome {
    let mut outcome = Outcome::default();

    for (name, test) in crate::runtime::net::SELF_TESTS
        .iter()
        .chain(crate::runtime::fs::SELF_TESTS)
        .copied()
        .flatten()
    {
        outcome.tests_run += 1;
        if let Err(err) = test() {
            outcome.failures += 1;
            log::error!("sys-io self-test '{name}' FAILED: {err}");
            if outcome.first_failure.is_empty() {
                outcome.first_failure = format!("{name}: {err}");
            }
        }
    }

    log::info!(
        "sys-io self-test: {} run, {} failed",
        outcome.tests_run,
        outcome.failures
    );
    outcome
}
