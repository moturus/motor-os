//! Trigger sys-io's in-process self-tests and report their verdict.
//!
//! sys-io has no reachable `cargo test`: it cannot build for the host, and no
//! harness runs a Motor-target one. Its unit tests therefore live inside sys-io
//! itself and run here, against the sys-io actually serving this VM. Debug
//! builds only, on both sides -- a release sys-io has no self-tests compiled in.

#[cfg(debug_assertions)]
pub fn run_all_tests() {
    let mut service = moto_sys_io::stats::IoStatsService::connect().unwrap();
    let outcome = service.run_self_tests().unwrap();

    assert_eq!(
        0, outcome.failures,
        "sys-io self-tests: {} of {} failed, first: {}",
        outcome.failures, outcome.tests_run, outcome.first_failure
    );
    // A suite that silently became empty would otherwise "pass" forever.
    assert!(
        outcome.tests_run > 0,
        "sys-io reported no self-tests at all"
    );

    println!("-- sys_io_self_test: {} tests PASS", outcome.tests_run);
}

/// Release builds have no self-tests to run.
#[cfg(not(debug_assertions))]
pub fn run_all_tests() {}
