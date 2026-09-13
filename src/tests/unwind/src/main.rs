use std::io::Write;
use std::process::{Command, ExitCode, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const ABORT_STATUS: i32 = -1;

struct Cleanup(Arc<AtomicUsize>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        assert!(std::thread::panicking());
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[inline(never)]
fn cancel(payload: usize, drops: &Arc<AtomicUsize>) {
    let _cleanup = Cleanup(drops.clone());
    std::panic::resume_unwind(Box::new(payload));
}

fn cancel_case() {
    let hooks = Arc::new(AtomicUsize::new(0));
    let counter = hooks.clone();
    std::panic::set_hook(Box::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    let drops = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for worker in 0..4 {
            let drops = &drops;
            scope.spawn(move || {
                for round in 0..32 {
                    let payload = worker * 32 + round;
                    let result = std::panic::catch_unwind(|| {
                        let _outer = Cleanup(drops.clone());
                        let result = std::panic::catch_unwind(|| cancel(payload, drops));
                        std::panic::resume_unwind(result.unwrap_err());
                    });
                    assert_eq!(*result.unwrap_err().downcast::<usize>().unwrap(), payload);
                    assert!(!std::thread::panicking());
                }
            });
        }
    });
    assert_eq!(drops.load(Ordering::SeqCst), 256);
    assert_eq!(hooks.load(Ordering::SeqCst), 0);
}

fn hook_case() {
    let hooks = Arc::new(AtomicUsize::new(0));
    let counter = hooks.clone();
    std::panic::set_hook(Box::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    assert!(std::panic::catch_unwind(|| panic!("ordinary panic")).is_err());
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
    assert!(!std::thread::panicking());
}

fn join_case() {
    let result = std::thread::spawn(|| panic!("joined panic")).join();
    let payload = result.unwrap_err();
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"joined panic"));
    assert!(!std::thread::panicking());
}

#[cfg(feature = "cxx")]
unsafe extern "C-unwind" {
    fn motor_cxx_catch_own() -> i32;
    fn motor_cxx_static_result() -> i32;
    fn motor_cxx_throw();
    fn motor_cxx_catch_through_rust(callback: extern "C-unwind" fn()) -> i32;
    fn motor_cxx_call_rust(callback: extern "C-unwind" fn(), drops: *mut u64);
}

#[cfg(feature = "cxx")]
fn cxx_case() {
    assert_eq!(unsafe { motor_cxx_catch_own() }, 29);
    let panic = std::panic::catch_unwind(|| panic!("Rust panic after C++ catch"));
    assert_eq!(
        panic.unwrap_err().downcast_ref::<&str>(),
        Some(&"Rust panic after C++ catch")
    );
}

#[cfg(feature = "cxx")]
fn cxx_static_case() {
    assert_eq!(unsafe { motor_cxx_static_result() }, 31);
}

#[cfg(feature = "cxx")]
static CXX_THROUGH_RUST_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "cxx")]
struct CxxThroughRustCleanup;

#[cfg(feature = "cxx")]
impl Drop for CxxThroughRustCleanup {
    fn drop(&mut self) {
        CXX_THROUGH_RUST_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(feature = "cxx")]
extern "C-unwind" fn cxx_through_rust_bridge() {
    let _cleanup = CxxThroughRustCleanup;
    unsafe { motor_cxx_throw() };
}

#[cfg(feature = "cxx")]
fn cxx_through_rust_case() {
    CXX_THROUGH_RUST_DROPS.store(0, Ordering::SeqCst);
    assert_eq!(
        unsafe { motor_cxx_catch_through_rust(cxx_through_rust_bridge) },
        37
    );
    assert_eq!(CXX_THROUGH_RUST_DROPS.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "cxx")]
extern "C-unwind" fn rust_through_cxx_bridge() {
    panic!("Rust panic through C++");
}

#[cfg(feature = "cxx")]
fn rust_through_cxx_case() {
    let mut drops = 0_u64;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        motor_cxx_call_rust(rust_through_cxx_bridge, &mut drops);
    }));
    assert_eq!(
        panic.unwrap_err().downcast_ref::<&str>(),
        Some(&"Rust panic through C++")
    );
    assert_eq!(drops, 1);
}

#[cfg(feature = "cxx")]
fn cxx_suite() {
    cxx_case();
    cxx_static_case();
    cxx_through_rust_case();
    rust_through_cxx_case();
}

struct PanicOnDrop;

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        println!("double cleanup entered");
        std::io::stdout().flush().unwrap();
        panic!("cleanup panic");
    }
}

fn double_child() {
    let _cleanup = PanicOnDrop;
    panic!("outer panic");
}

extern "C" fn extern_c_child() {
    panic!("panic crossed an extern C boundary");
}

fn child(case: &str) -> std::io::Result<Output> {
    Command::new(std::env::current_exe()?).arg(case).output()
}

fn expect(case: &str, expected_status: i32, marker: Option<&[u8]>) -> bool {
    let output = match child(case) {
        Ok(output) => output,
        Err(err) => {
            eprintln!("{case}: failed to start child: {err}");
            return false;
        }
    };
    let status = output.status.code();
    let marker_ok = marker.is_none_or(|marker| {
        output
            .stdout
            .windows(marker.len())
            .any(|window| window == marker)
    });
    if status == Some(expected_status) && marker_ok {
        println!("{case} PASS");
        true
    } else {
        eprintln!(
            "{case}: status {status:?}, expected {expected_status}; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }
}

fn unwind_suite() -> bool {
    let cases = [
        expect("cancel", 0, None),
        expect("hook", 0, None),
        expect("join", 0, None),
        expect("abort-child", ABORT_STATUS, None),
        expect(
            "double-child",
            ABORT_STATUS,
            Some(b"double cleanup entered"),
        ),
        expect("extern-c-child", ABORT_STATUS, None),
    ];
    cases.into_iter().all(|passed| passed)
}

fn abort_suite() -> bool {
    expect("cancel", ABORT_STATUS, None) && expect("abort-child", ABORT_STATUS, None)
}

fn main() -> ExitCode {
    let passed = match std::env::args().nth(1).as_deref() {
        Some("cancel") => return run(cancel_case),
        Some("hook") => return run(hook_case),
        Some("join") => return run(join_case),
        Some("abort-child") => {
            let _ = std::panic::catch_unwind(std::process::abort);
            unreachable!()
        }
        Some("double-child") => return run(double_child),
        Some("extern-c-child") => return run(|| extern_c_child()),
        #[cfg(feature = "cxx")]
        Some("cxx") => return run(cxx_case),
        #[cfg(feature = "cxx")]
        Some("cxx-static") => return run(cxx_static_case),
        #[cfg(feature = "cxx")]
        Some("cxx-through-rust") => return run(cxx_through_rust_case),
        #[cfg(feature = "cxx")]
        Some("rust-through-cxx") => return run(rust_through_cxx_case),
        #[cfg(feature = "cxx")]
        Some("cxx-suite") => return run(cxx_suite),
        Some("suite") => unwind_suite(),
        Some("abort-suite") => abort_suite(),
        _ => {
            eprintln!("usage: motor-unwind-test <suite|abort-suite>");
            false
        }
    };
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(case: impl FnOnce()) -> ExitCode {
    case();
    ExitCode::SUCCESS
}
