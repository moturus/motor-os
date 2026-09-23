use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};

const CHILD: &str = "rt-diagnostic-child";
const ORDINARY_MARKER: &str = "ordinary moto-rt diagnostic marker";
const PANIC_MARKER: &str = "complete piped diagnostic panic";
const BACKTRACE_THREADS: usize = 4;
const BACKTRACES_PER_THREAD: usize = 8;

const WITHOUT_LOG: u64 =
    moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_INTERACTIVE | crate::IO_CAPS;
const WITH_LOG: u64 = WITHOUT_LOG | moto_sys::caps::CAP_LOG;

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg == CHILD)
}

pub fn run_child(args: &[String]) -> ! {
    match args[2].as_str() {
        "records" => {
            assert_eq!(
                0,
                moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_LOG
            );
            assert_eq!(
                Err(moto_rt::E_NOT_ALLOWED),
                moto_sys::SysRay::log("unprivileged direct kernel log")
            );
            moto_rt::moto_log!("{ORDINARY_MARKER}\n");
            assert_eq!(1, moto_rt::internal_helper(1, 0, 0, 0, 0, 0));

            let path = std::path::Path::new(&args[3]);
            let _ = std::fs::remove_dir(path);
            std::fs::create_dir(path).unwrap();
            std::fs::remove_dir(path).unwrap();
            moto_rt::error::log_backtrace(-1);
            std::process::exit(0)
        }
        "panic" => {
            let default_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                default_hook(info);
                moto_rt::error::log_backtrace(-1);
            }));
            panic!("{PANIC_MARKER}")
        }
        "route" => {
            println!("ready");
            std::io::stdout().flush().unwrap();
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
            let mode = args[3].parse().unwrap();
            println!("route={}", moto_rt::internal_helper(1, mode, 0, 0, 0, 0));
            std::process::exit(0)
        }
        "vdso-panic-at-floor" => {
            // The floor refuses stack growth too, and a refused fault on a
            // fresh stack page kills the thread: map what a report may use.
            map_stack_below();

            // Pin the machine at the user floor, where the heap cannot grow,
            // then take every free slot of every size class, the small ones
            // last: from here on no allocation of any size succeeds.
            while moto_sys::SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_SMALL, 8).is_ok() {}
            for shift in (4..=12).rev() {
                let layout = std::alloc::Layout::from_size_align(1 << shift, 8).unwrap();
                // black_box: an allocation that is only compared with null is
                // elided, and the comparison folded to "not null".
                while !std::hint::black_box(unsafe { std::alloc::alloc(layout) }).is_null() {}
            }
            moto_rt::internal_helper(1, 4, 0, 0, 0, 0);
            unreachable!()
        }
        "vdso-nested-panic" => {
            let threads = args[3].parse().unwrap();
            let barrier = std::sync::Barrier::new(threads);
            std::thread::scope(|scope| {
                for _ in 1..threads {
                    scope.spawn(|| {
                        barrier.wait();
                        moto_rt::internal_helper(1, 5, 0, 0, 0, 0);
                    });
                }
                barrier.wait();
                moto_rt::internal_helper(1, 5, 0, 0, 0, 0);
            });
            unreachable!()
        }
        "vdso-multibyte-panic" => {
            moto_rt::internal_helper(1, 6, 0, 0, 0, 0);
            unreachable!()
        }
        "vdso-guarded-panic" => {
            moto_rt::internal_helper(1, 7, 0, 0, 0, 0);
            unreachable!()
        }
        "fd-backtrace-under-guard" => {
            assert_eq!(0, moto_rt::internal_helper(1, 8, 0, 0, 0, 0));
            std::process::exit(0)
        }
        "concurrent-backtraces" => {
            let barrier = std::sync::Barrier::new(BACKTRACE_THREADS);
            std::thread::scope(|scope| {
                for _ in 0..BACKTRACE_THREADS {
                    scope.spawn(|| {
                        barrier.wait();
                        for _ in 0..BACKTRACES_PER_THREAD {
                            deep_backtrace(32);
                        }
                    });
                }
            });
            std::process::exit(0)
        }
        _ => unreachable!(),
    }
}

/// Touches the stack below the caller's frame, which is where whatever the
/// caller calls next will run.
#[inline(never)]
fn map_stack_below() {
    std::hint::black_box(&mut [0_u8; 32 << 10]);
}

#[inline(never)]
fn deep_backtrace(depth: usize) {
    if depth == 0 {
        moto_rt::error::log_backtrace(-1);
    } else {
        deep_backtrace(depth - 1);
        std::hint::black_box(depth); // Keep the frames in release builds too.
    }
}

fn child(mode: &str, caps: u64) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg(CHILD)
        .arg(mode)
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn test_records_and_panic_use_stderr() {
    let debug_path = crate::temp_path("rt-diagnostic-debug-marker");
    let output = child("records", WITHOUT_LOG)
        .arg(debug_path.to_str().unwrap())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(ORDINARY_MARKER), "{stderr:?}");
    assert!(
        stderr.contains("rt.vdso diagnostic test marker"),
        "{stderr:?}"
    );
    assert!(stderr.contains("backtrace:"), "{stderr:?}");
    assert!(stderr.ends_with("\n\n"), "incomplete backtrace: {stderr:?}");
    #[cfg(debug_assertions)]
    assert!(
        stderr.contains(&format!("mkdir({})", debug_path.display())),
        "debug record missing from stderr: {stderr:?}"
    );

    let output = child("panic", WITHOUT_LOG).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(PANIC_MARKER), "{stderr:?}");
    assert!(stderr.contains("backtrace:"), "{stderr:?}");
    assert!(
        stderr.ends_with("\n\n"),
        "incomplete panic backtrace: {stderr:?}"
    );
}

fn failed_route(mode: u64, caps: u64) -> u64 {
    let mut child = child("route", caps)
        .arg(mode.to_string())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    assert_eq!("ready\n", ready);

    let mut stderr = Some(child.stderr.take().unwrap());
    if mode == 2 {
        drop(stderr.take());
    }
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    if mode == 3 {
        let mut partial = [0; 64];
        stderr.as_mut().unwrap().read_exact(&mut partial).unwrap();
        drop(stderr.take());
    }

    let mut result = String::new();
    stdout.read_to_string(&mut result).unwrap();
    assert!(child.wait().unwrap().success(), "{result:?}");
    result
        .trim()
        .strip_prefix("route=")
        .unwrap()
        .parse()
        .unwrap()
}

fn test_failure_and_reentry_policy() {
    let with_log = !crate::skip_without_cap_log("diagnostics::failure_and_reentry_policy/with_log");
    for mode in [1, 2, 3] {
        assert_eq!(3, failed_route(mode, WITHOUT_LOG));
        if with_log {
            assert_eq!(2, failed_route(mode, WITH_LOG));
        }
    }
}

/// A panic inside rt.vdso is reported whole even when no allocation can
/// succeed. The handler used to format its report on the heap; a failure there
/// re-entered it, and the original message and backtrace were lost.
pub fn test_vdso_panic_at_floor() {
    // The child pins the machine at the user floor until its handle is
    // released, and this process cannot grow its heap meanwhile. So read into
    // a buffer allocated up front, and assert only after the release. Nothing
    // is inherited either: relaying stdio is runtime work at the floor.
    let mut stderr = vec![0_u8; 16 << 10];
    let mut child = child("vdso-panic-at-floor", WITHOUT_LOG)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut pipe = child.stderr.take().unwrap();
    let mut len = 0;
    while let Ok(n @ 1..) = pipe.read(&mut stderr[len..]) {
        len += n;
    }
    let status = child.wait().unwrap();
    drop(pipe);
    drop(child);

    let stderr = String::from_utf8_lossy(&stderr[..len]);
    assert!(!status.success(), "{stderr:?}");
    assert_eq!(1, stderr.matches("PANIC").count(), "{stderr:?}");
    assert!(stderr.contains("rt.vdso panic test marker"), "{stderr:?}");
    assert!(stderr.contains("backtrace:"), "{stderr:?}");
    assert!(
        stderr.ends_with("\n\n"),
        "incomplete panic backtrace: {stderr:?}"
    );
    println!("diagnostics::test_vdso_panic_at_floor PASS");
}

/// Formatting a panic can itself panic. The first marker must survive, and
/// concurrent panicking threads must not bypass the recursion guard.
fn test_vdso_nested_panic() {
    for threads in [1, 4] {
        let output = child("vdso-nested-panic", WITHOUT_LOG)
            .arg(threads.to_string())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(output.stderr, b"PANIC\n", "{output:?}");
    }
}

fn test_vdso_multibyte_panic() {
    let output = child("vdso-multibyte-panic", WITHOUT_LOG).output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(1, stderr.matches("PANIC").count(), "{stderr:?}");
    assert!(
        stderr.contains(&format!(
            "multibyte panic test marker {}\n",
            "é🦀".repeat(128)
        )),
        "{stderr:?}"
    );
    assert!(stderr.contains("backtrace:"), "{stderr:?}");
    assert!(stderr.ends_with("\n\n"), "{stderr:?}");
}

/// A first panic on a thread that owns the diagnostic sink -- one raised inside
/// a diagnostic write -- cannot use stderr, which that write may hold. Through
/// the kernel log it still says where it happened, and what, if the message
/// is a literal.
fn test_vdso_guarded_panic() {
    if crate::skip_without_cap_log("diagnostics::vdso_guarded_panic") {
        return;
    }
    let output = child("vdso-guarded-panic", WITH_LOG).output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    crate::kernel_log::wait_for_file_records(&[
        b"PANIC: panicked while reporting a diagnostic at lib/rt.vdso/src/util/logging.rs:",
        b": rt.vdso guarded panic test marker\n",
    ]);
}

/// A backtrace sent to a descriptor goes there whoever owns the diagnostic
/// sink, this thread included: that sink's ownership is not its business.
fn test_fd_backtrace_under_guard() {
    let output = child("fd-backtrace-under-guard", WITHOUT_LOG)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("backtrace: "), "{stderr:?}");
    assert!(stderr.ends_with("\n\n"), "{stderr:?}");
}

fn test_concurrent_backtraces() {
    let output = child("concurrent-backtraces", WITHOUT_LOG)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let mut count = 0;
    for trace in stderr.split_terminator("\n\n") {
        assert!(
            trace.len() > 256,
            "must exercise multiple chunks: {trace:?}"
        );
        assert!(trace.starts_with("backtrace: "), "{trace:?}");
        assert_eq!(trace.matches("backtrace: ").count(), 1, "{trace:?}");
        for line in trace.lines().skip(1) {
            let line = line.trim().trim_end_matches(" \\");
            if line == "-- rt.vdso" || line == "^^^" {
                continue;
            }
            let addr = line.strip_prefix("0x").expect("backtrace address");
            assert!(u64::from_str_radix(addr, 16).is_ok(), "{trace:?}");
        }
        count += 1;
    }
    assert_eq!(count, BACKTRACE_THREADS * BACKTRACES_PER_THREAD);
    assert!(stderr.ends_with("\n\n"), "{stderr:?}");
}

pub fn run_all_tests() {
    test_records_and_panic_use_stderr();
    test_failure_and_reentry_policy();
    test_vdso_nested_panic();
    test_vdso_multibyte_panic();
    test_vdso_guarded_panic();
    test_fd_backtrace_under_guard();
    test_concurrent_backtraces();
    println!("diagnostics tests PASS");
}
