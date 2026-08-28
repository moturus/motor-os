use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};

const CHILD: &str = "rt-diagnostic-child";
const ORDINARY_MARKER: &str = "ordinary moto-rt diagnostic marker";
const PANIC_MARKER: &str = "complete piped diagnostic panic";

const WITHOUT_LOG: u64 = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_INTERACTIVE;
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
        _ => unreachable!(),
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
    let with_log =
        !crate::skip_without_cap_log("diagnostics::failure_and_reentry_policy/with_log");
    for mode in [1, 2, 3] {
        assert_eq!(3, failed_route(mode, WITHOUT_LOG));
        if with_log {
            assert_eq!(2, failed_route(mode, WITH_LOG));
        }
    }
}

pub fn run_all_tests() {
    test_records_and_panic_use_stderr();
    test_failure_and_reentry_policy();
    println!("diagnostics tests PASS");
}
