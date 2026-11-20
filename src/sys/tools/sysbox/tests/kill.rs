//! Run natively on Motor OS; the command must also kill a sibling process.
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use moto_sys::caps::{ProcessRole, MOTOR_OS_CAPS_ENV_KEY};

const SYSBOX: &str = env!("CARGO_BIN_EXE_sysbox");

fn run(args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("kill")
        .args(args)
        .output()
        .unwrap()
}

fn expect_failure(args: &[&str]) {
    let output = run(args);
    assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
    assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    assert!(!output.stderr.is_empty(), "{args:?}: {output:?}");
}

fn sleeper() -> Child {
    Command::new(SYSBOX)
        .args(["sleep", "60"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn expect_killed(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "sleep exited normally: {status}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "kill did not terminate the child"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn main() {
    assert!(run(&["--help"]).status.success());
    let help = Command::new(SYSBOX).arg("help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("\tsysbox kill\n"));

    for args in [
        &[][..],
        &["not-a-pid"],
        &["1", "2"],
        &["-1"],
        &["18446744073709551616"],
        &["18446744073709551615"],
    ] {
        expect_failure(args);
    }
    let missing = run(&[&u64::MAX.to_string()]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no such process"));
    // A None-role killer cannot terminate its ancestor.
    let output = Command::new(SYSBOX)
        .args(["kill", &std::process::id().to_string()])
        .env(MOTOR_OS_CAPS_ENV_KEY, "0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("operation not permitted"));

    let own = moto_sys::ProcessStaticPage::get().capabilities;
    if ProcessRole::from_caps(own) != ProcessRole::Interactive {
        println!("sysbox kill: PASS (sibling termination requires Interactive authority)");
        return;
    }

    let mut child = sleeper();
    let denied = Command::new(SYSBOX)
        .args(["kill", &child.id().to_string()])
        .env(MOTOR_OS_CAPS_ENV_KEY, "0")
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    assert!(child.try_wait().unwrap().is_none());
    let output = run(&[&child.id().to_string()]);
    assert!(output.status.success(), "{output:?}");
    expect_killed(&mut child);

    let mut child = sleeper();
    let output = Command::new("/user/bin/rush")
        .args(["-c", "kill \"$1\"", "kill-test", &child.id().to_string()])
        .output()
        .unwrap();
    assert!(output.status.success(), "external wrapper: {output:?}");
    expect_killed(&mut child);

    // Quoting in the wrapper must preserve this as one invalid PID.
    let mut child = sleeper();
    let output = Command::new("/user/bin/kill")
        .arg(format!(" {} ", child.id()))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();

    println!("sysbox kill: ALL PASS");
}
