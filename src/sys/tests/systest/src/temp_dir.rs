//! A child's `TMPDIR` follows its role (docs/fs-permissions.md): rt.vdso
//! fills in the role's directory and replaces an inherited one when the
//! child's role is lower, but keeps a `TMPDIR` the parent chose.

use moto_sys::caps::{CAP_FS_WRITE, CAP_SPAWN, MOTOR_OS_CAPS_ENV_KEY};
use std::process::Command;

const PRINT_TMPDIR: &str = "print-tmpdir";

pub fn is_print_tmpdir_child(args: &[String]) -> bool {
    args.len() == 2 && args[1] == PRINT_TMPDIR
}

pub fn run_print_tmpdir_child() -> ! {
    println!("{}", std::env::var("TMPDIR").unwrap_or_default());
    std::process::exit(0)
}

fn child_tmpdir(configure: impl FnOnce(&mut Command)) -> String {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.arg(PRINT_TMPDIR);
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}

/// Run as Interactive with an explicit `TMPDIR`, as full-test.sh does.
pub fn test_child_temp_dir() {
    let own = std::env::var("TMPDIR").unwrap();
    let none = format!("0x{:x}", CAP_SPAWN | CAP_FS_WRITE);
    assert_eq!(child_tmpdir(|_| {}), own, "same role, inherited");
    let unset = child_tmpdir(|command| {
        command.env_remove("TMPDIR");
    });
    assert_eq!(unset, "/user/tmp", "same role, none");
    let lower = child_tmpdir(|command| {
        command.env(MOTOR_OS_CAPS_ENV_KEY, &none);
    });
    assert_eq!(lower, "/none/tmp", "lower role, inherited");
    let chosen = child_tmpdir(|command| {
        command
            .env(MOTOR_OS_CAPS_ENV_KEY, &none)
            .env("TMPDIR", "/chosen/tmp");
    });
    assert_eq!(chosen, "/chosen/tmp", "lower role, chosen by the parent");
    println!("test_child_temp_dir PASS");
}
