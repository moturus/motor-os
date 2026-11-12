#![cfg(target_os = "motor")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use moto_rt::fs::{PERM_EXEC, PERM_READ, PERM_WRITE};
use moto_sys::caps::{CAP_SPAWN, ProcessRole};

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let pid = moto_sys::ProcessStaticPage::get().pid;
        let root = Path::new("/none/tmp").join(format!("rush-permissions-{pid}-{name}"));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn file(&self, name: &str, permissions: u64) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, b"file predicate fixture\n").unwrap();
        set_permissions(&path, permissions);
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let blocked = self.0.join("blocked");
        if blocked.exists() {
            // Restore traversal for cleanup through Motor's Rw -> Rx -> Rwx path.
            set_permissions(&blocked, PERM_READ | PERM_EXEC);
            set_permissions(&blocked, PERM_READ | PERM_WRITE | PERM_EXEC);
        }
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn set_permissions(path: &Path, permissions: u64) {
    moto_rt::fs::set_perm(path.to_str().unwrap(), permissions).unwrap();
}

fn check_execute(path: &Path, expected: bool, caps: Option<u64>) {
    for expression in ["test -x \"$1\"", "[ -x \"$1\" ]"] {
        let mut command = Command::new(RUSH);
        command
            .args(["-c", expression, "rush-permissions"])
            .arg(path)
            .env_remove("MOTOR_OS_CAPS");
        if let Some(caps) = caps {
            command.env("MOTOR_OS_CAPS", format!("0x{caps:x}"));
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if expected { 0 } else { 1 }),
            "{expression}, path={}, caps={caps:?}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn execute_predicates_check_file_and_directory_permissions() {
    let fixture = Fixture::new("predicates");
    let data = fixture.file("data", PERM_READ | PERM_WRITE);
    let read_only = fixture.file("read-only", PERM_READ);
    let executable = fixture.file("executable", PERM_READ | PERM_EXEC);
    let blocked = fixture.0.join("blocked");
    fs::create_dir(&blocked).unwrap();
    let blocked_executable = fixture.file("blocked/executable", PERM_READ | PERM_EXEC);
    set_permissions(&blocked, PERM_READ | PERM_WRITE);

    check_execute(&data, false, None);
    check_execute(&read_only, false, None);
    check_execute(&executable, true, None);
    check_execute(Path::new(RUSH), true, None);
    check_execute(&fixture.0, true, None);
    check_execute(&blocked, false, None);
    check_execute(&blocked_executable, false, None);
    check_execute(&fixture.0.join("missing"), false, None);
}

#[test]
fn execute_predicates_use_the_childs_role() {
    let caps = moto_sys::ProcessStaticPage::get().capabilities;
    if ProcessRole::from_caps(caps) != ProcessRole::Interactive {
        return;
    }

    let fixture = Fixture::new("roles");
    // Adding x for Interactive does not grant x to None on a newly created file.
    let executable = fixture.file("interactive-executable", PERM_READ | PERM_EXEC);
    check_execute(&executable, true, None);
    check_execute(&fixture.0, true, Some(CAP_SPAWN));
    check_execute(&executable, false, Some(CAP_SPAWN));
}
