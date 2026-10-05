//! Native directory-creation regressions, also exercising the shell shim.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(root: &Path, arguments: &[&str]) -> Output {
    Command::new("/system/bin/sysbox")
        .arg("mkdir")
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[track_caller]
fn success(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[track_caller]
fn failure(output: Output, message: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    // Runtime debug records share stderr; inspect the command's own messages.
    let messages: Vec<_> = std::str::from_utf8(&output.stderr)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("mkdir:"))
        .collect();
    assert_eq!(messages, [message]);
}

pub fn run_test() {
    let root = std::env::temp_dir().join("systest-sysbox-mkdir");
    std::fs::create_dir(&root).unwrap();
    success(run(&root, &["plain", "second"]));
    assert!(root.join("plain").is_dir());
    assert!(root.join("second").is_dir());
    failure(
        run(&root, &["plain"]),
        "mkdir: cannot create directory 'plain': File exists",
    );
    failure(
        run(&root, &["missing/child"]),
        "mkdir: cannot create directory 'missing/child': No such file or directory",
    );
    assert!(!root.join("missing").exists());

    success(run(&root, &["-p", "parents/a/b", "plain", "."]));
    success(run(&root, &["--parents", "parents/a/b"]));
    success(run(&root, &["after/operand/child", "-pp"]));
    assert!(root.join("parents/a/b").is_dir());
    assert!(root.join("after/operand/child").is_dir());
    success(run(&root, &["-p", "with space/literal*", "--", "-p"]));
    assert!(root.join("with space/literal*").is_dir());
    assert!(root.join("-p").is_dir());

    std::fs::write(root.join("file"), b"preserve me").unwrap();
    failure(
        run(&root, &["-p", "file"]),
        "mkdir: cannot create directory 'file': File exists",
    );
    failure(
        run(&root, &["-p", "file/child"]),
        "mkdir: cannot create directory 'file/child': Not a directory",
    );
    failure(
        run(&root, &["file", "created-after-error"]),
        "mkdir: cannot create directory 'file': File exists",
    );
    assert!(root.join("created-after-error").is_dir());
    assert_eq!(std::fs::read(root.join("file")).unwrap(), b"preserve me");

    for arguments in [vec![], vec!["-p"], vec!["--"]] {
        failure(run(&root, &arguments), "mkdir: missing operand");
    }
    for arguments in [vec![""], vec!["-p", ""]] {
        failure(
            run(&root, &arguments),
            "mkdir: cannot create directory '': No such file or directory",
        );
    }
    for flag in ["-m", "-v", "--mode=700", "--unknown"] {
        failure(
            run(&root, &["must-not-exist", flag]),
            &format!("mkdir: unsupported option '{flag}'"),
        );
        assert!(!root.join("must-not-exist").exists());
    }
    let help = run(&root, &["--help"]);
    assert!(help.status.success(), "{help:?}");
    assert!(help.stdout.starts_with(b"usage: mkdir"), "{help:?}");

    let shim = Command::new("/system/bin/mkdir")
        .args(["-p", "shim with space/literal*", "shim second"])
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    success(shim);
    assert!(root.join("shim with space/literal*").is_dir());
    assert!(root.join("shim second").is_dir());
    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_mkdir::run_test PASS");
}
