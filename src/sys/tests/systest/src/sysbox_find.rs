//! Tests for `sysbox find`.

use std::path::{Path, PathBuf};

const SYSBOX: &str = "/sys/sysbox";

fn build_tree(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root.join("sub1").join("sub2")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    std::fs::write(root.join("sub1").join("b.txt"), b"b").unwrap();
    std::fs::write(root.join("sub1").join("sub2").join("c.txt"), b"c").unwrap();
}

fn run_find(cwd: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(SYSBOX)
        .arg("find")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn assert_lines(output: &std::process::Output, expected: &[&str]) {
    assert!(
        output.status.success(),
        "find failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines, expected);
}

pub fn run_test() {
    let root: PathBuf = std::env::temp_dir().join("systest-sysbox-find");
    build_tree(&root);

    // `find` and `find .` walk the cwd: preorder, children sorted by name.
    let expected = [
        ".",
        "./a.txt",
        "./empty",
        "./sub1",
        "./sub1/b.txt",
        "./sub1/sub2",
        "./sub1/sub2/c.txt",
    ];
    assert_lines(&run_find(&root, &[]), &expected);
    assert_lines(&run_find(&root, &["."]), &expected);

    // An explicit path prefixes the output; -type d keeps only directories.
    let sub1 = root.join("sub1");
    let sub1_str = sub1.to_str().unwrap();
    assert_lines(
        &run_find(&root, &[sub1_str, "-type", "d"]),
        &[sub1_str, &format!("{sub1_str}/sub2")],
    );

    // Relative paths stay relative in the output.
    assert_lines(
        &run_find(&sub1, &["..", "-type", "f"]),
        &["../a.txt", "../sub1/b.txt", "../sub1/sub2/c.txt"],
    );
    assert_lines(&run_find(&root, &["a.txt", "-type", "f"]), &["a.txt"]);

    // A missing path fails with empty stdout.
    let output = run_find(&root, &["no-such-path"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    std::fs::remove_dir_all(&root).unwrap();
    println!("sysbox_find::run_test PASS");
}
