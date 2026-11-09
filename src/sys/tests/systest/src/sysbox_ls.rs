//! Tests for `sysbox ls` argument parsing.

use std::path::Path;
use std::process::{Command, Output};

const SYSBOX: &str = "/system/bin/sysbox";

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("ls")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn assert_lists(output: Output, marker: &str) {
    assert!(
        output.status.success(),
        "ls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Debug rt.vdso startup records intentionally use the child's stderr.
    #[cfg(not(debug_assertions))]
    assert!(output.stderr.is_empty(), "ls diagnostic: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.split_whitespace().any(|field| field == marker),
        "ls did not list {marker:?}: {stdout:?}"
    );
}

pub fn run_test() {
    let root = crate::temp_path(&format!(
        "systest-sysbox-ls-{}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    let _ = std::fs::remove_dir_all(&root);
    let directory = root.join("-lh");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("marker.txt"), b"marker").unwrap();

    // After `--`, an option-looking operand is a directory, not `-l` and `-h`.
    assert_lists(run(&root, &["--", "-lh"]), "marker.txt");
    // Options before the delimiter still apply to that directory.
    assert_lists(run(&root, &["-l", "--", "-lh"]), "marker.txt");

    // A file operand lists itself, named as it was typed, as ls(1) does.
    assert_lists(run(&root, &["--", "-lh/marker.txt"]), "-lh/marker.txt");
    assert_lists(
        run(&root, &["-l", "--", "-lh/marker.txt"]),
        "-lh/marker.txt",
    );

    // An inaccessible operand is ls(1)'s "serious trouble": stderr and status 2.
    let output = run(&root, &["missing-entry"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "ls of a missing path: {output:?}"
    );
    assert!(output.stdout.is_empty(), "ls of a missing path: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error reading directory"),
        "ls of a missing path: {output:?}"
    );

    test_operands_kept_as_typed(&root);
    test_multiple_operands(&root);
    test_shell_globbing(&root);

    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_ls::run_test PASS");
}

/// The exact stdout of a successful `ls`, with the status checked.
#[track_caller]
fn stdout_of(output: Output) -> String {
    assert!(output.status.success(), "ls failed: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// Operands reach the file system as typed: no trimming, no skipping, and no
/// wildcard expansion of their own (the shell owns globbing).
fn test_operands_kept_as_typed(root: &Path) {
    let names = ["has space.txt", "*.md", "a.md", "trimmed"];
    let directory = root.join("typed");
    std::fs::create_dir_all(&directory).unwrap();
    for name in names {
        std::fs::write(directory.join(name), name).unwrap();
    }

    // A file operand lists itself under the name it was given, so a trimmed
    // or re-expanded operand would print a different name or fail.
    for name in names {
        assert_eq!(
            stdout_of(run(&directory, &[name])),
            format!("{name} \n"),
            "ls of {name:?}"
        );
        let long = stdout_of(run(&directory, &["-l", name]));
        assert!(
            long.ends_with(&format!(" {name}\n")),
            "ls -l of {name:?}: {long:?}"
        );
    }

    // Motor OS paths cannot have surrounding whitespace, so these operands
    // name nothing: they must fail rather than be trimmed to `trimmed` or `.`.
    for operand in ["", "  ", " trimmed", "trimmed "] {
        let output = run(&directory, &[operand]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "ls of {operand:?}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "ls of {operand:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(&format!("error reading directory '{operand}'")),
            "ls of {operand:?}: {output:?}"
        );
    }

    // A lone `-` is an operand, not an empty option group.
    let output = run(&directory, &["-"]);
    assert_eq!(output.status.code(), Some(2), "ls of \"-\": {output:?}");
    std::fs::write(directory.join("-"), b"dash").unwrap();
    assert_eq!(stdout_of(run(&directory, &["-"])), "- \n");
}

/// Several operands list as ls(1) does: file operands first, then each
/// directory under a heading, groups separated by a blank line, with a
/// failed operand reported on stderr and status 2 after the others.
fn test_multiple_operands(root: &Path) {
    let directory = root.join("multi");
    for sub in ["d1", "d2"] {
        std::fs::create_dir_all(directory.join(sub)).unwrap();
    }
    let sizes = [
        ("d1/x", 1),
        ("d1/y", 2),
        ("d2/z", 3),
        ("f1", 4),
        ("f2", 12),
        ("big", 2048),
    ];
    for (name, size) in sizes {
        std::fs::write(directory.join(name), vec![b'.'; size]).unwrap();
    }

    // One operand keeps the plain presentation: no heading.
    assert_eq!(stdout_of(run(&directory, &["d1"])), "x y \n");

    // Files sort by name; directories sort by operand and get headings.
    assert_eq!(stdout_of(run(&directory, &["f2", "f1"])), "f1 f2 \n");
    assert_eq!(
        stdout_of(run(&directory, &["d2", "d1"])),
        "d1:\nx y \n\nd2:\nz \n"
    );
    assert_eq!(
        stdout_of(run(&directory, &["d1", "f1", "d2", "f2"])),
        "f1 f2 \n\nd1:\nx y \n\nd2:\nz \n"
    );

    // Long output aligns sizes within each group: the file group's widths
    // come from f2's two digits, d1's from its one-digit sizes.
    let long = stdout_of(run(&directory, &["-l", "d1", "f2", "f1"]));
    let lines: Vec<&str> = long.lines().collect();
    assert_eq!(lines.len(), 6, "{long:?}");
    assert!(lines[0].ends_with("  4 f1"), "{long:?}");
    assert!(lines[1].ends_with(" 12 f2"), "{long:?}");
    assert_eq!(lines[2], "", "{long:?}");
    assert_eq!(lines[3], "d1:", "{long:?}");
    assert!(lines[4].ends_with(" 1 x"), "{long:?}");
    assert!(lines[5].ends_with(" 2 y"), "{long:?}");
    assert!(
        lines[0].len() == lines[1].len() && lines[4].len() == lines[5].len(),
        "{long:?}"
    );
    // -h applies to every operand.
    let human = stdout_of(run(&directory, &["-lh", "big", "d2"]));
    assert!(
        human.contains(" 2.00K big\n") && human.contains(" 3 z\n"),
        "{human:?}"
    );

    // Inaccessible operands are reported and skipped; the rest still list.
    let output = run(&directory, &["missing", "f1", "d1", "also-missing"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "f1 \n\nd1:\nx y \n"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error reading directory 'missing'")
            && stderr.contains("error reading directory 'also-missing'"),
        "{stderr:?}"
    );
}

/// Runs a shell command line in `cwd` through rush, the way an interactive
/// user does; `ls` in it is the packaged /system/bin/ls wrapper.
fn rush(cwd: &Path, command: &str) -> Output {
    Command::new("/system/bin/rush")
        .args(["-c", command])
        .current_dir(cwd)
        .output()
        .unwrap()
}

#[track_caller]
fn expect_rush(cwd: &Path, command: &str, status: i32, stdout: &str, errors: &[&str]) {
    let output = rush(cwd, command);
    assert_eq!(output.status.code(), Some(status), "{command}: {output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        stdout,
        "{command}: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for operand in errors {
        assert!(
            stderr.contains(&format!("error reading directory '{operand}'")),
            "{command}: {output:?}"
        );
    }
}

/// The whole path a typed `ls *.md` takes: rush expands the pattern, the
/// packaged wrapper forwards the words intact, and sysbox lists them all.
fn test_shell_globbing(root: &Path) {
    let directory = root.join("glob");
    std::fs::create_dir_all(directory.join("sub")).unwrap();
    for name in [
        "a.md",
        "b.md",
        "has space.md",
        "*.md",
        ".hidden.md",
        "c.txt",
    ] {
        std::fs::write(directory.join(name), name).unwrap();
    }
    let dash = directory.join("dash");
    std::fs::create_dir_all(&dash).unwrap();
    std::fs::write(dash.join("-x.md"), b"dash").unwrap();

    // Zero, one and several matches. An unmatched pattern stays a literal
    // operand that does not exist. Dot files are skipped by the shell.
    expect_rush(&directory, "ls *.rs", 2, "", &["*.rs"]);
    expect_rush(&directory, "ls *.txt", 0, "c.txt \n", &[]);
    expect_rush(
        &directory,
        "ls *.md",
        0,
        "*.md a.md b.md has space.md \n",
        &[],
    );
    expect_rush(&directory, "ls .hidden.md", 0, ".hidden.md \n", &[]);
    expect_rush(
        &directory,
        "ls -l *.txt sub",
        0,
        "-rwxrw-r-- 5 c.txt\n\nsub:\n",
        &[],
    );

    // Quoted and escaped wildcards name the literal `*.md` file only; sysbox
    // must not expand the word again.
    expect_rush(&directory, "ls '*.md'", 0, "*.md \n", &[]);
    expect_rush(&directory, "ls \"*.md\"", 0, "*.md \n", &[]);
    expect_rush(&directory, "ls \\*.md", 0, "*.md \n", &[]);
    expect_rush(&directory, "set -f; ls *.md", 0, "*.md \n", &[]);
    expect_rush(&directory, "ls '*.txt'", 2, "", &["*.txt"]);

    // Expansion happens before option parsing: a matched name that starts
    // with `-` needs `--`.
    expect_rush(&dash, "ls -*.md", 1, "", &[]);
    expect_rush(&dash, "ls -- -*.md", 0, "-x.md \n", &[]);

    // Missing operands before and after matches are reported after the
    // listing finishes, and the status says so.
    expect_rush(
        &directory,
        "ls missing *.txt sub gone",
        2,
        "c.txt \n\nsub:\n\n",
        &["missing", "gone"],
    );
}
