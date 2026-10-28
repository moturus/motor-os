//! Upstream WASI filesystem and stdio programs through the installed runtime,
//! with the preopens and arguments upstream's own tests give them. Role None
//! needs `CAP_FS_WRITE` (0x200) to write; files the driver writes stay
//! read-only to it.
use std::fs;

use super::{Result, Suite, expect, invocation};

/// Programs whose only grant is a writable scratch preopen `.`, also their argument.
const SCRATCH_PROGRAMS: [&str; 34] = [
    "p2_close_preopen",
    "p2_dangling_fd",
    "p2_dir_fd_op_failures",
    "p1_directory_seek",
    "p2_fd_advise",
    "p1_fd_filestat_get",
    "p1_fd_flags_set",
    "p1_fd_readdir",
    "p1_file_allocate",
    "p1_file_pread_pwrite",
    "p1_file_read_write",
    "p1_file_seek_tell",
    "p1_file_truncation",
    "p1_file_unbuffered_write",
    "p1_file_write",
    "p2_interesting_paths",
    "p1_overwrite_preopen",
    "p2_path_open_create_existing",
    "p2_path_open_dirfd_not_dir",
    "p1_path_open_lots",
    "p2_path_open_missing",
    "p1_path_open_nonblock",
    "p2_path_open_preopen",
    "p2_path_open_read_write",
    "p2_path_rename",
    "p1_path_rename_dir_trailing_slashes",
    "p1_poll_oneoff_files",
    "p1_regular_file_isatty",
    "p2_remove_directory",
    "p2_remove_nonempty_directory",
    "p1_renumber",
    "p2_unlink_file_trailing_slashes",
    "p2_adapter_badfd",
    "p2_file_read_write",
];
/// Programs that also get a preopen `readonly` whose `test.txt` they must not change.
const READONLY_PROGRAMS: [&str; 4] = [
    "p1_file_rename_across_perms",
    "p1_file_truncation_readonly",
    "p2_file_rename_across_perms",
    "p2_file_truncation_readonly",
];
/// The p1 programs expect Unix errno values.
const OPTIONS: &str = "--env ERRNO_MODE_UNIX=1";
const READONLY_CONTENTS: &str = "read only test file\n";
const STDIN: &str = "So rested he by the Tumtum tree";

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    for program in SCRATCH_PROGRAMS {
        let scratch = suite.writable_dir(program)?;
        let options = format!("{OPTIONS} --dir {}::.", scratch.display());
        suite.command(program, &(invocation("0x200", &options, program) + " ."), 0)?;
    }
    let readonly = suite.root.join("readonly");
    fs::create_dir(&readonly)?;
    fs::write(readonly.join("test.txt"), READONLY_CONTENTS)?;
    for program in READONLY_PROGRAMS {
        let scratch = suite.writable_dir(program)?;
        let options = format!(
            "{OPTIONS} --dir {}::. --dir {}::readonly",
            scratch.display(),
            readonly.display()
        );
        suite.command(program, &(invocation("0x200", &options, program) + " ."), 0)?;
    }
    expect(
        "readonly contents",
        &fs::read_to_string(readonly.join("test.txt"))?,
        READONLY_CONTENTS,
    )?;
    // Without CAP_FS_WRITE, role None cannot create the program's file.
    let denied = suite.writable_dir("write-denied")?;
    let options = format!("{OPTIONS} --dir {}::.", denied.display());
    let (_, stderr) = suite.command(
        "write-denied",
        &(invocation("0", &options, "p1_file_write") + " ."),
        -1,
    )?;
    if !stderr.contains("PERM") {
        return Err(format!("write-denied: missing PERM: {stderr}").into());
    }
    cli(suite)
}

/// The CLI programs, run as upstream's `cli_tests.rs` runs them.
fn cli(suite: &mut Suite) -> Result<()> {
    let files = suite.root.join("files");
    fs::create_dir(&files)?;
    fs::write(files.join("bar.txt"), "And stood awhile in thought")?;
    let root = format!("--dir {}::/", files.display());
    suite.command(
        "p2_cli_file_read",
        &invocation("0x200", &root, "p2_cli_file_read"),
        0,
    )?;
    suite.command(
        "p2_cli_file_dir_sync",
        &invocation("0x200", &root, "p2_cli_file_dir_sync"),
        0,
    )?;

    let listed = suite.root.join("listed");
    fs::create_dir_all(listed.join("sub"))?;
    for name in [
        "foo.txt",
        "bar.txt",
        "baz.txt",
        "sub/wow.txt",
        "sub/yay.txt",
    ] {
        fs::write(listed.join(name), "")?;
    }
    let root = format!("--dir {}::/", listed.display());
    suite.command(
        "p2_cli_directory_list",
        &invocation("0x200", &root, "p2_cli_directory_list"),
        0,
    )?;
    let three = format!(
        "--dir {0}::/a --dir {0}::/b --dir {0}::/c",
        listed.display()
    );
    suite.command(
        "p2_cli_multiple_preopens",
        &invocation("0x200", &three, "p2_cli_multiple_preopens"),
        0,
    )?;
    suite.command(
        "p2_cli_initial_cwd",
        &invocation("0", "-S cwd=/sandbox", "p2_cli_initial_cwd"),
        0,
    )?;

    // The guest appends to a file it owns, so role None creates it, with a
    // builtin: it has no CAP_SPAWN to run other commands.
    let append = suite.writable_dir("append")?;
    suite.command(
        "p2_cli_file_append-seed",
        &format!(
            "MOTOR_OS_CAPS=0x200 /system/bin/rush -c \"printf 'Twas brillig, and the slithy toves.\\n' > {}/bar.txt\"",
            append.display()
        ),
        0,
    )?;
    let root = format!("--dir {}::/", append.display());
    suite.command(
        "p2_cli_file_append",
        &invocation("0x200", &root, "p2_cli_file_append"),
        0,
    )?;
    expect(
        "p2_cli_file_append contents",
        &fs::read_to_string(append.join("bar.txt"))?,
        "Twas brillig, and the slithy toves.\nDid gyre and gimble in the wabe;\n\
         All mimsy were the borogoves,\nAnd the mome raths outgrabe.\n",
    )?;

    fs::write(suite.root.join("stdin.txt"), STDIN)?;
    for program in ["p2_cli_stdin", "p2_cli_stdin_empty"] {
        suite.command(program, &(invocation("0", "", program) + " < stdin.txt"), 0)?;
    }
    let (stdout, _) = suite.command(
        "p2_cli_splice_stdin",
        &(invocation("0", "", "p2_cli_splice_stdin") + " < stdin.txt"),
        0,
    )?;
    expect(
        "p2_cli_splice_stdin",
        &stdout,
        &format!(
            "before splice\n{STDIN}\ncompleted splicing {} bytes\n",
            STDIN.len()
        ),
    )?;
    let chunk = "a".repeat(1024);
    let (stdout, _) = suite.command(
        "p2_cli_much_stdout",
        &(invocation("0", "", "p2_cli_much_stdout") + &format!(" {chunk} 256")),
        0,
    )?;
    if stdout.len() != 256 * 1024 || stdout.bytes().any(|b| b != b'a') {
        return Err(format!("p2_cli_much_stdout: {} bytes", stdout.len()).into());
    }
    Ok(())
}
