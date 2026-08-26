const PREFIX: &str = "stdio-file-relay-";

fn spawn(
    args: &[&str],
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> Result<moto_rt::process::SpawnResult, moto_rt::Error> {
    spawn_program(
        std::env::current_exe().unwrap().to_str().unwrap(),
        args,
        stdin,
        stdout,
        stderr,
    )
}

fn spawn_program(
    program: &str,
    args: &[&str],
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> Result<moto_rt::process::SpawnResult, moto_rt::Error> {
    moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: program.to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: std::env::vars().collect(),
        cwd: None,
        stdin,
        stdout,
        stderr,
    })
}

fn spawn_error(
    args: &[&str],
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> moto_rt::ErrorCode {
    match spawn(args, stdin, stdout, stderr) {
        Err(error) => error.into(),
        Ok(_) => panic!("stdio relay spawn unexpectedly succeeded"),
    }
}

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg.starts_with(PREFIX))
}

pub fn run_child(args: &[String]) -> ! {
    match args[1].as_str() {
        "stdio-file-relay-writer" => writer_child(args),
        "stdio-file-relay-exit-parent" => exit_parent(args),
        "stdio-file-relay-exit-writer" => exit_writer(args),
        "stdio-file-relay-idle" => {
            std::thread::sleep(std::time::Duration::from_millis(300));
            std::process::exit(0)
        }
        "stdio-file-relay-output-parent" => output_parent(),
        "stdio-file-relay-conflict-parent" => conflict_parent(),
        "stdio-file-relay-independent-parent" => independent_parent(),
        "stdio-file-relay-lock-parent" => lock_parent(),
        "stdio-file-relay-failure-parent" => failure_parent(),
        "stdio-file-relay-alias-parent" => alias_parent(),
        "stdio-file-relay-dual-writer" => dual_writer(),
        _ => panic!("unknown file-relay child: {}", args[1]),
    }
}

fn writer_child(args: &[String]) -> ! {
    let byte = args[2].parse::<u8>().unwrap();
    let len = args[3].parse::<usize>().unwrap();
    let delay_ms = args[4].parse::<u64>().unwrap();
    let trickle = args.get(5).is_some_and(|arg| arg == "trickle");
    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    if trickle {
        for _ in 0..len {
            assert_eq!(moto_rt::fs::write(moto_rt::FD_STDOUT, &[byte]).unwrap(), 1);
            moto_sys::SysCpu::sched_yield();
        }
    } else {
        let bytes = vec![byte; len];
        let mut written = 0;
        while written < bytes.len() {
            written += moto_rt::fs::write(moto_rt::FD_STDOUT, &bytes[written..]).unwrap();
        }
    }
    std::process::exit(0)
}

fn dual_writer() -> ! {
    let attr = moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT).unwrap();
    assert_eq!(attr.file_type, moto_rt::fs::FILETYPE_FIFO);
    assert!(moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR).is_err());
    std::thread::sleep(std::time::Duration::from_millis(50));
    let stdout = std::thread::spawn(|| {
        for _ in 0..512 {
            assert_eq!(
                moto_rt::fs::write(moto_rt::FD_STDOUT, b"OOOOoooo").unwrap(),
                8
            );
        }
    });
    let stderr = std::thread::spawn(|| {
        for _ in 0..512 {
            assert_eq!(
                moto_rt::fs::write(moto_rt::FD_STDERR, b"EEEEeeee").unwrap(),
                8
            );
        }
    });
    stdout.join().unwrap();
    stderr.join().unwrap();
    std::process::exit(0)
}

fn alias_parent() -> ! {
    let child = spawn(
        &["stdio-file-relay-dual-writer"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_INHERIT,
    )
    .unwrap();
    expect_busy(moto_rt::fs::seek(
        moto_rt::FD_STDOUT,
        0,
        moto_rt::fs::SEEK_CUR,
    ));
    let mut saw_pending = false;
    let status = loop {
        match moto_rt::process::try_wait(child.handle) {
            Ok(status) => break status,
            Err(error) if error_code(error) == moto_rt::E_NOT_READY => {
                saw_pending = true;
                std::thread::yield_now();
            }
            Err(error) => panic!("unexpected try_wait error: {error:?}"),
        }
    };
    assert!(saw_pending);
    assert_eq!(status, 0);
    assert_eq!(
        moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        8192
    );
    std::process::exit(0)
}

/// Spawns a writer through an output relay and then exits without waiting for
/// it. Exit must flush what the relay already holds instead of dropping it on
/// a deadline.
fn exit_parent(args: &[String]) -> ! {
    let child = spawn(
        &["stdio-file-relay-exit-writer", args[2].as_str()],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    // Long enough that the writer is mid-stream, so the relay is genuinely
    // interrupted rather than idle.
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(child.pid > 0);
    std::process::exit(0)
}

/// Writes until the relay refuses, then records how many bytes it was *told*
/// went through. Not one of those may be missing from the file.
fn exit_writer(args: &[String]) -> ! {
    const CAP: u64 = 64 * 1024 * 1024;
    let buf = vec![b'X'; 4096];
    let mut accepted = 0_u64;
    while accepted < CAP {
        match moto_rt::fs::write(moto_rt::FD_STDOUT, &buf) {
            Ok(0) | Err(_) => break,
            Ok(written) => accepted += written as u64,
        }
    }
    std::fs::write(&args[2], format!("{accepted}\n")).unwrap();
    std::process::exit(0)
}

fn error_code(error: moto_rt::Error) -> moto_rt::ErrorCode {
    error.into()
}

fn expect_busy<T>(result: Result<T, moto_rt::Error>) {
    let error: moto_rt::ErrorCode = result.err().expect("operation was not excluded").into();
    assert_eq!(error, moto_rt::E_ALREADY_IN_USE);
}

fn output_parent() -> ! {
    let first = spawn(
        &["stdio-file-relay-writer", "65", "1048576", "0"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    let second = spawn(
        &["stdio-file-relay-writer", "66", "256", "300", "trickle"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();

    let mut byte = [0_u8; 1];
    expect_busy(moto_rt::fs::read(moto_rt::FD_STDOUT, &mut byte));
    expect_busy(moto_rt::fs::write(moto_rt::FD_STDOUT, b"x"));
    expect_busy(moto_rt::fs::read_vectored(
        moto_rt::FD_STDOUT,
        &mut [&mut byte],
    ));
    expect_busy(moto_rt::fs::write_vectored(moto_rt::FD_STDOUT, &[b"x"]));
    expect_busy(moto_rt::fs::seek(
        moto_rt::FD_STDOUT,
        0,
        moto_rt::fs::SEEK_CUR,
    ));
    assert!(moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT).is_ok());
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-writer", "67", "1", "0"],
            moto_rt::process::STDIO_NULL,
            moto_rt::FD_STDOUT,
            moto_rt::process::STDIO_NULL,
        ),
        moto_rt::E_ALREADY_IN_USE
    );
    let lock_error: moto_rt::ErrorCode =
        moto_rt::fs::file_lock(moto_rt::FD_STDOUT, moto_rt::fs::TRY_LOCK_EXCLUSIVE)
            .unwrap_err()
            .into();
    assert_eq!(lock_error, moto_rt::E_NOT_ALLOWED);

    let mut waiters = Vec::new();
    for _ in 0..3 {
        let handle = first.handle;
        waiters.push(std::thread::spawn(move || {
            moto_rt::process::wait(handle).unwrap()
        }));
    }
    for waiter in waiters {
        assert_eq!(waiter.join().unwrap(), 0);
    }
    expect_busy(moto_rt::fs::seek(
        moto_rt::FD_STDOUT,
        0,
        moto_rt::fs::SEEK_CUR,
    ));
    assert_eq!(moto_rt::process::wait(second.handle).unwrap(), 0);
    assert_eq!(
        moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        1048576 + 256
    );
    std::process::exit(0)
}

fn conflict_parent() -> ! {
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-idle"],
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_PARENT_STDIN,
            moto_rt::process::STDIO_NULL,
        ),
        moto_rt::E_INVALID_ARGUMENT
    );
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-idle"],
            moto_rt::process::STDIO_PARENT_STDOUT,
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_NULL,
        ),
        moto_rt::E_INVALID_ARGUMENT
    );
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-writer", "65", "1", "0"],
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_NULL,
        ),
        // A bidirectional relay of one open description is an input/output
        // relay overlap, not an unimplemented transport combination.
        moto_rt::E_ALREADY_IN_USE
    );
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-writer", "65", "1", "0"],
            moto_rt::process::STDIO_NULL,
            moto_rt::FD_STDOUT,
            moto_rt::process::STDIO_PARENT_STDOUT,
        ),
        moto_rt::E_NOT_IMPLEMENTED
    );

    let input = spawn(
        &["stdio-file-relay-idle"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-writer", "65", "1", "0"],
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_NULL,
        ),
        moto_rt::E_ALREADY_IN_USE
    );
    assert_eq!(moto_rt::process::wait(input.handle).unwrap(), 0);

    let output = spawn(
        &["stdio-file-relay-writer", "66", "1", "300"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-idle"],
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_NULL,
        ),
        moto_rt::E_ALREADY_IN_USE
    );
    assert_eq!(moto_rt::process::wait(output.handle).unwrap(), 0);
    std::process::exit(0)
}

fn independent_parent() -> ! {
    let input = spawn(
        &["stdio-file-relay-idle"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    let output = spawn(
        &["stdio-file-relay-writer", "73", "4096", "0"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(output.handle).unwrap(), 0);
    assert_eq!(moto_rt::process::wait(input.handle).unwrap(), 0);
    std::process::exit(0)
}

fn lock_parent() -> ! {
    moto_rt::fs::file_lock(moto_rt::FD_STDOUT, moto_rt::fs::LOCK_EXCLUSIVE).unwrap();
    assert_eq!(
        spawn_error(
            &["stdio-file-relay-writer", "76", "1", "0"],
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_NULL,
        ),
        moto_rt::E_NOT_ALLOWED
    );
    moto_rt::fs::file_lock(moto_rt::FD_STDOUT, moto_rt::fs::UNLOCK).unwrap();
    let child = spawn(
        &["stdio-file-relay-writer", "76", "4096", "100"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    let error: moto_rt::ErrorCode =
        moto_rt::fs::file_lock(moto_rt::FD_STDOUT, moto_rt::fs::TRY_LOCK_EXCLUSIVE)
            .unwrap_err()
            .into();
    assert_eq!(error, moto_rt::E_NOT_ALLOWED);
    moto_rt::fs::close(moto_rt::FD_STDOUT).unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    std::process::exit(0)
}

fn failure_parent() -> ! {
    let missing = crate::temp_path("definitely-missing-stdio-test");
    let invalid = crate::temp_path("stdio-relay-invalid-elf");
    for _ in 0..16 {
        let error: moto_rt::ErrorCode = match spawn_program(
            missing.to_str().unwrap(),
            &[],
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_NULL,
        ) {
            Err(error) => error.into(),
            Ok(_) => panic!("missing executable unexpectedly spawned"),
        };
        assert_eq!(error, moto_rt::E_NOT_FOUND);
        assert_eq!(
            moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR).unwrap(),
            0
        );
    }
    let invalid_error: moto_rt::ErrorCode = match spawn_program(
        invalid.to_str().unwrap(),
        &[],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    ) {
        Err(error) => error.into(),
        Ok(_) => panic!("invalid executable unexpectedly spawned"),
    };
    assert_eq!(invalid_error, moto_rt::E_INVALID_ARGUMENT);
    assert_eq!(
        moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        0
    );
    let child = spawn(
        &["stdio-file-relay-writer", "82", "32", "0"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    std::process::exit(0)
}

pub fn run_tests() {
    let output_path = crate::temp_path("stdio-relay-concurrent");
    let output = moto_rt::fs::open(
        output_path.to_str().unwrap(),
        moto_rt::fs::O_CREATE
            | moto_rt::fs::O_TRUNCATE
            | moto_rt::fs::O_READ
            | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let child = spawn(
        &["stdio-file-relay-output-parent"],
        moto_rt::process::STDIO_NULL,
        output,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    let bytes = std::fs::read(&output_path).unwrap();
    assert_eq!(bytes.len(), 1048576 + 256);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'A').count(), 1048576);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'B').count(), 256);
    moto_rt::fs::close(output).unwrap();

    concurrent_stdout_stderr_test();
    exit_flush_test();

    conflict_and_cleanup_tests();
    std::fs::remove_file(&output_path).unwrap();
    println!("stdio_file_relay tests PASS");
}

fn concurrent_stdout_stderr_test() {
    let path = crate::temp_path("stdio-relay-stdout-stderr");
    let output = moto_rt::fs::open(
        path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let alias = moto_rt::fs::duplicate(output).unwrap();
    let parent = spawn(
        &["stdio-file-relay-alias-parent"],
        moto_rt::process::STDIO_NULL,
        output,
        alias,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 8192);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'O').count(), 2048);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'o').count(), 2048);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'E').count(), 2048);
    assert_eq!(bytes.iter().filter(|byte| **byte == b'e').count(), 2048);
    moto_rt::fs::close(alias).unwrap();
    moto_rt::fs::close(output).unwrap();
    std::fs::remove_file(&path).unwrap();
}

fn exit_flush_test() {
    let path = crate::temp_path("stdio-relay-exit-flush");
    let count = crate::temp_path("stdio-relay-exit-count");
    let _ = std::fs::remove_file(&count);
    let output = moto_rt::fs::open(
        path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let parent = spawn(
        &["stdio-file-relay-exit-parent", count.to_str().unwrap()],
        moto_rt::process::STDIO_NULL,
        output,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    moto_rt::fs::close(output).unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let accepted = loop {
        if let Ok(text) = std::fs::read_to_string(&count)
            && let Some(text) = text.strip_suffix('\n')
        {
            break text.parse::<u64>().unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "writer never reported"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.iter().all(|byte| *byte == b'X'));
    assert!(accepted > 0, "the relay never carried anything");
    // Every accepted byte reached the file. The relay may hold slightly more
    // than the writer counts -- a publish racing the final drain is disowned
    // by the writer even when the reader took it -- but never fewer.
    assert!(
        bytes.len() as u64 >= accepted,
        "exit dropped {} accepted bytes",
        accepted - bytes.len() as u64
    );
    assert!(
        bytes.len() as u64 - accepted <= 64 * 1024,
        "file ran ahead of the writer by more than one relay chunk"
    );

    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&count).unwrap();
}

fn conflict_and_cleanup_tests() {
    let path = crate::temp_path("stdio-relay-conflicts");
    let invalid = crate::temp_path("stdio-relay-invalid-elf");
    let path_str = path.to_str().unwrap();
    std::fs::write(&path, vec![b'x'; 65536]).unwrap();
    std::fs::write(&invalid, b"not an executable").unwrap();
    moto_rt::fs::set_perm(
        invalid.to_str().unwrap(),
        moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC,
    )
    .unwrap();
    let shared = moto_rt::fs::open(path_str, moto_rt::fs::O_READ | moto_rt::fs::O_WRITE).unwrap();
    let duplicate = moto_rt::fs::duplicate(shared).unwrap();
    let child = spawn(
        &["stdio-file-relay-conflict-parent"],
        shared,
        duplicate,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    moto_rt::fs::close(shared).unwrap();
    moto_rt::fs::close(duplicate).unwrap();

    let input = moto_rt::fs::open(path_str, moto_rt::fs::O_READ).unwrap();
    let output = moto_rt::fs::open(path_str, moto_rt::fs::O_WRITE).unwrap();
    let child = spawn(
        &["stdio-file-relay-independent-parent"],
        input,
        output,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    moto_rt::fs::close(input).unwrap();
    moto_rt::fs::close(output).unwrap();

    for (mode, byte, len) in [
        ("stdio-file-relay-lock-parent", b'L', 4096_usize),
        ("stdio-file-relay-failure-parent", b'R', 32_usize),
    ] {
        let fd =
            moto_rt::fs::open(path_str, moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE).unwrap();
        let child = spawn(
            &[mode],
            moto_rt::process::STDIO_NULL,
            fd,
            moto_rt::process::STDIO_NULL,
        )
        .unwrap();
        assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), vec![byte; len]);
        moto_rt::fs::close(fd).unwrap();
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&invalid).unwrap();
}
