use std::io::Read;
use std::os::fd::FromRawFd;

const PREFIX: &str = "stdio-file-input-";

fn spawn_with_env(
    args: &[&str],
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
    extra_env: &[(&str, &str)],
) -> Result<moto_rt::process::SpawnResult, moto_rt::Error> {
    let mut env: Vec<(String, String)> = std::env::vars().collect();
    env.extend(
        extra_env
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env,
        cwd: None,
        stdin,
        stdout,
        stderr,
    })
}

fn spawn(
    args: &[&str],
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> Result<moto_rt::process::SpawnResult, moto_rt::Error> {
    spawn_with_env(args, stdin, stdout, stderr, &[])
}

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg.starts_with(PREFIX))
}

pub fn run_child(args: &[String]) -> ! {
    match args[1].as_str() {
        "stdio-file-input-read-all" => read_all_child(args),
        "stdio-file-input-read-all-parent" => read_all_parent(args),
        "stdio-file-input-growth" => growth_child(args),
        "stdio-file-input-growth-parent" => growth_parent(args),
        "stdio-file-input-source-error-parent" => source_error_parent(args),
        "stdio-file-input-source-error-reader" => source_error_reader(args),
        "stdio-file-input-nested-parent" => nested_parent(),
        "stdio-file-input-nested-bridge" => nested_bridge(),
        "stdio-file-input-nested-reader" => nested_reader(),
        "stdio-file-input-delayed-writer" => delayed_writer(args),
        "stdio-file-input-lifetime-parent" => lifetime_parent(args),
        "stdio-file-input-long-grandchild-parent" => long_grandchild_parent(),
        "stdio-file-input-idle" => {
            std::thread::sleep(std::time::Duration::from_secs(1));
            std::process::exit(0)
        }
        "stdio-file-input-access-parent" => access_parent(),
        "stdio-file-input-null-parent" => null_parent(),
        "stdio-file-input-lifetime-suite" => {
            privileged_lifetime_tests();
            println!("stdio_file_input privileged lifetime tests PASS");
            std::process::exit(0)
        }
        _ => panic!("unknown file-input child: {}", args[1]),
    }
}

fn read_all_child(args: &[String]) -> ! {
    if args.get(3).is_some_and(|arg| arg == "relay") {
        let attr = moto_rt::fs::get_file_attr(moto_rt::FD_STDIN).unwrap();
        assert_eq!(attr.file_type, moto_rt::fs::FILETYPE_FIFO);
        assert!(moto_rt::fs::seek(moto_rt::FD_STDIN, 0, moto_rt::fs::SEEK_CUR).is_err());
    }
    let expected = if args[2] == "<empty>" {
        b"".as_slice()
    } else {
        args[2].as_bytes()
    };
    let mut bytes = vec![0_u8; expected.len()];
    let mut read = 0;
    while read < bytes.len() {
        read += moto_rt::fs::read(moto_rt::FD_STDIN, &mut bytes[read..]).unwrap();
    }
    assert_eq!(bytes, expected);
    let mut byte = [0_u8; 1];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).unwrap(), 0);
    std::process::exit(0)
}

fn read_all_parent(args: &[String]) -> ! {
    let child = spawn(
        &["stdio-file-input-read-all", &args[2], "relay"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    std::process::exit(0)
}

fn growth_child(args: &[String]) -> ! {
    let mut byte = [0_u8; 1];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).unwrap(), 1);
    assert_eq!(byte[0], b'a');
    assert_eq!(moto_rt::fs::write(moto_rt::FD_STDOUT, b"ready").unwrap(), 5);
    moto_rt::fs::flush(moto_rt::FD_STDOUT).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let read = moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).unwrap();
    if args[2] == "direct" {
        assert_eq!(read, 1);
        assert_eq!(byte[0], b'b');
    } else {
        assert_eq!(read, 0);
    }
    std::process::exit(0)
}

fn append_after_ready(child: &moto_rt::process::SpawnResult, path: &str) {
    let mut ready = unsafe { std::fs::File::from_raw_fd(child.stdout) };
    let mut bytes = [0_u8; 5];
    ready.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ready");
    let append = moto_rt::fs::open(path, moto_rt::fs::O_APPEND).unwrap();
    assert_eq!(moto_rt::fs::write(append, b"b").unwrap(), 1);
    moto_rt::fs::close(append).unwrap();
}

fn growth_parent(args: &[String]) -> ! {
    let child = spawn(
        &["stdio-file-input-growth", "relay"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_MAKE_PIPE,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    append_after_ready(&child, &args[2]);
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    std::process::exit(0)
}

fn source_error_parent(args: &[String]) -> ! {
    let child = spawn(
        &["stdio-file-input-source-error-reader", &args[2]],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    let consumed = moto_rt::fs::seek(moto_rt::FD_STDIN, 0, moto_rt::fs::SEEK_CUR).unwrap();
    assert!(
        consumed > 0 && consumed < 1024 * 1024,
        "source-error relay reconciled an invalid consumed prefix: {consumed}"
    );
    let mut byte = [0_u8; 1];
    assert!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).is_err());
    std::process::exit(0)
}

fn source_error_reader(args: &[String]) -> ! {
    let mut byte = [0_u8; 1];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).unwrap(), 1);
    std::fs::remove_file(&args[2]).unwrap();
    let mut bytes = [0_u8; 4096];
    loop {
        match moto_rt::fs::read(moto_rt::FD_STDIN, &mut bytes) {
            Ok(0) => panic!("source-error relay unexpectedly reached EOF"),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    std::process::exit(0)
}

fn nested_parent() -> ! {
    let child = spawn(
        &["stdio-file-input-nested-bridge"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    let pos = moto_rt::fs::seek(moto_rt::FD_STDIN, 0, moto_rt::fs::SEEK_CUR).unwrap();
    assert!(
        pos > 5,
        "nested relay did not expose its documented read-ahead limit: {pos}"
    );
    std::process::exit(0)
}

fn nested_bridge() -> ! {
    let child = spawn(
        &["stdio-file-input-nested-reader"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    std::process::exit(0)
}

fn nested_reader() -> ! {
    let mut bytes = [0_u8; 5];
    let mut read = 0;
    while read < bytes.len() {
        read += moto_rt::fs::read(moto_rt::FD_STDIN, &mut bytes[read..]).unwrap();
    }
    assert_eq!(&bytes, b"abcde");
    std::process::exit(0)
}

fn delayed_writer(args: &[String]) -> ! {
    assert_eq!(
        moto_sys::caps::ProcessRole::Interactive,
        moto_sys::caps::ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities)
    );
    std::thread::sleep(std::time::Duration::from_millis(100));
    let result = moto_rt::fs::write(moto_rt::FD_STDOUT, b"survived");
    if args[2] == "direct" {
        assert_eq!(result.unwrap(), 8);
    } else {
        assert!(result.is_err());
    }
    std::fs::write(&args[3], b"done").unwrap();
    std::process::exit(0)
}

fn lifetime_parent(args: &[String]) -> ! {
    let route = &args[2];
    let stdout = if route == "direct" {
        moto_rt::FD_STDOUT
    } else {
        moto_rt::process::STDIO_INHERIT
    };
    spawn_with_env(
        &["stdio-file-input-delayed-writer", route, &args[3]],
        moto_rt::process::STDIO_NULL,
        stdout,
        moto_rt::process::STDIO_NULL,
        &[(moto_sys::caps::MOTOR_OS_DETACHED_ENV_KEY, "true")],
    )
    .unwrap();
    std::process::exit(0)
}

fn long_grandchild_parent() -> ! {
    spawn(
        &["stdio-file-input-idle"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    std::process::exit(0)
}

fn access_parent() -> ! {
    for stdin in [
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_PARENT_STDIN,
    ] {
        let input_error: moto_rt::ErrorCode = match spawn(
            &["stdio-file-input-idle"],
            stdin,
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_NULL,
        ) {
            Err(error) => error.into(),
            Ok(_) => panic!("unreadable inherited stdin unexpectedly succeeded"),
        };
        assert_eq!(input_error, moto_rt::E_NOT_ALLOWED);
    }
    for stdout in [
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_PARENT_STDOUT,
    ] {
        let output_error: moto_rt::ErrorCode = match spawn(
            &["stdio-file-input-idle"],
            moto_rt::process::STDIO_NULL,
            stdout,
            moto_rt::process::STDIO_NULL,
        ) {
            Err(error) => error.into(),
            Ok(_) => panic!("unwritable inherited stdout unexpectedly succeeded"),
        };
        assert_eq!(output_error, moto_rt::E_NOT_ALLOWED);
    }
    std::process::exit(0)
}

fn null_parent() -> ! {
    use std::io::Write;

    let child = spawn(
        &["stdio-file-input-read-all", "<empty>"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    std::io::stdout().write_all(b"discarded stdout").unwrap();
    std::io::stderr().write_all(b"discarded stderr").unwrap();
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    std::process::exit(0)
}

pub fn run_tests() {
    eof_and_growth_tests();
    source_error_and_nested_tests();
    lifetime_and_pipe_counter_tests();
    post_publish_error_progress_test();
    access_and_null_tests();
    println!("stdio_file_input tests PASS");
}

fn eof_and_growth_tests() {
    let path = crate::temp_path("stdio-input-growth");
    let path_str = path.to_str().unwrap();
    std::fs::write(&path, b"a").unwrap();
    let input = moto_rt::fs::open(path_str, moto_rt::fs::O_READ).unwrap();
    let parent = spawn(
        &["stdio-file-input-growth-parent", path_str],
        input,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    moto_rt::fs::close(input).unwrap();

    std::fs::write(&path, b"a").unwrap();
    let input = moto_rt::fs::open(path_str, moto_rt::fs::O_READ).unwrap();
    let child = spawn(
        &["stdio-file-input-growth", "direct"],
        input,
        moto_rt::process::STDIO_MAKE_PIPE,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    append_after_ready(&child, path_str);
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    moto_rt::fs::close(input).unwrap();

    std::fs::write(&path, b"complete").unwrap();
    let input = moto_rt::fs::open(path_str, moto_rt::fs::O_READ).unwrap();
    let parent = spawn(
        &["stdio-file-input-read-all-parent", "complete"],
        input,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    moto_rt::fs::close(input).unwrap();
    std::fs::remove_file(&path).unwrap();
}

fn source_error_and_nested_tests() {
    let error_path = crate::temp_path("stdio-input-source-error");
    let error_str = error_path.to_str().unwrap();
    std::fs::write(&error_path, vec![b'e'; 1024 * 1024]).unwrap();
    let input = moto_rt::fs::open(error_str, moto_rt::fs::O_READ).unwrap();
    let parent = spawn(
        &["stdio-file-input-source-error-parent", error_str],
        input,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    moto_rt::fs::close(input).unwrap();

    let nested = crate::temp_path("stdio-input-nested");
    let bytes: Vec<u8> = (0..1024).map(|idx| b'a' + (idx % 26) as u8).collect();
    std::fs::write(&nested, bytes).unwrap();
    let input = moto_rt::fs::open(nested.to_str().unwrap(), moto_rt::fs::O_READ).unwrap();
    let parent = spawn(
        &["stdio-file-input-nested-parent"],
        input,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    moto_rt::fs::close(input).unwrap();
    std::fs::remove_file(&nested).unwrap();
}

fn wait_for_file(path: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !std::path::Path::new(path).exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "detached child did not finish"
        );
        std::thread::yield_now();
    }
}

fn lifetime_and_pipe_counter_tests() {
    let path = crate::temp_path("stdio-long-grandchild");
    let output = moto_rt::fs::open(
        path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let parent = spawn(
        &["stdio-file-input-long-grandchild-parent"],
        moto_rt::process::STDIO_NULL,
        output,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    assert!(start.elapsed() < std::time::Duration::from_millis(500));
    moto_rt::fs::close(output).unwrap();
    std::fs::remove_file(&path).unwrap();

    let (reader_data, writer_data) =
        moto_ipc::stdio_pipe::make_pair(moto_sys::SysHandle::SELF, moto_sys::SysHandle::SELF)
            .unwrap();
    let reader = unsafe { moto_ipc::stdio_pipe::StdioPipe::new_reader(reader_data) };
    let writer = unsafe { moto_ipc::stdio_pipe::StdioPipe::new_writer(writer_data) };
    writer.close_writer().unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(reader.read(&mut byte).unwrap(), 0);
}

pub fn post_publish_error_progress_test() {
    let child = spawn(
        &["stdio-file-input-idle"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    let (local, _remote) = moto_ipc::stdio_pipe::make_pair(
        moto_sys::SysHandle::SELF,
        moto_sys::SysHandle::from_u64(child.handle),
    )
    .unwrap();
    let writer = unsafe { moto_ipc::stdio_pipe::StdioPipe::new_writer(local) };
    moto_rt::process::kill(child.handle).unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), -1);

    let payload = b"published-on-peer-loss";
    let (published, result) = writer.nonblocking_write_progress(payload);
    assert!(result.is_err());
    assert_eq!(published, payload.len());
    assert_eq!(writer.total_written(), payload.len());
    assert_eq!(writer.peer_bytes_read().unwrap(), 0);

    let mut recovered = writer.take_unread().unwrap();
    recovered.extend_from_slice(&payload[published..]);
    assert_eq!(recovered, payload);
    println!("post_publish_error_progress_test PASS");
}

fn privileged_lifetime_tests() {
    assert_eq!(
        moto_sys::caps::ProcessRole::Interactive,
        moto_sys::caps::ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities)
    );
    assert_ne!(
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SPAWN_DETACHED,
        0
    );
    let caps = format!(
        "0x{:x}",
        moto_sys::caps::CAP_SPAWN
            | moto_sys::caps::CAP_LOG
            | moto_sys::caps::CAP_SPAWN_DETACHED
            | moto_sys::caps::CAP_INTERACTIVE
    );
    for route in ["direct", "relay"] {
        let output_path = crate::temp_path(&format!("stdio-lifetime-{route}"));
        let done_path = crate::temp_path(&format!("stdio-lifetime-{route}-done"));
        let _ = std::fs::remove_file(&done_path);
        let output = moto_rt::fs::open(
            output_path.to_str().unwrap(),
            moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
        )
        .unwrap();
        let parent = spawn_with_env(
            &[
                "stdio-file-input-lifetime-parent",
                route,
                done_path.to_str().unwrap(),
            ],
            moto_rt::process::STDIO_NULL,
            output,
            moto_rt::process::STDIO_NULL,
            &[(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, &caps)],
        )
        .unwrap();
        assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
        wait_for_file(done_path.to_str().unwrap());
        let expected = if route == "direct" {
            b"survived".as_slice()
        } else {
            b""
        };
        assert_eq!(std::fs::read(&output_path).unwrap(), expected);
        moto_rt::fs::close(output).unwrap();
        std::fs::remove_file(output_path).unwrap();
        std::fs::remove_file(done_path).unwrap();
    }
}

fn access_and_null_tests() {
    let path = crate::temp_path("stdio-input-access");
    let path_str = path.to_str().unwrap();
    std::fs::write(&path, b"x").unwrap();
    let write_only = moto_rt::fs::open(path_str, moto_rt::fs::O_WRITE).unwrap();
    let read_only = moto_rt::fs::open(path_str, moto_rt::fs::O_READ).unwrap();
    let parent = spawn(
        &["stdio-file-input-access-parent"],
        write_only,
        read_only,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    moto_rt::fs::close(write_only).unwrap();
    moto_rt::fs::close(read_only).unwrap();
    let null = spawn(
        &["stdio-file-input-null-parent"],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_MAKE_PIPE,
    )
    .unwrap();
    let mut stderr = unsafe { std::fs::File::from_raw_fd(null.stderr) };
    let mut message = Vec::new();
    stderr.read_to_end(&mut message).unwrap();
    assert_eq!(
        moto_rt::process::wait(null.handle).unwrap(),
        0,
        "null-inheritance stderr: {}",
        String::from_utf8_lossy(&message)
    );
    std::fs::remove_file(&path).unwrap();
}
