use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::FromRawFd;

const PREFIX: &str = "stdio-file-direct-";

fn spawn(
    args: &[&str],
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> moto_rt::process::SpawnResult {
    moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: std::env::vars().collect(),
        cwd: None,
        stdin,
        stdout,
        stderr,
    })
    .unwrap()
}

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg.starts_with(PREFIX))
}

pub fn run_child(args: &[String]) -> ! {
    match args[1].as_str() {
        "stdio-file-direct-ops" => direct_ops_child(args),
        "stdio-file-direct-access" => access_child(),
        "stdio-file-direct-alias" => alias_child(),
        "stdio-file-direct-rename" => rename_child(args),
        "stdio-file-direct-unlock" => unlock_child(),
        "stdio-file-direct-kind" => kind_child(args),
        _ => panic!("unknown direct-file child: {}", args[1]),
    }
}

fn error_code(error: moto_rt::Error) -> moto_rt::ErrorCode {
    error.into()
}

fn direct_ops_child(args: &[String]) -> ! {
    let expected_id = args[2].parse::<u128>().unwrap();
    assert_eq!(
        moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT)
            .unwrap()
            .entry_id,
        expected_id
    );
    assert_eq!(
        moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        4
    );
    assert_eq!(
        moto_rt::fs::write_vectored(moto_rt::FD_STDOUT, &[b"12", b"34"]).unwrap(),
        4
    );
    moto_rt::fs::flush(moto_rt::FD_STDOUT).unwrap();
    moto_rt::fs::truncate(moto_rt::FD_STDOUT, 6).unwrap();
    moto_rt::fs::set_file_perm(
        moto_rt::FD_STDOUT,
        moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE,
    )
    .unwrap();
    assert_eq!(
        moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT).unwrap().size,
        6
    );
    moto_rt::net::set_nonblocking(moto_rt::FD_STDOUT, true).unwrap();
    moto_rt::net::set_nonblocking(moto_rt::FD_STDOUT, false).unwrap();
    let registry = moto_rt::poll::new().unwrap();
    assert_eq!(
        error_code(
            moto_rt::poll::add(
                registry,
                moto_rt::FD_STDOUT,
                1,
                moto_rt::poll::POLL_WRITABLE,
            )
            .unwrap_err()
        ),
        moto_rt::E_INVALID_ARGUMENT
    );
    moto_rt::fs::close(registry).unwrap();

    assert_eq!(
        moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_END).unwrap(),
        6
    );
    let mut stdout = std::io::stdout().lock();
    assert_eq!(
        stdout
            .write_vectored(&[IoSlice::new(b"V"), IoSlice::new(b"W")])
            .unwrap(),
        2
    );
    stdout.flush().unwrap();

    let duplicate = moto_rt::fs::duplicate(moto_rt::FD_STDOUT).unwrap();
    let mut file = unsafe { std::fs::File::from_raw_fd(duplicate) };
    assert_eq!(
        moto_rt::fs::seek(duplicate, 0, moto_rt::fs::SEEK_SET).unwrap(),
        0
    );
    let mut left = [0_u8; 3];
    let mut right = [0_u8; 5];
    assert_eq!(
        file.read_vectored(&mut [IoSliceMut::new(&mut left), IoSliceMut::new(&mut right)])
            .unwrap(),
        8
    );
    assert_eq!([left.as_slice(), right.as_slice()].concat(), b"seed12VW");

    let mut left = [0_u8; 2];
    let mut right = [0_u8; 3];
    assert_eq!(
        std::io::stdin()
            .lock()
            .read_vectored(&mut [IoSliceMut::new(&mut left), IoSliceMut::new(&mut right)])
            .unwrap(),
        5
    );
    assert_eq!([left.as_slice(), right.as_slice()].concat(), b"input");
    let mut byte = [0_u8; 1];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).unwrap(), 0);
    assert_eq!(
        moto_rt::fs::write(moto_rt::FD_STDERR, b"mixed-ok").unwrap(),
        8
    );
    std::process::exit(0)
}

fn alias_child() -> ! {
    let first = std::thread::spawn(|| {
        for _ in 0..512 {
            assert_eq!(
                moto_rt::fs::write_vectored(moto_rt::FD_STDOUT, &[b"AAAA", b"aaaa"]).unwrap(),
                8
            );
        }
    });
    let second = std::thread::spawn(|| {
        for _ in 0..512 {
            assert_eq!(
                moto_rt::fs::write_vectored(moto_rt::FD_STDERR, &[b"BBBB", b"bbbb"]).unwrap(),
                8
            );
        }
    });
    first.join().unwrap();
    second.join().unwrap();
    std::process::exit(0)
}

fn access_child() -> ! {
    let mut byte = [0_u8; 1];
    assert_eq!(
        error_code(moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte).unwrap_err()),
        moto_rt::E_NOT_ALLOWED
    );
    assert_eq!(
        error_code(moto_rt::fs::write(moto_rt::FD_STDOUT, b"x").unwrap_err()),
        moto_rt::E_NOT_ALLOWED
    );
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDOUT, &mut byte).unwrap(), 1);
    assert_eq!(byte[0], b'r');
    assert_eq!(moto_rt::fs::write(moto_rt::FD_STDIN, b"w").unwrap(), 1);
    std::process::exit(0)
}

fn rename_child(args: &[String]) -> ! {
    std::thread::sleep(std::time::Duration::from_millis(100));
    let expected_id = args[2].parse::<u128>().unwrap();
    assert_eq!(
        moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT)
            .unwrap()
            .entry_id,
        expected_id
    );
    assert_eq!(moto_rt::fs::write(moto_rt::FD_STDOUT, b"child").unwrap(), 5);
    std::process::exit(0)
}

fn unlock_child() -> ! {
    moto_rt::fs::file_lock(moto_rt::FD_STDOUT, moto_rt::fs::UNLOCK).unwrap();
    std::process::exit(0)
}

fn kind_child(args: &[String]) -> ! {
    for (idx, fd) in [moto_rt::FD_STDIN, moto_rt::FD_STDOUT, moto_rt::FD_STDERR]
        .into_iter()
        .enumerate()
    {
        let actual = match moto_rt::fs::get_file_attr(fd).unwrap().file_type {
            moto_rt::fs::FILETYPE_FILE => "file",
            moto_rt::fs::FILETYPE_FIFO => "pipe",
            moto_rt::fs::FILETYPE_CHARACTER_DEVICE if !moto_rt::fs::is_terminal(fd) => "null",
            other => panic!("unexpected stdio file type: {other}"),
        };
        if args.get(idx + 2).is_some_and(|expected| expected != actual) {
            std::process::exit(10 + idx as i32);
        }
    }
    if args.get(3).is_some_and(|kind| kind == "file")
        && args.get(4).is_some_and(|kind| kind == "file")
        && moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT)
            .unwrap()
            .entry_id
            != moto_rt::fs::get_file_attr(moto_rt::FD_STDERR)
                .unwrap()
                .entry_id
    {
        std::process::exit(20);
    }
    if let Some(destination) = args.get(5) {
        let destination_fd = moto_rt::fs::open(destination, moto_rt::fs::O_READ).unwrap();
        let destination_id = moto_rt::fs::get_file_attr(destination_fd).unwrap().entry_id;
        moto_rt::fs::close(destination_fd).unwrap();
        if destination_id == 0
            || moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT)
                .unwrap()
                .entry_id
                != destination_id
        {
            std::process::exit(21);
        }
    }
    assert_eq!(
        moto_rt::fs::write(moto_rt::FD_STDOUT, b"kind-ok").unwrap(),
        7
    );
    std::process::exit(0)
}

pub fn run_tests() {
    let input_path = crate::temp_path("stdio-direct-input");
    let ops = crate::temp_path("stdio-direct-ops");
    std::fs::write(&input_path, b"input").unwrap();
    let input = moto_rt::fs::open(input_path.to_str().unwrap(), moto_rt::fs::O_READ).unwrap();
    let fd = moto_rt::fs::open(
        ops.to_str().unwrap(),
        moto_rt::fs::O_CREATE
            | moto_rt::fs::O_TRUNCATE
            | moto_rt::fs::O_READ
            | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    assert_eq!(moto_rt::fs::write(fd, b"seed").unwrap(), 4);
    let id = moto_rt::fs::get_file_attr(fd).unwrap().entry_id;
    let child = spawn(
        &["stdio-file-direct-ops", &id.to_string()],
        input,
        fd,
        moto_rt::process::STDIO_MAKE_PIPE,
    );
    let mut stderr = unsafe { std::fs::File::from_raw_fd(child.stderr) };
    let mut message = Vec::new();
    stderr.read_to_end(&mut message).unwrap();
    let status = moto_rt::process::wait(child.handle).unwrap();
    assert_eq!(
        status,
        0,
        "direct operation child stderr: {}",
        String::from_utf8_lossy(&message)
    );
    assert_eq!(message, b"mixed-ok");
    assert_eq!(
        moto_rt::fs::seek(input, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        0
    );
    assert_eq!(moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_CUR).unwrap(), 4);
    assert_eq!(std::fs::read(&ops).unwrap(), b"seed12VW");
    assert_eq!(moto_rt::fs::write(fd, b"P").unwrap(), 1);
    assert_eq!(std::fs::read(&ops).unwrap(), b"seedP2VW");
    moto_rt::fs::close(input).unwrap();
    moto_rt::fs::close(fd).unwrap();

    let access = crate::temp_path("stdio-direct-access");
    std::fs::write(&access, b"r").unwrap();
    let write_only = moto_rt::fs::open(access.to_str().unwrap(), moto_rt::fs::O_WRITE).unwrap();
    let read_only = moto_rt::fs::open(access.to_str().unwrap(), moto_rt::fs::O_READ).unwrap();
    let child = spawn(
        &["stdio-file-direct-access"],
        write_only,
        read_only,
        moto_rt::process::STDIO_NULL,
    );
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    moto_rt::fs::close(write_only).unwrap();
    moto_rt::fs::close(read_only).unwrap();

    alias_position_tests();
    rename_and_lock_tests();
    for path in [&input_path, &ops, &access] {
        std::fs::remove_file(path).unwrap();
    }
    println!("stdio_file_direct tests PASS");
}

fn alias_position_tests() {
    let path = crate::temp_path("stdio-direct-alias");
    let fd = moto_rt::fs::open(
        path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let alias = moto_rt::fs::duplicate(fd).unwrap();
    let child = spawn(
        &["stdio-file-direct-alias"],
        moto_rt::process::STDIO_NULL,
        fd,
        alias,
    );
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 8192);
    let (chunks, remainder) = bytes.as_chunks::<8>();
    assert!(remainder.is_empty());
    for chunk in chunks {
        assert!(chunk == b"AAAAaaaa" || chunk == b"BBBBbbbb", "{chunk:?}");
    }
    moto_rt::fs::close(alias).unwrap();
    moto_rt::fs::close(fd).unwrap();
    std::fs::remove_file(&path).unwrap();
}

fn rename_and_lock_tests() {
    let old = crate::temp_path("stdio-direct-rename-old");
    let new = crate::temp_path("stdio-direct-rename-new");
    let old_str = old.to_str().unwrap();
    let new_str = new.to_str().unwrap();
    let _ = std::fs::remove_file(&old);
    let _ = std::fs::remove_file(&new);
    let fd = moto_rt::fs::open(old_str, moto_rt::fs::O_CREATE | moto_rt::fs::O_WRITE).unwrap();
    let id = moto_rt::fs::get_file_attr(fd).unwrap().entry_id;
    let child = spawn(
        &["stdio-file-direct-rename", &id.to_string()],
        moto_rt::process::STDIO_NULL,
        fd,
        moto_rt::process::STDIO_NULL,
    );
    moto_rt::fs::rename(old_str, new_str).unwrap();
    std::fs::write(&old, b"replacement").unwrap();
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    assert_eq!(std::fs::read(&new).unwrap(), b"child");
    assert_eq!(std::fs::read(&old).unwrap(), b"replacement");

    moto_rt::fs::file_lock(fd, moto_rt::fs::LOCK_EXCLUSIVE).unwrap();
    let child = spawn(
        &["stdio-file-direct-unlock"],
        moto_rt::process::STDIO_NULL,
        fd,
        moto_rt::process::STDIO_NULL,
    );
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);
    let probe = moto_rt::fs::open(new_str, moto_rt::fs::O_READ).unwrap();
    assert!(moto_rt::fs::file_lock(probe, moto_rt::fs::TRY_LOCK_EXCLUSIVE).is_err());
    moto_rt::fs::file_lock(fd, moto_rt::fs::UNLOCK).unwrap();
    moto_rt::fs::file_lock(probe, moto_rt::fs::TRY_LOCK_EXCLUSIVE).unwrap();
    moto_rt::fs::file_lock(probe, moto_rt::fs::UNLOCK).unwrap();
    moto_rt::fs::close(probe).unwrap();
    moto_rt::fs::close(fd).unwrap();
    std::fs::remove_file(&old).unwrap();
    std::fs::remove_file(&new).unwrap();
}
