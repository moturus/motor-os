use std::io::Write;
use std::os::fd::AsRawFd;

const NULL_CHILD: &str = "descriptor-attr-null-child";
const PIPE_CHILD: &str = "descriptor-attr-pipe-child";

fn attr(fd: i32) -> moto_rt::fs::FileAttr {
    moto_rt::fs::get_file_attr(fd).unwrap()
}

fn assert_synthetic(fd: i32, file_type: u8) -> moto_rt::fs::FileAttr {
    let attr = attr(fd);
    assert_eq!(attr.file_type, file_type, "fd {fd}");
    assert_eq!(attr.size, 0, "fd {fd}");
    assert_eq!(attr.perm, 0, "fd {fd}");
    assert_eq!(attr.created, 0, "fd {fd}");
    assert_eq!(attr.modified, 0, "fd {fd}");
    assert_eq!(attr.accessed, 0, "fd {fd}");
    assert_ne!(attr.entry_id, 0, "fd {fd}");
    assert_eq!(attr.entry_id >> 64, 0, "fd {fd}");
    attr
}

pub fn is_null_child(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some(NULL_CHILD)
}

pub fn run_null_child(args: &[String]) -> ! {
    assert_eq!(args.len(), 3);
    let fd = args[2].parse().unwrap();
    let ok = moto_rt::fs::get_file_attr(fd).is_ok_and(|attr| {
        attr.file_type == moto_rt::fs::FILETYPE_CHARACTER_DEVICE
            && attr.entry_id != 0
            && !moto_rt::fs::is_terminal(fd)
    });
    std::process::exit(if ok { 0 } else { 1 })
}

pub fn is_pipe_child(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some(PIPE_CHILD)
}

pub fn run_pipe_child(args: &[String]) -> ! {
    assert_eq!(args.len(), 2);
    let mut command = String::new();
    let ok = std::io::stdin().read_line(&mut command).is_ok() && command == "exit 0\n";
    std::process::exit(if ok { 0 } else { 1 })
}

fn test_self_stdio() {
    let attrs = [
        assert_synthetic(
            moto_rt::FD_STDIN,
            if moto_rt::fs::is_terminal(moto_rt::FD_STDIN) {
                moto_rt::fs::FILETYPE_CHARACTER_DEVICE
            } else {
                moto_rt::fs::FILETYPE_FIFO
            },
        ),
        assert_synthetic(
            moto_rt::FD_STDOUT,
            if moto_rt::fs::is_terminal(moto_rt::FD_STDOUT) {
                moto_rt::fs::FILETYPE_CHARACTER_DEVICE
            } else {
                moto_rt::fs::FILETYPE_FIFO
            },
        ),
        assert_synthetic(
            moto_rt::FD_STDERR,
            if moto_rt::fs::is_terminal(moto_rt::FD_STDERR) {
                moto_rt::fs::FILETYPE_CHARACTER_DEVICE
            } else {
                moto_rt::fs::FILETYPE_FIFO
            },
        ),
    ];
    assert!(attrs[0].entry_id != attrs[1].entry_id);
    assert!(attrs[0].entry_id != attrs[2].entry_id);
    assert!(attrs[1].entry_id != attrs[2].entry_id);
}

fn test_child_stdio() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(PIPE_CHILD)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let attrs = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()]
        .map(|fd| assert_synthetic(fd, moto_rt::fs::FILETYPE_FIFO));
    assert!(attrs[0].entry_id != attrs[1].entry_id);
    assert!(attrs[0].entry_id != attrs[2].entry_id);
    assert!(attrs[1].entry_id != attrs[2].entry_id);
    stdin.write_all(b"exit 0\n").unwrap();
    stdin.flush().unwrap();
    assert!(child.wait().unwrap().success());
}

fn test_null_stdio() {
    for fd in [moto_rt::FD_STDIN, moto_rt::FD_STDOUT, moto_rt::FD_STDERR] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.arg(NULL_CHILD).arg(fd.to_string());
        match fd {
            moto_rt::FD_STDIN => command.stdin(std::process::Stdio::null()),
            moto_rt::FD_STDOUT => command.stdout(std::process::Stdio::null()),
            moto_rt::FD_STDERR => command.stderr(std::process::Stdio::null()),
            _ => unreachable!(),
        };
        assert!(command.status().unwrap().success(), "null fd {fd}");
    }
}

fn test_filesystem_attrs() {
    let root = std::env::temp_dir().join("descriptor-attr-test");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let path = root.join("file");
    std::fs::write(&path, b"attr").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let file_attr = attr(file.as_raw_fd());
    assert_eq!(file_attr.file_type, moto_rt::fs::FILETYPE_FILE);
    assert_eq!(file_attr.size, 4);
    assert_ne!(file_attr.entry_id, 0);

    let dir_fd = moto_rt::fs::opendir(root.to_str().unwrap()).unwrap();
    let dir_attr = attr(dir_fd);
    let path_attr = moto_rt::fs::stat(root.to_str().unwrap()).unwrap();
    assert_eq!(dir_attr.file_type, moto_rt::fs::FILETYPE_DIRECTORY);
    assert_eq!(dir_attr.entry_id, path_attr.entry_id);
    moto_rt::fs::closedir(dir_fd).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

fn test_sockets_and_registry_identity() {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_synthetic(udp.as_raw_fd(), moto_rt::fs::FILETYPE_SOCKET);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    assert_synthetic(tcp.as_raw_fd(), moto_rt::fs::FILETYPE_SOCKET);

    let first = moto_rt::poll::new().unwrap();
    let first_attr = assert_synthetic(first, moto_rt::fs::FILETYPE_ANONYMOUS);
    let duplicate = moto_rt::fs::duplicate(first).unwrap();
    let duplicate_attr = assert_synthetic(duplicate, moto_rt::fs::FILETYPE_ANONYMOUS);
    assert_eq!(first_attr.entry_id, duplicate_attr.entry_id);
    moto_rt::fs::close(duplicate).unwrap();

    let second = moto_rt::poll::new().unwrap();
    let second_attr = assert_synthetic(second, moto_rt::fs::FILETYPE_ANONYMOUS);
    assert_ne!(first_attr.entry_id, second_attr.entry_id);
    moto_rt::fs::close(second).unwrap();

    moto_rt::fs::close(first).unwrap();
    let reused = moto_rt::poll::new().unwrap();
    assert_eq!(reused, first);
    let reused_attr = assert_synthetic(reused, moto_rt::fs::FILETYPE_ANONYMOUS);
    assert_ne!(reused_attr.entry_id, first_attr.entry_id);
    moto_rt::fs::close(reused).unwrap();
}

fn test_invalid_descriptors() {
    assert!(matches!(
        moto_rt::fs::get_file_attr(-1),
        Err(moto_rt::Error::BadHandle)
    ));
    assert!(matches!(
        moto_rt::fs::get_file_attr(i32::MAX),
        Err(moto_rt::Error::BadHandle)
    ));
}

pub fn run_all_tests() {
    test_self_stdio();
    test_child_stdio();
    test_null_stdio();
    test_filesystem_attrs();
    test_sockets_and_registry_identity();
    test_invalid_descriptors();
    println!("descriptor_attr PASS");
}
