#![allow(dead_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

#[cfg(not(target_os = "motor"))]
use crate::diagnostic::Error;
use crate::diagnostic::Result;

/// The versioned observable build-script isolation contract.
pub const CONTRACT_VERSION: &str = "lorry-build-script-sandbox-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAccess {
    Deny,
}

/// One executable a sandboxed build script may start.
///
/// An empty prefix permits the exact executable with arbitrary arguments. A
/// non-empty prefix requires a backend capable of inspecting child argv; a
/// backend must fail closed when it cannot enforce that restriction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Executable {
    pub path: PathBuf,
    pub argument_prefix: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Package, dependency, toolchain, and runtime paths exposed read-only.
    pub read_only: Vec<PathBuf>,
    /// The assigned OUT_DIR and private temporary directory.
    pub writable: Vec<PathBuf>,
    /// Child executables, excluding the initial build-script executable.
    pub executables: Vec<Executable>,
    pub network: NetworkAccess,
}

/// Platform boundary for applying the complete build-script isolation policy.
///
/// Environment construction, output capture, and time limits are portable
/// execution concerns. This trait owns the OS-enforced filesystem, network,
/// and child-executable restrictions.
pub trait Sandbox {
    fn apply(&self, command: &mut Command, policy: &Policy) -> Result<()>;

    fn contract_version(&self) -> &'static str {
        CONTRACT_VERSION
    }
}

pub fn platform() -> impl Sandbox {
    PlatformSandbox
}

#[derive(Clone, Copy, Debug)]
struct PlatformSandbox;

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::Path;

    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

    const ACCESS_EXECUTE: u64 = 1 << 0;
    const ACCESS_WRITE_FILE: u64 = 1 << 1;
    const ACCESS_READ_FILE: u64 = 1 << 2;
    const ACCESS_READ_DIR: u64 = 1 << 3;
    const ACCESS_REMOVE_DIR: u64 = 1 << 4;
    const ACCESS_REMOVE_FILE: u64 = 1 << 5;
    const ACCESS_MAKE_CHAR: u64 = 1 << 6;
    const ACCESS_MAKE_DIR: u64 = 1 << 7;
    const ACCESS_MAKE_REG: u64 = 1 << 8;
    const ACCESS_MAKE_SOCK: u64 = 1 << 9;
    const ACCESS_MAKE_FIFO: u64 = 1 << 10;
    const ACCESS_MAKE_BLOCK: u64 = 1 << 11;
    const ACCESS_MAKE_SYM: u64 = 1 << 12;
    const ACCESS_REFER: u64 = 1 << 13;
    const ACCESS_TRUNCATE: u64 = 1 << 14;

    const READ_ACCESS: u64 = ACCESS_READ_FILE | ACCESS_READ_DIR;
    const WRITE_ACCESS: u64 = ACCESS_WRITE_FILE
        | ACCESS_REMOVE_DIR
        | ACCESS_REMOVE_FILE
        | ACCESS_MAKE_CHAR
        | ACCESS_MAKE_DIR
        | ACCESS_MAKE_REG
        | ACCESS_MAKE_SOCK
        | ACCESS_MAKE_FIFO
        | ACCESS_MAKE_BLOCK
        | ACCESS_MAKE_SYM
        | ACCESS_REFER
        | ACCESS_TRUNCATE;
    const HANDLED_ACCESS: u64 = ACCESS_EXECUTE | READ_ACCESS | WRITE_ACCESS;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
        _padding: u32,
    }

    struct Prepared {
        ruleset: OwnedFd,
        _paths: Vec<File>,
    }

    impl Sandbox for PlatformSandbox {
        fn apply(&self, command: &mut Command, policy: &Policy) -> Result<()> {
            if policy.network != NetworkAccess::Deny {
                return Err(Error::failure(
                    "Linux build-script sandbox received an unsupported network policy",
                ));
            }
            if let Some(executable) = policy
                .executables
                .iter()
                .find(|executable| !executable.argument_prefix.is_empty())
            {
                return Err(Error::failure(format!(
                    "Linux build-script sandbox cannot yet enforce the argument prefix for `{}`",
                    executable.path.display()
                ))
                .with_help(
                    "use an exact executable without a prefix until the tool broker is available",
                ));
            }

            let initial_program = canonical_file(Path::new(command.get_program()), "build script")?;
            let prepared = prepare(policy, &initial_program)?;
            // SAFETY: this closure calls only async-signal-safe syscalls, does
            // not allocate, and either installs the restrictions or makes the
            // child fail before exec.
            unsafe {
                command.pre_exec(move || {
                    install_no_new_privileges()?;
                    restrict_self(prepared.ruleset.as_raw_fd())?;
                    install_network_filter()?;
                    Ok(())
                });
            }
            Ok(())
        }
    }

    fn prepare(policy: &Policy, initial_program: &Path) -> Result<Prepared> {
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi < 0 {
            return Err(last_os_error("query Linux Landlock ABI"));
        }
        if abi < 3 {
            return Err(Error::failure(format!(
                "Linux Landlock ABI {abi} cannot enforce build-script truncation; ABI 3 or newer is required"
            )));
        }

        let attr = RulesetAttr {
            handled_access_fs: HANDLED_ACCESS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr,
                std::mem::size_of::<RulesetAttr>(),
                0,
            )
        };
        if fd < 0 {
            return Err(last_os_error("create Linux Landlock ruleset"));
        }
        // SAFETY: a successful syscall returned a new owned descriptor.
        let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let mut paths = Vec::new();

        for path in &policy.read_only {
            add_path_rule(&ruleset, path, READ_ACCESS, "read-only", &mut paths)?;
        }
        for path in &policy.writable {
            add_path_rule(
                &ruleset,
                path,
                READ_ACCESS | WRITE_ACCESS,
                "writable",
                &mut paths,
            )?;
        }
        add_path_rule(
            &ruleset,
            initial_program,
            READ_ACCESS | ACCESS_EXECUTE,
            "initial executable",
            &mut paths,
        )?;
        if let Some(interpreter) = elf_interpreter(initial_program)? {
            add_path_rule(
                &ruleset,
                &interpreter,
                READ_ACCESS | ACCESS_EXECUTE,
                "ELF interpreter",
                &mut paths,
            )?;
        }
        for executable in &policy.executables {
            let path = canonical_file(&executable.path, "approved executable")?;
            add_path_rule(
                &ruleset,
                &path,
                READ_ACCESS | ACCESS_EXECUTE,
                "approved executable",
                &mut paths,
            )?;
            if let Some(interpreter) = elf_interpreter(&path)? {
                add_path_rule(
                    &ruleset,
                    &interpreter,
                    READ_ACCESS | ACCESS_EXECUTE,
                    "ELF interpreter",
                    &mut paths,
                )?;
            }
        }
        Ok(Prepared {
            ruleset,
            _paths: paths,
        })
    }

    fn add_path_rule(
        ruleset: &OwnedFd,
        path: &Path,
        access: u64,
        description: &str,
        paths: &mut Vec<File>,
    ) -> Result<()> {
        let canonical = std::fs::canonicalize(path).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize sandbox {description} path `{}`: {error}",
                path.display()
            ))
        })?;
        let metadata = std::fs::metadata(&canonical).map_err(|error| {
            Error::failure(format!(
                "failed to inspect sandbox {description} path `{}`: {error}",
                canonical.display()
            ))
        })?;
        let access = if metadata.is_dir() {
            access
        } else if metadata.is_file() {
            access & (ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_WRITE_FILE | ACCESS_TRUNCATE)
        } else {
            return Err(Error::failure(format!(
                "sandbox {description} path `{}` is neither a regular file nor a directory",
                canonical.display()
            )));
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&canonical)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to open sandbox {description} path `{}`: {error}",
                    canonical.display()
                ))
            })?;
        let attr = PathBeneathAttr {
            allowed_access: access,
            parent_fd: file.as_raw_fd(),
            _padding: 0,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &attr,
                0,
            )
        };
        if result < 0 {
            return Err(last_os_error(&format!(
                "add Linux Landlock rule for `{}`",
                canonical.display()
            )));
        }
        paths.push(file);
        Ok(())
    }

    fn canonical_file(path: &Path, description: &str) -> Result<PathBuf> {
        let path = std::fs::canonicalize(path).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize sandbox {description} `{}`: {error}",
                path.display()
            ))
        })?;
        if !path.is_file() {
            return Err(Error::failure(format!(
                "sandbox {description} `{}` is not a regular file",
                path.display()
            )));
        }
        Ok(path)
    }

    fn elf_interpreter(path: &Path) -> Result<Option<PathBuf>> {
        let mut file = File::open(path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect sandbox executable `{}`: {error}",
                path.display()
            ))
        })?;
        let mut header = [0_u8; 64];
        file.read_exact(&mut header).map_err(|error| {
            Error::failure(format!(
                "failed to read sandbox executable `{}`: {error}",
                path.display()
            ))
        })?;
        if &header[..4] != b"\x7fELF" {
            return Ok(None);
        }
        if header[4] != 2 || header[5] != 1 {
            return Err(Error::failure(format!(
                "sandbox executable `{}` is not a little-endian 64-bit ELF file",
                path.display()
            )));
        }
        let program_offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
        let entry_size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as usize;
        let entry_count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as usize;
        if entry_size < 56 || entry_count > 1024 {
            return Err(Error::failure(format!(
                "sandbox executable `{}` has an invalid ELF program table",
                path.display()
            )));
        }
        let mut entry = vec![0_u8; entry_size];
        for index in 0..entry_count {
            file.seek(SeekFrom::Start(
                program_offset + (index.checked_mul(entry_size).unwrap()) as u64,
            ))
            .map_err(|error| {
                Error::failure(format!("failed to seek ELF program table: {error}"))
            })?;
            file.read_exact(&mut entry).map_err(|error| {
                Error::failure(format!("failed to read ELF program table: {error}"))
            })?;
            if u32::from_le_bytes(entry[0..4].try_into().unwrap()) != 3 {
                continue;
            }
            let offset = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let size = u64::from_le_bytes(entry[32..40].try_into().unwrap());
            if !(2..=4096).contains(&size) {
                return Err(Error::failure("ELF interpreter path has an invalid size"));
            }
            let mut bytes = vec![0_u8; size as usize];
            file.seek(SeekFrom::Start(offset)).map_err(|error| {
                Error::failure(format!("failed to seek ELF interpreter: {error}"))
            })?;
            file.read_exact(&mut bytes).map_err(|error| {
                Error::failure(format!("failed to read ELF interpreter: {error}"))
            })?;
            if bytes.pop() != Some(0) || bytes.contains(&0) {
                return Err(Error::failure("ELF interpreter path is malformed"));
            }
            let interpreter = std::str::from_utf8(&bytes)
                .map_err(|_| Error::failure("ELF interpreter path is not valid UTF-8"))?;
            return canonical_file(Path::new(interpreter), "ELF interpreter").map(Some);
        }
        Ok(None)
    }

    fn install_no_new_privileges() -> io::Result<()> {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn restrict_self(ruleset: i32) -> io::Result<()> {
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn install_network_filter() -> io::Result<()> {
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x15;
        const BPF_RET_K: u16 = 0x06;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

        let denied = [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_recvmmsg,
        ];
        let mut filters = Vec::with_capacity(denied.len() * 2 + 2);
        filters.push(libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        });
        for syscall in denied {
            filters.push(libc::sock_filter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: syscall as u32,
            });
            filters.push(libc::sock_filter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
            });
        }
        filters.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
        let program = libc::sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_mut_ptr(),
        };
        if unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn last_os_error(action: &str) -> Error {
        Error::failure(format!(
            "failed to {action}: {}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "motor")]
mod platform {
    use super::*;

    impl Sandbox for PlatformSandbox {
        fn apply(&self, _command: &mut Command, _policy: &Policy) -> Result<()> {
            eprintln!(
                "warning: Motor OS build-script sandbox is not implemented; continuing without isolation"
            );
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "motor")))]
mod platform {
    use super::*;

    impl Sandbox for PlatformSandbox {
        fn apply(&self, _command: &mut Command, _policy: &Policy) -> Result<()> {
            Err(Error::failure(
                "build-script sandbox is unsupported on this operating system",
            ))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        source: PathBuf,
        output: PathBuf,
        outside: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("lorry-sandbox-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let source = root.join("source");
            let output = root.join("output");
            let outside = root.join("outside");
            fs::create_dir_all(&source).unwrap();
            fs::create_dir_all(&output).unwrap();
            fs::create_dir_all(&outside).unwrap();
            fs::write(source.join("input"), b"input").unwrap();
            fs::write(outside.join("secret"), b"secret").unwrap();
            Self {
                root,
                source,
                output,
                outside,
            }
        }

        fn policy(&self) -> Policy {
            let mut read_only = vec![self.source.clone()];
            for path in ["/lib", "/lib64", "/usr/lib", "/etc/ld.so.cache"] {
                if PathBuf::from(path).exists() {
                    read_only.push(PathBuf::from(path));
                }
            }
            Policy {
                read_only,
                writable: vec![self.output.clone()],
                executables: Vec::new(),
                network: NetworkAccess::Deny,
            }
        }

        fn run(&self, action: &str, policy: &Policy) -> std::process::Output {
            let executable = std::env::current_exe().unwrap();
            let mut command = Command::new(executable);
            command
                .args(["--exact", "sandbox::tests::sandbox_child", "--nocapture"])
                .env_clear()
                .env("LORRY_SANDBOX_CHILD", action)
                .env("LORRY_SANDBOX_SOURCE", &self.source)
                .env("LORRY_SANDBOX_OUTPUT", &self.output)
                .env("LORRY_SANDBOX_OUTSIDE", &self.outside)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            platform().apply(&mut command, policy).unwrap();
            command.output().unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn linux_enforces_filesystem_network_and_exec_policy() {
        let fixture = Fixture::new();
        let policy = fixture.policy();
        for action in [
            "read-source",
            "write-output",
            "deny-source-write",
            "deny-outside-read",
            "deny-network",
            "deny-exec",
        ] {
            let output = fixture.run(action, &policy);
            assert!(
                output.status.success(),
                "{action}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut tool_policy = policy.clone();
        tool_policy.executables.push(Executable {
            path: PathBuf::from("/bin/true"),
            argument_prefix: Vec::new(),
        });
        let output = fixture.run("allow-exec", &tool_policy);
        assert!(
            output.status.success(),
            "allow-exec: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(fixture.output.join("generated")).unwrap(), b"ok");
        assert_eq!(fs::read(fixture.source.join("input")).unwrap(), b"input");
    }

    #[test]
    fn linux_rejects_unenforceable_argument_prefix() {
        let fixture = Fixture::new();
        let mut policy = fixture.policy();
        policy.executables.push(Executable {
            path: PathBuf::from("/bin/true"),
            argument_prefix: vec![OsString::from("fixed")],
        });
        let mut command = Command::new(std::env::current_exe().unwrap());
        assert!(platform().apply(&mut command, &policy).is_err());
    }

    #[test]
    fn sandbox_child() {
        let Ok(action) = std::env::var("LORRY_SANDBOX_CHILD") else {
            return;
        };
        let source = PathBuf::from(std::env::var_os("LORRY_SANDBOX_SOURCE").unwrap());
        let output = PathBuf::from(std::env::var_os("LORRY_SANDBOX_OUTPUT").unwrap());
        let outside = PathBuf::from(std::env::var_os("LORRY_SANDBOX_OUTSIDE").unwrap());
        match action.as_str() {
            "read-source" => assert_eq!(fs::read(source.join("input")).unwrap(), b"input"),
            "write-output" => fs::write(output.join("generated"), b"ok").unwrap(),
            "deny-source-write" => assert!(fs::write(source.join("input"), b"bad").is_err()),
            "deny-outside-read" => assert!(fs::read(outside.join("secret")).is_err()),
            "deny-network" => assert!(
                std::net::TcpStream::connect("127.0.0.1:9")
                    .is_err_and(|error| { error.kind() == std::io::ErrorKind::PermissionDenied })
            ),
            "deny-exec" => assert!(Command::new("/bin/true").status().is_err()),
            "allow-exec" => assert!(Command::new("/bin/true").status().unwrap().success()),
            _ => panic!("unknown sandbox child action {action}"),
        }
    }
}
