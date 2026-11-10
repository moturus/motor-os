use moto_sys::caps::*;
use moto_sys::stats::ProcessInfoV1;
use moto_sys::syscalls::{SYS_RAY, SyscallResult, do_syscall};
use moto_sys::{ProcessStaticPage, SysRay};

fn query_cmdline(version: u16, flags: u32, args: [u64; 6]) -> SyscallResult {
    let nr = (u64::from(SYS_RAY) << 56)
        | (u64::from(SysRay::OP_QUERY_CMDLINE) << 48)
        | (u64::from(flags) << 16)
        | u64::from(version);
    do_syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5])
}

pub fn cmdline_denied(role: ProcessRole) {
    assert_eq!(
        ProcessRole::from_caps(ProcessStaticPage::get().capabilities),
        role
    );
    let mut buf = [0xa5; 16];
    assert_eq!(SysRay::query_cmdline(&mut buf), Err(moto_rt::E_NOT_ALLOWED));
    assert_eq!(buf, [0xa5; 16]);
    assert_eq!(SysRay::query_cmdline(&mut []), Err(moto_rt::E_NOT_ALLOWED));
    // Access is refused before touching even an invalid caller buffer.
    assert_eq!(
        query_cmdline(0, 0, [u64::MAX, 1, 0, 0, 0, 0]).error_code(),
        moto_rt::E_NOT_ALLOWED
    );
}

pub fn cmdline(expected: Option<&[u8]>) {
    assert_ne!(ProcessStaticPage::get().capabilities & CAP_SYS, 0);
    let (written, len) = SysRay::query_cmdline(&mut []).unwrap();
    assert_eq!(written, 0);
    assert!(len <= SysRay::MAX_CMDLINE_LEN);
    let mut buf = [0xa5; SysRay::MAX_CMDLINE_LEN + 1];
    assert_eq!(SysRay::query_cmdline(&mut buf), Ok((len, len)));
    assert!(buf[len..].iter().all(|byte| *byte == 0xa5));
    assert!(!buf[..len].contains(&0));
    if let Some(expected) = expected {
        assert_eq!(&buf[..len], expected);
    }
    let mut prefix = [0xa5; 1];
    assert_eq!(SysRay::query_cmdline(&mut prefix), Ok((len.min(1), len)));
    assert_eq!(&prefix[..len.min(1)], &buf[..len.min(1)]);
    assert_eq!(
        query_cmdline(1, 0, [0; 6]).error_code(),
        moto_rt::E_VERSION_TOO_HIGH
    );
    assert_eq!(
        query_cmdline(0, 1, [0; 6]).error_code(),
        moto_rt::E_INVALID_ARGUMENT
    );
    for arg in 2..6 {
        let mut args = [0; 6];
        args[arg] = 1;
        assert_eq!(
            query_cmdline(0, 0, args).error_code(),
            moto_rt::E_INVALID_ARGUMENT
        );
    }
    if len != 0 {
        assert_eq!(
            query_cmdline(0, 0, [u64::MAX, 1, 0, 0, 0, 0]).error_code(),
            moto_rt::E_INVALID_ARGUMENT
        );
    }
    println!("kernel command-line query PASS");
}

// The debugger can read a sibling's immutable process page without stopping
// it. Run this check over SSH, since sys-tty cannot be a debugger's ancestor.
fn capabilities(pid: u64) -> u64 {
    let debug = SysRay::dbg_attach(pid).unwrap();
    let mut bytes = [0; 8];
    let result = SysRay::dbg_get_mem(
        debug,
        ProcessStaticPage::VADDR + core::mem::offset_of!(ProcessStaticPage, capabilities) as u64,
        &mut bytes,
    );
    SysRay::dbg_detach(debug).unwrap();
    assert_eq!(result, Ok(bytes.len()));
    u64::from_ne_bytes(bytes)
}

pub fn console(system_tty: bool) {
    cmdline_denied(ProcessRole::Interactive);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("boot-cmdline-denied")
        .env(MOTOR_OS_CAPS_ENV_KEY, "0x0")
        .status()
        .unwrap();
    assert!(child.success());
    let role = if system_tty {
        ProcessRole::System
    } else {
        ProcessRole::Interactive
    };
    let role_cap = if system_tty { CAP_SYS } else { CAP_INTERACTIVE };
    let mut processes = [ProcessInfoV1::default(); 128];
    let count = ProcessInfoV1::list(0, &mut processes).unwrap();
    assert!(count < processes.len());
    let processes = &processes[..count];
    let active = |name| {
        processes
            .iter()
            .find(|p| p.active != 0 && p.debug_name() == name)
            .unwrap()
    };
    let tty = active("/system/services/sys-tty");
    let shell = processes
        .iter()
        .find(|p| {
            p.active != 0
                && p.parent_pid == tty.pid
                && p.debug_name().starts_with("/system/bin/rush")
        })
        .unwrap();
    let expected_shell = role_cap | CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED | PARENT_OWNED_CAPS;
    assert_eq!(capabilities(tty.pid), expected_shell | CAP_IO_MANAGER);
    assert_eq!(capabilities(shell.pid), expected_shell);
    assert_eq!(tty.process_role, role as u8);
    assert_eq!(shell.process_role, role as u8);
    for (name, expected) in [
        ("/system/services/strobe", ProcessRole::System),
        ("/system/services/dns-resolver", ProcessRole::Interactive),
    ] {
        assert_eq!(active(name).process_role, expected as u8);
    }
    assert_eq!(
        ProcessRole::from_caps(ProcessStaticPage::get().capabilities),
        ProcessRole::Interactive
    );
    println!("boot console: {role:?} PASS");
}

pub fn no_network() {
    // The standard image configures this address on its NIC. With no device
    // the address cannot be bound, but the configured loopback still works.
    let error = std::net::UdpSocket::bind("192.168.4.2:0").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(socket.local_addr().unwrap().ip().is_loopback());
    println!("boot without network device PASS");
}
