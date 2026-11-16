use moto_sys::caps::*;
use moto_sys::stats::ProcessInfoV1;

const CAP_NAMES: [(u64, &str); 10] = [
    (CAP_SYS, "CAP_SYS"),
    (CAP_IO_MANAGER, "CAP_IO_MANAGER"),
    (CAP_SPAWN, "CAP_SPAWN"),
    (CAP_LOG, "CAP_LOG"),
    (CAP_SHUTDOWN, "CAP_SHUTDOWN"),
    (CAP_SPAWN_DETACHED, "CAP_SPAWN_DETACHED"),
    (CAP_INTERACTIVE, "CAP_INTERACTIVE"),
    (CAP_VSOCK, "CAP_VSOCK"),
    (CAP_NET, "CAP_NET"),
    (CAP_FS_WRITE, "CAP_FS_WRITE"),
];

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Print process capabilities.");
    eprintln!("usage:\n\tcaps [PID]\n");
    eprintln!("Without PID, prints the capabilities of the parent process.");
    std::process::exit(exit_code);
}

/// Formats a mask as "0x304 = CAP_SPAWN | CAP_NET | CAP_FS_WRITE".
/// Bits without a name are shown together as one hex value.
pub fn format_caps(caps: u64) -> String {
    let mut names: Vec<String> = CAP_NAMES
        .iter()
        .filter(|(bit, _)| caps & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect();
    let unknown = caps & !CAP_NAMES.iter().fold(0, |all, (bit, _)| all | bit);
    if unknown != 0 {
        names.push(format!("{unknown:#x}"));
    }
    if names.is_empty() {
        names.push("(none)".to_string());
    }
    format!("{caps:#x} = {}", names.join(" | "))
}

fn process_info(pid: u64) -> Option<ProcessInfoV1> {
    let mut info = [ProcessInfoV1::default()];
    // The listing starts at the first process at or after `pid`.
    match ProcessInfoV1::list(pid, &mut info) {
        Ok(1) if info[0].pid == pid => Some(info[0]),
        _ => None,
    }
}

fn fail(msg: String) -> ! {
    eprintln!("caps: {msg}");
    std::process::exit(1);
}

pub fn do_command(args: &[String]) {
    let pid = match args.len() {
        1 => {
            let own_pid = moto_sys::ProcessStaticPage::get().pid;
            match process_info(own_pid) {
                Some(info) => info.parent_pid,
                None => fail(format!("cannot find own process {own_pid}")),
            }
        }
        2 => match args[1].parse::<u64>() {
            Ok(pid) => pid,
            Err(_) => print_usage_and_exit(1),
        },
        _ => print_usage_and_exit(1),
    };

    let Some(info) = process_info(pid) else {
        fail(format!("no such process: {pid}"));
    };
    // The kernel reports no capabilities once a process has exited.
    if info.active == 0 {
        fail(format!("process {pid} has exited"));
    }
    println!(
        "PID {pid}: capabilities: {}",
        format_caps(info.capabilities)
    );
}
