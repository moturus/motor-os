fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tkill PID\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    if args.len() != 2 {
        print_usage_and_exit(1);
    }
    if args[1] == "--help" {
        print_usage_and_exit(0);
    }
    let pid = match args[1].parse::<u64>() {
        Ok(pid) => pid,
        Err(_) => print_usage_and_exit(1),
    };

    // Motor OS terminates a process directly; it has no POSIX signals.
    if let Err(err) = moto_sys::SysCpu::kill_pid(pid) {
        let reason = match err {
            moto_rt::E_INVALID_ARGUMENT | moto_rt::E_NOT_FOUND => "no such process".to_string(),
            moto_rt::E_NOT_ALLOWED => "operation not permitted".to_string(),
            _ => moto_rt::Error::from(err).to_string(),
        };
        eprintln!("kill: {pid}: {reason}");
        std::process::exit(1);
    }
}
