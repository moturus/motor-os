fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tkill $PID\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "kill");

    if args.len() != 2 {
        print_usage_and_exit(1);
    }

    let arg_str = args[1].as_str();
    if arg_str == "--help" {
        print_usage_and_exit(0);
    }

    let pid = match arg_str.parse::<u64>() {
        Ok(pid) => pid,
        Err(_) => print_usage_and_exit(1),
    };

    if let Err(err) = moto_sys::syscalls::SysCpu::kill_pid(pid) {
        eprintln!("kill failed: {:?}", err);
    }
}
