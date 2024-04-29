fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tloop $CMD [args]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "loop");

    if args.len() < 2 {
        print_usage_and_exit(1);
    }

    crate::spawn_generic_input_listener();

    loop {
        let mut cmd = std::process::Command::new(args[1].as_str());

        for idx in 2..args.len() {
            cmd.arg(args[idx].as_str());
        }

        match cmd.spawn() {
            Ok(mut child) => {
                child.wait().ok(); // Don't break the loop on child errors.
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::InvalidFilename => {
                    eprintln!("{}: command not found.", args[1]);
                    return;
                }
                _ => {
                    eprintln!("Command [{}] failed with error: [{}].", args[1], e);
                    return;
                }
            },
        }
    }
}
