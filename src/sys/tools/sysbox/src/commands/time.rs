fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\ttime $CMD [args]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "time");

    if args.len() < 2 {
        print_usage_and_exit(1);
    }

    let mut cmd = std::process::Command::new(args[1].as_str());

    for arg in &args[2..] {
        cmd.arg(arg);
    }

    let start = std::time::Instant::now();
    match cmd.spawn() {
        Ok(mut child) => {
            child.wait().ok();
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::InvalidFilename => {
                println!("{}: command not found.", args[1]);
                return;
            }
            _ => {
                println!("Command [{}] failed with error: [{}].", args[1], e);
                return;
            }
        },
    }
    let stop = std::time::Instant::now();
    let duration = stop.duration_since(start);

    let secs = duration.as_secs();
    let millis = duration.as_millis() % 1000;
    let minutes = secs / 60;
    let secs = secs % 60;

    println!("\nreal  {minutes}m{secs}.{millis:03}s");
}
