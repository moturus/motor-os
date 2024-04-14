fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tsleep $number\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "sleep");

    if args.len() != 2 {
        print_usage_and_exit(1);
    }

    match args[1].parse::<u64>() {
        Ok(secs) => std::thread::sleep(std::time::Duration::new(secs, 0)),
        Err(_) => print_usage_and_exit(1),
    }
}
