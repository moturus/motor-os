fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tmkdir [$DIR]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "mkdir");

    if args.len() != 2 {
        print_usage_and_exit(1);
    }

    if let Err(err) = std::fs::create_dir(std::path::Path::new(&args[1])) {
        eprintln!("mkdir failed: {err:?}");
    }
}
