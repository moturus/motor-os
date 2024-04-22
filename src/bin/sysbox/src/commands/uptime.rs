pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "uptime");

    println!("{:?}", moto_sys::time::since_system_start());

    if args.len() > 1 {
        std::process::exit(1);
    }
}
