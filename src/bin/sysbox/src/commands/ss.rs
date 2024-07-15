fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tss\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "ss");

    if args.len() > 1 {
        print_usage_and_exit(1);
    }

    let mut svc = moto_sys_io::stats::IoStatsService::connect().unwrap();
    let stats = svc.get_tcp_socket_stats(0).unwrap();

    for stat in stats {
        println!("{:?}", stat);
    }
}
