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

    let mut num_sockets = 0;
    let mut last_socket_id = 0;

    loop {
        let stats = svc.get_tcp_socket_stats(last_socket_id).unwrap();
        if stats.is_empty() {
            break;
        }

        for stat in stats {
            println!("{stat:?}");
        }

        num_sockets += stats.len();
        last_socket_id = stats[stats.len() - 1].id + 1;
    }

    println!("\nss: {num_sockets} sockets");
}
