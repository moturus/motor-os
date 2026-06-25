use moto_stats::Collector;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Report process stats (via the federated stats collector).");
    eprintln!("usage:\n\tpstat $PID\n");
    eprintln!("Equivalent to: sysbox stats get kernel <metric> $PID");
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    if args.len() != 2 {
        print_usage_and_exit(1)
    }

    let pid = match args[1].as_str().parse::<u64>() {
        Ok(pid) => pid,
        Err(_) => print_usage_and_exit(1),
    };

    // Process metrics are kernel metrics scoped to the process's PID.
    let kernel = Collector::kernel();
    let entries = match Collector::query_scoped(&kernel, pid) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("pstat failed: {err:?}.");
            std::process::exit(err as i32);
        }
    };

    if entries.is_empty() {
        eprintln!("pstat: no such process: {pid}");
        std::process::exit(1);
    }

    // Names/units come from the kernel's metric catalog (best effort).
    let descs = Collector::describe(&kernel).unwrap_or_default();
    for e in &entries {
        let name = descs
            .iter()
            .find(|d| d.id == e.metric)
            .map(|d| d.name.as_str())
            .unwrap_or("?");
        println!("{name:>24} {}", e.value);
    }
}
