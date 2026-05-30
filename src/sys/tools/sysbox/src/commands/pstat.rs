use moto_sys::stats::{MetricType, ProcessStatsV1};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Report process stats.");
    eprintln!("usage:\n\tpstat $PPID\n");
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    if args.len() != 2 {
        print_usage_and_exit(1)
    }

    let pid = if args.len() == 2 {
        match args[1].as_str().parse::<u64>() {
            Ok(pid) => pid,
            Err(_) => print_usage_and_exit(1),
        }
    } else {
        print_usage_and_exit(1)
    };

    let mut stats = ProcessStatsV1::default();
    let cnt = match ProcessStatsV1::list(pid, std::slice::from_mut(&mut stats)) {
        Ok(cnt) => cnt,
        Err(err) => {
            eprintln!("pstat failed: {err:?}.");
            std::process::exit(err as i32);
        }
    };

    assert_eq!(cnt, 1);

    for idx in 0..(MetricType::TotalMetricTypes as usize) {
        let metric = MetricType::from_idx(idx);
        let val = stats.metrics[idx];
        println!("{:>24} {val}", format!("{metric:?}"));
    }
}
