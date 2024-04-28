fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\ttop\n");
    std::process::exit(exit_code);
}

fn tsc_to_sec(tsc: u64) -> f64 {
    let tsc_in_sec = moto_sys::KernelStaticPage::get().tsc_in_sec as f64;
    (tsc as f64) / tsc_in_sec
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "top");

    if args.len() != 1 {
        print_usage_and_exit(1);
    }

    let stats = moto_sys::stats::CpuStatsV1::new();
    let num_cpus = stats.num_cpus();
    let num_entries = stats.num_entries();

    // Figure out column widths.
    let mut max_pid = 0;
    let mut max_tsc = 0;
    for idx in 0..num_entries {
        let entry = stats.entry(idx as usize);
        if entry.pid > max_pid {
            max_pid = entry.pid;
        }

        for cpu in 0..num_cpus {
            let k = entry.percpu_entries[cpu as usize].kernel;
            let u = entry.percpu_entries[cpu as usize].uspace;
            max_tsc = max_tsc.max(k);
            max_tsc = max_tsc.max(u);
        }
    }

    let max_sec = tsc_to_sec(max_tsc);
    let pid_width = max_pid.to_string().len();
    let sec_width = format!("{:.3}", max_sec).len();

    let mut header = format!("{:>w$}   ", "pid", w = pid_width);
    for cpu in 0..num_cpus {
        header += &format!(" {:>w$}", cpu, w = sec_width);
    }

    for idx in 0..num_entries {
        let entry = stats.entry(idx as usize);
        let mut line_k = format!("{:>w$} k ", entry.pid, w = pid_width);

        for cpu in 0..num_cpus {
            line_k += &format!(
                " {:>w$.3}",
                tsc_to_sec(entry.percpu_entries[cpu as usize].kernel),
                w = sec_width
            );
        }

        println!("{}", line_k);

        let mut line_u = format!("{:>w$} u ", " ", w = pid_width);

        for cpu in 0..num_cpus {
            line_u += &format!(
                " {:>w$.3}",
                tsc_to_sec(entry.percpu_entries[cpu as usize].uspace),
                w = sec_width
            );
        }

        println!("{}", line_u);
    }
}
