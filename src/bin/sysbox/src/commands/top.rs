use std::collections::HashMap;

use moto_sys::stats::ProcessStatsV1;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\ttop\n");
    std::process::exit(exit_code);
}

fn tsc_to_sec(tsc: u64) -> f64 {
    let tsc_in_sec = moto_sys::KernelStaticPage::get().tsc_in_sec as f64;
    (tsc as f64) / tsc_in_sec
}

fn get_cmd_string(cmd_cache: &mut HashMap<u64, String>, pid: u64) -> String {
    if pid == moto_sys::stats::PID_SYSTEM {
        return "(idle)".to_owned();
    }
    if pid == moto_sys::stats::PID_KERNEL {
        return "kernel".to_owned();
    }
    if pid == moto_sys::stats::PID_SYS_IO {
        return "sys-io".to_owned();
    }

    fn update_cache(cmd_cache: &mut HashMap<u64, String>, pid: u64) {
        const MAX_PROCS: usize = 256;
        let mut processes: Vec<ProcessStatsV1> = Vec::with_capacity(MAX_PROCS);
        for _ in 0..MAX_PROCS {
            processes.push(ProcessStatsV1::default());
        }

        ProcessStatsV1::list(pid, &mut processes[..]).unwrap();
        for stats in &processes {
            cmd_cache.insert(stats.pid, stats.debug_name().to_owned());
        }
    }

    if cmd_cache.len() == 0 {
        update_cache(cmd_cache, moto_sys::stats::PID_SYSTEM);
    }

    if let Some(cmd) = cmd_cache.get(&pid) {
        return cmd.clone();
    }

    update_cache(cmd_cache, pid);
    if let Some(cmd) = cmd_cache.get(&pid) {
        return cmd.clone();
    }

    "(???)".to_owned()
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "top");

    if args.len() != 1 {
        print_usage_and_exit(1);
    }

    let mut cmd_cache: HashMap<u64, String> = HashMap::new();

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

    let num_cpus_len: usize = if num_cpus > 100 {
        3
    } else if num_cpus > 10 {
        2
    } else {
        1
    };

    let max_sec = tsc_to_sec(max_tsc);
    let pid_width = max_pid.to_string().len().max(3);
    let sec_width = format!("{:.3}", max_sec).len().max(num_cpus_len + 3);

    let mut header = format!("{:>w$}  * ", "pid", w = pid_width);
    for cpu in 0..num_cpus {
        header += &format!(" {:>w$}{}", "CPU", cpu, w = (sec_width - num_cpus_len));
    }
    header += " command";

    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all("\x1b[2J".as_bytes()).unwrap(); // Clear screen.
    stdout.write_all("\x1b[H".as_bytes()).unwrap(); // Move the cursor to 1:1 pos.
    stdout.flush().unwrap();

    println!("{}", header);
    // let mut border = String::new();
    // for _ in 0..header.len() {
    //     border += "-";
    // }
    // println!("{border}");

    for idx in 0..num_entries {
        let entry = stats.entry(idx as usize);
        let mut line_k = format!("{:>w$}  k ", entry.pid, w = pid_width);

        for cpu in 0..num_cpus {
            line_k += &format!(
                " {:>w$.3}",
                tsc_to_sec(entry.percpu_entries[cpu as usize].kernel),
                w = sec_width
            );
        }

        line_k += &format!(" {}", get_cmd_string(&mut cmd_cache, entry.pid));

        println!("{}", line_k);

        if entry.pid == moto_sys::stats::PID_SYSTEM {
            continue;
        }
        if entry.pid == moto_sys::stats::PID_KERNEL {
            continue;
        }

        let mut line_u = format!("{:>w$}  u ", " ", w = pid_width);

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
