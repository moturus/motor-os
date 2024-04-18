use moto_sys::stats::{ProcessStatsV1, PID_KERNEL, PID_SYSTEM};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Report some process stats.");
    eprintln!("Note 1: PPID = parent pid.");
    eprintln!("Note 2: Memory usage here is virtual memory used per process.");
    eprintln!("        Kernel memory usage is a bit underreported, as some bootup memory is not captured.");
    eprintln!("        Process memory usage captures shared memory, meaning that total/cumulative");
    eprintln!("        virtual memory usage is higher than actual physical memory usage.");
    eprintln!("        Lazily mapped virtual memory (e.g. stacks) is included here, which also");
    eprintln!("        leads to overstating virtual memory usage vs physical memory usage.");
    eprintln!("usage:\n\tps [-H]\n");
    std::thread::sleep(std::time::Duration::new(0, 1_000_000));
    std::process::exit(exit_code);
}

const PS_BUF_SIZE: usize = 1024;

pub fn do_command(args: &[String]) {
    let mut should_print_tree = false;
    if args.len() > 2 {
        print_usage_and_exit(1)
    }

    if args.len() == 2 {
        match args[1].as_str() {
            "-H" => should_print_tree = true,
            _ => print_usage_and_exit(1),
        }
    }

    let mut processes: Vec<ProcessStatsV1> = Vec::with_capacity(PS_BUF_SIZE);
    for _ in 0..PS_BUF_SIZE {
        processes.push(ProcessStatsV1::default());
    }

    let cnt = match ProcessStatsV1::list(PID_SYSTEM, &mut processes[..]) {
        Ok(cnt) => cnt,
        Err(err) => {
            eprintln!("PS failed.");
            std::process::exit(err as u16 as i32);
        }
    };

    if cnt == PS_BUF_SIZE {
        // Ask for more.
        eprintln!("\nsysbox ps: implement paging.\n");
    }

    let mut max_num = 123456;
    for proc in &processes[0..cnt] {
        max_num = max_num.max(proc.pid);
        max_num = max_num.max(proc.parent_pid);
        max_num = max_num.max(proc.total_threads);
        max_num = max_num.max(proc.total_children);
        max_num = max_num.max(proc.total_bytes() >> 10)
    }

    let col_width = max_num.to_string().len();

    println!(
        "{:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:<w$} ST   Name",
        "PID",
        "PPID",
        "A_THR",
        "T_THR",
        "A_CHLD",
        "T_CHLD",
        "P_USER",
        "P_KERN",
        "KBYTES",
        w = col_width
    );

    if should_print_tree {
        print_tree(&processes[0..cnt], col_width);
        return;
    }

    for proc in &processes[0..cnt] {
        print_line(proc, col_width, 0);
    }
}

fn print_line(proc: &ProcessStatsV1, col_width: usize, name_offset: usize) {
    println!(
        "{:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {} {:off$} {}",
        proc.pid,
        proc.parent_pid,
        proc.active_threads,
        proc.total_threads,
        proc.active_children,
        proc.total_children,
        proc.pages_user,
        proc.pages_kernel,
        proc.total_bytes() >> 10,
        if proc.active == 1 { "RUN " } else { "DEAD" },
        "",
        proc.debug_name(),
        w = col_width,
        off = name_offset
    );
}

fn print_tree(processes: &[ProcessStatsV1], col_width: usize) {
    assert!(processes.len() > 2);
    // TODO: construct a proper tree for printing, instead of doing
    // the inefficient thing below.

    // Assertions below are not part of the API, but for now they work.
    assert_eq!(processes[0].pid, PID_SYSTEM);
    assert_eq!(processes[1].pid, PID_KERNEL);

    print_line(&processes[0], col_width, 0);
    print_line(&processes[1], col_width, 0);

    print_subtree(processes, PID_KERNEL, col_width, 1);
}

fn print_subtree(processes: &[ProcessStatsV1], parent_pid: u64, col_width: usize, sublevel: usize) {
    for proc in processes {
        if proc.parent_pid != parent_pid {
            continue;
        }

        print_line(proc, col_width, sublevel * 2);
        print_subtree(processes, proc.pid, col_width, sublevel + 1);
    }
}
