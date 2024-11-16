use moto_rt::time::Instant;
use moto_sys::stats::{CpuStatsV1, ProcessStatsV1};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    #[allow(unused)]
    Percent = 1,
    Total = 2,
    Diff = 3,
}

impl From<u32> for Mode {
    fn from(value: u32) -> Self {
        unsafe { core::mem::transmute(value) }
    }
}

static MODE: AtomicU32 = AtomicU32::new(1);

static SLEEP: AtomicU32 = AtomicU32::new(0);

struct Context {
    num_cpus: u32,
    stats_prev: CpuStatsV1,
    stats_now: CpuStatsV1,
    cmd_cache: HashMap<u64, String>,
    elapsed: Duration,
    mode: Mode,
}

fn hide_cursor() {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all("\x1b[?25l".as_bytes()).unwrap();
    stdout.flush().unwrap();
}

fn show_cursor() {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();

    stdout.write_all("\x1b[?25h".as_bytes()).unwrap();
    stdout.write_all("\x1b[1 q".as_bytes()).unwrap();
    stdout.flush().unwrap();
}

fn write_line(row: u32, line: &str) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();

    if row == 1 {
        stdout.write_all("\x1b[H".as_bytes()).unwrap(); // Move the cursor to 1:1 pos.
    } else {
        stdout
            .write_all(format!("\x1b[{};{}H", row, 1).as_bytes())
            .unwrap();
    }
    stdout.write_all(line.as_bytes()).unwrap();
    stdout.write_all("\x1b[K".as_bytes()).unwrap(); // Clear until the end of the line.
    stdout.flush().unwrap();
}

fn clear_remaining_screen() {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all("\x1b[0J".as_bytes()).unwrap(); // Clear screen.
    stdout.flush().unwrap();
}

fn print_preamble(ctx: &Context) -> u32 {
    let uptime = moto_rt::time::since_system_start();
    let seconds = uptime.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    let millis = uptime.subsec_millis();

    let mode = match ctx.mode {
        Mode::Percent => "%",
        Mode::Total => "sec",
        Mode::Diff => "msec",
    };

    write_line(
        1,
        &format!(
            "uptime: {:02}:{:02}:{:02}.{:03}  cpus: {}  processes: {}  mode: {}",
            hours,
            minutes,
            secs,
            millis,
            ctx.num_cpus,
            ctx.stats_now.num_entries() - 2,
            mode
        ),
    );

    write_line(2, "    press [space] to toggle, 'q' or [esc] to exit");

    2
}

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\ttop\n");
    std::process::exit(exit_code);
}

fn tsc_to_sec(tsc: u64) -> f64 {
    if tsc == 0 {
        return 0.0;
    }
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

    if cmd_cache.is_empty() {
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

fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            match *b {
                3 /* ^C */ | 27 /* esc */ | b'q' | b'Q' =>
                    { SLEEP.store(2, Ordering::Release);
                        moto_rt::futex::futex_wake(&SLEEP);
                    }
                b' ' => {
                    match MODE.load(Ordering::Acquire) {
                        1 => MODE.store(2, Ordering::Release),
                        2 => MODE.store(3, Ordering::Release),
                        3 => MODE.store(1, Ordering::Release),
                        _ => unreachable!()
                    }
                    SLEEP.store(1, Ordering::Release);
                        moto_rt::futex::futex_wake(&SLEEP);
                }
                _ => {}
            }
        }
    }
}

fn calc_column_widths(
    ctx: &Context,
    values: &HashMap<u64, Vec<(String, String)>>,
) -> (usize, usize, usize) {
    let num_cpus = ctx.stats_now.num_cpus();
    let num_entries = ctx.stats_now.num_entries();

    // Figure out column widths.
    let mut max_pid = 0;
    let mut max_len = 0;
    for idx in 0..num_entries {
        let entry = ctx.stats_now.entry(idx as usize);
        if entry.pid > max_pid {
            max_pid = entry.pid;
        }

        let line = values.get(&entry.pid).unwrap();
        for (k, u) in line {
            if k.len() > max_len {
                max_len = k.len();
            }
            if u.len() > max_len {
                max_len = u.len();
            }
        }
    }

    let num_cpus_len: usize = if num_cpus > 100 {
        3
    } else if num_cpus > 10 {
        2
    } else {
        1
    };

    let pid_width = max_pid.to_string().len().max(3);
    let num_width = max_len.max(num_cpus_len + 3);

    (pid_width, num_width, num_cpus_len)
}

// Go through stats, calculate the diff (if needed).
fn calc_values(ctx: &Context) -> HashMap<u64, Vec<(f64, f64)>> {
    let mut values = HashMap::new();

    // First pass: fill with abs values from stats_now.
    for idx in 0..ctx.stats_now.num_entries() {
        let entry = ctx.stats_now.entry(idx as usize);
        let mut line = Vec::new();

        for cpu in 0..ctx.stats_now.num_cpus() {
            line.push((
                tsc_to_sec(entry.percpu_entries[cpu as usize].kernel),
                tsc_to_sec(entry.percpu_entries[cpu as usize].uspace),
            ));
        }

        values.insert(entry.pid, line);
    }

    if ctx.mode == Mode::Total {
        return values; // Only absolute values are shown.
    }

    assert_eq!(ctx.stats_now.num_cpus(), ctx.stats_prev.num_cpus());

    // Second pass: calculate diffs.
    for idx in 0..ctx.stats_prev.num_entries() {
        let entry = ctx.stats_prev.entry(idx as usize);

        if let Some(line) = &mut values.get_mut(&entry.pid) {
            // Found a match.
            for cpu in 0..ctx.stats_prev.num_cpus() {
                line[cpu as usize].0 -= tsc_to_sec(entry.percpu_entries[cpu as usize].kernel);
                line[cpu as usize].1 -= tsc_to_sec(entry.percpu_entries[cpu as usize].uspace);
            }
        }
    }

    if ctx.mode == Mode::Diff {
        return values;
    }

    // Third pass: calculate % per CPU.
    let total_diff = ctx.elapsed.as_secs_f64();
    assert_ne!(total_diff, 0.0);

    for line in values.values_mut() {
        for (k, u) in line {
            *k /= total_diff;
            *u /= total_diff;
        }
    }

    values
}

fn format_value(ctx: &Context, val: f64) -> String {
    let empty = "-";
    match ctx.mode {
        Mode::Percent => {
            let res = format!("{:.3}", val * 100.0);
            if res.as_str() == "0.000" {
                empty.to_owned()
            } else {
                res
            }
        }
        Mode::Total => {
            let res = format!("{:.3}", val);
            if res.as_str() == "0.000" {
                empty.to_owned()
            } else {
                res
            }
        }

        Mode::Diff => {
            let res = format!("{:.0}", val * 1000.0);
            if res.as_str() == "0" {
                empty.to_owned()
            } else {
                res
            }
        }
    }
}

fn format_values(
    ctx: &Context,
    values_f64: HashMap<u64, Vec<(f64, f64)>>,
) -> HashMap<u64, Vec<(String, String)>> {
    let mut values = HashMap::new();

    for (pid, line_f64) in &values_f64 {
        let mut line = Vec::new();

        for (k, u) in line_f64 {
            line.push((format_value(ctx, *k), format_value(ctx, *u)));
        }

        values.insert(*pid, line);
    }

    values
}

fn tick(ctx: &mut Context) {
    hide_cursor();
    let mut row = print_preamble(ctx);
    let values_f64 = calc_values(ctx);
    let values = format_values(ctx, values_f64);

    let (pid_width, num_width, num_cpus_len) = calc_column_widths(ctx, &values);

    let num_cpus = ctx.stats_now.num_cpus();
    let num_entries = ctx.stats_now.num_entries();

    let mut header = format!("{:>w$}  * ", "PID", w = pid_width);
    for cpu in 0..num_cpus {
        header += &format!(" {:>w$}{}", "CPU", cpu, w = (num_width - num_cpus_len));
    }
    header += "  COMMAND";

    let mut border = String::new();
    for _ in 0..(header.len() + 10) {
        border += "-";
    }

    row += 1;
    write_line(row, border.as_str());
    row += 1;
    write_line(row, header.as_str());
    row += 1;
    write_line(row, border.as_str());

    for idx in 0..num_entries {
        let entry_now = ctx.stats_now.entry(idx as usize);

        let mut line_k = format!("{:>w$}  k ", entry_now.pid, w = pid_width);

        let line = values.get(&entry_now.pid).unwrap();

        for cpu in 0..num_cpus {
            line_k += &format!(" {:>w$}", line[cpu as usize].0, w = num_width);
        }

        line_k += &format!("  {}", get_cmd_string(&mut ctx.cmd_cache, entry_now.pid));
        row += 1;
        write_line(row, line_k.as_str());

        if entry_now.pid == moto_sys::stats::PID_SYSTEM {
            continue;
        }
        if entry_now.pid == moto_sys::stats::PID_KERNEL {
            continue;
        }

        let mut line_u = format!("{:>w$}  u ", " ", w = pid_width);

        for cpu in 0..num_cpus {
            line_u += &format!(" {:>w$}", line[cpu as usize].1, w = num_width);
        }

        row += 1;
        write_line(row, line_u.as_str());
    }

    write_line(row + 1, "");
    clear_remaining_screen();
    show_cursor();
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "top");

    if args.len() != 1 {
        print_usage_and_exit(1);
    }

    std::thread::spawn(input_listener);
    let cmd_cache: HashMap<u64, String> = HashMap::new();

    let stats_prev = CpuStatsV1::new();
    let mut tick_prev = Instant::now();

    std::thread::sleep(Duration::new(0, 100_000_000));
    let stats_now = CpuStatsV1::new();
    let mut tick_now = Instant::now();

    let mut ctx = Context {
        num_cpus: stats_now.num_cpus(),
        stats_prev,
        stats_now,
        cmd_cache,
        elapsed: tick_now.duration_since(tick_prev),
        mode: MODE.load(Ordering::Relaxed).into(),
    };

    loop {
        tick(&mut ctx);

        moto_rt::futex::futex_wait(&SLEEP, 0, Some(Duration::new(1, 0)));
        let sleep = SLEEP.load(Ordering::Acquire);
        if sleep == 2 {
            std::process::exit(0);
        } else if sleep == 1 {
            SLEEP.store(0, Ordering::Release);
        }

        core::mem::swap(&mut ctx.stats_prev, &mut ctx.stats_now);
        tick_prev = tick_now;

        ctx.stats_now.tick();
        tick_now = Instant::now();
        ctx.elapsed = tick_now.duration_since(tick_prev);
        ctx.mode = MODE.load(Ordering::Acquire).into();
    }
}
