use moto_stats::{Collector, MetricEntry, ProviderInfo};
use moto_sys::caps::ProcessRole;
use moto_sys::stats::{ProcessInfoV1, PID_KERNEL, PID_SYSTEM};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Report some process stats.");
    eprintln!("Note 1: PPID = parent pid.");
    eprintln!("Note 2: System processes are marked with '*'; Interactive with '+'.");
    eprintln!("Note 3: V_USER/V_KERN count reserved user/kernel memory in 4 KiB pages.");
    eprintln!("        VIRT_KB is total reserved memory; RES_KB is its RAM backing, in KiB.");
    eprintln!(
        "        Untouched lazy pages, unbacked reservations, guards and MMIO use no RES_KB."
    );
    eprintln!(
        "        Shared pages count per mapping; kernel stacks also count in the kernel row."
    );
    eprintln!("        Totals are not unique RAM usage. Some boot mappings, fixed process-static");
    eprintln!("        pages and per-process kernel bookkeeping are outside this accounting.\n");
    eprintln!("usage:\n\tps [-H]\n");
    std::thread::sleep(std::time::Duration::new(0, 50_000_000));
    std::process::exit(exit_code);
}

const PS_BUF_SIZE: usize = 1024;

/// The kernel metric names `ps` renders as columns. They are resolved to ids at
/// runtime via the federated describe op, so `ps` never hardcodes metric ids and
/// keeps working as the kernel's metric set evolves.
mod metric_names {
    pub const ACTIVE_THREADS: &str = "active_threads";
    pub const THREADS_CREATED: &str = "threads_created";
    pub const ACTIVE_CHILDREN: &str = "active_children";
    pub const TOTAL_CHILDREN: &str = "total_children";
    pub const PAGES_USER: &str = "pages_user";
    pub const PAGES_KERNEL: &str = "pages_kernel";
    pub const MEMORY_USAGE: &str = "memory_usage";
    pub const MEMORY_RESIDENT: &str = "memory_resident";
    pub const CPU_USAGE: &str = "cpu_usage";
}

/// The kernel metric ids `ps` reads, resolved once (by name) per invocation.
struct ColumnIds {
    active_threads: u32,
    threads_created: u32,
    active_children: u32,
    total_children: u32,
    pages_user: u32,
    pages_kernel: u32,
    memory_usage: u32,
    memory_resident: u32,
    cpu_usage: u32,
}

/// A process row: its identity plus the metric values fetched for its scope.
#[derive(Default)]
struct ProcRow {
    ident: ProcessInfoV1,
    active_threads: u64,
    threads_created: u64,
    active_children: u64,
    total_children: u64,
    pages_user: u64,
    pages_kernel: u64,
    reserved_kbytes: u64,
    resident_kbytes: u64,
    cpu: u64, // raw cpu_usage, in tsc
}

fn resolve_column_ids(kernel: &ProviderInfo) -> ColumnIds {
    let descs = Collector::describe(kernel).unwrap_or_else(|err| {
        eprintln!("ps: failed to describe kernel metrics: {err:?}");
        std::process::exit(err as i32);
    });
    let find = |name: &str| -> u32 {
        descs
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.id)
            .unwrap_or_else(|| {
                eprintln!("ps: kernel metric '{name}' not found");
                std::process::exit(1);
            })
    };
    ColumnIds {
        active_threads: find(metric_names::ACTIVE_THREADS),
        threads_created: find(metric_names::THREADS_CREATED),
        active_children: find(metric_names::ACTIVE_CHILDREN),
        total_children: find(metric_names::TOTAL_CHILDREN),
        pages_user: find(metric_names::PAGES_USER),
        pages_kernel: find(metric_names::PAGES_KERNEL),
        memory_usage: find(metric_names::MEMORY_USAGE),
        memory_resident: find(metric_names::MEMORY_RESIDENT),
        cpu_usage: find(metric_names::CPU_USAGE),
    }
}

fn value_of(entries: &[MetricEntry], id: u32) -> u64 {
    entries
        .iter()
        .find(|e| e.metric == id)
        .map(|e| e.value)
        .unwrap_or(0)
}

pub fn do_command(args: &[String]) {
    let mut should_print_tree = false;
    if args.len() > 2 {
        print_usage_and_exit(1)
    }

    if args.len() == 2 {
        match args[1].as_str() {
            "-H" => should_print_tree = true,
            "--help" => print_usage_and_exit(0),
            _ => print_usage_and_exit(1),
        }
    }

    // The kernel is the (syscall-transport) provider of process metrics; resolve
    // the column metric ids by name once.
    let kernel = Collector::kernel();
    let ids = resolve_column_ids(&kernel);

    let mut idents: Vec<ProcessInfoV1> = vec![ProcessInfoV1::default(); PS_BUF_SIZE];
    let cnt = match ProcessInfoV1::list(PID_SYSTEM, &mut idents[..]) {
        Ok(cnt) => cnt,
        Err(err) => {
            eprintln!("PS failed.");
            std::process::exit(err as i32);
        }
    };
    idents.truncate(cnt);

    if cnt == PS_BUF_SIZE {
        // Ask for more.
        eprintln!("\nsysbox ps: implement paging.\n");
    }

    // Fetch each process's metric values via the federated kernel query (one
    // query per process, scoped to its pid).
    let mut rows: Vec<ProcRow> = Vec::with_capacity(idents.len());
    for ident in idents {
        let entries = Collector::query_scoped(&kernel, ident.pid).unwrap_or_default();
        rows.push(ProcRow {
            active_threads: value_of(&entries, ids.active_threads),
            threads_created: value_of(&entries, ids.threads_created),
            active_children: value_of(&entries, ids.active_children),
            total_children: value_of(&entries, ids.total_children),
            pages_user: value_of(&entries, ids.pages_user),
            pages_kernel: value_of(&entries, ids.pages_kernel),
            reserved_kbytes: value_of(&entries, ids.memory_usage) >> 10,
            resident_kbytes: value_of(&entries, ids.memory_resident) >> 10,
            cpu: value_of(&entries, ids.cpu_usage),
            ident,
        });
    }

    if rows.is_empty() {
        return;
    }

    let mut max_num = 123456u64;
    let mut total_cpu: u64 = 0;
    for row in &rows {
        max_num = max_num.max(row.ident.pid);
        max_num = max_num.max(row.ident.parent_pid);
        max_num = max_num.max(row.threads_created);
        max_num = max_num.max(row.total_children);
        max_num = max_num.max(row.reserved_kbytes).max(row.resident_kbytes);
        total_cpu += row.cpu;
    }

    // The first element (System) reports idle CPU; we show the sum of the rest
    // as its CPU.
    total_cpu -= rows[0].cpu;
    rows[0].cpu = total_cpu;

    let col_width = max_num.to_string().len().max("VIRT_KB".len());
    let cpu_width = (total_cpu / moto_sys::KernelStaticPage::get().tsc_in_sec)
        .to_string()
        .len()
        + 4;

    println!(
        "{:>w$}* {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>wsec$}  ST   Name",
        "PID",
        "PPID",
        "A_THR",
        "T_THR",
        "A_CHLD",
        "T_CHLD",
        "V_USER",
        "V_KERN",
        "VIRT_KB",
        "RES_KB",
        "CPU",
        w = col_width,
        wsec = cpu_width
    );

    if should_print_tree {
        print_tree(&rows, col_width, cpu_width);
        return;
    }

    for row in &rows {
        print_line(row, col_width, cpu_width, 0);
    }
}

fn print_line(row: &ProcRow, col_width: usize, cpu_width: usize, name_offset: usize) {
    let tsc_f64 = moto_sys::KernelStaticPage::get().tsc_in_sec as f64;
    let proc = &row.ident;

    println!(
        "{:>w$}{} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>w$} {:>cpu_width$.3} {} {:off$} {}",
        proc.pid,
        match ProcessRole::try_from(proc.process_role) {
            Ok(ProcessRole::System) => "*",
            Ok(ProcessRole::Interactive) => "+",
            Ok(ProcessRole::None) => " ",
            Err(()) => "?",
        },
        proc.parent_pid,
        row.active_threads,
        row.threads_created,
        row.active_children,
        row.total_children,
        row.pages_user,
        row.pages_kernel,
        row.reserved_kbytes,
        row.resident_kbytes,
        (row.cpu as f64) / tsc_f64,
        if proc.active == 1 { "RUN " } else { "DEAD" },
        "",
        proc.debug_name(),
        w = col_width,
        cpu_width = cpu_width,
        off = name_offset
    );
}

fn print_tree(rows: &[ProcRow], col_width: usize, cpu_width: usize) {
    assert!(rows.len() > 2);
    // TODO: construct a proper tree for printing, instead of doing
    // the inefficient thing below.

    // Assertions below are not part of the API, but for now they work.
    assert_eq!(rows[0].ident.pid, PID_SYSTEM);
    assert_eq!(rows[1].ident.pid, PID_KERNEL);

    print_line(&rows[0], col_width, cpu_width, 0);
    print_line(&rows[1], col_width, cpu_width, 0);

    print_subtree(rows, PID_KERNEL, col_width, cpu_width, 1);
}

fn print_subtree(
    rows: &[ProcRow],
    parent_pid: u64,
    col_width: usize,
    cpu_width: usize,
    sublevel: usize,
) {
    for row in rows {
        if row.ident.parent_pid != parent_pid {
            continue;
        }

        print_line(row, col_width, cpu_width, sublevel * 2);
        print_subtree(rows, row.ident.pid, col_width, cpu_width, sublevel + 1);
    }
}
