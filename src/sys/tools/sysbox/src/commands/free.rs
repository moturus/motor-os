fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Report PHYSICAL RAM available and used.");
    eprintln!("This is different from `ps`, which reports VIRTUAL RAM usage.");
    eprintln!("usage:\n\tfree [-(b|k|m|g)] [reclaim]\n");
    std::thread::sleep(std::time::Duration::new(0, 1_000_000));
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    if args.len() > 3 {
        print_usage_and_exit(-1)
    }

    let mut reclaim = false;
    if args.len() == 3 {
        if args[2].as_str() == "reclaim" {
            reclaim = true;
        } else {
            print_usage_and_exit(-1);
        }
    }

    let mut shift_bits = 0;
    let mut human_friendly = false;
    if args.len() > 1 {
        match args[1].as_str() {
            "-b" => {}
            "-h" => human_friendly = true,
            "--help" => print_usage_and_exit(0),
            "-k" => shift_bits = 10,
            "-m" => shift_bits = 20,
            "-g" => shift_bits = 30,
            "reclaim" => {
                if reclaim {
                    print_usage_and_exit(-1);
                } else {
                    reclaim = true;
                }
            }
            _ => print_usage_and_exit(1),
        }
    }
    if reclaim {
        moto_sys::SysMem::reclaim(moto_sys::syscalls::SysHandle::KERNEL).unwrap();
    }

    // Read memory via the unified stats collector (kernel provider) instead of a
    // direct syscall, so `free` consumes the same federated API that also serves
    // userspace providers like sys-io. Metrics are resolved by name — nothing is
    // hardcoded to a numeric id; the kernel describes its own metric set.
    use moto_stats::Collector;
    let kernel = Collector::kernel();
    let metrics = Collector::query(&kernel).unwrap_or_default();
    let descs = Collector::describe(&kernel).unwrap_or_default();
    let metric = |name: &str| {
        let Some(desc) = descs.iter().find(|d| d.name == name) else {
            return 0;
        };
        metrics
            .iter()
            .find(|e| e.metric == desc.id && e.scope == moto_stats::SCOPE_GLOBAL)
            .map(|e| e.value)
            .unwrap_or(0)
    };

    let total = metric("mem.available") >> shift_bits;
    let used = metric("mem.used") >> shift_bits;

    println!("               total         used         free        kheap    pages");

    if human_friendly {
        use crate::format_bytes;

        println!(
            "Mem:    {:>12} {:>12} {:>12} {:>12}    {}",
            format_bytes(total),
            format_bytes(used),
            format_bytes(total - used),
            format_bytes(metric("mem.heap_total")),
            metric("mem.used_pages"),
        );
    } else {
        println!(
            "Mem:    {:12} {:12} {:12} {:12}    {}",
            total,
            used,
            total - used,
            metric("mem.heap_total") >> shift_bits,
            metric("mem.used_pages"),
        );
    }
}
